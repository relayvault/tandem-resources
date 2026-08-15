#requires -Version 5.1
<#
.SYNOPSIS
    Read-only preflight checks for a Relay Vault edge-agent installation.

.DESCRIPTION
    This script reports host, Node.js, local MariaDB/Open Dental, grants,
    outbound TLS, DPAPI, Windows Service, and antivirus readiness. It does not
    install software, change the registry, register a service, write files, or
    send credentials. The only file it can write is the path supplied to
    -OutFile.

    Database checks that need credentials use a PSCredential and only query
    server metadata, schema presence, Open Dental version preferences, and
    grants. Patient tables are never queried.

.PARAMETER DbCredential
    Optional PSCredential for the local MariaDB account. The password is held
    in memory only and is never printed or passed as a command-line argument.

.EXAMPLE
    .\Test-RelayVaultPrereqs.ps1

.EXAMPLE
    $cred = Get-Credential
    .\Test-RelayVaultPrereqs.ps1 -DbCredential $cred -DbName opendental `
        -OutFile C:\Temp\relay-vault-doctor.txt
#>

[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    "PSReviewUnusedParameter",
    "",
    Justification = "Script parameters are consumed by helper functions."
)]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutFile,

    [Parameter(Mandatory = $false)]
    [string]$DbHost = "127.0.0.1",

    [Parameter(Mandatory = $false)]
    [int]$DbPort = 3306,

    [Parameter(Mandatory = $false)]
    [string]$DbName = "opendental",

    [Parameter(Mandatory = $false)]
    [PSCredential]$DbCredential,

    [Parameter(Mandatory = $false)]
    [string]$RelayVaultUrl = "https://relay-vault.onrender.com",

    [Parameter(Mandatory = $false)]
    [string]$InstallDirectory = "C:\Program Files\Relay Vault",

    [Parameter(Mandatory = $false)]
    [string]$ServiceName = "RelayVaultEdgeAgent"
)

Set-StrictMode -Version 2.0

$script:ReportLines = @()
$script:Statuses = @()
$script:CertificateSubject = $null
$script:CertificateIssuer = $null
$script:CertificateErrors = $null

function Format-OneLine {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return ""
    }

    $text = [string]$Value
    $text = $text -replace "[\r\n\t]+", " "
    if ($text.Length -gt 220) {
        return $text.Substring(0, 220) + "..."
    }
    return $text
}

function Format-OneLineUnbounded {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return ""
    }

    return ([string]$Value -replace "[\r\n\t]+", " ")
}

function Add-Check {
    param(
        [string]$Name,
        [ValidateSet("Pass", "Fail", "Warn", "Unknown")]
        [string]$Status,
        [string]$Explanation
    )

    $line = "[{0}] {1}: {2}" -f $Status.ToUpperInvariant(), $Name, (Format-OneLine $Explanation)
    $script:ReportLines += $line
    $script:Statuses += $Status
}

function Add-CheckLine {
    param(
        [string]$Name,
        [ValidateSet("Pass", "Fail", "Warn", "Unknown")]
        [string]$Status,
        [string]$Explanation
    )

    $line = "[{0}] {1}: {2}" -f $Status.ToUpperInvariant(), $Name, (Format-OneLineUnbounded $Explanation)
    $script:ReportLines += $line
    $script:Statuses += $Status
}

function Get-ExceptionKind {
    param([System.Exception]$Exception)

    if ($null -eq $Exception) {
        return "unknown error"
    }
    return $Exception.GetType().Name
}

function Find-Executable {
    param(
        [string]$CommandName,
        [string[]]$CandidateRoots
    )

    $command = Get-Command $CommandName -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        return $command.Source
    }

    foreach ($root in $CandidateRoots) {
        if (-not [string]::IsNullOrWhiteSpace($root) -and (Test-Path -LiteralPath $root)) {
            $match = Get-ChildItem -LiteralPath $root -Filter $CommandName -File -Recurse `
                -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($null -ne $match) {
                return $match.FullName
            }
        }
    }

    return $null
}

function Test-TcpPort {
    param(
        [string]$HostName,
        [int]$Port,
        [int]$TimeoutMilliseconds = 2000
    )

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMilliseconds)) {
            return $false
        }
        $client.EndConnect($async)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function Invoke-MySqlMetadataQuery {
    param([string]$Sql)

    if ($null -eq $script:MySqlPath -or $null -eq $DbCredential) {
        return [pscustomobject]@{ Success = $false; Output = @() }
    }

    $oldPassword = $env:MYSQL_PWD
    $passwordWasSet = $null -ne $oldPassword
    $env:MYSQL_PWD = $DbCredential.GetNetworkCredential().Password
    try {
        $output = @(
            & $script:MySqlPath `
                "--protocol=TCP" `
                "--host=$DbHost" `
                "--port=$DbPort" `
                "--user=$($DbCredential.UserName)" `
                "--database=$DbName" `
                "--batch" `
                "--raw" `
                "--skip-column-names" `
                "--execute=$Sql" 2>$null
        )
        return [pscustomobject]@{
            Success = ($LASTEXITCODE -eq 0)
            Output = $output
        }
    } catch {
        return [pscustomobject]@{ Success = $false; Output = @() }
    } finally {
        if ($passwordWasSet) {
            $env:MYSQL_PWD = $oldPassword
        } else {
            Remove-Item Env:\MYSQL_PWD -ErrorAction SilentlyContinue
        }
    }
}

function Get-GrantText {
    param([string]$Grant)

    if ([string]::IsNullOrWhiteSpace($Grant)) {
        return ""
    }
    return (Format-OneLineUnbounded ($Grant -replace "(?i)(IDENTIFIED\b[^'`"]*?)(['`"])[^'`"]*\2", '$1$2[redacted]$2'))
}

function Test-GrantRedaction {
    $samples = @(
        "GRANT USAGE ON *.* TO 'agent'@'localhost' IDENTIFIED BY 'plain-secret'",
        "GRANT USAGE ON *.* TO 'agent'@'localhost' IDENTIFIED BY PASSWORD '*ABC123HASH'",
        "GRANT USAGE ON *.* TO 'agent'@'localhost' IDENTIFIED VIA mysql_native_password USING '*DEF456HASH'",
        "GRANT USAGE ON *.* TO 'agent'@'localhost' IDENTIFIED VIA ed25519 USING 'ed25519-secret'"
    )
    foreach ($sample in $samples) {
        $redacted = Get-GrantText $sample
        if ($redacted -match "(?i)plain-secret|ABC123HASH|DEF456HASH|ed25519-secret") {
            return $false
        }
    }
    return $true
}

function Test-Host {
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        Add-Check "Host" "Pass" ("Edition={0}; Build={1}; Architecture={2}; PowerShell={3}" -f `
                (Format-OneLine $os.Caption), (Format-OneLine $os.BuildNumber), `
                (Format-OneLine $computer.SystemType), $PSVersionTable.PSVersion.ToString())
    } catch {
        Add-Check "Host" "Unknown" ("Could not read Windows host metadata ({0})" -f (Get-ExceptionKind $_.Exception))
    }

    try {
        $effectivePolicy = Get-ExecutionPolicy -ErrorAction Stop
        if ($effectivePolicy -eq "Restricted") {
            Add-Check "Execution policy" "Warn" "Restricted; this script may need to be run with an approved policy."
        } else {
            Add-Check "Execution policy" "Pass" ("Effective policy is {0}." -f $effectivePolicy)
        }
    } catch {
        Add-Check "Execution policy" "Unknown" "Could not read the effective PowerShell execution policy."
    }

    try {
        $systemDrive = $env:SystemDrive
        $disk = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $systemDrive) `
            -ErrorAction Stop
        $freeGb = [math]::Round($disk.FreeSpace / 1GB, 1)
        if ($freeGb -lt 1) {
            Add-Check "Free disk space" "Fail" ("{0} has {1} GB free; the SEA executable needs roughly 121 MiB before installer overhead." -f $systemDrive, $freeGb)
        } elseif ($freeGb -lt 2) {
            Add-Check "Free disk space" "Warn" ("{0} has {1} GB free." -f $systemDrive, $freeGb)
        } else {
            Add-Check "Free disk space" "Pass" ("{0} has {1} GB free." -f $systemDrive, $freeGb)
        }
    } catch {
        Add-Check "Free disk space" "Unknown" "Could not read free space for the system drive."
    }
}

function Test-ClockSkew {
    $url = $RelayVaultUrl.TrimEnd("/") + "/api/health"
    $request = $null
    $response = $null
    try {
        $request = [System.Net.HttpWebRequest]::Create($url)
        $request.Method = "GET"
        $request.Timeout = 10000
        $request.ServerCertificateValidationCallback = {
            $certificate = $args[1]
            $sslPolicyErrors = $args[3]
            if ($null -ne $certificate) {
                $script:CertificateSubject = $certificate.Subject
                $script:CertificateIssuer = $certificate.Issuer
            }
            $script:CertificateErrors = $sslPolicyErrors
            return ($sslPolicyErrors -eq [System.Net.Security.SslPolicyErrors]::None)
        }
        $response = $request.GetResponse()
        $dateValue = $response.Headers["Date"]
        if ([string]::IsNullOrWhiteSpace($dateValue)) {
            Add-Check "System clock skew" "Unknown" "The HTTPS response did not include a Date header."
            return
        }

        $serverTime = [DateTime]::Parse($dateValue).ToUniversalTime()
        $skewSeconds = [math]::Abs(([DateTime]::UtcNow - $serverTime).TotalSeconds)
        if ($skewSeconds -gt 300) {
            Add-Check "System clock skew" "Fail" ("Clock differs from the Relay Vault HTTPS Date by {0} seconds." -f [math]::Round($skewSeconds, 1))
        } elseif ($skewSeconds -gt 60) {
            Add-Check "System clock skew" "Warn" ("Clock differs from the Relay Vault HTTPS Date by {0} seconds." -f [math]::Round($skewSeconds, 1))
        } else {
            Add-Check "System clock skew" "Pass" ("Clock differs from the Relay Vault HTTPS Date by {0} seconds." -f [math]::Round($skewSeconds, 1))
        }
    } catch {
        Add-Check "System clock skew" "Unknown" "Could not obtain a trusted HTTPS Date header from Relay Vault."
    } finally {
        if ($null -ne $response) {
            $response.Close()
        }
    }
}

function Test-Node {
    $roots = @(
        (Join-Path $env:ProgramFiles "nodejs"),
        (Join-Path ${env:ProgramFiles(x86)} "nodejs"),
        (Join-Path $env:LOCALAPPDATA "Programs\nodejs"),
        (Join-Path $env:ProgramData "nvm")
    )
    $nodePath = Find-Executable "node.exe" $roots
    if ($null -eq $nodePath) {
        Add-Check "Node.js presence" "Pass" "node.exe was not found on PATH or in common install locations; this is the expected state for a self-contained SEA target."
        return
    }

    $version = (& $nodePath --version 2>$null | Select-Object -First 1)
    Add-Check "Node.js presence" "Warn" ("node.exe exists at {0}; version {1}. A later SEA test on this host would not prove a Node-free target." -f `
            (Format-OneLine $nodePath), (Format-OneLine $version))
}

function Test-Database {
    $roots = @(
        (Join-Path $env:ProgramFiles "MariaDB"),
        (Join-Path ${env:ProgramFiles(x86)} "MariaDB"),
        (Join-Path $env:ProgramFiles "MySQL"),
        (Join-Path ${env:ProgramFiles(x86)} "MySQL"),
        (Join-Path $env:ProgramFiles "MySQL\MySQL Server")
    )
    $script:MySqlPath = Find-Executable "mysql.exe" $roots
    $listening = Test-TcpPort $DbHost $DbPort
    if (-not $listening) {
        Add-Check "MariaDB/MySQL listener" "Fail" ("No local TCP listener responded at {0}:{1}." -f $DbHost, $DbPort)
    } else {
        Add-Check "MariaDB/MySQL listener" "Pass" ("A local TCP listener responded at {0}:{1}." -f $DbHost, $DbPort)
    }

    if ($null -eq $script:MySqlPath) {
        Add-Check "MariaDB/MySQL client" "Unknown" "mysql.exe was not found; database metadata checks cannot run without installing or locating a client."
        Add-Check "Open Dental database" "Unknown" "Could not check schema presence because mysql.exe is unavailable."
        Add-Check "Open Dental version" "Unknown" "Could not read preference metadata because mysql.exe is unavailable."
        Add-Check "MariaDB grants" "Unknown" "Could not read grants because mysql.exe is unavailable."
        return
    }

    Add-Check "MariaDB/MySQL client" "Pass" ("Using the existing client at {0}." -f (Format-OneLine $script:MySqlPath))
    if ($null -eq $DbCredential) {
        Add-Check "Open Dental database" "Unknown" "No PSCredential was supplied; no database connection was attempted."
        Add-Check "Open Dental version" "Unknown" "No PSCredential was supplied; no preference metadata was read."
        Add-Check "MariaDB grants" "Unknown" "No PSCredential was supplied; no account or grants were read."
        return
    }

    $schemaResult = Invoke-MySqlMetadataQuery ("SELECT COUNT(*) FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = '{0}';" -f $DbName.Replace("'", "''"))
    if (-not $schemaResult.Success) {
        Add-Check "Open Dental database" "Fail" "The supplied credentials could not query the local database server."
        Add-Check "MariaDB/MySQL version" "Unknown" "Server version is unavailable because the database query failed."
        Add-Check "Open Dental version" "Unknown" "Version metadata is unavailable because the database query failed."
        Add-Check "MariaDB grants" "Unknown" "Account and grants are unavailable because the database query failed."
        return
    }

    $serverVersionResult = Invoke-MySqlMetadataQuery "SELECT VERSION();"
    if (-not $serverVersionResult.Success) {
        Add-Check "MariaDB/MySQL version" "Unknown" "Could not read the database server version."
    } else {
        $serverVersion = Format-OneLine ($serverVersionResult.Output | Select-Object -First 1)
        Add-Check "MariaDB/MySQL version" "Pass" ("Database server version: {0}" -f $serverVersion)
    }

    $schemaPresent = (($schemaResult.Output | Select-Object -First 1) -as [int]) -eq 1
    if ($schemaPresent) {
        Add-Check "Open Dental database" "Pass" ("The configured database '{0}' exists. No patient tables were queried." -f (Format-OneLine $DbName))
    } else {
        Add-Check "Open Dental database" "Fail" ("The configured database '{0}' does not exist." -f (Format-OneLine $DbName))
    }

    $versionResult = Invoke-MySqlMetadataQuery "SELECT PrefName, ValueString FROM preference WHERE PrefName IN ('ProgramVersion', 'DataBaseVersion');"
    if (-not $versionResult.Success) {
        Add-Check "Open Dental version" "Unknown" "Could not read Open Dental preference metadata."
    } else {
        $versionRows = @($versionResult.Output | ForEach-Object { Format-OneLine $_ })
        if ($versionRows.Count -eq 0) {
            Add-Check "Open Dental version" "Warn" "The preference table returned no ProgramVersion or DataBaseVersion rows."
        } else {
            Add-Check "Open Dental version" "Pass" ("Program/database version metadata: {0}" -f ($versionRows -join "; "))
        }
    }

    $identityResult = Invoke-MySqlMetadataQuery "SELECT CURRENT_USER();"
    $grantsResult = Invoke-MySqlMetadataQuery "SHOW GRANTS FOR CURRENT_USER();"
    if (-not $identityResult.Success -or -not $grantsResult.Success) {
        Add-Check "MariaDB grants" "Unknown" "Could not read the connected account or its grants."
    } else {
        $identity = Format-OneLine ($identityResult.Output | Select-Object -First 1)
        $grants = @($grantsResult.Output | ForEach-Object { Get-GrantText $_ })
        if ($identity -match "(?i)^root@") {
            Add-Check "MariaDB account safety" "Warn" "The connected account is root; the edge agent must not run with a root database account."
        } elseif ($grants -match "(?i)ALL\s+PRIVILEGES\s+ON\s+\*\.\*" -or $grants -match "(?i)WITH\s+GRANT\s+OPTION") {
            Add-Check "MariaDB account safety" "Warn" "The connected account has broad privileges or grant-option authority; the edge agent must use a dedicated least-privilege account."
        } else {
            Add-Check "MariaDB account safety" "Pass" "The connected account is not identified as root and no broad global privilege or grant option was reported."
        }

        Add-Check "MariaDB grants" "Pass" ("Connected account: {0}; grant rows follow." -f $identity)
        foreach ($grant in $grants) {
            Add-CheckLine "MariaDB grant" "Pass" $grant
        }
    }
}

function Test-OutboundConnectivity {
    $url = $RelayVaultUrl.TrimEnd("/") + "/api/health"
    $script:CertificateSubject = $null
    $script:CertificateIssuer = $null
    $script:CertificateErrors = $null
    try {
        $uri = New-Object System.Uri($url)
        $proxy = [System.Net.WebRequest]::DefaultWebProxy
        if ($null -eq $proxy) {
            Add-Check "System proxy" "Pass" "No system WebRequest proxy is configured."
        } else {
            $proxyUri = $proxy.GetProxy($uri)
            if ($proxyUri.Host -eq $uri.Host -and $proxyUri.Port -eq $uri.Port) {
                Add-Check "System proxy" "Pass" "The configured proxy resolves this endpoint directly."
            } else {
                Add-Check "System proxy" "Warn" ("HTTPS requests use proxy {0}:{1}." -f $proxyUri.Host, $proxyUri.Port)
            }
        }
    } catch {
        Add-Check "System proxy" "Unknown" "Could not determine the system WebRequest proxy."
    }

    try {
        $winHttp = (& netsh winhttp show proxy 2>$null | Out-String).Trim()
        if ([string]::IsNullOrWhiteSpace($winHttp)) {
            Add-Check "WinHTTP proxy" "Unknown" "Could not read WinHTTP proxy settings."
        } else {
            Add-Check "WinHTTP proxy" "Pass" (Format-OneLine $winHttp)
        }
    } catch {
        Add-Check "WinHTTP proxy" "Unknown" "Could not read WinHTTP proxy settings."
    }

    $request = $null
    $response = $null
    try {
        $request = [System.Net.HttpWebRequest]::Create($url)
        $request.Method = "GET"
        $request.Timeout = 15000
        $request.ServerCertificateValidationCallback = {
            $certificate = $args[1]
            $sslPolicyErrors = $args[3]
            if ($null -ne $certificate) {
                $script:CertificateSubject = $certificate.Subject
                $script:CertificateIssuer = $certificate.Issuer
            }
            $script:CertificateErrors = $sslPolicyErrors
            return ($sslPolicyErrors -eq [System.Net.Security.SslPolicyErrors]::None)
        }
        $response = $request.GetResponse()
        Add-Check "Outbound HTTPS" "Pass" ("HTTPS reached {0} with HTTP {1}." -f $uri.Host, [int]$response.StatusCode)

        $subject = Format-OneLine $script:CertificateSubject
        $issuer = Format-OneLine $script:CertificateIssuer
        if ($subject -match "(?i)onrender\.com" -and $script:CertificateErrors -eq [System.Net.Security.SslPolicyErrors]::None) {
            Add-Check "TLS certificate" "Pass" ("Certificate subject={0}; issuer={1}; chain validation passed." -f $subject, $issuer)
        } else {
            Add-Check "TLS certificate" "Fail" ("Certificate did not validate as the expected public onrender.com certificate. subject={0}; issuer={1}; errors={2}" -f `
                    $subject, $issuer, (Format-OneLine $script:CertificateErrors))
        }
    } catch {
        Add-Check "Outbound HTTPS" "Fail" "HTTPS could not reach Relay Vault; TLS interception, proxy policy, or firewall rules may be blocking the agent."
        if ($null -ne $script:CertificateSubject) {
            Add-Check "TLS certificate" "Fail" ("A certificate was presented but the request was not trusted. subject={0}; issuer={1}; errors={2}" -f `
                    (Format-OneLine $script:CertificateSubject), (Format-OneLine $script:CertificateIssuer), (Format-OneLine $script:CertificateErrors))
        } else {
            Add-Check "TLS certificate" "Unknown" "No certificate metadata was available because the TLS handshake did not complete."
        }
    } finally {
        if ($null -ne $response) {
            $response.Close()
        }
    }
}

function Test-Dpapi {
    try {
        Add-Type -AssemblyName System.Security
        $plain = New-Object byte[] 16
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($plain)
        $protected = [System.Security.Cryptography.ProtectedData]::Protect(
            $plain,
            $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )
        $roundTrip = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $protected,
            $null,
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine
        )
        $equal = ($plain.Length -eq $roundTrip.Length)
        if ($equal) {
            for ($index = 0; $index -lt $plain.Length; $index++) {
                if ($plain[$index] -ne $roundTrip[$index]) {
                    $equal = $false
                    break
                }
            }
        }
        if ($equal) {
            Add-Check "DPAPI machine scope" "Pass" "In-memory LocalMachine Protect/Unprotect round-trip succeeded; no bytes were persisted."
        } else {
            Add-Check "DPAPI machine scope" "Fail" "The in-memory LocalMachine Protect/Unprotect round-trip changed the data."
        }
    } catch {
        Add-Check "DPAPI machine scope" "Unknown" ("Could not complete the in-memory round-trip ({0}); group policy or platform restrictions may block key storage." -f (Get-ExceptionKind $_.Exception))
    }
}

function Test-ServiceCapability {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Add-Check "Windows Service privilege" "Pass" "The current user is an Administrator and should be able to register a service later."
        } else {
            Add-Check "Windows Service privilege" "Warn" "The current user is not an Administrator; service registration would require approved elevation."
        }
    } catch {
        Add-Check "Windows Service privilege" "Unknown" "Could not determine whether the current user has service-registration privilege."
    }

    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($null -eq $service) {
            Add-Check "Existing edge-agent service" "Pass" ("No service named '{0}' exists." -f (Format-OneLine $ServiceName))
        } else {
            Add-Check "Existing edge-agent service" "Warn" ("Service '{0}' already exists with status {1}; this may be a reinstall." -f `
                    (Format-OneLine $ServiceName), (Format-OneLine $service.Status))
        }
    } catch {
        Add-Check "Existing edge-agent service" "Unknown" "Could not enumerate the intended service name."
    }
}

function Test-Antivirus {
    $products = @()
    try {
        $products = @(Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop)
        if ($products.Count -eq 0) {
            Add-Check "Antivirus products" "Warn" "No antivirus product was reported by Windows Security Center."
        } else {
            $names = @($products | ForEach-Object { Format-OneLine $_.displayName })
            Add-Check "Antivirus products" "Pass" ("Security Center reports: {0}" -f ($names -join ", "))
        }
    } catch {
        Add-Check "Antivirus products" "Unknown" "Security Center data was unavailable; elevation or endpoint-management policy may restrict it."
    }

    try {
        $defenderCommand = Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($null -eq $defenderCommand) {
            Add-Check "Defender real-time protection" "Unknown" "Get-MpComputerStatus is unavailable on this host."
        } else {
            $defender = Get-MpComputerStatus -ErrorAction Stop
            if ($defender.RealTimeProtectionEnabled) {
                Add-Check "Defender real-time protection" "Pass" "Microsoft Defender real-time protection is enabled."
            } else {
                Add-Check "Defender real-time protection" "Warn" "Microsoft Defender real-time protection is not enabled."
            }
        }
    } catch {
        Add-Check "Defender real-time protection" "Unknown" "Could not read Defender real-time protection status."
    }

    try {
        $preferenceCommand = Get-Command Get-MpPreference -ErrorAction SilentlyContinue
        if ($null -eq $preferenceCommand) {
            Add-Check "Install-directory exclusion" "Unknown" "Get-MpPreference is unavailable; the intended directory exclusion could not be checked."
        } else {
            $preference = Get-MpPreference -ErrorAction Stop
            $excluded = @($preference.ExclusionPath | ForEach-Object { (Format-OneLine $_).TrimEnd("\") })
            $target = $InstallDirectory.TrimEnd("\")
            $match = $excluded | Where-Object { $_ -ieq $target }
            if ($null -ne $match) {
                Add-Check "Install-directory exclusion" "Pass" ("The intended directory '{0}' is excluded from Defender scanning." -f (Format-OneLine $InstallDirectory))
            } else {
                Add-Check "Install-directory exclusion" "Warn" ("The intended directory '{0}' is not listed as a Defender exclusion." -f (Format-OneLine $InstallDirectory))
            }
        }
    } catch {
        Add-Check "Install-directory exclusion" "Unknown" "Could not read Defender exclusions."
    }
}

if (Test-GrantRedaction) {
    Add-Check "Grant redaction self-test" "Pass" "Sample MariaDB credential forms are redacted before they can enter the report."
} else {
    Add-Check "Grant redaction self-test" "Fail" "A sample credential survived grant redaction; do not use the report until this is fixed."
}

Test-Host
Test-Node
Test-Database
Test-ClockSkew
Test-OutboundConnectivity
Test-Dpapi
Test-ServiceCapability
Test-Antivirus

$failCount = @($script:Statuses | Where-Object { $_ -eq "Fail" }).Count
$unknownCount = @($script:Statuses | Where-Object { $_ -eq "Unknown" }).Count
$warnCount = @($script:Statuses | Where-Object { $_ -eq "Warn" }).Count

if ($failCount -gt 0) {
    $summary = "OVERALL: NOT READY - {0} failing check(s); resolve them before installation." -f $failCount
} elseif ($unknownCount -gt 0) {
    $summary = "OVERALL: UNKNOWN - no failures were observed, but {0} check(s) could not be verified on this host." -f $unknownCount
} elseif ($warnCount -gt 0) {
    $summary = "OVERALL: CONDITIONAL - {0} warning(s) need operator or IT review before installation." -f $warnCount
} else {
    $summary = "OVERALL: READY - all checks passed."
}

$script:ReportLines += $summary
$script:ReportLines | ForEach-Object { Write-Output $_ }

if (-not [string]::IsNullOrWhiteSpace($OutFile)) {
    Set-Content -LiteralPath $OutFile -Value $script:ReportLines -Encoding UTF8
}
