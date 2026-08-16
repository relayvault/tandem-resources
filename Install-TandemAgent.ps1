[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$PairingCode,

    [string]$VaultUrl = 'https://relay-vault.onrender.com',
    [string]$DbHost = '127.0.0.1',
    [int]$DbPort = 3306,
    [string]$DbName = 'opendental',
    [string]$DbUser = 'tandem_agent',
    [string]$InstallDirectory = 'C:\Program Files\Tandem',
    [string]$BundlePath,
    [string]$BundleUrl,
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$BundleSha256
)

$ErrorActionPreference = 'Stop'
$taskName = 'TandemEdgeAgent'
$configDirectory = Join-Path $env:ProgramData 'Tandem'
$configPath = Join-Path $configDirectory 'agent-config.dpapi'
$bundleInstallPath = Join-Path $InstallDirectory 'relay-vault-edge-agent.cjs'
$tempDirectory = Join-Path $env:TEMP ("tandem-agent-" + [guid]::NewGuid().ToString('N'))
$downloadPath = Join-Path $tempDirectory 'agent-bundle.cjs'
$nodePath = $null
$taskCreated = $false
$bundleBackupPath = Join-Path $tempDirectory 'agent-bundle.previous.cjs'
$configBackupPath = Join-Path $tempDirectory 'agent-config.previous.dpapi'
$bundleHadPrevious = $false
$configHadPrevious = $false

function Fail([string]$Message) {
    throw $Message
}

function Assert-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Fail 'Run this installer from an elevated PowerShell window.'
    }
}

function Assert-BundleSource {
    if ([string]::IsNullOrWhiteSpace($BundlePath) -and [string]::IsNullOrWhiteSpace($BundleUrl)) {
        Fail 'Provide either -BundlePath for a local bundle or -BundleUrl for a downloaded bundle.'
    }
    if (-not [string]::IsNullOrWhiteSpace($BundlePath) -and -not [string]::IsNullOrWhiteSpace($BundleUrl)) {
        Fail 'Provide only one of -BundlePath and -BundleUrl.'
    }
    if (-not [string]::IsNullOrWhiteSpace($BundleUrl) -and [string]::IsNullOrWhiteSpace($BundleSha256)) {
        Fail '-BundleSha256 is required when -BundleUrl is used.'
    }
}

function Find-Node {
    $candidates = @()
    $command = Get-Command node.exe -ErrorAction SilentlyContinue
    if ($command) { $candidates += $command.Source }
    $candidates += @(
        'C:\Program Files\nodejs\node.exe',
        'C:\Program Files (x86)\nodejs\node.exe'
    )
    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
        $versionOutput = & $candidate --version 2>$null
        if ($LASTEXITCODE -ne 0 -or $versionOutput -notmatch '^v(\d+)\.') { continue }
        $major = [int]$Matches[1]
        if ($major -ge 22) { return $candidate }
        Fail "Node.js 22 or newer is required. Found $versionOutput at $candidate. Install the current Node.js 22 LTS MSI from https://nodejs.org/en/download and rerun this installer."
    }
    Fail 'Node.js 22 or newer was not found. Install the current Node.js 22 LTS MSI from https://nodejs.org/en/download (system-wide, with node.exe on PATH) and rerun this installer.'
}

function Find-MySql {
    $command = Get-Command mysql.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    $candidates = @(
        'C:\Program Files\MariaDB 10.5\bin\mysql.exe',
        'C:\Program Files\MariaDB 10.6\bin\mysql.exe',
        'C:\Program Files\MariaDB 10.11\bin\mysql.exe'
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    Fail 'MariaDB/MySQL client not found. Install MariaDB client tools or add mysql.exe to PATH.'
}

function Test-Database([string]$MysqlPath, [string]$Password) {
    $oldPassword = $env:MYSQL_PWD
    $env:MYSQL_PWD = $Password
    try {
        $oldPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            & $MysqlPath --host=$DbHost --port=$DbPort --user=$DbUser --database=$DbName --batch --skip-column-names --execute 'SELECT 1' 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) {
                Fail 'MariaDB connection failed. Check the tandem_agent password, host, port, database, and grants.'
            }
        }
        finally {
            $ErrorActionPreference = $oldPreference
        }
    }
    finally {
        if ($null -eq $oldPassword) { Remove-Item Env:MYSQL_PWD -ErrorAction SilentlyContinue }
        else { $env:MYSQL_PWD = $oldPassword }
    }
}

function Write-ProtectedConfig([hashtable]$Config) {
    Add-Type -AssemblyName System.Security
    $json = $Config | ConvertTo-Json -Compress
    $plain = [Text.Encoding]::UTF8.GetBytes($json)
    $cipher = [Security.Cryptography.ProtectedData]::Protect(
        $plain,
        $null,
        [Security.Cryptography.DataProtectionScope]::LocalMachine)
    New-Item -ItemType Directory -Path $configDirectory -Force | Out-Null
    [Convert]::ToBase64String($cipher) | Set-Content -LiteralPath $configPath -NoNewline
}

function Read-ProtectedConfig {
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { return $null }
    Add-Type -AssemblyName System.Security
    $cipher = [Convert]::FromBase64String((Get-Content -LiteralPath $configPath -Raw).Trim())
    $plain = [Security.Cryptography.ProtectedData]::Unprotect(
        $cipher,
        $null,
        [Security.Cryptography.DataProtectionScope]::LocalMachine)
    return ([Text.Encoding]::UTF8.GetString($plain) | ConvertFrom-Json)
}

function Remove-InstalledTask {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()
    $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existing) {
        if ($PSCmdlet.ShouldProcess($taskName, 'Stop and remove existing scheduled task')) {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        }
    }
}

try {
    Assert-Elevated
    Assert-BundleSource
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    New-Item -ItemType Directory -Path $tempDirectory -Force | Out-Null
    $nodePath = Find-Node

    if (-not [string]::IsNullOrWhiteSpace($BundleUrl)) {
        Write-Host "Downloading the edge-agent bundle..."
        Invoke-WebRequest -Uri $BundleUrl -OutFile $downloadPath -UseBasicParsing
        $actualHash = (Get-FileHash -LiteralPath $downloadPath -Algorithm SHA256).Hash
        if ($actualHash -ne $BundleSha256.ToUpperInvariant()) {
            Fail "Bundle SHA-256 mismatch. Expected $BundleSha256 but downloaded $actualHash."
        }
        $sourceBundlePath = $downloadPath
    }
    else {
        if (-not (Test-Path -LiteralPath $BundlePath -PathType Leaf)) {
            Fail "Bundle path does not exist: $BundlePath"
        }
        $sourceBundlePath = (Resolve-Path -LiteralPath $BundlePath).Path
    }

    $mysqlPath = Find-MySql
    $dbPassword = Read-Host 'MariaDB tandem_agent password' -AsSecureString
    $passwordBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($dbPassword)
    try {
        $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordBstr)
        Test-Database -MysqlPath $mysqlPath -Password $password
    }
    finally {
        if ($passwordBstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordBstr)
        }
    }

    New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
    if (Test-Path -LiteralPath $bundleInstallPath -PathType Leaf) {
        Copy-Item -LiteralPath $bundleInstallPath -Destination $bundleBackupPath -Force
        $bundleHadPrevious = $true
    }
    if (Test-Path -LiteralPath $configPath -PathType Leaf) {
        Copy-Item -LiteralPath $configPath -Destination $configBackupPath -Force
        $configHadPrevious = $true
    }
    Copy-Item -LiteralPath $sourceBundlePath -Destination $bundleInstallPath -Force
    Write-ProtectedConfig @{
        vaultUrl = $VaultUrl
        registrationToken = $PairingCode
        dbHost = $DbHost
        dbPort = $DbPort
        dbName = $DbName
        dbUser = $DbUser
        dbPassword = $password
        opendentalMode = 'real'
        runWf01 = 'false'
    }

    Remove-InstalledTask
    $taskAction = New-ScheduledTaskAction -Execute $nodePath -Argument ('"{0}"' -f $bundleInstallPath)
    $taskTrigger = New-ScheduledTaskTrigger -AtStartup
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $taskSettings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
    Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings -Description 'Relay Vault Tandem edge agent' | Out-Null
    $taskCreated = $true
    Start-ScheduledTask -TaskName $taskName

    Write-Host 'Waiting for the agent to register...'
    for ($attempt = 1; $attempt -le 30; $attempt++) {
        Start-Sleep -Seconds 2
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if (-not $task) { Fail "The $taskName scheduled task disappeared while registering." }
        try {
            $config = Read-ProtectedConfig
            if ($config.connectorId) {
                Write-Host "Tandem edge agent connected successfully (connector $($config.connectorId))."
                exit 0
            }
        }
        catch {
            Fail "The agent configuration could not be read after startup: $($_.Exception.Message)"
        }
    }
    Fail 'The scheduled task is running but the agent did not register within 60 seconds. Check Windows Event Viewer and the Vault URL.'
}
catch {
    if ($taskCreated -or (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    if ($bundleHadPrevious) {
        Copy-Item -LiteralPath $bundleBackupPath -Destination $bundleInstallPath -Force -ErrorAction SilentlyContinue
    }
    elseif (Test-Path -LiteralPath $bundleInstallPath -PathType Leaf) {
        Remove-Item -LiteralPath $bundleInstallPath -Force -ErrorAction SilentlyContinue
    }
    if ($configHadPrevious) {
        Copy-Item -LiteralPath $configBackupPath -Destination $configPath -Force -ErrorAction SilentlyContinue
    }
    elseif (Test-Path -LiteralPath $configPath -PathType Leaf) {
        Remove-Item -LiteralPath $configPath -Force -ErrorAction SilentlyContinue
    }
    Write-Error $_.Exception.Message
    exit 1
}
finally {
    if (Test-Path -LiteralPath $tempDirectory) {
        Remove-Item -LiteralPath $tempDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
    $password = $null
    $dbPassword = $null
}
