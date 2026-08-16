<#
.SYNOPSIS
Grants the read-only tandem_agent account SELECT on every Open Dental schema on
this server, then reports which schema actually holds the patient data.

.DESCRIPTION
New-TandemAgentDbAccount.ps1 grants SELECT on a single named schema (default
'opendental'). When the practice's database is named something else, the agent
connects successfully and reads an empty schema, which looks like a healthy
connector with no data.

This script closes that gap. Run it as the MariaDB root user. It grants SELECT
on every non-system schema to tandem_agent on both host forms, then connects AS
tandem_agent and counts the rows in each `patient` table, so the output names
the schema to pass to Install-TandemAgent.ps1 -DbName.

System schemas (mysql, information_schema, performance_schema, sys) are
deliberately excluded: mysql holds password hashes and the agent never reads it.
No write privilege is granted at any point.

.EXAMPLE
.\Grant-TandemAgentSchemaAccess.ps1
#>
[CmdletBinding()]
param(
    [string]$DbHost = '127.0.0.1',
    [int]$DbPort = 3306,
    [string]$AgentUser = 'tandem_agent',
    [string]$MysqlPath
)

$ErrorActionPreference = 'Stop'

function Fail([string]$Message) {
    throw $Message
}

function Find-MysqlClient {
    if ($MysqlPath) {
        if (-not (Test-Path -LiteralPath $MysqlPath -PathType Leaf)) {
            Fail "No MySQL client at $MysqlPath."
        }
        return $MysqlPath
    }

    $command = Get-Command mysql.exe -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }

    # Derive the client from the running server rather than guessing at
    # version-stamped install paths.
    $service = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq 'Running' -and $_.PathName -match 'mysqld|mariadbd' } |
        Select-Object -First 1
    if ($service -and $service.PathName -match '"?([^"]+\\bin)\\[^\\]*(mysqld|mariadbd)[^\\]*\.exe"?') {
        $candidate = Join-Path $Matches[1] 'mysql.exe'
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }

    Fail 'Could not find mysql.exe. Pass -MysqlPath with its full path.'
}

function ConvertFrom-SecureStringPlain([System.Security.SecureString]$Password) {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Invoke-Sql {
    param(
        [string]$Client,
        [string]$User,
        [string]$Password,
        [string]$Query,
        [switch]$Raw
    )
    # The password goes through MYSQL_PWD rather than an option file or the
    # command line: option files silently mis-parse passwords containing '#',
    # quotes or backslashes, and a command line is readable from the process
    # list. MYSQL_PWD is scoped to this process and cleared straight after.
    $env:MYSQL_PWD = $Password
    # PowerShell 5.1 turns a native command's stderr into error records, and
    # with $ErrorActionPreference = 'Stop' that makes an expected non-zero exit
    # terminating. Scope the relaxation to the call itself.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $Client "--host=$DbHost" "--port=$DbPort" "--user=$User" `
            --batch --skip-column-names --execute $Query 2>&1
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previous
        Remove-Item Env:\MYSQL_PWD -ErrorAction SilentlyContinue
    }
    if ($Raw) {
        return [pscustomobject]@{ ExitCode = $code; Output = $output }
    }
    if ($code -ne 0) {
        Fail "Query failed: $($output -join ' ')"
    }
    return $output
}

$rootPlain = $null
$agentPlain = $null

try {
    $client = Find-MysqlClient
    Write-Host "MySQL client: $client"

    $rootUser = Read-Host 'MariaDB admin user [root]'
    if ([string]::IsNullOrWhiteSpace($rootUser)) { $rootUser = 'root' }
    $rootPlain = ConvertFrom-SecureStringPlain (Read-Host "$rootUser password" -AsSecureString)

    $probe = Invoke-Sql -Client $client -User $rootUser -Password $rootPlain -Query 'SELECT 1' -Raw
    if ($probe.ExitCode -ne 0) {
        Fail ("Could not connect as $rootUser. MariaDB said: " + ($probe.Output -join ' '))
    }
    Write-Host "Connected as $rootUser."

    $schemas = @(Invoke-Sql -Client $client -User $rootUser -Password $rootPlain -Query @"
SELECT DISTINCT table_schema FROM information_schema.tables
WHERE table_name = 'patient'
  AND table_schema NOT IN ('mysql','information_schema','performance_schema','sys')
ORDER BY table_schema;
"@ | Where-Object { $_ -and $_.Trim() })

    if ($schemas.Count -eq 0) {
        Fail 'No schema on this server contains a patient table. Is this the Open Dental database server?'
    }

    Write-Host ''
    Write-Host ("Open Dental schemas found: {0}" -f ($schemas -join ', '))

    foreach ($schema in $schemas) {
        foreach ($agentHost in @('localhost', '127.0.0.1')) {
            $grant = "GRANT SELECT ON ``$schema``.* TO '$AgentUser'@'$agentHost';"
            [void](Invoke-Sql -Client $client -User $rootUser -Password $rootPlain -Query $grant)
        }
        Write-Host "  granted SELECT on $schema to $AgentUser"
    }
    [void](Invoke-Sql -Client $client -User $rootUser -Password $rootPlain -Query 'FLUSH PRIVILEGES;')

    # Prove the grants from the agent's own credentials rather than assuming
    # they took: this is the connection the edge agent will actually make.
    Write-Host ''
    $agentPlain = ConvertFrom-SecureStringPlain (Read-Host "$AgentUser password" -AsSecureString)

    $counts = @()
    foreach ($schema in $schemas) {
        $result = Invoke-Sql -Client $client -User $AgentUser -Password $agentPlain -Raw `
            -Query "SELECT COUNT(*) FROM ``$schema``.patient;"
        if ($result.ExitCode -ne 0) {
            $counts += [pscustomobject]@{ Schema = $schema; Patients = 'unreadable' }
        }
        else {
            $counts += [pscustomobject]@{ Schema = $schema; Patients = ($result.Output | Select-Object -First 1).Trim() }
        }
    }

    Write-Host ''
    Write-Host "Patient rows visible to ${AgentUser}:"
    $counts | ForEach-Object { Write-Host ("  {0,-24} {1}" -f $_.Schema, $_.Patients) }

    $populated = @($counts | Where-Object { $_.Patients -match '^\d+$' -and [int]$_.Patients -gt 0 })
    Write-Host ''
    if ($populated.Count -eq 0) {
        Write-Host 'Every Open Dental schema on this server is empty. The agent has nothing to sync.'
    }
    else {
        foreach ($row in $populated) {
            Write-Host ("Install the agent against this schema: -DbName '{0}'  ({1} patients)" -f $row.Schema, $row.Patients)
        }
    }

    $writeTest = Invoke-Sql -Client $client -User $AgentUser -Password $agentPlain -Raw `
        -Query "UPDATE ``$($schemas[0])``.preference SET ValueString = ValueString WHERE PrefName = 'ProgramVersion';"
    if ($writeTest.ExitCode -eq 0) {
        Write-Warning "$AgentUser was able to write. It should be read-only — re-run New-TandemAgentDbAccount.ps1."
    }
    else {
        Write-Host 'Write test: PASS (write correctly denied)'
    }
}
finally {
    $rootPlain = $null
    $agentPlain = $null
    Remove-Item Env:\MYSQL_PWD -ErrorAction SilentlyContinue
}
