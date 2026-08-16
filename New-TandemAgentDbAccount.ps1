<#
.SYNOPSIS
    Creates the least-privilege Tandem edge-agent MariaDB account and verifies it.

.DESCRIPTION
    Run on the practice's Open Dental server as a user who knows the MariaDB root
    password. Creates 'tandem_agent' with read-only access to the Open Dental
    database, then proves the account can read and cannot write.

    The generated password is shown once and copied to the clipboard. Store it in
    a password manager before closing the window.
#>

[CmdletBinding()]
param(
    [string]$MySqlBin = 'C:\Program Files\MariaDB 10.5\bin',
    [string]$DbHost = '127.0.0.1',
    [int]$DbPort = 3306,
    [string]$DbName = 'opendental',
    [string]$AgentUser = 'tandem_agent',
    [string]$RootUser = 'root'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$mysql = Join-Path $MySqlBin 'mysql.exe'
if (-not (Test-Path -LiteralPath $mysql -PathType Leaf)) {
    throw "mysql.exe not found at $mysql. Pass -MySqlBin with the correct directory."
}

function Invoke-MySql {
    param(
        [Parameter(Mandatory)][string]$User,
        [Parameter(Mandatory)][string]$Password,
        [Parameter(Mandatory)][string]$Sql,
        [switch]$AllowFailure
    )

    # Windows PowerShell 5.1 turns a native command's stderr into ErrorRecords
    # when redirected, and $ErrorActionPreference = 'Stop' then makes an expected
    # failure - such as the write-denial probe below - terminate the script. The
    # preference is relaxed for the duration of the call only.
    $previousPreference = $ErrorActionPreference
    $env:MYSQL_PWD = $Password
    try {
        $ErrorActionPreference = 'Continue'
        $output = & $mysql --protocol=TCP --host=$DbHost --port=$DbPort --user=$User `
            --batch --skip-column-names --execute=$Sql 2>&1
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousPreference
        Remove-Item Env:\MYSQL_PWD -ErrorAction SilentlyContinue
    }

    if ($code -ne 0 -and -not $AllowFailure) {
        throw ("MySQL command failed (exit {0}): {1}" -f $code, ($output -join ' '))
    }

    return [pscustomobject]@{
        ExitCode = $code
        Output   = ($output | ForEach-Object { [string]$_ })
    }
}

function Hide-GrantSecret {
    # SHOW GRANTS echoes the account's password hash. It is redacted here for the
    # same reason the prerequisite doctor redacts it: this output gets pasted
    # into chat and tickets.
    param([string]$Line)

    $redacted = $Line
    $redacted = [regex]::Replace($redacted, "(?i)(IDENTIFIED\s+BY\s+PASSWORD\s+)'[^']*'", "`$1'[redacted]'")
    $redacted = [regex]::Replace($redacted, "(?i)(IDENTIFIED\s+BY\s+)'[^']*'", "`$1'[redacted]'")
    $redacted = [regex]::Replace($redacted, "(?i)(IDENTIFIED\s+VIA\s+.*?USING\s+)'[^']*'", "`$1'[redacted]'")
    return $redacted
}

# --- root credentials ------------------------------------------------------
$rootSecure = Read-Host "MariaDB password for $RootUser" -AsSecureString
$rootPlain = (New-Object System.Management.Automation.PSCredential($RootUser, $rootSecure)).GetNetworkCredential().Password

$check = Invoke-MySql -User $RootUser -Password $rootPlain -Sql "SELECT 1" -AllowFailure
if ($check.ExitCode -ne 0) {
    throw "Could not connect as $RootUser. Nothing was changed."
}

$dbExists = Invoke-MySql -User $RootUser -Password $rootPlain `
    -Sql "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name = '$DbName'"
if (($dbExists.Output -join '') -notmatch '^\s*1\s*$') {
    throw "Database '$DbName' was not found. Nothing was changed."
}

# --- generate the agent password -------------------------------------------
$agentPassword = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object { [char]$_ })

# --- create the account -----------------------------------------------------
# The statements carry the new password, so they go through a temp file rather
# than the command line: process arguments are readable by other users on this
# server, and the file is deleted immediately afterwards.
$sqlFile = Join-Path ([System.IO.Path]::GetTempPath()) ("tandem-grant-{0}.sql" -f [guid]::NewGuid())
@"
CREATE OR REPLACE USER '$AgentUser'@'localhost' IDENTIFIED BY '$agentPassword';
CREATE OR REPLACE USER '$AgentUser'@'$DbHost' IDENTIFIED BY '$agentPassword';
GRANT SELECT ON ``$DbName``.* TO '$AgentUser'@'localhost';
GRANT SELECT ON ``$DbName``.* TO '$AgentUser'@'$DbHost';
FLUSH PRIVILEGES;
"@ | Set-Content -LiteralPath $sqlFile -Encoding ASCII

try {
    $null = Invoke-MySql -User $RootUser -Password $rootPlain -Sql ("SOURCE {0}" -f $sqlFile)
}
finally {
    Remove-Item -LiteralPath $sqlFile -Force -ErrorAction SilentlyContinue
}
Write-Host "Created $AgentUser with SELECT on $DbName." -ForegroundColor Green

# --- verify: grants ---------------------------------------------------------
Write-Host "`nGrants:" -ForegroundColor Cyan
foreach ($hostForm in @('localhost', $DbHost)) {
    $grants = Invoke-MySql -User $RootUser -Password $rootPlain -Sql "SHOW GRANTS FOR '$AgentUser'@'$hostForm'"
    $grants.Output | ForEach-Object { Write-Host ("  " + (Hide-GrantSecret $_)) }

    $unexpected = @($grants.Output | Where-Object {
            $_ -notmatch 'GRANT USAGE ON' -and $_ -notmatch "GRANT SELECT ON ``?$DbName``?\.\*"
        })
    if ($unexpected.Count -gt 0) {
        Write-Host "  UNEXPECTED GRANT ABOVE - review before using this account" -ForegroundColor Red
    }
}

# --- verify: the account can read ------------------------------------------
$read = Invoke-MySql -User $AgentUser -Password $agentPassword `
    -Sql "SELECT COUNT(*) FROM $DbName.preference" -AllowFailure
if ($read.ExitCode -eq 0) {
    Write-Host "`nRead test: PASS (read $DbName.preference over TCP)" -ForegroundColor Green
}
else {
    Write-Host "`nRead test: FAIL - $($read.Output -join ' ')" -ForegroundColor Red
}

# --- verify: the account cannot write --------------------------------------
# A no-op UPDATE: it still requires the UPDATE privilege, but its WHERE clause
# matches no rows, so it changes nothing even if the privilege were present.
$write = Invoke-MySql -User $AgentUser -Password $agentPassword `
    -Sql "UPDATE $DbName.preference SET ValueString = ValueString WHERE 1 = 0" -AllowFailure
if ($write.ExitCode -ne 0 -and ($write.Output -join ' ') -match '(?i)denied') {
    Write-Host "Write test: PASS (write correctly denied)" -ForegroundColor Green
}
else {
    Write-Host "Write test: FAIL - the account was NOT denied write access. Do not use it." -ForegroundColor Red
}

# --- hand over the password -------------------------------------------------
Write-Host "`n$AgentUser password (store it now, it is not saved anywhere):" -ForegroundColor Yellow
Write-Host "  $agentPassword" -ForegroundColor Yellow
try {
    Set-Clipboard -Value $agentPassword
    Write-Host "Copied to clipboard." -ForegroundColor Yellow
}
catch {
    Write-Host "Clipboard unavailable; copy it from above." -ForegroundColor Yellow
}
