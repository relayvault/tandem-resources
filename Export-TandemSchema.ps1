#requires -Version 5.1
<#
.SYNOPSIS
    Captures Open Dental schema metadata using the read-only tandem_agent account.

.DESCRIPTION
    This script reads information_schema metadata and the two Open Dental
    version preferences. It does not read table data or change the database.
    Query C reads configuration from the preference table, not patient data.
#>

[CmdletBinding()]
param(
    [string]$MySqlBin = 'C:\Program Files\MariaDB 10.5\bin',
    [string]$DbHost = '127.0.0.1',
    [int]$DbPort = 3306,
    [string]$DbName = 'opendental',
    [string]$DbUser = 'tandem_agent',
    [string]$OutDirectory = 'C:\Temp'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:DbPassword = $null

if ($DbName -notmatch '^[A-Za-z0-9_]+$') {
    throw "DbName must contain only letters, numbers, and underscores."
}

$mysql = Join-Path $MySqlBin 'mysql.exe'
if (-not (Test-Path -LiteralPath $mysql -PathType Leaf)) {
    throw "mysql.exe not found at $mysql. Pass -MySqlBin with the correct directory."
}

if (-not (Test-Path -LiteralPath $OutDirectory -PathType Container)) {
    throw "Output directory not found: $OutDirectory. No directory was created."
}

function Invoke-MySql {
    param(
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][int]$Port,
        [Parameter(Mandatory)][string]$Sql
    )

    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $env:MYSQL_PWD = $script:DbPassword
        $output = & $mysql --protocol=TCP --host=$HostName --port=$Port --user=$DbUser `
            --batch --skip-column-names --execute=$Sql 2>&1
        $code = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousPreference
        Remove-Item Env:\MYSQL_PWD -ErrorAction SilentlyContinue
    }

    return [pscustomobject]@{
        ExitCode = $code
        Output = @($output | ForEach-Object { [string]$_ })
    }
}

function Invoke-RequiredQuery {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$HostName,
        [Parameter(Mandatory)][int]$Port,
        [Parameter(Mandatory)][string]$Sql
    )

    $result = Invoke-MySql -HostName $HostName -Port $Port -Sql $Sql
    if ($result.ExitCode -ne 0) {
        if ($Name -eq 'Query A') {
            throw "The tandem_agent connection failed during Query A; the account or its grants are the problem. No schema files were written."
        }
        throw "$Name failed with exit code $($result.ExitCode). Stop and report this result; no substitute query was used."
    }
    if ($result.Output.Count -eq 0) {
        throw "$Name returned zero rows. Stop and report this result; no substitute query was used."
    }
    return $result.Output
}

function Write-Tsv {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Header,
        [Parameter(Mandatory)][string[]]$Rows
    )

    @($Header) + $Rows | Set-Content -LiteralPath $Path -Encoding UTF8
}

$queryA = "SELECT TABLE_NAME, ORDINAL_POSITION, COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE, COLUMN_DEFAULT, EXTRA, COLUMN_KEY FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = '$DbName' ORDER BY TABLE_NAME, ORDINAL_POSITION"
$queryB = "SELECT TABLE_NAME, ENGINE, TABLE_COLLATION FROM information_schema.TABLES WHERE TABLE_SCHEMA = '$DbName' AND TABLE_TYPE = 'BASE TABLE' ORDER BY TABLE_NAME"
$queryC = "SELECT PrefName, ValueString FROM $DbName.preference WHERE PrefName IN ('ProgramVersion','DataBaseVersion')"

Write-Host "Capturing schema metadata from '$DbName' as '$DbUser' over TCP."
Write-Host "The output contains schema metadata only; no table data is read."
Write-Host "Query C reads two configuration rows from the preference table (ProgramVersion and DataBaseVersion), not patient data."

try {
    $securePassword = Read-Host "MariaDB password for $DbUser" -AsSecureString
    $script:DbPassword = (New-Object System.Management.Automation.PSCredential($DbUser, $securePassword)).GetNetworkCredential().Password
    $securePassword = $null

    $columnRows = Invoke-RequiredQuery -Name 'Query A' -HostName $DbHost -Port $DbPort -Sql $queryA
    $tableRows = Invoke-RequiredQuery -Name 'Query B' -HostName $DbHost -Port $DbPort -Sql $queryB
    $versionRows = Invoke-RequiredQuery -Name 'Query C' -HostName $DbHost -Port $DbPort -Sql $queryC

    $versions = @{}
    foreach ($row in $versionRows) {
        $parts = $row -split "`t", 2
        if ($parts.Count -eq 2) {
            $versions[$parts[0]] = $parts[1]
        }
    }
    if (-not $versions.ContainsKey('ProgramVersion') -or -not $versions.ContainsKey('DataBaseVersion')) {
        throw "Query C did not return both ProgramVersion and DataBaseVersion rows. Stop and report this result."
    }

    $columnsPath = Join-Path $OutDirectory "$DbName-columns.tsv"
    $tablesPath = Join-Path $OutDirectory "$DbName-tables.tsv"
    $versionPath = Join-Path $OutDirectory "$DbName-version.tsv"

    Write-Tsv -Path $columnsPath `
        -Header "TABLE_NAME`tORDINAL_POSITION`tCOLUMN_NAME`tCOLUMN_TYPE`tIS_NULLABLE`tCOLUMN_DEFAULT`tEXTRA`tCOLUMN_KEY" `
        -Rows $columnRows
    Write-Tsv -Path $tablesPath `
        -Header "TABLE_NAME`tENGINE`tTABLE_COLLATION" `
        -Rows $tableRows
    Write-Tsv -Path $versionPath `
        -Header "PrefName`tValueString" `
        -Rows $versionRows

    Write-Host ""
    Write-Host ("Tables: {0}" -f $tableRows.Count)
    Write-Host ("Columns: {0}" -f $columnRows.Count)
    Write-Host ("ProgramVersion: {0}" -f $versions['ProgramVersion'])
    Write-Host ("DataBaseVersion: {0}" -f $versions['DataBaseVersion'])
    Write-Host ""
    Write-Host "Schema metadata written to:"
    Write-Host "  $columnsPath"
    Write-Host "  $tablesPath"
    Write-Host "  $versionPath"
}
finally {
    $script:DbPassword = $null
}
