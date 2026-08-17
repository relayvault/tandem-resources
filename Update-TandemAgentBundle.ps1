#requires -Version 5.1
<#
.SYNOPSIS
    Replaces the installed Tandem edge-agent bundle.

.DESCRIPTION
    Stops the TandemEdgeAgent scheduled task with schtasks.exe, replaces the
    locked bundle, verifies its published SHA-256, and starts the task again.
    Run this script from an elevated PowerShell window.

.PARAMETER BundlePath
    Path to the reviewed relay-vault-edge-agent.cjs bundle.

.PARAMETER ExpectedSha256
    Published SHA-256 from SHA256SUMS. A checkout with CRLF conversion is also
    accepted when its LF-normalized bytes match this published hash.

.PARAMETER InstallDirectory
    Existing agent installation directory.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$BundlePath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedSha256,

    [string]$InstallDirectory = 'C:\Program Files\Tandem'
)

$ErrorActionPreference = 'Stop'
$taskName = 'TandemEdgeAgent'
$bundleInstallPath = Join-Path $InstallDirectory 'relay-vault-edge-agent.cjs'
$tempDirectory = Join-Path $env:TEMP ('tandem-agent-update-' + [guid]::NewGuid().ToString('N'))
$backupPath = Join-Path $tempDirectory 'relay-vault-edge-agent.previous.cjs'
$bundleWasRunning = $false
$bundleWasBackedUp = $false

function Fail([string]$Message) {
    throw $Message
}

function Assert-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Fail 'Run this bundle updater from an elevated PowerShell window.'
    }
}

function Get-Sha256([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToUpperInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Get-CanonicalBundleHash([string]$Path) {
    $bytes = [IO.File]::ReadAllBytes($Path)
    $text = [Text.Encoding]::UTF8.GetString($bytes)
    $canonicalBytes = [Text.Encoding]::UTF8.GetBytes(($text -replace "`r`n", "`n"))
    return Get-Sha256 $canonicalBytes
}

function Assert-BundleHash([string]$Path) {
    $expected = $ExpectedSha256.ToUpperInvariant()
    $raw = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($raw -eq $expected) {
        return 'exact'
    }
    $canonical = Get-CanonicalBundleHash $Path
    if ($canonical -eq $expected) {
        Write-Warning "Bundle bytes use checkout line endings; LF-normalized bytes match the published hash $expected."
        return 'normalized'
    }
    Fail "Bundle SHA-256 mismatch. Expected $expected but found $raw (LF-normalized: $canonical)."
}

function Assert-TaskExists {
    & schtasks.exe /Query /TN $taskName /FO CSV /NH 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Fail "Scheduled task $taskName was not found."
    }
}

function Stop-AgentTask {
    $query = & schtasks.exe /Query /TN $taskName /FO LIST 2>&1
    if ($LASTEXITCODE -ne 0) {
        Fail "Unable to query scheduled task $taskName."
    }
    $script:bundleWasRunning = $query -match '(?im)^\s*Status:\s+Running\s*$'
    if ($script:bundleWasRunning) {
        & schtasks.exe /End /TN $taskName 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Fail "Unable to stop scheduled task $taskName."
        }
        for ($attempt = 1; $attempt -le 30; $attempt++) {
            Start-Sleep -Seconds 1
            $query = & schtasks.exe /Query /TN $taskName /FO LIST 2>&1
            if ($query -notmatch '(?im)^\s*Status:\s+Running\s*$') {
                return
            }
        }
        Fail "Scheduled task $taskName did not stop within 30 seconds."
    }
}

function Start-AgentTask {
    & schtasks.exe /Run /TN $taskName 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Fail "Unable to start scheduled task $taskName."
    }
}

try {
    Assert-Elevated
    if (-not (Test-Path -LiteralPath $BundlePath -PathType Leaf)) {
        Fail "Bundle path does not exist: $BundlePath"
    }
    if (-not (Test-Path -LiteralPath $bundleInstallPath -PathType Leaf)) {
        Fail "Installed bundle does not exist: $bundleInstallPath"
    }
    [void](Assert-BundleHash -Path $BundlePath)
    Assert-TaskExists
    New-Item -ItemType Directory -Path $tempDirectory -Force | Out-Null
    Copy-Item -LiteralPath $bundleInstallPath -Destination $backupPath -Force
    $bundleWasBackedUp = $true
    Stop-AgentTask
    Copy-Item -LiteralPath $BundlePath -Destination $bundleInstallPath -Force
    $hashMode = Assert-BundleHash -Path $bundleInstallPath
    Start-AgentTask
    Write-Host "Tandem edge-agent bundle updated successfully."
    Write-Host "Installed path: $bundleInstallPath"
    Write-Host "Hash verification: $hashMode"
}
catch {
    if ($bundleWasBackedUp) {
        Copy-Item -LiteralPath $backupPath -Destination $bundleInstallPath -Force -ErrorAction SilentlyContinue
    }
    if ($bundleWasRunning) {
        Start-AgentTask
    }
    Write-Error $_.Exception.Message
    exit 1
}
finally {
    if (Test-Path -LiteralPath $tempDirectory) {
        Remove-Item -LiteralPath $tempDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}
