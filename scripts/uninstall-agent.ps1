<#
.SYNOPSIS
    Enterprise Uninstaller for AgentEdict.

.DESCRIPTION
    Safely removes AgentEdict from Windows workstations:
    - Stops and removes AgentEdictService
    - Cleans up Gemini CLI system environment registry overrides
    - Removes installation files from C:\Program Files\AgentEdict
    - Optionally purges cached vault and enforced policy files (-PurgeData)

.PARAMETER PurgeData
    Switch to also remove cached bundles and delete enforced policy files.

.EXAMPLE
    .\uninstall-agent.ps1 -PurgeData
#>

[CmdletBinding()]
param (
    [switch]$PurgeData
)

$ErrorActionPreference = "Stop"

function Write-Log {
    param ([string]$Message, [string]$Level = "INFO")
    $Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $Color = switch ($Level) {
        "ERROR"   { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        default   { "Cyan" }
    }
    Write-Host "[$Timestamp] [$Level] $Message" -ForegroundColor $Color
}

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Log "This script must be executed from an elevated Administrator prompt." "ERROR"
    exit 1
}

Write-Log "Starting AgentEdict uninstallation..."

$ServiceName = "AgentEdictService"
$InstallDir  = "C:\Program Files\AgentEdict"
$DataDir     = "C:\ProgramData\AgentEdict"

# 1. Stop and Delete Service
$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Log "Stopping $ServiceName..."
    if ($svc.Status -eq "Running") {
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 2
    }
    Write-Log "Deleting $ServiceName from Service Control Manager..."
    & sc.exe delete $ServiceName | Out-Null
} else {
    Write-Log "Service $ServiceName was not installed."
}

# 2. Remove Gemini CLI Environment Override
$EnvRegKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
$GeminiVar = "GEMINI_CLI_SYSTEM_SETTINGS_PATH"
if ((Get-ItemProperty -Path $EnvRegKey -Name $GeminiVar -ErrorAction SilentlyContinue)) {
    Write-Log "Removing $GeminiVar from system environment..."
    Remove-ItemProperty -Path $EnvRegKey -Name $GeminiVar -Force
}

# 3. Ask the installed binary which files it manages before removing it, so
# this list never drifts from the targets the service locks.
$exe = Join-Path $InstallDir "edict.exe"
$ManagedFiles = @()
if (Test-Path -LiteralPath $exe) {
    $ManagedFiles = @(& $exe targets | ForEach-Object {
        $purpose, $path = $_ -split "`t", 2
        [pscustomobject]@{ Purpose = $purpose; Path = $path }
    })
    if ($LASTEXITCODE -ne 0) { throw "edict targets failed (exit $LASTEXITCODE)." }
} else {
    Write-Log "edict.exe not found; managed policy files cannot be listed or unlocked." "WARNING"
}

# 4. Unlock and Remove Program Files
if (Test-Path $InstallDir) {
    Write-Log "Removing installation directory: $InstallDir"
    if (Test-Path $exe) {
        attrib -R "$exe" 2>$null
    }
    Remove-Item -Path $InstallDir -Recurse -Force
}

# 5. Unlock managed files. Hook registrations run edict.exe, which was just
# removed, so they are always deleted; a fail-closed client would otherwise
# deny every tool call. Policy files are kept unless -PurgeData is set.
foreach ($file in $ManagedFiles) {
    if (-not (Test-Path -LiteralPath $file.Path -PathType Leaf)) { continue }
    attrib -R "$($file.Path)" 2>$null
    if ($PurgeData -or $file.Purpose -eq "hook-registration") {
        Write-Log "Removing managed file: $($file.Path)"
        Remove-Item -LiteralPath $file.Path -Force -ErrorAction SilentlyContinue
    }
}

# 6. Optional: Purge cached vault
if ($PurgeData) {
    Write-Log "Purging cached vault..."
    if (Test-Path $DataDir) {
        attrib -R -H -S "$DataDir" 2>$null
        attrib -R -H -S "$DataDir\*" /S /D 2>$null
        Remove-Item -Path $DataDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Log "AgentEdict uninstallation completed successfully." "SUCCESS"
exit 0
