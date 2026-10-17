<#
.SYNOPSIS
    Automated Enterprise Installer for AgentEdict (Intune, SCCM, GPO, or PowerShell).

.DESCRIPTION
    Installs AgentEdict on Windows workstations:
    - Verifies Administrator elevation
    - Creates C:\Program Files\AgentEdict with hardened NTFS ACLs
    - Installs edict.exe
    - Configures AgentEdictService with automatic recovery
    - Executes an initial sync to seed policies
    - Starts the Windows Service

.PARAMETER BundleUrl
    HTTPS URL to the GitLab policy-bundle.tar.gz package.

.PARAMETER DeployTokenFile
    Path to a securely transferred file containing a read_package_registry deploy token.

.PARAMETER SyncIntervalMinutes
    Interval between policy pulls (Default: 15).

.PARAMETER BinarySource
    Path to edict.exe (Default: searches current directory and .\bin\edict.exe).

.EXAMPLE
    .\install-agent.ps1 -BundleUrl "https://gitlab.example.com/api/v4/projects/42/packages/generic/agent-edict-bundle/latest/policy-bundle.tar.gz" -DeployTokenFile "C:\secure\agent-edict-token"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$BundleUrl,

    [Parameter(Mandatory = $false)]
    [string]$DeployTokenFile = "",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 1440)]
    [int]$SyncIntervalMinutes = 15,

    [Parameter(Mandatory = $false)]
    [string]$BinarySource = ""
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

function Invoke-CheckedNative {
    param([string]$Command, [string[]]$Arguments)
    $global:LASTEXITCODE = 0
    $Output = & $Command @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Native command failed: $Command (exit $LASTEXITCODE)." }
    return $Output
}

function Assert-NoReparsePoint {
    param([string]$Path)
    $Cursor = [IO.Path]::GetFullPath($Path)
    while (-not [string]::IsNullOrEmpty($Cursor)) {
        if (Test-Path -LiteralPath $Cursor) {
            if ((Get-Item -Force -LiteralPath $Cursor).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Installation and credential paths must not contain reparse points: $Cursor"
            }
        }
        $Cursor = [IO.Path]::GetDirectoryName($Cursor)
    }
}

function Assert-TrustedWindowsDescriptor {
    param($Descriptor, [switch]$Strict)
    $Trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    if ($Descriptor.OwnerSid -notin $Trusted) { throw 'Untrusted owner on service executable path.' }
    if (-not $Descriptor.HasDacl) { throw 'Missing DACL on service executable path.' }
    # DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL, GENERIC_WRITE, FILE_DELETE_CHILD.
    $Mask = 0x500D0040
    if ($Strict) { $Mask = $Mask -bor 0x116 } # WRITE_DATA, APPEND_DATA, WRITE_EA, WRITE_ATTRIBUTES
    foreach ($Ace in $Descriptor.Aces) {
        if (($Ace.Flags -band 0x08) -ne 0 -or $Ace.Type -eq 1) { continue } # inherit-only or deny
        if ($Ace.Type -ne 0) { throw 'Unsupported ACE on service executable path.' }
        if (($Ace.Mask -band $Mask) -ne 0 -and $Ace.Sid -notin $Trusted) {
            throw 'Untrusted write/delete/security grant on service executable path.'
        }
    }
}

function Get-WindowsPathDescriptor {
    param([string]$Path)
    $Acl = Get-Acl -LiteralPath $Path
    $Raw = [Security.AccessControl.RawSecurityDescriptor]::new($Acl.GetSecurityDescriptorBinaryForm(), 0)
    $Aces = @()
    if ($null -ne $Raw.DiscretionaryAcl) {
        foreach ($Ace in $Raw.DiscretionaryAcl) {
            $Entry = @{ Type = [int]$Ace.AceType; Flags = [int]$Ace.AceFlags; Mask = 0; Sid = '' }
            if ($Ace -is [Security.AccessControl.CommonAce]) {
                $Entry.Mask = $Ace.AccessMask
                $Entry.Sid = $Ace.SecurityIdentifier.Value
            }
            $Aces += $Entry
        }
    }
    return @{ OwnerSid = $Raw.Owner.Value; HasDacl = ($null -ne $Raw.DiscretionaryAcl); Aces = $Aces }
}

function Assert-TrustedInstallationPath {
    param([string]$Path)
    Assert-NoReparsePoint $Path
    $Cursor = [IO.Path]::GetFullPath($Path)
    $Strict = $true
    while (-not [string]::IsNullOrEmpty($Cursor)) {
        if (Test-Path -LiteralPath $Cursor) {
            try { Assert-TrustedWindowsDescriptor (Get-WindowsPathDescriptor $Cursor) -Strict:$Strict }
            catch { throw "Unsafe service executable path: $Cursor. Administrator review is required. $($_.Exception.Message)" }
            $Strict = $false
        }
        $Cursor = [IO.Path]::GetDirectoryName($Cursor)
    }
}

function Set-InstallAcl {
    param([string]$Path, [switch]$Directory, [switch]$AllowUsersRead)
    Assert-NoReparsePoint $Path
    if ($Directory) {
        $Acl = [Security.AccessControl.DirectorySecurity]::new()
        $Flags = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else {
        $Acl = [Security.AccessControl.FileSecurity]::new()
        $Flags = [Security.AccessControl.InheritanceFlags]::None
    }
    $System = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $Admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $Acl.SetOwner($Admins)
    $Acl.SetAccessRuleProtection($true, $false)
    foreach ($Sid in @($System, $Admins)) {
        $Acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($Sid, 'FullControl', $Flags, 'None', 'Allow'))
    }
    if ($AllowUsersRead) {
        $Users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
        $Acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($Users, 'ReadAndExecute', $Flags, 'None', 'Allow'))
    }
    # Replace the entire DACL and owner, including on adopted existing paths.
    Set-Acl -LiteralPath $Path -AclObject $Acl
}

$ParsedBundleUri = $null
if (-not [Uri]::TryCreate($BundleUrl, [UriKind]::Absolute, [ref]$ParsedBundleUri) -or
    $ParsedBundleUri.Scheme -cne 'https' -or $ParsedBundleUri.UserInfo -ne '') {
    throw 'BundleUrl must be an HTTPS URL without embedded credentials.'
}
$DeployToken = ""
if ($DeployTokenFile) {
    Assert-NoReparsePoint $DeployTokenFile
    if (-not (Test-Path -LiteralPath $DeployTokenFile -PathType Leaf)) { throw 'DeployTokenFile must be a regular file.' }
    $DeployToken = [IO.File]::ReadAllText((Resolve-Path -LiteralPath $DeployTokenFile).Path).TrimEnd("`r", "`n")
    if ([string]::IsNullOrWhiteSpace($DeployToken)) { throw 'DeployTokenFile is empty.' }
}
if ($DeployToken -match '\s') { throw 'Invalid deploy-token format.' }

# 1. Verify Administrative Elevation
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Log "This script must be executed from an elevated Administrator prompt." "ERROR"
    exit 1
}

# A service executable must live below the system Program Files directory.
# Arbitrary user-selected installation trees are deliberately unsupported.
$ProgramFilesRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
if ([string]::IsNullOrWhiteSpace($ProgramFilesRoot)) { throw 'Cannot resolve the system Program Files directory.' }
$InstallDir = Join-Path $ProgramFilesRoot 'AgentEdict'
Assert-TrustedInstallationPath $InstallDir

Write-Log "Starting AgentEdict enterprise installation..."

# 2. Locate Source Binary
$CandidatePaths = @(
    $BinarySource,
    (Join-Path $PSScriptRoot "edict.exe"),
    (Join-Path $PSScriptRoot "..\bin\edict.exe"),
    (Join-Path $PSScriptRoot "bin\edict.exe"),
    (Join-Path (Get-Location) "edict.exe")
)

$ResolvedBinary = $null
foreach ($path in $CandidatePaths) {
    if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path $path -PathType Leaf)) {
        $ResolvedBinary = (Resolve-Path $path).Path
        break
    }
}

if (-not $ResolvedBinary) {
    Write-Log "Could not locate edict.exe. Please specify -BinarySource or place edict.exe in the script folder." "ERROR"
    exit 1
}
Write-Log "Found binary at: $ResolvedBinary"

# 3. Create and Secure Target Installation Directory
Assert-TrustedInstallationPath $InstallDir
if (-not (Test-Path $InstallDir)) {
    Write-Log "Creating installation directory: $InstallDir"
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

Write-Log "Setting protected NTFS owner and permissions on $InstallDir..."
Set-InstallAcl $InstallDir -Directory -AllowUsersRead
Assert-TrustedInstallationPath $InstallDir

$DestinationExe = Join-Path $InstallDir "edict.exe"
Assert-TrustedInstallationPath $DestinationExe

# 4. Stop and Clean Any Existing AgentEdict Services
$ServiceName = "AgentEdictService"
Get-Service *AgentEdict* -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Log "Stopping and removing existing service: $($_.Name)..."
    Stop-Service -Name $_.Name -Force -ErrorAction SilentlyContinue
    Invoke-CheckedNative sc.exe @('delete', $_.Name) | Out-Null
    Start-Sleep -Seconds 1
}

# 5. Copy Binary
Write-Log "Deploying binary to $DestinationExe"
Assert-TrustedInstallationPath $DestinationExe
Copy-Item -Path $ResolvedBinary -Destination $DestinationExe -Force

# Lock the binary itself
Set-InstallAcl $DestinationExe -AllowUsersRead
Assert-TrustedInstallationPath $DestinationExe

$InstalledTokenFile = ""
if ($DeployToken) {
    $CredentialDir = Join-Path $InstallDir "credentials"
    Assert-NoReparsePoint $CredentialDir
    if (-not (Test-Path -LiteralPath $CredentialDir)) { New-Item -ItemType Directory -Path $CredentialDir | Out-Null }
    Set-InstallAcl $CredentialDir -Directory
    $InstalledTokenFile = Join-Path $CredentialDir "deploy-token"
    Assert-NoReparsePoint $InstalledTokenFile
    $TemporaryTokenFile = Join-Path $CredentialDir ([guid]::NewGuid().ToString("N"))
    try {
        [IO.File]::WriteAllText($TemporaryTokenFile, $DeployToken + "`n", [Text.UTF8Encoding]::new($false))
        Set-InstallAcl $TemporaryTokenFile
        Move-Item -LiteralPath $TemporaryTokenFile -Destination $InstalledTokenFile -Force
        Set-InstallAcl $InstalledTokenFile
    } finally {
        if (Test-Path -LiteralPath $TemporaryTokenFile) { Remove-Item -LiteralPath $TemporaryTokenFile -Force }
    }
}
$DeployToken = $null

# 6. Register Windows Service using only a protected credential-file path.
Write-Log "Registering Windows Service ($ServiceName)..."
$InstallArgs = @('service', 'install', '-bundle-url', $BundleUrl, '-interval', "$($SyncIntervalMinutes)m")
if ($InstalledTokenFile) { $InstallArgs += @('-deploy-token-file', $InstalledTokenFile) }
Invoke-CheckedNative $DestinationExe $InstallArgs | Out-Null
if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) { throw 'Service installation did not register the expected service.' }
Invoke-CheckedNative sc.exe @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/10000/restart/30000') | Out-Null

# 7. An initial enforcement failure must stop installation rather than report success.
Write-Log 'Executing initial policy sync and verification...'
$SyncArgs = @('sync-once', '-bundle-url', $BundleUrl)
if ($InstalledTokenFile) { $SyncArgs += @('-deploy-token-file', $InstalledTokenFile) }
Invoke-CheckedNative $DestinationExe $SyncArgs | Out-Null
Write-Log 'Initial policy sync completed.' 'SUCCESS'

# 8. Start Service
Write-Log "Starting $ServiceName..."
Start-Service -Name $ServiceName
Start-Sleep -Seconds 1

$FinalStatus = (Get-Service -Name $ServiceName).Status
if ($FinalStatus -eq "Running") {
    Write-Log "AgentEdict installed and running successfully!" "SUCCESS"
    exit 0
} else {
    Write-Log "Service is in state: $FinalStatus. Check Windows Event Viewer / Application log." "ERROR"
    exit 1
}
