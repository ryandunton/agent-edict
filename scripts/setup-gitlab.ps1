<#
.SYNOPSIS
    Configure GitLab using an explicitly supplied management credential.
.DESCRIPTION
    Reads GITLAB_TOKEN or prompts without echo. Creates a scoped endpoint token
    in a protected file. Never prints credentials or embeds them in git URLs.
#>
[CmdletBinding()]
param (
    [string]$Token = $env:GITLAB_TOKEN,
    [string]$Namespace = $env:GITLAB_NAMESPACE,
    [string]$ProjectName = 'agent-edict'
)
$ErrorActionPreference = 'Stop'

function Invoke-CheckedNative {
    param([string]$Command, [string[]]$Arguments)
    $global:LASTEXITCODE = 0
    $Output = & $Command @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Native command failed: $Command (exit $LASTEXITCODE)." }
    return $Output
}

function Protect-SetupPath {
    param([string]$Path, [switch]$Directory)
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $Owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
        if ($Directory) {
            $Acl = [Security.AccessControl.DirectorySecurity]::new()
            $Flags = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        } else {
            $Acl = [Security.AccessControl.FileSecurity]::new()
            $Flags = [Security.AccessControl.InheritanceFlags]::None
        }
        $Acl.SetOwner($Owner)
        $Acl.SetAccessRuleProtection($true, $false)
        foreach ($Sid in @($Owner, [Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
            $Acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($Sid, 'FullControl', $Flags, 'None', 'Allow'))
        }
        Set-Acl -LiteralPath $Path -AclObject $Acl
    } else {
        $Mode = if ($Directory) { '700' } else { '600' }
        Invoke-CheckedNative chmod @($Mode, $Path) | Out-Null
    }
}

function Write-PrivateText {
    param([string]$Path, [string]$Text)
    # Parent must already be private. CreateNew prevents overwrites or symlink following.
    $Stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $Bytes = [Text.UTF8Encoding]::new($false).GetBytes($Text)
        $Stream.Write($Bytes, 0, $Bytes.Length)
    } finally { $Stream.Dispose() }
    Protect-SetupPath $Path
}

function Set-EmbeddedPublicKey {
    param([string]$MainGo, [string]$PublicKey)
    $PubPem = [IO.File]::ReadAllText($PublicKey).Trim()
    if ($PubPem.Contains('`') -or -not $PubPem.StartsWith('-----BEGIN PUBLIC KEY-----') -or -not $PubPem.EndsWith('-----END PUBLIC KEY-----')) {
        throw 'Invalid public key PEM.'
    }
    $Content = [IO.File]::ReadAllText($MainGo)
    $Pattern = 'const defaultPublicKeyPEM = `[^`]*`'
    if ([regex]::Matches($Content, $Pattern).Count -ne 1) { throw 'Expected exactly one defaultPublicKeyPEM declaration; source unchanged.' }
    $Replacement = 'const defaultPublicKeyPEM = `' + $PubPem + '`'
    $Content = [regex]::Replace($Content, $Pattern, [Text.RegularExpressions.MatchEvaluator]{ param($Match) $Replacement })
    [IO.File]::WriteAllText($MainGo, $Content, [Text.UTF8Encoding]::new($false))
}

function Save-EndpointToken {
    param($Response, [string]$Path)
    $Scopes = @($Response.scopes)
    if ($Response.token -isnot [string] -or [string]::IsNullOrWhiteSpace($Response.token) -or
        $Response.token -match '\s' -or $Scopes.Count -ne 1 -or $Scopes[0] -cne 'read_package_registry' -or
        $Response.revoked -eq $true -or $Response.expired -eq $true) {
        throw 'Deploy-token creation failed validation; no management-token fallback is permitted.'
    }
    Write-PrivateText $Path ($Response.token + "`n")
}

function Invoke-GitLabRequest {
    param([string]$Method, [string]$Path, $Body = $null, [int]$ExpectedStatus = 200, [switch]$AllowNotFound)
    $Options = @{ Uri = "https://gitlab.com/api/v4/$Path"; Method = $Method; Headers = $script:Headers; MaximumRedirection = 0; UseBasicParsing = $true; TimeoutSec = 60 }
    if ($null -ne $Body) { $Options.Body = ConvertTo-Json -InputObject $Body -Depth 10 -Compress }
    try { $Response = Invoke-WebRequest @Options }
    catch {
        $Status = 0
        if ($null -ne $_.Exception.Response) { $Status = [int]$_.Exception.Response.StatusCode }
        if ($AllowNotFound -and $Status -eq 404) { return $null }
        throw "GitLab request failed ($Method, HTTP $Status). Response body was not logged."
    }
    if ([int]$Response.StatusCode -ne $ExpectedStatus) { throw "Unexpected GitLab HTTP status: $($Response.StatusCode)." }
    try { return ConvertFrom-Json -InputObject $Response.Content -ErrorAction Stop }
    catch { throw 'Invalid GitLab JSON response.' }
}

function Get-ResponseId {
    param($Response)
    if ($null -eq $Response -or $Response.id -isnot [ValueType] -or "$($Response.id)" -notmatch '^[1-9][0-9]*$') { throw 'Invalid GitLab resource ID.' }
    return $Response.id
}

function Invoke-GitLabSetup {
    if ([string]::IsNullOrWhiteSpace($Token)) {
        $SecureToken = Read-Host 'GitLab management token' -AsSecureString
        $Token = [Net.NetworkCredential]::new('', $SecureToken).Password
    }
    if ([string]::IsNullOrWhiteSpace($Token) -or $Token -match '[\r\n]') { throw 'An explicit GitLab management token is required.' }
    Remove-Item Env:GITLAB_TOKEN -ErrorAction SilentlyContinue
    $script:Headers = @{ 'PRIVATE-TOKEN' = $Token; 'Content-Type' = 'application/json' }
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $TempDir = Join-Path ([IO.Path]::GetTempPath()) ('agent-edict-setup-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $TempDir | Out-Null
    Protect-SetupPath $TempDir -Directory
    $PreviousAskPass = $env:GIT_ASKPASS
    $PreviousTokenFile = $env:EDICT_SETUP_TOKEN_FILE
    $PreviousPrompt = $env:GIT_TERMINAL_PROMPT
    Push-Location $RepoRoot
    try {
        Write-Host '[1/7] Verifying GitLab credentials...'
        $User = Invoke-GitLabRequest GET user
        if ([string]::IsNullOrWhiteSpace($User.username)) { throw 'Missing GitLab username.' }
        if ([string]::IsNullOrWhiteSpace($Namespace)) { $Namespace = $User.username }

        Write-Host '[2/7] Preparing Ed25519 signing keys...'
        $KeysDir = Join-Path $RepoRoot 'keys'
        if (-not (Test-Path $KeysDir)) { New-Item -ItemType Directory -Path $KeysDir | Out-Null }
        if ((Get-Item -Force $KeysDir).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'keys must not be a reparse point.' }
        Protect-SetupPath $KeysDir -Directory
        $PrivateKey = Join-Path $KeysDir 'agent-edict-signing-key.pem'
        $PublicKey = Join-Path $KeysDir 'agent-edict-public-key.pem'
        if (-not (Test-Path $PrivateKey)) { Invoke-CheckedNative openssl @('genpkey', '-algorithm', 'ED25519', '-out', $PrivateKey) | Out-Null }
        Invoke-CheckedNative openssl @('pkey', '-in', $PrivateKey, '-pubout', '-out', $PublicKey) | Out-Null
        Protect-SetupPath $PrivateKey

        Write-Host '[3/7] Embedding public verification key...'
        Set-EmbeddedPublicKey (Join-Path $RepoRoot 'cmd/edict/main.go') $PublicKey

        Write-Host '[4/7] Ensuring the GitLab project exists...'
        $EncodedPath = [Uri]::EscapeDataString("$Namespace/$ProjectName")
        $Project = Invoke-GitLabRequest GET "projects/$EncodedPath" -AllowNotFound
        if ($null -eq $Project) {
            $NamespaceData = Invoke-GitLabRequest GET ('namespaces/' + [Uri]::EscapeDataString($Namespace))
            $Project = Invoke-GitLabRequest POST projects @{ name = $ProjectName; path = $ProjectName; namespace_id = (Get-ResponseId $NamespaceData); visibility = 'private'; initialize_with_readme = $false } 201
        }
        $ProjectId = Get-ResponseId $Project

        Write-Host '[5/7] Committing and pushing the codebase...'
        Invoke-CheckedNative git @('init', '-b', 'main') | Out-Null
        Invoke-CheckedNative git @('config', 'user.name', $User.username) | Out-Null
        Invoke-CheckedNative git @('config', 'user.email', "$($User.username)@users.noreply.gitlab.com") | Out-Null
        Invoke-CheckedNative git @('add', '-A') | Out-Null
        Invoke-CheckedNative git @('commit', '-m', 'Initialize AgentEdict Universal Policy Engine', '--allow-empty') | Out-Null
        $Remote = "https://gitlab.com/$Namespace/$ProjectName.git"
        $Remotes = Invoke-CheckedNative git @('remote')
        if ($Remotes -contains 'origin') { Invoke-CheckedNative git @('remote', 'set-url', 'origin', $Remote) | Out-Null }
        else { Invoke-CheckedNative git @('remote', 'add', 'origin', $Remote) | Out-Null }
        $TokenFile = Join-Path $TempDir 'management-token'
        Write-PrivateText $TokenFile $Token
        # Git for Windows executes askpass scripts through its bundled sh.
        $AskPass = Join-Path $TempDir 'askpass.sh'
        $Helper = '#!/bin/sh' + "`n" + 'case "$1" in *Username*) printf "%s\n" oauth2 ;; *Password*) cat "$EDICT_SETUP_TOKEN_FILE" ;; *) exit 1 ;; esac' + "`n"
        Write-PrivateText $AskPass $Helper
        if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { Invoke-CheckedNative chmod @('700', $AskPass) | Out-Null }
        $env:GIT_ASKPASS = $AskPass
        $env:GIT_TERMINAL_PROMPT = '0'
        $env:EDICT_SETUP_TOKEN_FILE = $TokenFile
        Invoke-CheckedNative git @('-c', 'credential.helper=', 'push', '-u', 'origin', 'HEAD:main') | Out-Null

        Write-Host '[6/7] Configuring the protected CI signing variable...'
        $Variable = @{ key = 'EDICT_SIGNING_PRIVATE_KEY'; value = [Convert]::ToBase64String([IO.File]::ReadAllBytes($PrivateKey)); protected = $true; masked = $false; raw = $true }
        $Existing = Invoke-GitLabRequest GET "projects/$ProjectId/variables/EDICT_SIGNING_PRIVATE_KEY" -AllowNotFound
        if ($null -eq $Existing) { Invoke-GitLabRequest POST "projects/$ProjectId/variables" $Variable 201 | Out-Null }
        else { Invoke-GitLabRequest PUT "projects/$ProjectId/variables/EDICT_SIGNING_PRIVATE_KEY" $Variable | Out-Null }

        Write-Host '[7/7] Creating a scoped endpoint credential...'
        $Deploy = Invoke-GitLabRequest POST "projects/$ProjectId/deploy_tokens" @{ name = 'agent-edict-endpoint-token'; scopes = @('read_package_registry') } 201
        $EndpointFile = Join-Path $KeysDir ('agent-edict-deploy-token-' + [guid]::NewGuid().ToString('N'))
        Save-EndpointToken $Deploy $EndpointFile
        Invoke-GitLabRequest POST "projects/$ProjectId/pipeline?ref=main" -ExpectedStatus 201 | Out-Null
        $BundleUrl = "https://gitlab.com/api/v4/projects/$ProjectId/packages/generic/agent-edict-bundle/latest/policy-bundle.tar.gz"
        Write-Host "Setup complete. Endpoint token saved to protected file: $EndpointFile"
        Write-Host 'Review policy-map.yaml before deployment: the pipeline signs whatever it contains.'
        Write-Host 'Securely copy the endpoint token file to each workstation; do not paste its contents into commands.'
        Write-Host ".\scripts\install-agent.ps1 -BundleUrl `"$BundleUrl`" -DeployTokenFile `"C:\secure\agent-edict-token`""
    } finally {
        $env:GIT_ASKPASS = $PreviousAskPass
        $env:EDICT_SETUP_TOKEN_FILE = $PreviousTokenFile
        $env:GIT_TERMINAL_PROMPT = $PreviousPrompt
        $script:Headers = $null
        Remove-Item -LiteralPath $TempDir -Recurse -Force
        Pop-Location
    }
}

if ($MyInvocation.InvocationName -ne '.') { Invoke-GitLabSetup }
