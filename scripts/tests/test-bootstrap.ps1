# Isolated tests: load only function definitions, never invoke setup or installer.
$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$ScriptPath = Join-Path $Root 'scripts/setup-gitlab.ps1'
$Tokens = $null
$Errors = $null
$Ast = [Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$Tokens, [ref]$Errors)
if ($Errors.Count) { throw 'Setup script parse failure.' }
foreach ($Function in $Ast.FindAll({param($Node) $Node -is [Management.Automation.Language.FunctionDefinitionAst]}, $false)) {
    . ([scriptblock]::Create($Function.Extent.Text))
}
function Assert([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Assert-Throws([scriptblock]$Action, [string]$Message) {
    $Thrown = $false
    try { & $Action } catch { $Thrown = $true }
    Assert $Thrown $Message
}
$Temp = Join-Path ([IO.Path]::GetTempPath()) ('edict-ps-test-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($Temp) | Out-Null
try {
    $Main = Join-Path $Temp 'main.go'
    $Public = Join-Path $Temp 'public.pem'
    [IO.File]::WriteAllText($Main, 'package main' + "`n" + 'const defaultPublicKeyPEM = `OLD`' + "`n")
    [IO.File]::WriteAllText($Public, "-----BEGIN PUBLIC KEY-----`nPUBLIC_TEST_DATA`n-----END PUBLIC KEY-----`n")
    Set-EmbeddedPublicKey $Main $Public
    $Source = [IO.File]::ReadAllText($Main)
    Assert ($Source.Contains('= `-----BEGIN PUBLIC KEY-----')) 'PEM must use a Go raw string.'
    Assert ($Source.Contains("PUBLIC_TEST_DATA`n-----END PUBLIC KEY-----" + '`')) 'PEM raw string must preserve newlines.'
    [IO.File]::WriteAllText($Main, 'package main')
    Assert-Throws { Set-EmbeddedPublicKey $Main $Public } 'Missing declaration must not report success.'

    # Mock private writer so validation tests invoke no ACL or external command.
    $script:Saved = $null
    function Write-PrivateText { param($Path, $Text) $script:Saved = @{Path=$Path; Text=$Text} }
    Save-EndpointToken ([pscustomobject]@{token='fake-endpoint'; scopes=@('read_package_registry')}) 'target-file'
    Assert ($script:Saved.Text -eq "fake-endpoint`n") 'Valid scoped token should be saved.'
    foreach ($Bad in @(
        [pscustomobject]@{token='fake-endpoint'; scopes=@('read_package_registry', 'write_repository')},
        [pscustomobject]@{token=''; scopes=@('read_package_registry')},
        [pscustomobject]@{token='fake-endpoint'; scopes=@('read_package_registry'); revoked=$true}
    )) {
        $script:Saved = $null
        Assert-Throws { Save-EndpointToken $Bad 'target-file' } 'Invalid token response must fail.'
        Assert ($null -eq $script:Saved) 'Invalid token must never be written.'
    }

    function Mock-NativeFailure { $global:LASTEXITCODE = 7; 'sensitive mock output' }
    Assert-Throws { Invoke-CheckedNative Mock-NativeFailure @() } 'Native nonzero exit must be fatal.'
    function Mock-NativeSuccess { $global:LASTEXITCODE = 0; 'ok' }
    Assert ((Invoke-CheckedNative Mock-NativeSuccess @()) -eq 'ok') 'Native success should return output.'
    $script:Headers = @{ 'PRIVATE-TOKEN' = 'fake-management' }
    function Invoke-WebRequest {
        param($Uri, $Method, $Headers, $MaximumRedirection, $UseBasicParsing, $TimeoutSec, $Body)
        Assert ($MaximumRedirection -eq 0) 'Credential-bearing API requests must not follow redirects.'
        return [pscustomobject]@{ StatusCode = 201; Content = '{"token":"fake-endpoint","scopes":["read_package_registry"]}' }
    }
    $Response = Invoke-GitLabRequest POST 'projects/12345/deploy_tokens' @{scopes=@('read_package_registry')} 201
    Assert ($Response.token -eq 'fake-endpoint') 'Expected JSON response was not parsed.'
    function Invoke-WebRequest { return [pscustomobject]@{StatusCode=403; Content='fake-management'} }
    Assert-Throws { Invoke-GitLabRequest POST 'projects/12345/deploy_tokens' -ExpectedStatus 201 } 'Failed HTTP status must abort.'
    function Invoke-WebRequest { return [pscustomobject]@{StatusCode=201; Content='not-json'} }
    Assert-Throws { Invoke-GitLabRequest POST 'projects/12345/deploy_tokens' -ExpectedStatus 201 } 'Malformed JSON must abort.'
    Write-Output 'PASS: PEM raw string, deployment scope validation, HTTP/JSON failures, redirect refusal, native exit handling.'
} finally {
    Remove-Item -LiteralPath $Temp -Recurse -Force
}
