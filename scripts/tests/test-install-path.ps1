# Pure/mocked installer tests: no service, ACL mutation, or native process runs.
$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$Tokens = $null
$Errors = $null
$Ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $Root 'scripts/install-agent.ps1'), [ref]$Tokens, [ref]$Errors)
if ($Errors.Count) { throw 'Installer parse failure.' }
foreach ($Function in $Ast.FindAll({param($Node) $Node -is [Management.Automation.Language.FunctionDefinitionAst]}, $false)) {
    . ([scriptblock]::Create($Function.Extent.Text))
}
function Assert([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Assert-Throws([scriptblock]$Action, [string]$Message) {
    $Thrown = $false
    try { & $Action } catch { $Thrown = $true }
    Assert $Thrown $Message
}
function Descriptor([int]$Mask=0, [string]$Sid='S-1-5-32-545', [string]$Owner='S-1-5-32-544', [int]$Flags=0) {
    return @{OwnerSid=$Owner; HasDacl=$true; Aces=@(@{Type=0; Flags=$Flags; Mask=$Mask; Sid=$Sid})}
}
Assert-TrustedWindowsDescriptor (Descriptor) -Strict
Assert-TrustedWindowsDescriptor (Descriptor -Mask 0x1F01FF -Sid 'S-1-5-18') -Strict
Assert-Throws { Assert-TrustedWindowsDescriptor (Descriptor -Owner 'S-1-5-21-123') } 'User-owned ancestor must fail.'
foreach ($Mask in @(0x10000, 0x40000, 0x80000, 0x40, 0x10000000, 0x40000000)) {
    Assert-Throws { Assert-TrustedWindowsDescriptor (Descriptor -Mask $Mask) } 'Ancestor delete/security grants must fail.'
}
foreach ($Mask in @(2, 4, 16, 256)) {
    Assert-Throws { Assert-TrustedWindowsDescriptor (Descriptor -Mask $Mask) -Strict } 'Writable executable or nearest parent must fail.'
}
Assert-TrustedWindowsDescriptor (Descriptor -Mask 2) # Unrelated child creation in higher ancestors is permitted.
Assert-TrustedWindowsDescriptor (Descriptor -Mask 0x1F01FF -Flags 8) -Strict # Inherit-only grant does not apply here.
Assert-Throws { Assert-TrustedWindowsDescriptor @{OwnerSid='S-1-5-18';HasDacl=$false;Aces=@()} } 'NULL DACL must fail.'
Assert-Throws { Assert-TrustedWindowsDescriptor @{OwnerSid='S-1-5-18';HasDacl=$true;Aces=@(@{Type=9;Flags=0;Mask=0;Sid=''})} } 'Unknown ACE must fail closed.'

$Temp = Join-Path ([IO.Path]::GetTempPath()) ('edict-installer-test-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory((Join-Path $Temp 'parent/bin')) | Out-Null
try {
    $Exe = Join-Path $Temp 'parent/bin/edict.exe'
    [IO.File]::WriteAllText($Exe, 'fixture')
    # Descriptor inspection is mocked to exercise the actual complete walk.
    $script:UnsafePath = Join-Path $Temp 'parent'
    $script:UnsafeMask = 0
    function Get-WindowsPathDescriptor {
        param($Path)
        if ($Path -eq $script:UnsafePath) { return Descriptor -Mask $script:UnsafeMask }
        return Descriptor
    }
    # macOS /var is a system symlink in its temp path; isolate ACL walking tests
    # from native Windows reparse evaluation, which has its own implementation.
    function Assert-NoReparsePoint { param($Path) }
    Assert-TrustedInstallationPath $Exe
    $script:UnsafeMask = 0x40
    Assert-Throws { Assert-TrustedInstallationPath $Exe } 'Intermediate DELETE_CHILD must be rejected.'
    $script:UnsafePath = Join-Path $Temp 'parent/bin'
    $script:UnsafeMask = 2
    Remove-Item -LiteralPath $Exe
    Assert-Throws { Assert-TrustedInstallationPath $Exe } 'Missing executable requires strict nearest-existing-parent checks.'
    $Params = @($Ast.ParamBlock.Parameters.Name.VariablePath.UserPath)
    Assert ('DeployToken' -notin $Params) 'Raw credential arguments must be unsupported.'
    Assert ('InstallDir' -notin $Params) 'Arbitrary service installation trees must be unsupported.'
    Write-Output 'PASS: trusted owners, DACL rights, intermediate ancestors, missing-leaf parent, and restricted installer inputs.'
} finally {
    Remove-Item -LiteralPath $Temp -Recurse -Force
}
