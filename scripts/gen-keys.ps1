# PowerShell script to generate Ed25519 keys for AgentEdict
$KeysDir = Join-Path $PSScriptRoot "..\keys"
if (-not (Test-Path $KeysDir)) {
    New-Item -ItemType Directory -Path $KeysDir | Out-Null
}

$PrivateKey = Join-Path $KeysDir "agent-edict-signing-key.pem"
$PublicKey  = Join-Path $KeysDir "agent-edict-public-key.pem"

Write-Host "Generating Ed25519 Keypair via openssl..."
openssl genpkey -algorithm ED25519 -out $PrivateKey
openssl pkey -in $PrivateKey -pubout -out $PublicKey

Write-Host "`n=== Ed25519 Keys Generated Successfully ==="
Write-Host "Private Key: $PrivateKey"
Write-Host "Public Key:  $PublicKey`n"

$Base64Key = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($PrivateKey))
Write-Host "1. GitLab CI Protected Variable (EDICT_SIGNING_PRIVATE_KEY):"
Write-Host $Base64Key -ForegroundColor Green

Write-Host "`n2. Public Key to embed in cmd/edict/main.go (defaultPublicKeyPEM):"
Get-Content $PublicKey | Write-Host -ForegroundColor Cyan
