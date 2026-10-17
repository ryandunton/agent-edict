#!/usr/bin/env bash
set -euo pipefail

# Generate Ed25519 Keypair for AgentEdict
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/../keys"
mkdir -p "${OUTPUT_DIR}"

PRIVATE_KEY="${OUTPUT_DIR}/agent-edict-signing-key.pem"
PUBLIC_KEY="${OUTPUT_DIR}/agent-edict-public-key.pem"

echo "Generating Ed25519 private key..."
openssl genpkey -algorithm ED25519 -out "${PRIVATE_KEY}"

echo "Extracting Ed25519 public key..."
openssl pkey -in "${PRIVATE_KEY}" -pubout -out "${PUBLIC_KEY}"

chmod 600 "${PRIVATE_KEY}"
chmod 644 "${PUBLIC_KEY}"

echo ""
echo "=== Ed25519 Keys Generated Successfully ==="
echo "Private Key: ${PRIVATE_KEY}"
echo "Public Key:  ${PUBLIC_KEY}"
echo ""
echo "1. In GitLab: Save the Base64 of your private key as a Protected & Masked CI Variable:"
echo "   Variable Name: EDICT_SIGNING_PRIVATE_KEY"
echo "   Value (Base64):"
base64 < "${PRIVATE_KEY}" | tr -d '\n'
echo ""
echo ""
echo "2. In AgentEdict (cmd/edict/main.go):"
echo "   Embed this public key into 'defaultPublicKeyPEM':"
cat "${PUBLIC_KEY}"
echo ""
