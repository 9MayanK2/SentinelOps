#!/bin/bash
set -euo pipefail

##############################################################
# PKI Key Generation Script (One-Time Setup)
# Generates cosign.key (Private Key) & cosign.pub (Public Key)
##############################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

KEYS_DIR="$PROJECT_ROOT/security/config/keys"
COSIGN_IMAGE="${COSIGN_IMAGE:-ghcr.io/sigstore/cosign/cosign:v2.2.4}"
COSIGN_PASSWORD="${COSIGN_PASSWORD:-devsecops123}"

mkdir -p "$KEYS_DIR"

echo "=================================================="
echo "          PKI KEYPAIR GENERATION (ONE-TIME)"
echo "=================================================="

if [ -f "$KEYS_DIR/cosign.key" ] && [ -f "$KEYS_DIR/cosign.pub" ]; then
    echo "[INFO] PKI Keys already exist in $KEYS_DIR."
    echo "Private Key: $KEYS_DIR/cosign.key"
    echo "Public Key : $KEYS_DIR/cosign.pub"
    echo "=================================================="
    exit 0
fi

echo "[INFO] Generating new PKI Key pair in $KEYS_DIR..."

docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e COSIGN_PASSWORD="$COSIGN_PASSWORD" \
  -v "$KEYS_DIR:/keys:rw" \
  "$COSIGN_IMAGE" generate-key-pair --output-key-prefix /keys/cosign

chmod 600 "$KEYS_DIR/cosign.key" 2>/dev/null || true
chmod 644 "$KEYS_DIR/cosign.pub" 2>/dev/null || true

echo "[SUCCESS] PKI Keypair generated successfully."
echo "Private Key: $KEYS_DIR/cosign.key"
echo "Public Key : $KEYS_DIR/cosign.pub"
echo "=================================================="
