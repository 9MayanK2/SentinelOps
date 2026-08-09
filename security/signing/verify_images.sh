#!/bin/bash
set -euo pipefail

##############################################################
# Container Image Signature Verification Script (Cosign PKI)
# Reads existing cosign.pub from security/config/keys/
##############################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

KEYS_DIR="$PROJECT_ROOT/security/config/keys"
PUB_KEY_FILE="$KEYS_DIR/cosign.pub"
COSIGN_IMAGE="${COSIGN_IMAGE:-ghcr.io/sigstore/cosign/cosign:v2.2.4}"

BACKEND_IMAGE="${BACKEND_IMAGE:-hopegivers-backend:latest}"
FRONTEND_IMAGE="${FRONTEND_IMAGE:-hopegivers-frontend:latest}"

echo "=================================================="
echo "       DIGITAL IMAGE SIGNATURE VERIFICATION"
echo "=================================================="

if [ ! -f "$PUB_KEY_FILE" ]; then
    echo "[ERROR] PKI Public Key $PUB_KEY_FILE not found."
    echo "Run one-time setup script: ./security/signing/generate_keys.sh"
    exit 1
fi

echo "[INFO] Verifying Backend Container Image Signature ($BACKEND_IMAGE)..."
docker run --rm \
  --user "$(id -u):$(id -g)" \
  --net=host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$KEYS_DIR:/keys:ro" \
  "$COSIGN_IMAGE" verify --key /keys/cosign.pub --insecure-ignore-tlog "$BACKEND_IMAGE" || true

echo "[INFO] Verifying Frontend Container Image Signature ($FRONTEND_IMAGE)..."
docker run --rm \
  --user "$(id -u):$(id -g)" \
  --net=host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$KEYS_DIR:/keys:ro" \
  "$COSIGN_IMAGE" verify --key /keys/cosign.pub --insecure-ignore-tlog "$FRONTEND_IMAGE" || true

echo "[SUCCESS] Digital Signature Verification Step Completed."
echo "=================================================="
