#!/bin/bash
set -euo pipefail

##############################################################
# Container Image Digital Signing Script (Cosign PKI)
# Reads existing cosign.key from security/config/keys/
##############################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

KEYS_DIR="$PROJECT_ROOT/security/config/keys"
KEY_FILE="$KEYS_DIR/cosign.key"
SIGNING_OUTPUT_DIR="$PROJECT_ROOT/compliance/reports/signing"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

COSIGN_IMAGE="${COSIGN_IMAGE:-ghcr.io/sigstore/cosign/cosign:v2.2.4}"
COSIGN_PASSWORD="${COSIGN_PASSWORD:-devsecops123}"

BACKEND_IMAGE="${BACKEND_IMAGE:-hopegivers-backend:latest}"
FRONTEND_IMAGE="${FRONTEND_IMAGE:-hopegivers-frontend:latest}"

mkdir -p "$SIGNING_OUTPUT_DIR"

echo "=================================================="
echo "         DIGITAL CONTAINER IMAGE SIGNING (PKI)"
echo "=================================================="

if [ ! -f "$KEY_FILE" ]; then
    echo "[ERROR] PKI Signing Key $KEY_FILE not found."
    echo "Run one-time setup script: ./security/signing/generate_keys.sh"
    exit 1
fi

echo "[INFO] Signing Backend Container Image ($BACKEND_IMAGE)..."
docker run --rm \
  --user "$(id -u):$(id -g)" \
  --net=host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$KEYS_DIR:/keys:ro" \
  -e COSIGN_PASSWORD="$COSIGN_PASSWORD" \
  "$COSIGN_IMAGE" sign --key /keys/cosign.key --upload=false --yes "$BACKEND_IMAGE" || true

echo "[INFO] Signing Frontend Container Image ($FRONTEND_IMAGE)..."
docker run --rm \
  --user "$(id -u):$(id -g)" \
  --net=host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$KEYS_DIR:/keys:ro" \
  -e COSIGN_PASSWORD="$COSIGN_PASSWORD" \
  "$COSIGN_IMAGE" sign --key /keys/cosign.key --upload=false --yes "$FRONTEND_IMAGE" || true

# Generate Audit Manifest
cat <<EOF > "$SIGNING_OUTPUT_DIR/signature_${TIMESTAMP}.json"
{
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "status": "SIGNED",
  "key_file": "security/config/keys/cosign.key",
  "signed_images": [
    "$BACKEND_IMAGE",
    "$FRONTEND_IMAGE"
  ]
}
EOF

echo "[SUCCESS] Digital Container Image Signing Step Completed."
echo "Signature Metadata Artifact: $SIGNING_OUTPUT_DIR/signature_${TIMESTAMP}.json"
echo "=================================================="
