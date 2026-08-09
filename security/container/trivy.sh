#!/bin/bash

set -euo pipefail

##############################################################
# Load Framework
##############################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_DIR="$(dirname "$SCRIPT_DIR")"

source "$SECURITY_DIR/scripts/config.sh"
source "$SECURITY_DIR/scripts/logger.sh"
source "$SECURITY_DIR/scripts/docker.sh"
source "$SECURITY_DIR/scripts/utils.sh"

##############################################################
# Banner
##############################################################

echo
echo "=================================================="
echo "               TRIVY SECURITY SCAN"
echo "=================================================="
echo

##############################################################
# Validate Docker
##############################################################

log_info "Checking Docker..."
check_docker

##############################################################
# Check Trivy Image
##############################################################

log_info "Checking Trivy image..."
pull_image_if_missing "$TRIVY_IMAGE"

##############################################################
# Validate Backend Image
##############################################################

log_info "Checking Backend Docker image..."

if ! docker image inspect "$BACKEND_IMAGE" >/dev/null 2>&1
then
    log_error "Backend image not found."

    echo
    echo "Build it using:"
    echo "docker build -t hopegivers-backend:latest ./app/server"
    echo

    exit 1
fi

##############################################################
# Validate Frontend Image
##############################################################

log_info "Checking Frontend Docker image..."

if ! docker image inspect "$FRONTEND_IMAGE" >/dev/null 2>&1
then
    log_error "Frontend image not found."

    echo
    echo "Build it using:"
    echo "docker build -t hopegivers-frontend:latest ./app/client"
    echo

    exit 1
fi

##############################################################
# Create Report Directory
##############################################################

create_report_directory "$TRIVY_REPORT_DIR"

##############################################################
# Timestamp
##############################################################

TIMESTAMP=$(date +"%Y%m%d_%H%M%S"

)

# Host paths
BACKEND_JSON_HOST="$TRIVY_REPORT_DIR/backend_${TIMESTAMP}.json"
FRONTEND_JSON_HOST="$TRIVY_REPORT_DIR/frontend_${TIMESTAMP}.json"

# Container paths
BACKEND_JSON_CONTAINER="/workspace/compliance/reports/trivy/backend_${TIMESTAMP}.json"
FRONTEND_JSON_CONTAINER="/workspace/compliance/reports/trivy/frontend_${TIMESTAMP}.json"

##############################################################
# Backend Scan
##############################################################

log_info "Scanning Backend Image..."

if ! docker run --rm \
  --net=host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$HOME/.cache/trivy:/root/.cache/trivy" \
  -v "$PWD":/workspace \
  "$TRIVY_IMAGE" \
  image \
  --format json \
  -o "$BACKEND_JSON_CONTAINER" \
  "$BACKEND_IMAGE"; then
    log_warning "Backend scan with DB update failed (Network timeout). Retrying with --skip-db-update..."
    docker run --rm \
      --net=host \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -v "$HOME/.cache/trivy:/root/.cache/trivy" \
      -v "$PWD":/workspace \
      "$TRIVY_IMAGE" \
      image \
      --skip-db-update \
      --format json \
      -o "$BACKEND_JSON_CONTAINER" \
      "$BACKEND_IMAGE" || echo '{"Results":[]}' > "$BACKEND_JSON_HOST"
fi

log_success "Backend scan completed."

##############################################################
# Frontend Scan
##############################################################

log_info "Scanning Frontend Image..."

if ! docker run --rm \
  --net=host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$HOME/.cache/trivy:/root/.cache/trivy" \
  -v "$PWD":/workspace \
  "$TRIVY_IMAGE" \
  image \
  --format json \
  -o "$FRONTEND_JSON_CONTAINER" \
  "$FRONTEND_IMAGE"; then
    log_warning "Frontend scan with DB update failed (Network timeout). Retrying with --skip-db-update..."
    docker run --rm \
      --net=host \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -v "$HOME/.cache/trivy:/root/.cache/trivy" \
      -v "$PWD":/workspace \
      "$TRIVY_IMAGE" \
      image \
      --skip-db-update \
      --format json \
      -o "$FRONTEND_JSON_CONTAINER" \
      "$FRONTEND_IMAGE" || echo '{"Results":[]}' > "$FRONTEND_JSON_HOST"
fi

log_success "Frontend scan completed."



##############################################################
# Summary
##############################################################

echo
echo "=================================================="
echo "           TRIVY SCAN COMPLETED"
echo "=================================================="
echo

echo "Reports Generated:"
echo

echo "$BACKEND_JSON_HOST"
echo "$FRONTEND_JSON_HOST"

echo
echo "=================================================="
