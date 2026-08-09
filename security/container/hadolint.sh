#!/bin/bash

##############################################################
# Hadolint Security Scanner
##############################################################

set -e

##############################################################
# Load Configuration
##############################################################

source security/config/tools.conf
source security/policies/security-policy.conf

##############################################################
# Load scripts Libraries
##############################################################

source security/scripts/logger.sh
source security/scripts/docker.sh
source security/scripts/utils.sh

##############################################################
# Banner
##############################################################

echo
echo "=================================================="
echo "             HADOLINT SECURITY SCAN"
echo "=================================================="
echo

##############################################################
# Check Policy
##############################################################

if [ "$HADOLINT_ENABLED" != "true" ]; then
    log_warning "Hadolint scanning is disabled."
    exit 0
fi

##############################################################
# Prepare Environment
##############################################################

log_info "Checking Docker..."

check_docker

log_info "Checking Dockerfiles..."

file_exists "$BACKEND_DOCKERFILE"
file_exists "$FRONTEND_DOCKERFILE"

log_info "Checking Hadolint image..."

pull_image_if_missing "$HADOLINT_IMAGE"

##############################################################
# Prepare Report Directory
##############################################################

mkdir -p "$HADOLINT_REPORT_DIR"

##############################################################
# Timestamp
##############################################################

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

BACKEND_REPORT="${HADOLINT_REPORT_DIR}/backend_${TIMESTAMP}.json"
FRONTEND_REPORT="${HADOLINT_REPORT_DIR}/frontend_${TIMESTAMP}.json"

##############################################################
# Backend Scan
##############################################################

log_info "Scanning Backend Dockerfile..."

docker run --rm \
-v "$PWD":/workspace \
"$HADOLINT_IMAGE" \
hadolint --format json "/workspace/$BACKEND_DOCKERFILE" \
> "$BACKEND_REPORT"

BACKEND_EXIT=$?

##############################################################
# Frontend Scan
##############################################################

log_info "Scanning Frontend Dockerfile..."

docker run --rm \
-v "$PWD":/workspace \
"$HADOLINT_IMAGE" \
hadolint --format json "/workspace/$FRONTEND_DOCKERFILE" \
> "$FRONTEND_REPORT"

FRONTEND_EXIT=$?

##############################################################
# Scan Summary
##############################################################

echo
echo "=================================================="

if [ $BACKEND_EXIT -eq 0 ]; then
    log_success "Backend Dockerfile Scan Completed"
else
    log_warning "Backend Dockerfile contains findings"
fi

if [ $FRONTEND_EXIT -eq 0 ]; then
    log_success "Frontend Dockerfile Scan Completed"
else
    log_warning "Frontend Dockerfile contains findings"
fi

echo
log_info "Reports Generated"

echo "$BACKEND_REPORT"
echo "$FRONTEND_REPORT"

echo
echo "=================================================="

##############################################################
# Exit
##############################################################

if [ "$HADOLINT_FAIL_ON_ERROR" = "true" ]; then
    if [ $BACKEND_EXIT -ne 0 ] || [ $FRONTEND_EXIT -ne 0 ]; then
        exit 1
    fi
fi

exit 0
