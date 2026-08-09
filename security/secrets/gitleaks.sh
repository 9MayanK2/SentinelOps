#!/bin/bash

##############################################################
# Gitleaks Secrets Scanner
##############################################################

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

source "$SECURITY_DIR/config/tools.conf"
source "$SECURITY_DIR/policies/security-policy.conf"

##############################################################
# Banner
##############################################################

echo
echo "=================================================="
echo "             GITLEAKS SECRETS SCAN"
echo "=================================================="
echo

##############################################################
# Check Policy
##############################################################

if [ "${GITLEAKS_ENABLED:-true}" != "true" ]; then
    log_warning "Gitleaks scanning is disabled."
    exit 0
fi

##############################################################
# Validate Docker
##############################################################

log_info "Checking Docker..."
check_docker

##############################################################
# Check Gitleaks Image
##############################################################

log_info "Checking Gitleaks image..."
pull_image_if_missing "${GITLEAKS_IMAGE:-zricethezav/gitleaks:latest}"

##############################################################
# Create Report Directory
##############################################################

create_report_directory "$GITLEAKS_REPORT_DIR"

##############################################################
# Timestamp & Report Paths
##############################################################

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

REPORT_HOST="$GITLEAKS_REPORT_DIR/gitleaks_${TIMESTAMP}.json"
REPORT_CONTAINER="/workspace/compliance/reports/gitleaks/gitleaks_${TIMESTAMP}.json"

##############################################################
# Execute Gitleaks Scan
##############################################################

log_info "Scanning codebase for secrets..."

SCAN_EXIT=0
docker run --rm \
  -v "$PWD":/workspace \
  "${GITLEAKS_IMAGE:-zricethezav/gitleaks:latest}" \
  detect \
  --source="/workspace" \
  --report-format=json \
  --report-path="$REPORT_CONTAINER" \
  --exit-code=0 || SCAN_EXIT=$?


log_success "Gitleaks scan completed."

##############################################################
# Summary
##############################################################

echo
echo "=================================================="
echo "          GITLEAKS SCAN COMPLETED"
echo "=================================================="
echo
echo "Report Generated:"
echo "$REPORT_HOST"
echo
echo "=================================================="

##############################################################
# Policy Enforcer
##############################################################

if [ "${GITLEAKS_FAIL_ON_ERROR:-false}" = "true" ] && [ $SCAN_EXIT -ne 0 ]; then
    log_error "Gitleaks scan failed with exit code $SCAN_EXIT"
    exit 1
fi

exit 0
