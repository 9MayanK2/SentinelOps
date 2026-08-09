#!/bin/bash

##################################################
# Project Configuration
##################################################

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

##################################################
# Report Directories
##################################################

REPORT_ROOT="$PROJECT_ROOT/compliance/reports"

HADOLINT_REPORT_DIR="$REPORT_ROOT/hadolint"
TRIVY_REPORT_DIR="$REPORT_ROOT/trivy"
SEMGREP_REPORT_DIR="$REPORT_ROOT/semgrep"
GITLEAKS_REPORT_DIR="$REPORT_ROOT/gitleaks"
ZAP_REPORT_DIR="$REPORT_ROOT/zap"

##################################################
# Tool Images
##################################################

HADOLINT_IMAGE="hadolint/hadolint:latest"

TRIVY_IMAGE="aquasec/trivy:latest"

GITLEAKS_IMAGE="zricethezav/gitleaks:latest"


##################################################
# Dockerfiles
##################################################

BACKEND_DOCKERFILE="$PROJECT_ROOT/app/server/Dockerfile"

FRONTEND_DOCKERFILE="$PROJECT_ROOT/app/client/Dockerfile"

##################################################
# Backend Image
##################################################

BACKEND_IMAGE="hopegivers-backend:latest"

##################################################
# Frontend Image
##################################################

FRONTEND_IMAGE="hopegivers-frontend:latest"
