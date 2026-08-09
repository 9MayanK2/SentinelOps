#!/bin/bash
set -euo pipefail

##############################################################
# DevSecOps Master Pipeline Runner
##############################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

PYTHONPATH=. python3 security/core/orchestrator.py "$@"
