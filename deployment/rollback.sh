#!/usr/bin/env bash

set -e

NAMESPACE="sentinelops"

echo "Rolling back Helm Release..."

helm rollback sentinelops \
--namespace ${NAMESPACE}

echo "Rollback Completed."

helm history sentinelops \
--namespace ${NAMESPACE}