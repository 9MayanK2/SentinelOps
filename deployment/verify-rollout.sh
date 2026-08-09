#!/usr/bin/env bash

set -e

NAMESPACE="sentinelops"

echo "Waiting for Backend rollout..."

kubectl rollout status deployment/backend \
-n ${NAMESPACE} \
--timeout=5m

echo "Waiting for Frontend rollout..."

kubectl rollout status deployment/frontend \
-n ${NAMESPACE} \
--timeout=5m

echo "All Deployments Rolled Out Successfully."