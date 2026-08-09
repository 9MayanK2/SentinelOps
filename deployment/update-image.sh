#!/usr/bin/env bash

set -e

IMAGE_TAG="$1"

NAMESPACE="sentinelops"

echo "========================================"
echo "Deploying Image Tag : ${IMAGE_TAG}"
echo "========================================"

helm upgrade \
--install sentinelops \
helm/sentinelops \
--namespace ${NAMESPACE} \
--set backend.image.tag=${IMAGE_TAG} \
--set frontend.image.tag=${IMAGE_TAG}

echo
echo "Helm Upgrade Completed."