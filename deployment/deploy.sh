#!/usr/bin/env bash

set -e

echo "Updating Images..."

IMAGE_TAG="$1"

echo "Deploying ${IMAGE_TAG}"

bash deployment/update-image.sh "${IMAGE_TAG}"

echo "Waiting for Rollout..."

bash deployment/verify-rollout.sh

echo "Deployment Successful."