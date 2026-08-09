#!/bin/bash

check_docker() {

    if ! command -v docker >/dev/null 2>&1
    then
        log_error "Docker is not installed."

        exit 1
    fi

    if ! docker info >/dev/null 2>&1
    then
        log_error "Docker daemon is not running."

        exit 1
    fi

    log_success "Docker is available."
}

pull_image_if_missing() {

    IMAGE="$1"

    if ! docker image inspect "$IMAGE" >/dev/null 2>&1
    then

        log_info "Pulling $IMAGE..."

        docker pull "$IMAGE"

    fi
}
