#!/bin/bash

create_report_directory() {

    mkdir -p "$1"

}

file_exists() {

    if [ ! -f "$1" ]
    then

        log_error "$1 not found."

        exit 1

    fi

}
