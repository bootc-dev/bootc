#!/bin/bash

SCRIPT_DIR=$(dirname $0)

cd $SCRIPT_DIR

podman build -t bootcseed -f Containerfile .
podman tag bootcseed:latest quay.io/otuchfel/bootc:seed
podman push quay.io/otuchfel/bootc:seed
