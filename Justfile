# The default entrypoint to working on this project.
# Commands here typically wrap e.g. `podman build` or
# other tools like `bcvk` which might launch local virtual machines.
# 
# See also `Makefile` and `xtask.rs`. Commands which end in `-local`
# skip containerization or virtualization (and typically just proxy `make`).
#
# Rules written here are *often* used by the Github Action flows,
# and should support being configurable where that makes sense (e.g.
# the `build` rule supports being provided a base image).

# --------------------------------------------------------------------

# Build the container image from current sources.
# Note commonly you might want to override the base image via e.g.
# `just build --build-arg=base=quay.io/fedora/fedora-bootc:42`
build *ARGS:
    podman build --jobs=4 -t localhost/bootc {{ARGS}} .

# Build a sealed image from current sources. This will default to
# generating Secure Boot keys in target/test-secureboot.
build-sealed *ARGS:
    podman build --build-arg=sdboot=1 --jobs=4 -t localhost/bootc-unsealed {{ARGS}} .
    ./tests/build-sealed localhost/bootc-unsealed localhost/bootc

# This container image has additional testing content and utilities
build-integration-test-image *ARGS:
    cd hack && podman build --jobs=4 -t localhost/bootc-integration -f Containerfile {{ARGS}} .
    # Keep these in sync with what's used in hack/lbi
    podman pull -q --retry 5 --retry-delay 5s quay.io/curl/curl:latest quay.io/curl/curl-base:latest registry.access.redhat.com/ubi9/podman:latest

test-composefs: build-sealed
    cargo run --release -p tests-integration -- composefs-bcvk localhost/bootc

# Only used by ci.yml right now
build-install-test-image: build-integration-test-image
    cd hack && podman build -t localhost/bootc-integration-install -f Containerfile.drop-lbis

build-disk-image container target:
    bcvk to-disk --format=qcow2 --disk-size 20G --filesystem ext4 {{container}} {{target}}

# These tests accept the container image as input, and may spawn it.
run-container-external-tests:
   ./tests/container/run localhost/bootc

# We build the unit tests into a container image
build-units:
    podman build --jobs=4 --target units -t localhost/bootc-units .

# Perform validation (build, linting) in a container build environment
validate:
    podman build --jobs=4 --target validate .

# Directly run validation (build, linting) using host tools
validate-local:
    make validate

# This generates a disk image (using bcvk) from the default container
build-disk *ARGS:
    ./tests/build.sh {{ARGS}}

# The tests which run a fully booted bootc system (i.e. where in place
# updates are supported) as if it were a production environment use
# https://github.com/teemtee/tmt.
#
# This task runs *all* of the tmt-based tests targeting the disk image generated
# in the previous step.
test-tmt *ARGS: build-disk
    ./tests/run-tmt.sh {{ARGS}}

# Like test-tmt but assumes that a disk image is already built
test-tmt-nobuild *ARGS:
    ./tests/run-tmt.sh {{ARGS}}

# Run just one tmt test: `just test-tmt-one test-20-local-upgrade`
test-tmt-one PLAN: build-disk
    ./tests/run-tmt.sh plan --name {{PLAN}}

# Run tests (unit and integration) that are containerized
test-container: build-units build-integration-test-image
    podman run --rm --read-only localhost/bootc-units /usr/bin/bootc-units
    podman run --rm localhost/bootc-integration bootc-integration-tests container

build-mdbook:
    cd docs && podman build -t localhost/bootc-mdbook -f Dockerfile.mdbook

# Generate the rendered HTML to the target DIR directory
build-mdbook-to DIR: build-mdbook
    #!/bin/bash
    set -xeuo pipefail
    # Create a temporary container to extract the built docs
    container_id=$(podman create localhost/bootc-mdbook)
    podman cp ${container_id}:/src/book {{DIR}}
    podman rm -f ${container_id}

mdbook-serve: build-mdbook
    #!/bin/bash
    set -xeuo pipefail
    podman run --init --replace -d --name bootc-mdbook --rm --publish 127.0.0.1::8000 localhost/bootc-mdbook
    echo http://$(podman port bootc-mdbook 8000/tcp)

# Update all generated files (man pages and JSON schemas)
#
# This is the unified command that:
# - Auto-discovers new CLI commands and creates man page templates
# - Syncs CLI options from Rust code to existing man page templates  
# - Updates JSON schema files
#
# Use this after adding, removing, or modifying CLI options or schemas.
update-generated:
    cargo run -p xtask update-generated
