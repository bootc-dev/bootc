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

# ostree: The default
# composefs-sealeduki-sdboot: A system with a sealed composefs using systemd-boot
variant := env("BOOTC_variant", "ostree")
base := env("BOOTC_base", "quay.io/centos-bootc/centos-bootc:stream10")

buildargs := "--build-arg=base=" + base + " --build-arg=variant=" + variant

# Build the container image from current sources.
# Note commonly you might want to override the base image via e.g.
# `just build --build-arg=base=quay.io/fedora/fedora-bootc:42`
build:
    podman build --jobs=4 -t localhost/bootc-bin {{buildargs}} .
    ./tests/build-sealed {{variant}} localhost/bootc-bin localhost/bootc

# This container image has additional testing content and utilities
build-integration-test-image: build
    cd hack && podman build --jobs=4 -t localhost/bootc-integration-bin {{buildargs}} -f Containerfile .
    ./tests/build-sealed {{variant}} localhost/bootc-integration-bin localhost/bootc-integration
    # Keep these in sync with what's used in hack/lbi
    podman pull -q --retry 5 --retry-delay 5s quay.io/curl/curl:latest quay.io/curl/curl-base:latest registry.access.redhat.com/ubi9/podman:latest

# Build+test composefs; compat alias
test-composefs:
    # These first two are currently a distinct test suite from tmt that directly
    # runs an integration test binary in the base image via bcvk
    just variant=composefs-sealeduki-sdboot build
    cargo run --release -p tests-integration -- composefs-bcvk localhost/bootc
    # We're trying to move more testing to tmt, so 
    just variant=composefs-sealeduki-sdboot test-tmt readonly

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

# Run tmt-based test suites using local virtual machines with
# bcvk.
#
# To run an individual test, pass it as an argument like:
# `just test-tmt readonly`
test-tmt *ARGS: build-integration-test-image
    cargo xtask run-tmt --env=BOOTC_variant={{variant}} localhost/bootc-integration {{ARGS}}

# Cleanup all test VMs created by tmt tests
tmt-vm-cleanup:
    bcvk libvirt rm --stop --force --label bootc.test=1

# Run tests (unit and integration) that are containerized
test-container: build-units build-integration-test-image
    podman run --rm --read-only localhost/bootc-units /usr/bin/bootc-units
    # Pass these through for cross-checking
    podman run --rm --env=BOOTC_variant={{variant}} --env=BOOTC_base={{base}} localhost/bootc-integration bootc-integration-tests container

# Print the container image reference for a given short $ID-VERSION_ID
pullspec-for-os NAME:
    @jq -r --arg v "{{NAME}}" '.[$v]' < hack/os-image-map.json

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
