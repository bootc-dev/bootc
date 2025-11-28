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

# This image is just the base image plus our updated bootc binary
base_img := "localhost/bootc"
# Derives from the above and adds nushell, cloudinit etc.
integration_img := base_img + "-integration"
# Has a synthetic upgrade
integration_upgrade_img := integration_img + "-upgrade"

# ostree: The default
# composefs-sealeduki-sdboot: A system with a sealed composefs using systemd-boot
variant := env("BOOTC_variant", "ostree")
base := env("BOOTC_base", "quay.io/centos-bootc/centos-bootc:stream10")
buildroot_base := env("BOOTC_buildroot_base", "quay.io/centos/centos:stream10")

testimage_label := "bootc.testimage=1"
# We used to have --jobs=4 here but sometimes that'd hit this
# ```
#   [2/3] STEP 2/2: RUN --mount=type=bind,from=context,target=/run/context <<EORUN (set -xeuo pipefail...)
#   --> Using cache b068d42ac7491067cf5fafcaaf2f09d348e32bb752a22c85bbb87f266409554d
#   --> b068d42ac749
#   + cd /run/context/
#   /bin/sh: line 3: cd: /run/context/: Permission denied
# ```
# TODO: Gather more info and file a buildah bug
base_buildargs := ""
buildargs := "--build-arg=base=" + base + " --build-arg=variant=" + variant

# Build the container image from current sources.
# Note commonly you might want to override the base image via e.g.
# `just build --build-arg=base=quay.io/fedora/fedora-bootc:42`
build:
    podman build {{base_buildargs}} -t {{base_img}}-bin {{buildargs}} .
    ./tests/build-sealed {{variant}} {{base_img}}-bin {{base_img}} {{buildroot_base}}

# Build a sealed image from current sources.
build-sealed:
    @just --justfile {{justfile()}} variant=composefs-sealeduki-sdboot build

# Build packages (e.g. RPM) using a container buildroot
_packagecontainer:
    #!/bin/bash
    set -xeuo pipefail
    # Compute version from git (matching xtask.rs gitrev logic)
    if VERSION=$(git describe --tags --exact-match 2>/dev/null); then
        VERSION="${VERSION#v}"
        VERSION="${VERSION//-/.}"
    else
        COMMIT=$(git rev-parse HEAD | cut -c1-10)
        COMMIT_TS=$(git show -s --format=%ct)
        TIMESTAMP=$(date -u -d @${COMMIT_TS} +%Y%m%d%H%M)
        VERSION="${TIMESTAMP}.g${COMMIT}"
    fi
    echo "Building RPM with version: ${VERSION}"
    podman build {{base_buildargs}} {{buildargs}} --build-arg=pkgversion=${VERSION} -t localhost/bootc-pkg --target=build .

# Build a packages (e.g. RPM) into target/
# Any old packages will be removed.
package: _packagecontainer
    mkdir -p target
    rm -vf target/*.rpm
    podman run --rm localhost/bootc-pkg tar -C /out/ -cf - . | tar -C target/ -xvf -

# This container image has additional testing content and utilities
build-integration-test-image: build
    cd hack && podman build {{base_buildargs}} -t {{integration_img}}-bin -f Containerfile .
    ./tests/build-sealed {{variant}} {{integration_img}}-bin {{integration_img}} {{buildroot_base}}
    # Keep these in sync with what's used in hack/lbi
    podman pull -q --retry 5 --retry-delay 5s quay.io/curl/curl:latest quay.io/curl/curl-base:latest registry.access.redhat.com/ubi9/podman:latest

# Build+test using the `composefs-sealeduki-sdboot` variant.
test-composefs:
    # These first two are currently a distinct test suite from tmt that directly
    # runs an integration test binary in the base image via bcvk
    just _composefs-build-image
    cargo run --release -p tests-integration -- composefs-bcvk {{integration_img}}
    # We're trying to move more testing to tmt
    just variant=composefs-sealeduki-sdboot test-tmt readonly local-upgrade-reboot

# Internal helper to build integration test image with composefs variant
_composefs-build-image:
    just variant=composefs-sealeduki-sdboot build-integration-test-image

# Only used by ci.yml right now
build-install-test-image: build-integration-test-image
    cd hack && podman build {{base_buildargs}} -t {{integration_img}}-install -f Containerfile.drop-lbis

# These tests accept the container image as input, and may spawn it.
run-container-external-tests:
   ./tests/container/run {{base_img}}

# We build the unit tests into a container image
build-units:
    podman build {{base_buildargs}} --target units -t localhost/bootc-units .

# Perform validation (build, linting) in a container build environment
validate:
    podman build {{base_buildargs}} --target validate .

# Run tmt-based test suites using local virtual machines with
# bcvk.
#
# To run an individual test, pass it as an argument like:
# `just test-tmt readonly`
test-tmt *ARGS: build-integration-test-image _build-upgrade-image
    @just test-tmt-nobuild {{ARGS}}

# Generate a local synthetic upgrade
_build-upgrade-image:
    cat tmt/tests/Dockerfile.upgrade | podman build -t {{integration_upgrade_img}}-bin --from={{integration_img}}-bin -
    ./tests/build-sealed {{variant}} {{integration_upgrade_img}}-bin {{integration_upgrade_img}} {{buildroot_base}}

# Assume the localhost/bootc-integration image is up to date, and just run tests.
# Useful for iterating on tests quickly.
test-tmt-nobuild *ARGS:
    cargo xtask run-tmt --env=BOOTC_variant={{variant}} --upgrade-image={{integration_upgrade_img}} {{integration_img}} {{ARGS}}

# Cleanup all test VMs created by tmt tests
tmt-vm-cleanup:
    bcvk libvirt rm --stop --force --label bootc.test=1

# Run tests (unit and integration) that are containerized
test-container: build-units build-integration-test-image
    podman run --rm --read-only localhost/bootc-units /usr/bin/bootc-units
    # Pass these through for cross-checking
    podman run --rm --env=BOOTC_variant={{variant}} --env=BOOTC_base={{base}} {{integration_img}} bootc-integration-tests container

# Remove all container images built (locally) via this Justfile, by matching a label
clean-local-images:
    podman images --filter "label={{testimage_label}}"
    podman images --filter "label={{testimage_label}}" --format "{{{{.ID}}" | xargs -r podman rmi -f

# Print the container image reference for a given short $ID-VERSION_ID for NAME
# and 'base' or 'buildroot-base' for TYPE (base image type)
pullspec-for-os TYPE NAME:
    @jq -r --arg v "{{NAME}}" '."{{TYPE}}"[$v]' < hack/os-image-map.json

build-mdbook:
    cd docs && podman build {{base_buildargs}} -t localhost/bootc-mdbook -f Dockerfile.mdbook

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
