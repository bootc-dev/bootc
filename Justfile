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
#
# By default the layering should be thus:
# Github Actions -> Justfile -> podman -> make -> rustc
#                            -> podman -> dnf|apt ...
#                            -> cargo xtask
# --------------------------------------------------------------------

# This image is just the base image plus our updated bootc binary
base_img := "localhost/bootc"
# Has a synthetic upgrade
upgrade_img := base_img + "-upgrade"

# ostree: The default
# composefs-sealeduki-sdboot: A system with a sealed composefs using systemd-boot
variant := env("BOOTC_variant", "ostree")
base := env("BOOTC_base", "quay.io/centos-bootc/centos-bootc:stream10")
buildroot_base := env("BOOTC_buildroot_base", "quay.io/centos/centos:stream10")

testimage_label := "bootc.testimage=1"
# Images used by hack/lbi; keep in sync
lbi_images := "quay.io/curl/curl:latest quay.io/curl/curl-base:latest registry.access.redhat.com/ubi9/podman:latest"
# We used to have --jobs=4 here but sometimes that'd hit this
# ```
#   [2/3] STEP 2/2: RUN --mount=type=bind,from=context,target=/run/context <<EORUN (set -xeuo pipefail...)
#   --> Using cache b068d42ac7491067cf5fafcaaf2f09d348e32bb752a22c85bbb87f266409554d
#   --> b068d42ac749
#   + cd /run/context/
#   /bin/sh: line 3: cd: /run/context/: Permission denied
# ```
# TODO: Gather more info and file a buildah bug
generic_buildargs := ""
# Args for package building (no secrets needed, just builds RPMs)
base_buildargs := generic_buildargs + " --build-arg=base=" + base + " --build-arg=variant=" + variant
# - scratch builds need extra perms per https://docs.fedoraproject.org/en-US/bootc/building-from-scratch/
# - we do secure boot signing here, so provide the keys
buildargs := base_buildargs \
             + " --cap-add=all --security-opt=label=type:container_runtime_t --device /dev/fuse" \
             + " --secret=id=secureboot_key,src=target/test-secureboot/db.key --secret=id=secureboot_cert,src=target/test-secureboot/db.crt"
# The default target: build the container image from current sources.
# Note commonly you might want to override the base image via e.g.
# `just build --build-arg=base=quay.io/fedora/fedora-bootc:42`
# into the container image.
#
# Note you can set `BOOTC_SKIP_PACKAGE=1` in the environment to bypass this stage. 
build: package _keygen && _pull-lbi-images
    #!/bin/bash
    set -xeuo pipefail
    test -d target/packages
    # Use --build-context to pass packages instead of -v to avoid mount stubs in /run
    pkg_path=$(realpath target/packages)
    podman build --build-context "packages=${pkg_path}" -t {{base_img}} {{buildargs}} .

# Pull images used by hack/lbi
_pull-lbi-images:
    podman pull -q --retry 5 --retry-delay 5s {{lbi_images}}

# Compute SOURCE_DATE_EPOCH and VERSION from git for reproducible builds.
# Outputs shell variable assignments that can be eval'd.
_git-build-vars:
    #!/bin/bash
    set -euo pipefail
    SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
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
    echo "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"
    echo "VERSION=${VERSION}"

# Needed by bootc install on ostree
fedora-coreos := "quay.io/fedora/fedora-coreos:testing-devel"
# Generate Secure Boot keys (only for our own CI/testing)
_keygen:
    ./hack/generate-secureboot-keys

# Build a sealed image from current sources.
build-sealed:
    @just --justfile {{justfile()}} variant=composefs-sealeduki-sdboot build

# Build packages (e.g. RPM) into target/packages/
# Any old packages will be removed.
# Set BOOTC_SKIP_PACKAGE=1 in the environment to bypass this stage. We don't
# yet have an accurate ability to avoid rebuilding this in CI yet.
package:
    #!/bin/bash
    set -xeuo pipefail
    packages=target/packages
    if test -n "${BOOTC_SKIP_PACKAGE:-}"; then
        if test '!' -d "${packages}"; then
            echo "BOOTC_SKIP_PACKAGE is set, but missing ${packages}" 1>&2; exit 1
        fi
        exit 0
    fi
    eval $(just _git-build-vars)
    echo "Building RPM with version: ${VERSION}"
    podman build {{base_buildargs}} --build-arg=SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} --build-arg=pkgversion=${VERSION} -t localhost/bootc-pkg --target=build .
    mkdir -p "${packages}"
    rm -vf "${packages}"/*.rpm
    podman run --rm localhost/bootc-pkg tar -C /out/ -cf - . | tar -C "${packages}"/ -xvf -
    chmod a+rx target "${packages}"
    chmod a+r "${packages}"/*.rpm
    # Keep localhost/bootc-pkg for layer caching; use `just clean-local-images` to reclaim space

# Build+test using the `composefs-sealeduki-sdboot` variant.
test-composefs:
    just variant=composefs-sealeduki-sdboot test-tmt readonly local-upgrade-reboot

# Only used by ci.yml right now
build-install-test-image: build
    cd hack && podman build {{base_buildargs}} -t {{base_img}}-install -f Containerfile.drop-lbis

# These tests accept the container image as input, and may spawn it.
run-container-external-tests:
   ./tests/container/run {{base_img}}

# We build the unit tests into a container image
build-units:
    #!/bin/bash
    set -xeuo pipefail
    eval $(just _git-build-vars)
    podman build {{base_buildargs}} --build-arg=SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} --build-arg=pkgversion=${VERSION} --target units -t localhost/bootc-units .

# Perform validation (build, linting) in a container build environment
validate:
    podman build {{base_buildargs}} --target validate .

# Run tmt-based test suites using local virtual machines with
# bcvk.
#
# To run an individual test, pass it as an argument like:
# `just test-tmt readonly`
test-tmt *ARGS: build
    @just _build-upgrade-image
    @just test-tmt-nobuild {{ARGS}}

# Generate a local synthetic upgrade
_build-upgrade-image:
    cat tmt/tests/Dockerfile.upgrade | podman build -t {{upgrade_img}} --from={{base_img}} -

# Assume the localhost/bootc image is up to date, and just run tests.
# Useful for iterating on tests quickly.
test-tmt-nobuild *ARGS:
    cargo xtask run-tmt --env=BOOTC_variant={{variant}} --upgrade-image={{upgrade_img}} {{base_img}} {{ARGS}}

# Build test container image for testing on coreos with SKIP_CONFIGS=1,
# which skips LBIs, test kargs, and install configs that would conflict with FCOS.
build-testimage-coreos PATH: _keygen
    #!/bin/bash
    set -xeuo pipefail
    pkg_path=$(realpath "{{PATH}}")
    # Use --build-context to pass packages instead of -v to avoid mount stubs in /run
    podman build --build-context "packages=${pkg_path}" \
        --build-arg SKIP_CONFIGS=1 \
        -t {{base_img}}-coreos {{buildargs}} .

# Run test bootc install on FCOS
# BOOTC_target is `bootc-coreos`, it will be used for bootc install.
# Run `just build-testimage-coreos target/packages` to build test image firstly,
# then run `just test-tmt-on-coreos plan-bootc-install-on-coreos`
test-tmt-on-coreos *ARGS:
    cargo xtask run-tmt --env=BOOTC_variant={{variant}} --env=BOOTC_target={{base_img}}-coreos:latest {{fedora-coreos}} {{ARGS}}

# Cleanup all test VMs created by tmt tests
tmt-vm-cleanup:
    bcvk libvirt rm --stop --force --label bootc.test=1

# Run tests (unit and integration) that are containerized
test-container: build build-units
    podman run --rm --read-only localhost/bootc-units /usr/bin/bootc-units
    # Pass these through for cross-checking
    podman run --rm --env=BOOTC_variant={{variant}} --env=BOOTC_base={{base}} {{base_img}} bootc-integration-tests container

# Remove all container images built (locally) via this Justfile, by matching a label
clean-local-images:
    podman images --filter "label={{testimage_label}}"
    podman images --filter "label={{testimage_label}}" --format "{{{{.ID}}" | xargs -r podman rmi -f
    podman image prune -f
    podman rmi {{fedora-coreos}} -f

# Print the container image reference for a given short $ID-VERSION_ID for NAME
# and 'base' or 'buildroot-base' for TYPE (base image type)
pullspec-for-os TYPE NAME:
    @jq -r --arg v "{{NAME}}" '."{{TYPE}}"[$v]' < hack/os-image-map.json

build-mdbook:
    #!/bin/bash
    set -xeuo pipefail
    secret_arg=""
    # Pass GH_TOKEN to avoid API rate limits when cargo-binstall fetches binaries
    if test -n "${GH_TOKEN:-}"; then
        secret_arg="--secret=id=GH_TOKEN,env=GH_TOKEN"
    fi
    podman build {{generic_buildargs}} ${secret_arg} -t localhost/bootc-mdbook -f docs/Dockerfile.mdbook .

# Generate the rendered HTML to the target DIR directory
build-mdbook-to DIR: build-mdbook
    #!/bin/bash
    set -xeuo pipefail
    # Create a temporary container to extract the built docs
    container_id=$(podman create localhost/bootc-mdbook)
    podman cp ${container_id}:/src/docs/book {{DIR}}
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

# Verify build system properties (reproducible builds)
#
# This runs `just package` twice and verifies that the resulting RPMs
# are bit-for-bit identical, confirming SOURCE_DATE_EPOCH is working.
check-buildsys:
    cargo run -p xtask check-buildsys
