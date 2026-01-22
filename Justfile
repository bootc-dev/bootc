# The default entrypoint to working on this project.
# Run `just --list` to see available targets organized by group.
#
# See also `Makefile` and `xtask.rs`. Commands which end in `-local`
# skip containerization or virtualization (and typically just proxy `make`).
#
# By default the layering is:
# Github Actions -> Justfile -> podman -> make -> rustc
#                            -> podman -> package manager
#                            -> cargo xtask
# --------------------------------------------------------------------

# Configuration variables (override via environment or command line)
# Example: BOOTC_base=quay.io/fedora/fedora-bootc:42 just build

# Output image name
base_img := "localhost/bootc"
# Synthetic upgrade image for testing
upgrade_img := base_img + "-upgrade"

# Build variant: ostree (default) or composefs-sealeduki-sdboot (sealed UKI)
variant := env("BOOTC_variant", "ostree")
# Base container image to build from
base := env("BOOTC_base", "quay.io/centos-bootc/centos-bootc:stream10")
# Buildroot base image
buildroot_base := env("BOOTC_buildroot_base", "quay.io/centos/centos:stream10")
# Optional: path to extra source (e.g. composefs-rs) for local development
# DEPRECATED: Use [patch] sections in Cargo.toml instead, which are auto-detected
extra_src := env("BOOTC_extra_src", "")
# Set to "1" to disable auto-detection of local Rust dependencies
no_auto_local_deps := env("BOOTC_no_auto_local_deps", "")

# Internal variables
nocache := env("BOOTC_nocache", "")
_nocache_arg := if nocache != "" { "--no-cache" } else { "" }
testimage_label := "bootc.testimage=1"
lbi_images := "quay.io/curl/curl:latest quay.io/curl/curl-base:latest registry.access.redhat.com/ubi9/podman:latest"
fedora-coreos := "quay.io/fedora/fedora-coreos:testing-devel"
generic_buildargs := ""
_extra_src_args := if extra_src != "" { "-v " + extra_src + ":/run/extra-src:ro --security-opt=label=disable" } else { "" }
base_buildargs := generic_buildargs + " " + _extra_src_args + " --build-arg=base=" + base + " --build-arg=variant=" + variant
buildargs := base_buildargs \
             + " --cap-add=all --security-opt=label=type:container_runtime_t --device /dev/fuse" \
             + " --secret=id=secureboot_key,src=target/test-secureboot/db.key --secret=id=secureboot_cert,src=target/test-secureboot/db.crt"

# ============================================================================
# Core workflows - the main targets most developers will use
# ============================================================================

# Build container image from current sources (default target)
[group('core')]
build: package _keygen && _pull-lbi-images
    #!/bin/bash
    set -xeuo pipefail
    test -d target/packages
    pkg_path=$(realpath target/packages)
    podman build {{_nocache_arg}} --build-context "packages=${pkg_path}" -t {{base_img}} {{buildargs}} .

# Show available build variants and current configuration
[group('core')]
list-variants:
    #!/bin/bash
    cat <<'EOF'
    Build Variants (set via BOOTC_variant= or variant=)
    ====================================================

    ostree (default)
        Standard bootc image using ostree backend.
        This is the traditional, production-ready configuration.

    composefs-sealeduki-sdboot
        Sealed composefs image with:
        - Unified Kernel Image (UKI) containing kernel + initramfs + cmdline
        - Secure Boot signing (using keys in target/test-secureboot/)
        - systemd-boot bootloader
        - composefs digest embedded in kernel cmdline for verified boot

        Use `just build-sealed` as a shortcut, or:
        just variant=composefs-sealeduki-sdboot build

    Current Configuration
    =====================
    EOF
    echo "    BOOTC_variant={{variant}}"
    echo "    BOOTC_base={{base}}"
    echo "    BOOTC_extra_src={{extra_src}}"
    echo ""

# Build a sealed composefs image (alias for variant=composefs-sealeduki-sdboot)
[group('core')]
build-sealed:
    @just --justfile {{justfile()}} variant=composefs-sealeduki-sdboot build

# Run tmt integration tests in VMs (e.g. `just test-tmt readonly`)
[group('core')]
test-tmt *ARGS: build
    @just _build-upgrade-image
    @just test-tmt-nobuild {{ARGS}}

# Run containerized unit and integration tests
[group('core')]
test-container: build build-units
    podman run --rm --read-only localhost/bootc-units /usr/bin/bootc-units
    podman run --rm --env=BOOTC_variant={{variant}} --env=BOOTC_base={{base}} {{base_img}} bootc-integration-tests container

# Build and test sealed composefs images
[group('core')]
test-composefs:
    just variant=composefs-sealeduki-sdboot test-tmt readonly local-upgrade-reboot

# Run cargo fmt and clippy checks in container
[group('core')]
validate:
    podman build {{base_buildargs}} --target validate .

# ============================================================================
# Testing variants and utilities
# ============================================================================

# Run tmt tests without rebuilding (for fast iteration)
[group('testing')]
test-tmt-nobuild *ARGS:
    cargo xtask run-tmt --env=BOOTC_variant={{variant}} --upgrade-image={{upgrade_img}} {{base_img}} {{ARGS}}

# Run tmt tests on Fedora CoreOS
[group('testing')]
test-tmt-on-coreos *ARGS:
    cargo xtask run-tmt --env=BOOTC_variant={{variant}} --env=BOOTC_target={{base_img}}-coreos:latest {{fedora-coreos}} {{ARGS}}

# Run external container tests against localhost/bootc
[group('testing')]
run-container-external-tests:
   ./tests/container/run {{base_img}}

# Remove all test VMs created by tmt tests
[group('testing')]
tmt-vm-cleanup:
    bcvk libvirt rm --stop --force --label bootc.test=1

# Build test image for Fedora CoreOS testing
[group('testing')]
build-testimage-coreos PATH: _keygen
    #!/bin/bash
    set -xeuo pipefail
    pkg_path=$(realpath "{{PATH}}")
    podman build --build-context "packages=${pkg_path}" \
        --build-arg SKIP_CONFIGS=1 \
        -t {{base_img}}-coreos {{buildargs}} .

# Build test image for install tests (used by CI)
[group('testing')]
build-install-test-image: build
    cd hack && podman build {{base_buildargs}} -t {{base_img}}-install -f Containerfile.drop-lbis

# ============================================================================
# Documentation
# ============================================================================

# Serve docs locally (prints URL)
[group('docs')]
mdbook-serve: build-mdbook
    #!/bin/bash
    set -xeuo pipefail
    podman run --init --replace -d --name bootc-mdbook --rm --publish 127.0.0.1::8000 localhost/bootc-mdbook
    echo http://$(podman port bootc-mdbook 8000/tcp)

# Build the documentation (mdbook)
[group('docs')]
build-mdbook:
    #!/bin/bash
    set -xeuo pipefail
    secret_arg=""
    if test -n "${GH_TOKEN:-}"; then
        secret_arg="--secret=id=GH_TOKEN,env=GH_TOKEN"
    fi
    podman build {{generic_buildargs}} ${secret_arg} -t localhost/bootc-mdbook -f docs/Dockerfile.mdbook .

# Build docs and extract to DIR
[group('docs')]
build-mdbook-to DIR: build-mdbook
    #!/bin/bash
    set -xeuo pipefail
    container_id=$(podman create localhost/bootc-mdbook)
    podman cp ${container_id}:/src/docs/book {{DIR}}
    podman rm -f ${container_id}

# ============================================================================
# Debugging and validation
# ============================================================================

# Validate composefs digests match between build and install views
[group('debugging')]
validate-composefs-digest:
    cargo xtask validate-composefs-digest {{base_img}}

# Verify reproducible builds (runs package twice, compares output)
[group('debugging')]
check-buildsys:
    cargo run -p xtask check-buildsys

# Get container image pullspec for a given OS (e.g. `pullspec-for-os base fedora-42`)
[group('debugging')]
pullspec-for-os TYPE NAME:
    @jq -r --arg v "{{NAME}}" '."{{TYPE}}"[$v]' < hack/os-image-map.json

# ============================================================================
# Maintenance
# ============================================================================

# Update generated files (man pages, JSON schemas)
[group('maintenance')]
update-generated:
    cargo run -p xtask update-generated

# Remove all locally-built test container images
[group('maintenance')]
clean-local-images:
    podman images --filter "label={{testimage_label}}"
    podman images --filter "label={{testimage_label}}" --format "{{{{.ID}}" | xargs -r podman rmi -f
    podman image prune -f
    podman rmi {{fedora-coreos}} -f

# Build packages (RPM) into target/packages/
[group('maintenance')]
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
    # Auto-detect local Rust path dependencies (e.g., from [patch] sections)
    local_deps_args=""
    if [[ -z "{{no_auto_local_deps}}" ]]; then
        local_deps_args=$(cargo xtask local-rust-deps)
    fi
    podman build {{base_buildargs}} --build-arg=SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} --build-arg=pkgversion=${VERSION} -t localhost/bootc-pkg --target=build $local_deps_args .
    mkdir -p "${packages}"
    rm -vf "${packages}"/*.rpm
    podman run --rm localhost/bootc-pkg tar -C /out/ -cf - . | tar -C "${packages}"/ -xvf -
    chmod a+rx target "${packages}"
    chmod a+r "${packages}"/*.rpm

# Build unit tests into a container image
[group('maintenance')]
build-units:
    #!/bin/bash
    set -xeuo pipefail
    eval $(just _git-build-vars)
    podman build {{base_buildargs}} --build-arg=SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} --build-arg=pkgversion=${VERSION} --target units -t localhost/bootc-units .

# ============================================================================
# Internal helpers (prefixed with _)
# ============================================================================

_pull-lbi-images:
    podman pull -q --retry 5 --retry-delay 5s {{lbi_images}}

_git-build-vars:
    #!/bin/bash
    set -euo pipefail
    SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
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

_keygen:
    ./hack/generate-secureboot-keys

_build-upgrade-image:
    cat tmt/tests/Dockerfile.upgrade | podman build -t {{upgrade_img}} --from={{base_img}} -
