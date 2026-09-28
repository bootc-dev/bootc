# NAME

bootc-switch - Target a new container image reference to boot

# SYNOPSIS

**bootc switch** \[*OPTIONS...*\] <*TARGET*>

# DESCRIPTION

Target a new container image reference to boot.

This is almost exactly the same operation as `upgrade`, but additionally changes the container image reference
instead.

## Usage

A common pattern is to have a management agent control operating system updates via container image tags;
for example, `quay.io/exampleos/someuser:v1.0` and `quay.io/exampleos/someuser:v1.1` where some machines
are tracking `:v1.0`, and as a rollout progresses, machines can be switched to `v:1.1`.

It is also supported to provide explicit digests, via e.g. `bootc switch quay.io/exampleos/someuser@sha256:9cca0703342e24806a9f64e08c053dca7f2cd90f10529af8ea872afb0a0c77d4`. When you do this, `bootc upgrade` will always be a no-op. In this model, upgrades are then always triggered by further `switch` operations.

## Applying Changes

The `--apply` option will automatically restart the system if it has
changed after switching to the new image.

## Soft Reboot

For shared `--apply` and `--soft-reboot` behavior, see
[Soft reboots](../upgrades.md#soft-reboots).

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
**TARGET**

    Target image to use for the next boot. Required unless `--from-downloaded` is present

**--quiet**

    Don't display progress

**--apply**

    Restart or reboot into the new target image

**--soft-reboot**=*SOFT_REBOOT*

    Configure soft reboot behavior

    Possible values:
    - required
    - auto

**--transport**=*TRANSPORT*

    The transport; e.g. registry, oci, oci-archive, docker-daemon, containers-storage.  Defaults to `registry`

    Default: registry

**--download-only**

    Download and stage the update without applying it

**--from-downloaded**

    Apply a staged deployment that was previously downloaded with --download-only

**--enforce-container-sigpolicy**

    This is the inverse of the previous `--target-no-signature-verification` (which is now a no-op)

**--retain**

    Retain reference to currently booted image

<!-- END GENERATED OPTIONS -->

# EXAMPLES

Switch to a different image version:

    bootc switch quay.io/exampleos/myapp:v1.1

Switch and immediately apply the changes:

    bootc switch --apply quay.io/exampleos/myapp:v1.1

Switch with soft reboot if possible:

    bootc switch --apply --soft-reboot=auto quay.io/exampleos/myapp:v1.1

# SEE ALSO

**bootc**(8), **bootc-upgrade**(8), **bootc-status**(8), **bootc-rollback**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
