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

The `--apply` option will automatically take action (rebooting) if the system has changed after switching to the new image. Currently, this option always reboots the system. In the future, this command may detect cases where no kernel changes are queued and perform a userspace-only restart instead.

## Soft Reboot

The `--soft-reboot` option configures soft reboot behavior when used with `--apply`:

- `required`: The operation will fail if soft reboot is not available on the target system
- `auto`: Uses soft reboot if available on the target system, otherwise falls back to a regular reboot

Soft reboot allows faster system restart by avoiding full hardware reboot when possible.

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
**TARGET**

    Target image to use for the next boot

    This argument is required.

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
