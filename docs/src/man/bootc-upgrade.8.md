# NAME

bootc-upgrade - Download and queue an updated container image to apply

# SYNOPSIS

**bootc upgrade** \[*OPTIONS...*\]

# DESCRIPTION

Download and queue an updated container image to apply.

This does not affect the running system; updates operate in an "A/B" style by default.

A queued update is visible as `staged` in `bootc status`.

## Checking for Updates

The `--check` option allows you to verify if updates are available without downloading the full image layers. This only downloads the updated manifest and image configuration (typically kilobyte-sized metadata), making it much faster than a full upgrade.

## Applying Updates

Currently by default, the update will be applied at shutdown time via `ostree-finalize-staged.service`.
There is also an explicit `bootc upgrade --apply` verb which will automatically take action (rebooting)
if the system has changed.

The `--apply` option currently always reboots the system. In the future, this command may detect cases where no kernel changes are queued and perform a userspace-only restart instead.

However, in the future this is likely to change such that reboots outside of a `bootc upgrade --apply`
do *not* automatically apply the update in addition.

## Soft Reboot

The `--soft-reboot` option configures soft reboot behavior when used with `--apply`:

- `required`: The operation will fail if soft reboot is not available on the target system
- `auto`: Uses soft reboot if available on the target system, otherwise falls back to a regular reboot

Soft reboot allows faster system restart by avoiding full hardware reboot when possible.

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
**--quiet**

    Don't display progress

**--check**

    Check if an update is available without applying it

**--apply**

    Restart or reboot into the new target image

**--soft-reboot**=*SOFT_REBOOT*

    Configure soft reboot behavior

    Possible values:
    - required
    - auto

**--download-only**

    Download and stage the update without applying it

<!-- END GENERATED OPTIONS -->

# EXAMPLES

Check for available updates:

    bootc upgrade --check

Upgrade and immediately apply the changes:

    bootc upgrade --apply

Upgrade with soft reboot if possible:

    bootc upgrade --apply --soft-reboot=auto

# SEE ALSO

**bootc**(8), **bootc-switch**(8), **bootc-status**(8), **bootc-rollback**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
