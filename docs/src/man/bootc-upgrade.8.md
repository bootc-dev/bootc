# NAME

bootc-upgrade - Download and queue an updated container image to apply

# SYNOPSIS

**bootc upgrade** [*OPTIONS*]

# DESCRIPTION

Download and queue an updated container image to apply.

This does not affect the running system; updates operate in an "A/B" style by default.

A queued update is visible as `staged` in `bootc status`.

Currently by default, the update will be applied at shutdown time via `ostree-finalize-staged.service`.
There is also an explicit `bootc upgrade --apply` verb which will automatically take action (rebooting)
if the system has changed.

However, in the future this is likely to change such that reboots outside of a `bootc upgrade --apply`
do *not* automatically apply the update in addition.

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
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
