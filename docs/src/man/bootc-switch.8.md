# NAME

bootc-switch - Target a new container image reference to boot

# SYNOPSIS

**bootc switch** [*OPTIONS*] <*TARGET*>

# DESCRIPTION

Target a new container image reference to boot.

This is almost exactly the same operation as `upgrade`, but additionally changes the container image reference
instead.

## Usage

A common pattern is to have a management agent control operating system updates via container image tags;
for example, `quay.io/exampleos/someuser:v1.0` and `quay.io/exampleos/someuser:v1.1` where some machines
are tracking `:v1.0`, and as a rollout progresses, machines can be switched to `v:1.1`.

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
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
