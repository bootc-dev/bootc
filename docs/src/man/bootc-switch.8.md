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

Use `--target-imgref` to fetch an image from local container storage or a temporary
registry while recording a different reference for subsequent updates. The
positional image and `--transport` select the source to fetch now; the target
reference is recorded without contacting it. A bare target name uses the registry
transport; explicit references such as `docker://quay.io/exampleos/myapp:v1.1`
are also accepted.

Repeating the same source and target leaves the current deployment unchanged,
even if the temporary source is no longer available. Use `--from-downloaded` to
make a deployment staged with `--download-only` ready for the next boot. Use
`bootc upgrade` to check the recorded update source for newer content.

On composefs, changing only the update origin of the identical OCI image preserves
the existing OS rollback entry. For a booted image, the change takes effect on
reboot after activation. Origin-only changes require a full reboot and cannot be
combined with UKI addons. `--soft-reboot=auto` leaves the change staged even with
`--apply`; `required` fails. Cancel any queued rollback or different staged
deployment before changing the booted image's origin.

`--target-imgref` cannot be combined with `--from-downloaded`, `--mutate-in-place`,
or `--from-delta`. On composefs, it also cannot be combined with
`--enforce-container-sigpolicy`.

## Applying Changes

The `--apply` option will automatically restart the system if it has
changed after switching to the new image.

## Soft Reboot

For shared `--apply` and `--soft-reboot` behavior, see
[Soft reboots](../bootc-upgrades.7.md#soft-reboots).

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

**--from-delta**=*PATH*

    Switch using a local oci-delta artifact instead of the network

**--uki-addon**=*SCOPED*

    Experimental. Name of the local/scoped UKI addons to install without the ".addon.efi" suffix. This option can be provided multiple times if multiple addons are to be installed (composefs backend only). On upgrade and switch, scoped addons already installed are carried forward; passing this flag adds further addons on top

**--global-uki-addon**=*GLOBAL*

    Experimental. Name of the global UKI addons to install without the ".addon.efi" suffix. This option can be provided multiple times if multiple addons are to be installed (composefs backend only). On upgrade and switch, global addons already installed are carried forward; passing this flag adds further addons on top

**--target-imgref**=*TARGET_IMGREF*

    Record a different image reference for subsequent updates

<!-- END GENERATED OPTIONS -->

# EXAMPLES

Switch to a different image version:

    bootc switch quay.io/exampleos/myapp:v1.1

Switch and immediately apply the changes:

    bootc switch --apply quay.io/exampleos/myapp:v1.1

Switch with soft reboot if possible:

    bootc switch --apply --soft-reboot=auto quay.io/exampleos/myapp:v1.1

Stage a locally loaded image while retaining a registry as the update source:

    bootc switch --download-only --transport containers-storage \
        --target-imgref quay.io/exampleos/myapp:v1.1 localhost/offline:v1.1
    bootc switch --from-downloaded
    systemctl reboot

Fetch from a technician's temporary registry and track the normal registry:

    bootc switch --target-imgref quay.io/exampleos/myapp:v1.1 \
        technician-laptop:5000/myapp:v1.1

# SEE ALSO

**bootc**(8), **bootc-upgrade**(8), **bootc-status**(8), **bootc-rollback**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
