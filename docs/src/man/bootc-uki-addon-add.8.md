# NAME

bootc-uki-addon-add - Add a UKI Addon to the current deployment

# SYNOPSIS

**bootc uki-addon add** <*NAME*> <*ADDON_TYPE*>

# DESCRIPTION

**This command is experimental and subject to change.**

Add a UKI addon from the currently booted image to the EFI System Partition.

The addon must exist in the booted image under `/boot`. If the addon is
already installed, the command is a no-op.

When a deployment is staged (after `bootc upgrade` or `bootc switch`), adding a
global addon operates on the staged copy at `loader/addons.staged`, which is
applied to the live `loader/addons` on the next boot.

A global addon added this way applies only to the deployment that is staged right
now. The next `bootc upgrade`/`bootc switch` rebuilds `loader/addons.staged` from
the live `loader/addons`, so a global addon added only to the staged copy is
discarded. To add a global addon persistently, run the command when no deployment
is staged (so it modifies `loader/addons` directly), or re-run it after staging
the new deployment.

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
**NAME**

    Addon name to be provided without the `.addon.efi` suffix

    This argument is required.

**ADDON_TYPE**

    The type of addon being added, global or scoped

    This argument is required.

<!-- END GENERATED OPTIONS -->

# EXAMPLES

Add a scoped addon (tied to the current deployment):

    bootc uki-addon add debug scoped

Add a global addon (applies to all deployments):

    bootc uki-addon add site-config global

# SEE ALSO

**bootc-uki-addon**(8), **bootc-uki-addon-list**(8), **bootc-uki-addon-remove**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
