# NAME

bootc-uki-addon-add - Add a UKI Addon to the current deployment

# SYNOPSIS

**bootc uki-addon add** <*NAME*> <*ADDON_TYPE*>

# DESCRIPTION

**This command is experimental and subject to change.**

Add a UKI addon from the currently booted image to the EFI System Partition.

The addon must exist in the booted image under `/boot`. If the addon is
already installed, the command is a no-op.

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
**NAME**

    Addon name to be provided without the `.efi.addon` suffix

    This argument is required.

**ADDON_TYPE**

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
