# NAME

bootc-uki-addon-remove - Remove a UKI Addon

# SYNOPSIS

**bootc uki-addon remove** <*NAME*> \[*DEPLOYMENT_ID*\]

# DESCRIPTION

**This command is experimental and subject to change.**

Remove a UKI addon from the EFI System Partition.

For global addons, only the addon name is needed. For scoped addons, the
deployment ID is required to identify which deployment's addon to remove.
Use `bootc uki-addon list --json` to find deployment IDs.

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
**NAME**

    Addon name to be provided without the `.efi.addon` suffix

    This argument is required.

**DEPLOYMENT_ID**

    If removing a scoped addon, deployment_id is required. If removing a global addon, deployment_id is not required

<!-- END GENERATED OPTIONS -->

# EXAMPLES

Remove a global addon:

    bootc uki-addon remove site-config

Remove a scoped addon (get the deployment ID from `list --json`):

    bootc uki-addon remove debug a1b2c3d4e5f6...

# SEE ALSO

**bootc-uki-addon**(8), **bootc-uki-addon-list**(8), **bootc-uki-addon-add**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
