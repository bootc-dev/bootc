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

When a deployment is staged (after `bootc upgrade` or `bootc switch`), removing a
global addon operates on the staged copy at `loader/addons.staged`, not the live
`loader/addons`. The staged copy is applied to `loader/addons` on the next boot.

Removing the last global addon empties `loader/addons.staged`, so that directory
is deleted. With no `loader/addons.staged` left, nothing is applied on the next
boot and the live `loader/addons` is kept as-is, so the removed global addon
comes back. To remove the last global addon, do it when no deployment is staged.

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
**NAME**

    Addon name to be provided without the `.addon.efi` suffix

    This argument is required.

**ADDON_TYPE**

    The type of addon being removed, global or scoped

    This argument is required.

<!-- END GENERATED OPTIONS -->

# EXAMPLES

Remove a global addon:

    bootc uki-addon remove site-config

Remove a scoped addon (get the deployment ID from `list --json`):

    bootc uki-addon remove debug a1b2c3d4e5f6...

Removing the last global addon while a deployment is staged. This command
reports success, but after reboot `site-config` is still installed because
`loader/addons.staged` was deleted and nothing replaced the live `loader/addons`:

    bootc uki-addon remove site-config global

Reboot first so no deployment is staged, then run the same command to remove it.

# SEE ALSO

**bootc-uki-addon**(8), **bootc-uki-addon-list**(8), **bootc-uki-addon-add**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
