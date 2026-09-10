# NAME

bootc-uki-addon - Manage UKI addons on the EFI System Partition

# SYNOPSIS

**bootc uki-addon** <*COMMAND*>

# DESCRIPTION

**This command is experimental and subject to change.**

Manage UKI (Unified Kernel Image) addons on the EFI System Partition.

UKI addons are PE binaries that systemd-stub loads alongside the main UKI at
boot. Each addon carries extra kernel command-line parameters that get merged
into the boot configuration.

There are two types of addons:

- **Scoped** addons are tied to a specific deployment. They are stored next to
  the deployment's UKI and are automatically cleaned up by garbage collection
  when the deployment is removed.

- **Global** addons apply to every UKI on the ESP. They persist across
  deployments and are not removed by garbage collection.

This command requires the composefs backend with UKI boot.

<!-- BEGIN GENERATED OPTIONS -->
<!-- END GENERATED OPTIONS -->

# COMMANDS

**list**
:   List all installed UKI addons. See **bootc-uki-addon-list**(8).

**add**
:   Add a UKI addon from the booted image. See **bootc-uki-addon-add**(8).

**remove**
:   Remove a UKI addon from the ESP. See **bootc-uki-addon-remove**(8).

# EXAMPLES

List all installed addons:

    bootc uki-addon list

Add a scoped addon from the booted image:

    bootc uki-addon add debug scoped

Remove a global addon:

    bootc uki-addon remove site-config

# SEE ALSO

**bootc**(8), **bootc-uki-addon-list**(8), **bootc-uki-addon-add**(8), **bootc-uki-addon-remove**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
