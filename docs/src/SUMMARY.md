# Summary

- [Introduction](intro.md)

# Installation

- [Installation](installation.md)

# Building images

- [Building images](building/guidance.md)
- [Container runtime vs bootc runtime](building/bootc-runtime.md)
- [Users, groups, SSH keys](building/users-and-groups.md)
- [Kernel arguments](building/kernel-arguments.md)
- [Secrets](building/secrets.md)
- [Management Services](building/management-services.md)

# Using bootc

- [Upgrade and rollback](upgrades.md)
- [Accessing registries and offline updates](registries-and-offline.md)
- [Logically bound images](logically-bound-images.md)
- [Booting local builds](booting-local-builds.md)
- [`man bootc`](man/bootc.8.md)
- [`man bootc-status`](man/bootc-status.8.md)
- [`man bootc-upgrade`](man/bootc-upgrade.8.md)
- [`man bootc-switch`](man/bootc-switch.8.md)
- [`man bootc-rollback`](man/bootc-rollback.8.md)
- [`man bootc-usr-overlay`](man/bootc-usr-overlay.8.md)
- [`man bootc-fetch-apply-updates.service`](man/bootc-fetch-apply-updates.service.5.md)
- [`man bootc-status-updated.path`](man/bootc-status-updated.path.5.md)
- [`man bootc-status-updated.target`](man/bootc-status-updated.target.5.md)
- [Controlling bootc via API](bootc-via-api.md)

# Using `bootc install`

- [Understanding `bootc install`](bootc-install.md)
- [`man bootc-install`](man/bootc-install.8.md)
- [`man bootc-install-config`](man/bootc-install-config.5.md)
- [`man bootc-install-to-disk`](man/bootc-install-to-disk.8.md)
- [`man bootc-install-to-filesystem`](man/bootc-install-to-filesystem.8.md)
- [`man bootc-install-to-existing-root`](man/bootc-install-to-existing-root.8.md)
- [`man bootc-destructive-cleanup.service`](man/bootc-destructive-cleanup.service.5.md)

# Bootc usage in containers

- [Read-only when in a default container](bootc-in-container.md)
- [`man bootc-container-lint`](man/bootc-container-lint.8.md)

# Architecture

- [Image layout](bootc-images.md)
- [Filesystem](filesystem.md)
- [Filesystem: sysroot](filesystem-sysroot.md)
- [Container storage](filesystem-storage.md)
- [Bootloader](bootloaders.md)

# Experimental features

- [bootc image](experimental-bootc-image.md)
- [composefs backend](experimental-composefs.md)
- [`man bootc-root-setup.service`](man/bootc-root-setup.service.5.md)
- [fsck](experimental-fsck.md)
- [install reset](experimental-install-reset.md)
- [--progress-fd](experimental-progress-fd.md)

# More information

- [Packaging and integration](packaging-and-integration.md)
- [Package manager integration](package-managers.md)
- [Relationship with other projects](relationships.md)
- [Relationship with OCI artifacs](relationship-oci-artifacts.md)
- [Relationship with systemd "particles"](relationship-particles.md)

# Development

- [Internals (rustdoc)](internals.md)
