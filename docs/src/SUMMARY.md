# Summary

- [Introduction](bootc-overview.7.md)

# Installation

- [Installation](bootc-base-images.7.md)

# Building images

- [Building images](building/bootc-building-images.7.md)
- [Container runtime vs bootc runtime](building/bootc-container-runtime.7.md)
- [DNS and resolv.conf](building/bootc-dns.7.md)
- [Users, groups, SSH keys](building/bootc-users-and-groups.7.md)
- [`man bootc-sysusers-shadow-sync.service`](man/bootc-sysusers-shadow-sync.service.5.md)
- [Kernel arguments](building/bootc-kernel-arguments.7.md)
- [Sealed images](building/bootc-sealed-images.7.md)
- [Secrets](building/bootc-secrets.7.md)
- [Management Services](building/bootc-management-services.7.md)

# Using bootc

- [Upgrade and rollback](bootc-upgrades.7.md)
- [Boot failure detection](bootc-boot-failure-detection.7.md)
- [Accessing registries and offline updates](bootc-registries-and-offline.7.md)
- [Logically bound images](bootc-logically-bound-images.7.md)
- [Booting local builds](bootc-local-builds.7.md)
- [Managing the initramfs after installation](bootc-initramfs.7.md)
- [`man bootc`](man/bootc.8.md)
- [`man bootc-config`](man/bootc-config.5.md)
- [`man bootc-config-diff`](man/bootc-config-diff.8.md)
- [`man bootc-edit`](man/bootc-edit.8.md)
- [`man bootc-status`](man/bootc-status.8.md)
- [`man bootc-upgrade`](man/bootc-upgrade.8.md)
- [`man bootc-switch`](man/bootc-switch.8.md)
- [`man bootc-rollback`](man/bootc-rollback.8.md)
- [`man bootc-usr-overlay`](man/bootc-usr-overlay.8.md)
- [`man bootc-fetch-apply-updates.service`](man/bootc-fetch-apply-updates.service.5.md)
- [`man bootc-status-updated.path`](man/bootc-status-updated.path.5.md)
- [`man bootc-status-updated.target`](man/bootc-status-updated.target.5.md)
- [Controlling bootc via API](bootc-api.7.md)

# Using `bootc install`

- [Understanding `bootc install`](bootc-installation.7.md)
- [`man bootc-install`](man/bootc-install.8.md)
- [`man bootc-install-config`](man/bootc-install-config.5.md)
- [`man bootc-install-to-disk`](man/bootc-install-to-disk.8.md)
- [`man bootc-install-to-filesystem`](man/bootc-install-to-filesystem.8.md)
- [`man bootc-install-to-existing-root`](man/bootc-install-to-existing-root.8.md)
- [`man bootc-install-mount`](man/bootc-install-mount.8.md)
- [`man bootc-install-finalize`](man/bootc-install-finalize.8.md)
- [`man bootc-install-ensure-completion`](man/bootc-install-ensure-completion.8.md)
- [`man bootc-install-print-configuration`](man/bootc-install-print-configuration.8.md)
- [`man system-reinstall-bootc`](man/system-reinstall-bootc.8.md)
- [`man bootc-destructive-cleanup.service`](man/bootc-destructive-cleanup.service.5.md)

# Bootc usage in containers

- [Read-only when in a default container](bootc-in-container.7.md)
- [`man bootc-container`](man/bootc-container.8.md)
- [`man bootc-container-inspect`](man/bootc-container-inspect.8.md)
- [`man bootc-container-split-kernel-and-rootfs`](man/bootc-container-split-kernel-and-rootfs.8.md)
- [`man bootc-container-ukify`](man/bootc-container-ukify.8.md)
- [`man bootc-container-compute-composefs-digest`](man/bootc-container-compute-composefs-digest.8.md)
- [`man bootc-container-lint`](man/bootc-container-lint.8.md)

# Architecture

- [Image layout](bootc-compatible-images.7.md)
- [Filesystem](bootc-filesystem.7.md)
- [Filesystem: sysroot](bootc-sysroot.7.md)
- [Container storage](bootc-container-storage.7.md)
- [composefs backend](bootc-composefs.7.md)
- [`man bootc-root-setup.service`](man/bootc-root-setup.service.5.md)
- [`man bootc-setup-root-conf.toml`](man/bootc-setup-root-conf.5.md)
- [`man bootc-composefs-finalize-staged`](man/bootc-composefs-finalize-staged.8.md)
- [Bootloader](bootc-bootloaders.7.md)
- [`man bootc-loader-entries`](man/bootc-loader-entries.8.md)
- [`man bootc-loader-entries-set-options-for-source`](man/bootc-loader-entries-set-options-for-source.8.md)
- [Disk encryption (e.g. LUKS)](bootc-filesystem-encryption.7.md)

# Security

- [Security and threat model](bootc-security.7.md)

# Experimental features

- [bootc image](bootc-experimental-image.7.md)
- [unified storage](bootc-experimental-unified-storage.7.md)
- [fsck](bootc-experimental-fsck.7.md)
- [install reset](bootc-experimental-install-reset.7.md)
- [--progress-fd](bootc-experimental-progress-fd.7.md)
- [container export](bootc-experimental-container-export.7.md)

# More information

- [Packaging and integration](bootc-packaging-and-integration.7.md)
- [Package manager integration](bootc-package-managers.7.md)
- [Relationship with other projects](bootc-relationships.7.md)
- [Relationship with OCI artifacts](bootc-oci-artifacts.7.md)
- [Relationship with systemd "particles"](bootc-systemd-particles.7.md)

# Development

- [Internals (rustdoc)](bootc-internals.7.md)
