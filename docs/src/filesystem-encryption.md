# Disk encryption (e.g. LUKS)

bootc supports any Linux filesystem and block storage setup,
and does not dictate any particular architecture. Once a writable
Linux filesystem is mounted, bootc can write content (images) into it,
in the same way e.g. podman, apt, and dnf do.

Concretely `bootc install to-filesystem` and `bootc upgrade` both operate
on pre-existing mounted filesystems. This includes LUKS and RAID
underneath for block storage.

However, LUKS is important enough that it deserves its own documentation.

## Recommendation: handle root filesystem encryption independently of bootc

If you want an encrypted root, set that up independently of bootc,
and then point `bootc install to-filesystem` at the resulting mounted
filesystem.

Reference implementations:

- **[Anaconda](https://github.com/rhinstaller/anaconda/)**, via its
  `bootc` kickstart command (which drives `to-filesystem` directly):
  kickstart's `--encrypted` options set up LUKS during install, and a
  `%post` script can add TPM2 binding with `systemd-cryptenroll`.
- **[`systemd-cryptsetup`](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptsetup@.service.html)
  and [`systemd-cryptenroll`](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html)**
  directly, for installers or provisioning tooling that don't use
  Anaconda. Note that data for this can be provided via **[`systemd-imdsd`](https://www.freedesktop.org/software/systemd/man/latest/systemd-imdsd@.service.html)**
  (systemd v261+): on recognized clouds.

Whichever you use, that setup is owned by whoever builds and
maintains the image or installer, not by bootc.

### `/boot` or XBOOTLDR partition

Some layouts need a separate `/boot` or XBOOTLDR partition — for
example `tpm2-luks` requires one, since GRUB and most bootloaders
can't read a LUKS-encrypted `/boot`. If yours does, pass
`--boot-mount-spec` to `to-filesystem` so bootc knows where to
install boot assets. See
[More advanced installation with `to-filesystem`](bootc-install.md#more-advanced-installation-with-to-filesystem).

### Root filesystem discovery

This is no different from non-LUKS cases; either use discoverable
partitions or `root=` plus `luks.uuid` style kernel arguments.

## First-boot encryption of an already-populated filesystem

It's common to have a "golden image" (a KubeVirt containerdisk, a
raw `.qcow2`, an AMI, and similar) that is already a bootc install
(i.e. the target OS) already. Typically, the filesystem is not already
encrypted, because there'd be nothing to use as a default unlocking
mechanism. Hence encrypting each instance uniquely means converting
that already-populated partition to LUKS2 in place, the first time it
boots. This is OS/distro-level work, not something bootc implements.

Fedora CoreOS is a reference architecture here: its disk
images ship unencrypted, and [Ignition](https://coreos.github.io/ignition/) can convert the root
filesystem to LUKS2 in place during the initramfs of the machine's
first real boot, optionally bound via `clevis` to `tpm2`, `tang`
(network-bound unlock), or a Shamir threshold across several pins. See
the [Fedora CoreOS storage docs](https://docs.fedoraproject.org/en-US/fedora-coreos/storage/)
for details. Other notes and prior art:

- [openSUSE's `disk-encryption-tool`](https://github.com/openSUSE/disk-encryption-tool) —
  shipping today via a dracut hook that runs
  `cryptsetup reencrypt --encrypt --reduce-device-size=<n>` before the
  partition is ever mounted.
- [`systemd-repart`'s `EncryptDataShift`](https://github.com/systemd/systemd/pull/29731) —
  open, unmerged RFC upstream.

This only protects data written after the per-device encryption
boundary exists; don't provision machine-specific secrets into the
image before that boundary is in place.

## Tracking

The following issues track requests to extend `tpm2-luks` further
(configurable PCRs, recovery keys, deferred/first-boot enrollment).
Given the direction above, the expectation is that these are better
solved by using `systemd-cryptsetup`/`systemd-cryptenroll` directly
in your own initramfs rather than by adding more options to bootc's
installer:

- [#421](https://github.com/bootc-dev/bootc/issues/421) install to-disk with LUKS + TPM broken
- [#476](https://github.com/bootc-dev/bootc/issues/476) Add config option to configure systemd-cryptenroll PCRs
- [#477](https://github.com/bootc-dev/bootc/issues/477) LUKS volumes need configurable password and/or recovery keys
- [#1329](https://github.com/bootc-dev/bootc/issues/1329) Support LUKS password on bootc install
- [#2089](https://github.com/bootc-dev/bootc/issues/2089) install to-disk --block-setup tpm2-luks hangs: libdevmapper udev cookie semaphore deadlock in container IPC namespace (closed; background on why install-time LUKS setup inside a container is fragile)
