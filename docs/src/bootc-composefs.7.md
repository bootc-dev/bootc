# composefs backend

bootc has two storage backends. The default is [ostree](https://github.com/ostreedev/ostree),
and the composefs backend uses [composefs-rs](https://github.com/composefs/composefs-rs)
instead of ostree to store and manage deployments. Both are supported and
covered by the project's [stability guarantees](https://github.com/bootc-dev/bootc/blob/main/RELEASES.md#stability-guarantees).
In particular, the project is committed to upgrading every composefs system
installed since bootc 1.16.0 in place.

The composefs backend is required for [sealed images](building/bootc-sealed-images.7.md),
and the image determines which backend `bootc install` uses; see
[Understanding `bootc install`](bootc-installation.7.md#composefs-backend). Its
on-disk layout is described in [Filesystem: sysroot](bootc-sysroot.7.md#composefs-backend-storage).

## Overview

The composefs backend has two independent integrity controls:

- **fs-verity enforcement.** By default every object in the composefs
  repository must have fs-verity enabled, and the root filesystem is only
  mounted if its digest matches the one on the kernel command line. Building a
  UKI with `--allow-missing-verity` adds a `?` marker to that argument, which
  makes fs-verity optional (for filesystems such as XFS that lack it). Both UKI
  and traditional kernel/initramfs installs can enforce fs-verity.
- **Boot authentication.** In a *sealed* deployment fs-verity is enforced and
  the expected root digest is embedded in a UKI signed for Secure Boot, so
  firmware authenticates the digest and the digest authenticates the root
  filesystem. A BLS entry or an
  unsigned UKI still has fs-verity checked at mount time, but nothing
  authenticates the digest itself.

## EROFS formats

composefs-rs can encode the EROFS image for a root filesystem in two formats,
which produce different digests for the same content:

- **V1** is compatible with the C composefs tools and is the default for new
  repositories.
- **V2** is the older composefs-rs format, kept as a fallback.

The `composefs.digest=` kernel argument names the format along with the
digest, for example `composefs.digest=v1-sha512-12:<digest>`, so it is
unambiguous. The older bare `composefs=<digest>` argument is not: released
UKIs carry either a V1 or a V2 digest there (see below), so bootc tries both.

By default `bootc container ukify` computes both digests and writes the V1
`composefs.digest=` argument followed by a bare `composefs=` argument with the
V2 digest, for older clients. `--erofs-version=v2` writes only the bare V2
argument.

Each argument names one exact image. Staging fails unless every digest in the
UKI matches an image bootc generated for that container image. At boot,
bootc's initramfs tries the arguments in order and moves on to the next one if
an image is missing, but an image that fails fs-verity checks stops the boot.
bootc never substitutes a different digest.

Existing repositories keep the format configuration recorded in their
metadata; opening one with a newer bootc doesn't convert it.

### The bare `composefs=` argument

Released UKIs have used the bare `composefs=<digest>` argument for different
formats:

- bootc 1.16.0 through 1.16.2 predate format versioning and use the original
  composefs-rs encoding that V2 descends from.
- bootc 1.16.3 writes a V2 digest.
- bootc 1.16.4 through 1.16.13 write a **V1** digest: the switch to the V1
  format shipped before the `composefs.digest=` argument did.
- Releases after 1.16.13 write V2 there again, after an explicit V1 argument.

So bootc accepts a bare `composefs=` digest that matches either a V1 or a V2
image, and only enforces the format for `composefs.digest=`.

### Upgrading from bootc 1.16

When you update bootc in an image, **regenerate the initramfs before
generating the UKI**. The initramfs contains bootc's own mount logic, and
keeping an old initramfs with a newer bootc is not supported.

For a sealed deployment, sign the new UKI with a key the existing machine
trusts. If the deployment was built with `--allow-missing-verity`, keep that
flag. Then publish the image and run `bootc upgrade` as usual.

What happens next depends on the bootc version doing the staging. A client
that only understands `composefs=`, such as 1.16.0, stages the V2 fallback;
the new initramfs boots it, and the next upgrade (now staged by the new bootc)
moves the system to V1. bootc 1.16.4 and later already understand
`composefs.digest=` and stage V1 directly.

The 1.16.0 path is covered by the `test-49-composefs-1-16-bridge` TMT test for
both sealed and `--allow-missing-verity` UKIs, including rollback and garbage
collection. Upgrades of UKI installs from other releases are not yet tested.

## Supported configurations

The following are supported with the composefs backend:

- `bootc install`, `upgrade`, `switch`, `rollback`, `status`, `usr-overlay`
  and soft reboots.
- [`bootc install mount`](man/bootc-install-mount.8.md), for changing an
  installed deployment before its first boot.
- Traditional kernel and initramfs installs booted through BLS entries, with
  either GRUB (via `bootupd`) or systemd-boot, and UKIs booted with
  systemd-boot, including sealed UKIs signed for Secure Boot. See
  [Bootloaders](bootc-bootloaders.7.md#composefs-backend).
- Root filesystems with fs-verity support, and filesystems without it (such
  as XFS) with fs-verity made optional. Sealed images require fs-verity.
  CI covers ext4 and XFS; btrfs is expected to work but is not tested.
- The [EROFS formats](#erofs-formats) and kernel arguments described above.
- The image build commands `bootc container ukify`,
  `bootc container split-kernel-and-rootfs` and
  `bootc container compute-composefs-digest`, and the initramfs setup
  configured by [`setup-root-conf.toml`](man/bootc-setup-root-conf.5.md).

On CentOS Stream 9, only sealed UKIs are tested; traditional kernel installs
require newer dracut and systemd features. Its dracut also doesn't install
`setup-root-conf.toml` into the initramfs automatically.

## Experimental parts

These remain [experimental](https://github.com/bootc-dev/bootc/blob/main/RELEASES.md#stability-guarantees)
and may change or be removed:

- The `grub-cc` bootloader (`--bootloader=grub-cc`).
- UKI addons (`--uki-addon`). Addons are only installed by `bootc install`:
  they aren't updated on upgrade, garbage collected, or reverted on
  rollback.
- [Unified storage](bootc-experimental-unified-storage.7.md).

## Limitations

- `bootc edit` and [`bootc install reset`](bootc-experimental-install-reset.7.md)
  are not yet implemented for the composefs backend.
- There is no `bootc-boot-complete.service` and no boot counting; see
  [boot failure detection](bootc-boot-failure-detection.7.md#composefs-backend-boot-failure-detection).
- There is no in-place transition from an ostree system to the composefs
  backend yet, so for now a system has to be reinstalled. We fully intend to
  support moving to composefs without a reinstall; see
  [Future work](#future-work).
- `--bootloader=none` is not supported.
- `--soft-reboot=auto` doesn't fall back to a regular reboot when the new
  deployment can't be soft rebooted into; see
  [Soft reboots](bootc-upgrades.7.md#soft-reboots).
- Only a single ESP is used (the first one found), and a separate
  XBOOTLDR partition is not supported.
- Rollback with GRUB and UKIs assumes exactly two deployments.
- `bootc internals fsck` doesn't yet comprehensively cover the composefs
  backend; see [#2497](https://github.com/bootc-dev/bootc/pull/2497).

For building and testing bootc itself with the composefs backend, see
[CONTRIBUTING.md](https://github.com/bootc-dev/bootc/blob/main/CONTRIBUTING.md).

## Future work

- [Unified storage](https://github.com/bootc-dev/bootc/issues/20)
- [Sealed image build UX](https://github.com/bootc-dev/bootc/issues/1498): Streamlined tooling for building sealed images
- In place transitions:
  - First: support [factory reset](https://github.com/bootc-dev/bootc/issues/404) from ostree to composefs
  - Next: Support copying /etc and /var

## Additional Resources

- See [filesystem.md](bootc-filesystem.7.md) for information about composefs in the standard ostree backend
- See [bootloaders.md](bootc-bootloaders.7.md) for bootloader configuration details
- See [sealed images](building/bootc-sealed-images.7.md) for building UKIs and sealed images
- [composefs-rs](https://github.com/composefs/composefs-rs) - The underlying composefs implementation
- [composefs-rs repository format](https://github.com/composefs/composefs-rs/blob/main/crates/composefs/src/repository_format.rs) - Detailed on-disk layout of the `/composefs` repository
- [Unified Kernel Images specification](https://uapi-group.org/specifications/specs/unified_kernel_image/)
- [ukify documentation](https://www.freedesktop.org/software/systemd/man/latest/ukify.html) - Tool for building UKIs
