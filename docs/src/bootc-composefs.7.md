# composefs backend

Experimental features are subject to change or removal. Please
do provide feedback on them.

## Overview

The composefs backend is an experimental alternative storage backend that uses [composefs-rs](https://github.com/composefs/composefs-rs) instead of ostree for storing and managing bootc system deployments.

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
  repositories. Its kernel argument is
  `composefs.digest=v1-sha512-12:<digest>`.
- **V2** is the older composefs-rs format, kept as a fallback. bootc writes
  its kernel argument as the bare `composefs=<digest>`.

By default `bootc container ukify` computes both digests and writes the V1
argument followed by the V2 one. `--erofs-version=v2` writes only the V2
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
- bootc 1.16.4 through 1.16.13 write a **V1** digest, because composefs-rs
  switched its default while `ukify` kept emitting only the bare argument.
- Releases after 1.16.13 write V2 there again, after an explicit V1 argument.

So bootc accepts a bare `composefs=` digest that matches either a V1 or a V2
image, and only enforces the format for the explicit
`composefs.digest=v1-…`/`composefs.digest=v2-…` form.

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
collection. Upgrades from other releases, and from BLS (non-UKI) composefs
installs, are not yet tested.

## Developing and Testing bootc with composefs

See [CONTRIBUTING.md](https://github.com/bootc-dev/bootc/blob/main/CONTRIBUTING.md) for information on building and testing bootc itself with composefs support.

## Known issues

The composefs backend is experimental; on-disk formats are subject to change.

- Upgrades are tested only from bootc 1.16.0 UKI installs (see
  [Upgrading from bootc 1.16](#upgrading-from-bootc-116)), and that test
  doesn't yet run in CI.
- Recovery from missing or corrupt images and deployment state is not yet
  tested, nor is garbage collection when deployments are referenced by both V1
  and V2 boot entries (for example, that GC keeps a V2 fallback image a
  rollback deployment still boots from).
- How container signature enforcement carries over from installation into the
  installed system is not settled yet.
- Extended install APIs: Ability to cleanly implement anaconda %post and osbuild post mutations and general post-install pre-reboot; right now some tools just mount the deployment directory (note this one also relates to [APIs in general](https://github.com/bootc-dev/bootc/issues/522))

## Related issues

- [Unified storage](https://github.com/bootc-dev/bootc/issues/20): Not strictly a blocker but a really nice to have
- [Sealed image build UX](https://github.com/bootc-dev/bootc/issues/1498): Streamlined tooling for building sealed images
- In place transitions: 
  - First: support [factory reset](https://github.com/bootc-dev/bootc/issues/404) from ostree to composefs
  - Next: Support copying /etc and /var

## Additional Resources

- See [filesystem.md](bootc-filesystem.7.md) for information about composefs in the standard ostree backend
- See [bootloaders.md](bootc-bootloaders.7.md) for bootloader configuration details
- [composefs-rs](https://github.com/composefs/composefs-rs) - The underlying composefs implementation
- [composefs-rs repository format](https://github.com/composefs/composefs-rs/blob/main/crates/composefs/src/repository_format.rs) - Detailed on-disk layout of the `/composefs` repository
- [Unified Kernel Images specification](https://uapi-group.org/specifications/specs/unified_kernel_image/)
- [ukify documentation](https://www.freedesktop.org/software/systemd/man/latest/ukify.html) - Tool for building UKIs
