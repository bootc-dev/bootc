# Filesystem: Physical /sysroot

The bootc project uses [ostree](https://github.com/ostreedev/ostree/) as a backend,
and maps fetched container images to a [deployment](https://ostreedev.github.io/ostree/deployment/).

## stateroot

The underlying `ostree` CLI and API tooling expose a concept of `stateroot`, which
is not yet exposed via `bootc`.  The `stateroot` used by `bootc install`
is just named `default`.

The stateroot concept allows having fully separate parallel operating
system installations with fully separate `/etc` and `/var`, while
still sharing an underlying root filesystem.

In the future, this functionality will be exposed and used by `bootc`.

## /sysroot mount

When booted, the physical root will be available at `/sysroot` as a
read-only mount point and the logical root `/` will be a bind mount
pointing to a deployment directory under `/sysroot/ostree`.  This is a
key aspect of how `bootc upgrade` operates: it fetches the updated
container image and writes the base image files (using OSTree storage
to `/sysroot/ostree/repo`).

Beyond that and debugging/introspection, there are few use cases for tooling to
operate on the physical root.

### bootc-owned container storage

For [logically bound images](bootc-logically-bound-images.7.md),
bootc maintains a dedicated [containers/storage](https://github.com/containers/storage)
instance using the `overlay` backend (the same type of thing that backs `/var/lib/containers`).

This storage is accessible via a `/usr/lib/bootc/storage` symbolic link which points into
`/sysroot`. (Avoid directly referencing the `/sysroot` target)

At the current time, this storage is *not* used for the base bootable image.
This [unified storage issue](https://github.com/bootc-dev/bootc/issues/20) tracks unification.

## Expanding the root filesystem

One notable use case that *does* need to operate on `/sysroot`
is expanding the root filesystem.

Some higher level tools such as e.g. `cloud-init` may (reasonably)
expect the `/` mount point to be the physical root.  Tools like
this will need to be adjusted to instead detect this and operate
on `/sysroot`.

### Growing the block device

Fundamentally bootc is agnostic to the underlying block device setup.
How to grow the root block device depends on the underlying
storage stack, from basic partitions to LVM.  However, a
common tool is the [growpart](https://manpages.debian.org/testing/cloud-guest-utils/growpart.1.en.html)
utility from `cloud-init`.

### Growing the filesystem

The systemd project ships a [systemd-growfs](https://www.freedesktop.org/software/systemd/man/latest/systemd-growfs.html#)
tool and corresponding `systemd-growfs@` services.  This is
a relatively thin abstraction over detecting the target
root filesystem type and running the underlying tool such as
`xfs_growfs`.

At the current time, most Linux filesystems require
the target to be mounted writable in order to grow.  Hence,
an invocation of `system-growfs /sysroot` or `xfs_growfs /sysroot`
will need to be further wrapped in a temporary mount namespace.

Using a `MountFlags=slave` drop-in stanza for `systemd-growfs@sysroot.service`
is recommended, along with an `ExecStartPre=mount -o remount,rw /sysroot`.

### Detecting bootc/ostree systems

See the [package managers](bootc-package-managers.7.md) section on "Detecting image based systems".

## composefs backend storage

Unlike the ostree backend, which keeps its repository at `/ostree/repo`, the composefs backend splits its on-disk state across two top-level directories in the physical sysroot:

- `/composefs`: The [composefs-rs repository](https://github.com/composefs/composefs-rs/blob/main/crates/composefs/src/repository_format.rs) (mode `0700`), containing:
  - `objects/`: content-addressed file storage, keyed by SHA-512 fs-verity digest and shared via reflink (`FICLONE`) where the filesystem supports it
  - `images/`: EROFS images describing each deployment's root filesystem metadata, possibly in both [formats](bootc-composefs.7.md#erofs-formats)
  - `streams/`: OCI manifest, config, and layer splitstreams captured during image pulls
  - `bootc/storage/`: the `containers-storage:` instance backing logically bound images, reflink-shared with the composefs object store
- `/state/deploy/<deployment-id>/`: Persistent per-deployment state, one directory per deployment (see below for how it is named):
  - `etc/`: a writable copy of the deployment's `/etc`, bind-mounted onto the booted root's `/etc`
  - `var`: a symlink to the shared `/state/os/default/var`, bind-mounted onto the booted root's `/var`
  - `<deployment-id>.origin`: an INI file recording the image reference, boot type (BLS or UKI) and digest, and the OCI manifest digest (the latter is what keeps a deployment's objects alive across garbage collection)

Although composefs-rs supports other fs-verity hash algorithms, bootc currently hardcodes `SHA-512` for the repository. This is why EROFS image IDs and object identifiers are 128-character hex strings.

Three kinds of digest show up here and are easy to confuse. The OCI manifest
digest names the pulled container image (see the origin file above). An EROFS
digest names one bootable image under `images/` and is what the kernel command
line refers to; a deployment may have one of each format. The deployment ID names the
state directory; it is the digest of the boot image selected when the
deployment was staged.

There is no `/ostree/repo`; the composefs backend doesn't use the ostree repository at all. A minimal `/ostree` directory is still created, but only to hold a compatibility symlink (`ostree/bootc -> ../composefs/bootc`) so that existing tooling expecting `/usr/lib/bootc/storage` to resolve through `ostree/bootc` keeps working.

Transient, not-yet-finalized deployment state (used while staging an update before reboot) lives under `/run/composefs/staged-deployment` and is never persisted to disk.
