# Filesystem

As noted in other chapters, the bootc project currently
depends on [ostree project](https://github.com/ostreedev/ostree/)
for storing the base container image. Additionally there is a [containers/storage](https://github.com/containers/storage) instance for [logically bound images](logically-bound-images.md).

However, bootc is intending to be a "fresh, new container-native interface",
and ostree is an implementation detail.

First, it is strongly recommended that bootc consumers use the ostree
[composefs backend](https://ostreedev.github.io/ostree/composefs/); to do this,
ensure that you have a `/usr/lib/ostree/prepare-root.conf` that contains at least

```ini
[composefs]
enabled = true
```

This will ensure that the entire `/` is a read-only filesystem which
is very important for achieving correct semantics.

## Understanding container build/runtime vs deployment

When run *as a container* (e.g. as part of a container build), the
filesystem is fully mutable in order to allow derivation to work.
For more on container builds, see [build guidance](building/guidance.md).

The rest of this document describes the state of the system when
"deployed" to a physical or virtual machine, and managed by `bootc`.

## Timestamps

bootc uses ostree, which currently [squashes all timestamps to zero](https://ostreedev.github.io/ostree/repo/#content-objects).
This is now viewed as an implementation bug and will be changed in the future.
For more information, see [this tracker issue](https://github.com/containers/bootc/issues/20).

## Understanding physical vs logical root with `/sysroot`

When the system is fully booted, it is into the equivalent of a `chroot`.
The "physical" host root filesystem will be mounted at `/sysroot`.
For more on this, see [filesystem: sysroot](filesystem-sysroot.md).

This `chroot` filesystem is called a "deployment root". All the remaining
filesystem paths below are part of a deployment root which is used as a
final target for the system boot.  The target deployment is determined
via the `ostree=` kernel commandline argument.

## `/usr`

The overall recommendation is to keep all operating system content in `/usr`,
with directories such as `/bin` being symbolic links to `/usr/bin`, etc.
See [UsrMove](https://fedoraproject.org/wiki/Features/UsrMove) for example.

However, with composefs enabled `/usr` is not different from `/`;
they are part of the same immutable image.  So there is not a fundamental
need to do a full "UsrMove" with a bootc system.

### `/usr/local`

The OSTree upstream recommendation suggests making `/usr/local` a symbolic
link to `/var/usrlocal`. But because the emphasis of a bootc-oriented system is
on users deriving custom container images as the default entrypoint,
it is recommended here that base images configure `/usr/local` be a regular
directory (i.e. the default).

Projects that want to produce "final" images that are themselves
not intended to be derived from in general can enable that symbolic link
in derived builds.

## `/etc`

The `/etc` directory contains mutable persistent state by default; however,
it is supported (and encouraged) to enable the [`etc.transient` config option](https://ostreedev.github.io/ostree/man/ostree-prepare-root.html),
see below as well.

When in persistent mode, it inherits the OSTree semantics of [performing a 3-way merge](https://ostreedev.github.io/ostree/atomic-upgrades/#assembling-a-new-deployment-directory)
across upgrades.  In a nutshell:

- The *new default* `/etc` is used as a base
- The diff between current and previous `/etc` is applied to the new `/etc`
- Locally modified files in `/etc` different from the default `/usr/etc` (of the same deployment) will be retained

You can view the state via `ostree admin config-diff`. Note that the "diff"
here includes metadata (uid, gid, extended attributes), so changing any of those
will also mean that updated files from the image are not applied.

The implementation of this defaults to being executed by `ostree-finalize-staged.service`
at shutdown time, before the new bootloader entry is created.

The rationale for this design is that in practice today, many components of a Linux system end up shipping
default configuration files in `/etc`.  And even if the default package doesn't, often the software
only looks for config files there by default.

Some other image-based update systems do not have distinct "versions" of `/etc` and
it may be populated only set up at install time, and untouched thereafter.  But
that creates "hysteresis" where the state of the system's `/etc` is strongly
influenced by the initial image version.  This can lead to problems
where e.g. a change to `/etc/sudoers.conf` (to give on simple example)
would require external intervention to apply.

For more on configuration file best practices, see [Building](building/guidance.md).

To emphasize again, it's recommended to enable `etc.transient` if possible, though
when using that you may need to store some machine-specific state in e.g. the
kernel commandline if applicable.

### `/usr/etc`

The `/usr/etc` tree is generated client side and contains the default container image's
view of `/etc`. This should generally be considered an internal implementation detail
of bootc/ostree. Do *not* explicitly put files into this location, it can create
undefined behavior. There is a check for this in `bootc container lint`.

## `/var`

Content in `/var` persists by default; it is however supported to make it or subdirectories
mount points (whether network or `tmpfs`).  There is exactly one `/var`.  If it is
not a distinct partition, then it is automatically made a bind from
`/ostree/deploy/$stateroot/var` and shared across "deployments" (bootloader entries).

You may include content in `/var` in your image - and reference base images may
have a few basic directories such as `/var/tmp` (in order to ease use in container
builds).

However, it is very important to understand that content included in `/var`
in the container image acts like a Docker `VOLUME /var`. This means its
contents are unpacked *only from the initial image* - subsequent changes to `/var`
in a container image are not automatically applied.

A common case is for applications to want some directory structure (e.g. `/var/lib/postgresql`) to be pre-created.
It's recommended to use [systemd tmpfiles.d](https://www.freedesktop.org/software/systemd/man/latest/tmpfiles.d.html)
for this.  An even better approach where applicable is [StateDirectory=](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#RuntimeDirectory=)
in units.

As of bootc 1.1.6, the `bootc container lint` command will check for missing `tmpfiles.d`
entries and warn.

Note this is very different from the handling of `/etc`.   The rationale for this is
that `/etc` is relatively small configuration files, and the expected configuration
files are often bound to the operating system binaries in `/usr`.

But `/var` has arbitrarily large data (system logs, databases, etc.).  It would
also not be expected to be rolled back if the operating system state is rolled
back.  A simple example is that an `apt|dnf downgrade postgresql` should not
affect the physical database in general in `/var/lib/postgres`.  Similarly,
a bootc update or rollback should not affect this application data.

Having `/var` separate also makes it work cleanly to "stage" new
operating system updates before applying them (they're downloaded
and ready, but only take effect on reboot).

In general, this is the same rationale for Docker `VOLUME`: decouple the application
code from its data.

## Other directories

It is not supported to ship content in `/run` or `/proc` or other [API Filesystems](https://www.freedesktop.org/wiki/Software/systemd/APIFileSystems/) in container images.

Besides those, for other toplevel directories such as `/usr` `/opt`, they will be lifecycled with the container image.

### `/opt`

In the default suggested model of using composefs (per above) the `/opt` directory will be read-only, alongside
other toplevels such as `/usr`.

Some software (especially "3rd party" deb/rpm packages) expect to be able to write to
a subdirectory of `/opt` such as `/opt/examplepkg`.

See [building images](building/guidance.md) for recommendations on how to build
container images and adjust the filesystem for cases like this.

However, for some use cases, it may be easier to allow some level of mutability.
There are two options for this, each with separate trade-offs: transient roots
and state overlays.

### Other toplevel directories

Creating other toplevel directories and content (e.g. `/afs`, `/arbitrarymountpoint`)
or in general further nested data is supported - just create the directory
as part of your container image build process (e.g. `RUN mkdir /arbitrarymountpoint`).
These directories will be lifecycled with the container image state,
and appear immutable by default, the same as all other directories
such as `/usr` and `/opt`.

Mounting separate filesystems there can be done by the usual mechanisms
of `/etc/fstab`, systemd `.mount` units, etc.

#### SELinux for arbitrary toplevels

Note that operating systems using SELinux may use a label such as
`default_t` for unknown toplevel directories, which may not be
accessible by some processes. In this situation you currently may
need to also ensure a label is defined for them in the file contexts.

## Enabling transient root

This feature enables a fully transient writable rootfs by default.
To do this, set the

```toml
[root]
transient = true
```

option in `/usr/lib/ostree/prepare-root.conf`.  In particular this will allow software to
write (transiently, i.e. until the next reboot) to all top-level directories,
including `/usr` and `/opt`, with symlinks to `/var` for content that should
persist.

This can be combined with `etc.transient` as well (below).

More on prepare-root: <https://ostreedev.github.io/ostree/man/ostree-prepare-root.html>

## Enabling transient etc

The default (per above) is to have `/etc` persist. If however you do
not need to use it for any per-machine state, then enabling a transient
`/etc` is a great way to reduce the amount of possible state drift. Set
the

```toml
[etc]
transient = true
```

option in `/usr/lib/ostree/prepare-root.conf`.

This can be combined with `root.transient` as well (above).

More on prepare-root: <https://ostreedev.github.io/ostree/man/ostree-prepare-root.html>

## Enabling state overlays

This feature enables a writable overlay on top of `/opt` (or really, any
toplevel or subdirectory baked into the image that is normally read-only).

The semantics here are somewhat nuanced:

- Changes persist across reboots by default
- During updates, new files from the container image override any locally modified version

The advantages are:
- It makes it very easy to make compatible applications that install into `/opt`.
- In contrast to transient root (above), a smaller surface of the filesystem is mutable.

The disadvantages are:
- There is no equivalent to this feature in the Docker/Podman ecosystem.
- It allows for some temporary state drift until the next update.

To enable this feature, instantiate the `ostree-state-overlay@.service`
unit template on the target path. For example, for `/opt`:

```
RUN systemctl enable ostree-state-overlay@opt.service
```

## More generally dealing with `/opt`

Both transient root and state overlays above provide ways for packages
that install in `/opt` to operate. However, for maximum immutability the
best approach is simply to symlink just the parts of the `/opt` needed
into `/var`. See the section on `/opt` in [Image building and configuration
guidance](building/guidance.md) for a more concrete example.

## Increased filesystem integrity with fsverity

The bootc project uses [composefs](https://github.com/composefs/composefs)
by default for the root filesystem (using ostree's support for composefs).
However, the default configuration as recommended for base images
uses composefs in a mode that does not require signatures or fsverity.

bootc supports with ostree's model of hard requiring fsverity
for underlying objects. Enabling this also causes bootc
to error out at install time if the target filesystem does
not enable fsverity.

To enable this, inside your container build update
`/usr/lib/ostree/prepare-root.conf` with:

```
[composefs]
enabled = verity
```

At the current time, there is no default recommended
mechanism to check the integrity of the upper composefs.
For more information about this, see
[this tracking issue](https://github.com/bootc-dev/bootc/issues/1190).

Note that the default `/etc` and `/var` mounts are unaffected by
this configuration. Because `/etc` in particular can easily
contain arbitrary executable code (`/etc/systemd/system` unit files),
many deployment scenarios that want to hard require fsverity will also
want a "transient etc" model.

### Caveats

#### Does not apply to logically bound images

The [logically bound images](logically-bound-images.md) store is currently
implemented using a separate mechanism and configuring fsverity
for the bootc storage has no effect on it.

#### Enabling fsverity across upgrades

At the current time the integration is only for
installation; there is not yet support for automatically ensuring that
fsverity is enabled when upgrading from a state with
`composefs.enabled = yes` to `composefs.enabled = verity`.
Because older objects may not have fsverity enabled,
the new system will likely fail at runtime to access these older files
across the upgrade.
