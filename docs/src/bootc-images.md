# "bootc compatible" images

It is a toplevel goal of this project to tightly integrate
with the OCI ecosystem and make booting containers a normal
activity.

However, there are a number of basic requirements and integration
points, some of which have distribution-specific variants.

Further at the current time, the bootc project makes a lot
of use of ostree, and this can appear in the base image
requirements.

## ostree-in-container

With [bootc 1.1.3](https://github.com/bootc-dev/bootc/releases/tag/v1.1.3)
or later, it is no longer required to have a `/ostree` directory
present in the base image.

To generate container images which do include `/ostree` from scratch,
the underlying `ostree container` tooling is designed to operate
on an existing ostree commit, and the `ostree container encapsulate`
command can turn the commit into an OCI image. If you already
have a pipeline which prdouces ostree commits as an output
(e.g. using [osbuild](https://www.osbuild.org/guides/image-builder-on-premises/building-ostree-images.html)
 to produce `ostree` commit artifacts), then this allows a
seamless transition to a bootc/OCI compatible ecosystem.

## Higher level base image build tooling

A well tested tool to produce compatible base images is 
[`rpm-ostree compose image`](https://coreos.github.io/rpm-ostree/container/#creating-base-images),
which is used by the [Fedora base image](https://gitlab.com/fedora/bootc/base-images).

## Standard image content

The bootc project provides a [baseimage](https://github.com/bootc-dev/bootc/tree/main/baseimage) reference
set of configuration files for base images. In particular at
the current time the content defined by `base` must be used
(or recreated). There is also suggested integration there with
e.g. `dracut` to ensure the initramfs is set up, etc.

## Standard metadata for bootc compatible images

It is strongly recommended to do:

```dockerfile
LABEL containers.bootc 1
```

This will signal that this image is intended to be usable with `bootc`.

## Deriving from existing base images

It's important to emphasize that from one
of these specially-formatted base images, every
tool and technique for container building applies!
In other words it will Just Work to do

```Dockerfile
FROM <bootc base image>
RUN dnf -y install foo && dnf clean all
```

You can then use `podman build`, `buildah`, `docker build`, or any other container
build tool to produce your customized image. The only requirement is that the
container build tool supports producing OCI container images.

## Kernel

The Linux kernel (and optionally initramfs) is embedded in the container image; the canonical location
is `/usr/lib/modules/$kver/vmlinuz`, and the initramfs should be in `initramfs.img`
in that directory. You should *not* include any content in `/boot` in your container image.
Bootc will take care of copying the kernel/initramfs as needed from the container image to
`/boot`.

Future work for supporting UKIs will follow the recommendations of the uapi-group in [Locations for Distribution-built UKIs Installed by Package Managers](https://uapi-group.org/specifications/specs/unified_kernel_image/#locations-for-distribution-built-ukis-installed-by-package-managers).

The `bootc container lint` command will check this.

## The `ostree container commit` command

You may find some references to this; it is no longer very useful
and is not recommended.

## The bootloader setup

At the current time bootc relies on the [bootupd](https://github.com/coreos/bootupd/)
project which handles bootloader installs and upgrades.  The invocation of
`bootc install` will always run `bootupd` to perform installations.
Additionally, `bootc upgrade` will currently not upgrade the bootloader;
you must invoke `bootupctl update`.

## SELinux

Container runtimes such as `podman` and `docker` commonly
apply a "coarse" SELinux policy to running containers.
See [container-selinux](https://github.com/containers/container-selinux/blob/main/container_selinux.8).
It is very important to understand that non-bootc base
images do not (usually) have any embedded `security.selinux` metadata
at all; all labels on the toplevel container image
are *dynamically* generated per container invocation,
and there are no individually distinct e.g. `etc_t` and
`usr_t` types.

In contrast, with the current OSTree backend for bootc,
it is possible to include label metadata (and precomputed ostree
checksums) in special metadata files in `/sysroot/ostree` that correspond
to components of the base image. This is optional as of bootc v1.1.3.

File content in derived layers will be labeled using the default file
contexts (from `/etc/selinux`). For example, you can do this (as of
bootc 1.1.0):

```
RUN semanage fcontext -a -t httpd_sys_content_t "/web(/.*)?"
```

(This command will write to `/etc/selinux/$policy/policy/`.)

It will currently not work to do e.g.:

```
RUN chcon -t foo_t /usr/bin/foo
```

Because the container runtime state will deny the attempt to
"physically" set the `security.selinux` extended attribute.

In the future, it is likely however that we add support
for handling the `security.selinux` extended attribute in tar
streams; but this can only currently be done with a custom
build process.

#### Forcing relabeling

Some distributions support a `/.autorelabel` file; this will not work
on a bootc managed system where `/` is immutable state from the base
image by default. The labels on the files under `/sysroot/ostree` are
also managed by bootc/ostree and should not be changed by external
tools.

Most typically, you instead want to only relabel targeted subdirectories
of `/etc` and `/var`. This can be done via a systemd unit, e.g.
`ExecStart=restorecon -R -v /var/lib/mysql`.

### Toplevel directories

In particular, a common problem is that inside a container image,
it's easy to create arbitrary toplevel directories such as
e.g. `/app` or `/aimodel` etc.  But in some SELinux policies
such as Fedora derivatives, these will be labeled as `default_t`
which few domains can access.

References:

- <https://github.com/ostreedev/ostree-rs-ext/issues/510>

## composefs

It is strongly recommended to enable the ostree composefs
backend (but not strictly required) for bootc.

A reference enablement file to do so is in the base image content referenced above.

More in [ostree-prepare-root](https://ostreedev.github.io/ostree/man/ostree-prepare-root.html).
