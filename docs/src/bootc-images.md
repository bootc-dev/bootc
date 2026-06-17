# "bootc compatible" images

It is a toplevel goal of this project to tightly integrate
with the OCI ecosystem and make booting containers a normal
activity.

However, there are a number of basic requirements and integration
points, some of which have distribution-specific variants.

## Generic requirements (composefs or ostree backends)

### `/sysroot`

Your container image must have a `/sysroot` directory - this is where the "physical root" will be mounted. The permissions (mode) should generally be the same as `/usr` i.e. `0755` or similar.

### `LABEL containers.bootc=1` 

The rationale for this required label is that many higher level tools which expect to operate only on bootc-compatible OCI images will want to be able to present only compatible images. 

### Kernel (split)

The Linux kernel (and optionally initramfs) is embedded in the container image; the canonical location is `/usr/lib/modules/$kver/vmlinuz`, and the initramfs should be in `initramfs.img` in that directory. You should *not* include any content in `/boot` in your container image. Bootc will take care of copying the kernel/initramfs as needed from the container image to `/boot`.

### Kernel (sealed UKI)

For the composefs backend, the UKI must be located at `/boot/EFI/Linux/$kver.efi`.

### /ostree symlink and `bootc container lint`

This is [a bug](https://github.com/bootc-dev/bootc/issues/2256): currently a `/ostree -> /sysroot/ostree` symlink is required just for `bootc container lint` to pass, even though it's not required for `/sysroot/ostree` to exist.

## composefs backend

There are no strict additional basic filesystem/layout requirements for images which plan to deploy with composefs. However, see also [bootloaders](bootloaders.md).

## ostree backend

### `prepare-root.conf`

The upstream ostree builds today do not default to composefs. You must enable this via a `prepare-root.conf`:

```
[composefs]
enabled = true
```

This is checked by `bootc container lint`.

### Historical usage of `/ostree`

Some images include a `/ostree` directory. A requirement for this was dropped in [bootc 1.1.3](https://github.com/bootc-dev/bootc/releases/tag/v1.1.3), and it is recommended that new images do not include it.

## Suggested image content

The bootc project provides a [baseimage](https://github.com/bootc-dev/bootc/tree/main/baseimage) reference
set of configuration files for base images. In particular at
the current time the content defined by `base` must be used
(or recreated). There is also suggested integration there with
e.g. `dracut` to ensure the initramfs is set up, etc.

The `bootc container lint` command will check this.

## SELinux

The default mechanism for labeling today is that bootc will load the file contexts from the image (e.g. `/etc/selinux/policy`) and apply labels dynamically. This is the only mechanism that will work today with a generic bootc-unaware build tooling.

It is not supported to add `security.selinux` extended attributes into the OCI tar layers, though support for this may be added if requested.

### More details

Container runtimes such as `podman` and `docker` commonly
apply a "coarse" SELinux policy to running containers.
See [container-selinux](https://github.com/containers/container-selinux/blob/main/container_selinux.8).
It is very important to understand that non-bootc base
images do not (usually) have any embedded `security.selinux` metadata
at all; all labels on the toplevel container image
are *dynamically* generated per container invocation,
and there are no individually distinct e.g. `etc_t` and
`usr_t` types.

### `/ostree`

Only with the ostree backend, there is support for including the ostree commit metadata in the OCI image, which includes all xattrs. File content in derived layers will be labeled using the default file
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
