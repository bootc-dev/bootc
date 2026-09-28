
# Container runtime vs "bootc runtime"

Fundamentally, `bootc` reuses the [OCI image format](https://github.com/opencontainers/image-spec)
as a way to transport serialized filesystem trees with included metadata such as a `version`
label, etc.

A bootc container operates in two basic modes.  First, when invoked by a container run time such as `podman` or `docker` (typically as part of a build process), the bootc container behaves exactly the same as any other container. For example, although there is a kernel embedded in the container image, it is not executed - the host kernel is used.  There's no additional mount namespaces, etc.  Ultimately, the container runtime is in full control here.

The second, and most important mode of operation is when a bootc container is installed to a physical or virtual machine.  Here, bootc is in control; the container runtime used to build is no longer relevant.  However, it's *very* important to understand that bootc's role is quite limited:

- On boot, there is code in the initramfs to do a "chroot" equivalent into the target filesystem root
- On upgrade, bootc will fetch new content, but this will not affect the running root

Crucially, besides setting up some mounts, bootc itself does not act as any kind of "container runtime".  It does not set up pid or other namespace, does not change cgroups, etc.  That remains the role of other code (typically systemd).  `bootc` is not a persistent daemon by default; it does not impose any runtime overhead.

This distinction also applies to DNS configuration. A container runtime may
inject `/etc/resolv.conf` while building or running a container, but it is not
present to do so after a bootc image boots. See
[DNS and `/etc/resolv.conf`](bootc-dns.7.md).

Another example of this: While one can add [Container configuration](https://github.com/opencontainers/image-spec/blob/main/config.md) metadata, `bootc` generally ignores that at runtime today.

## Labels

A key aspect of OCI is the ability to use standardized (or semi-standardized)
labels.  The are stored and rendered by `bootc`; especially the
`org.opencontainers.image.version` label.

## Example ignored runtime metadata, and recommendations

### `ENTRYPOINT` and `CMD` (OCI: `Entrypoint`/`Cmd`)

Ignored by bootc.

It's recommended for bootc containers to set `CMD /sbin/init`; but this is not required.

The booted host system will launch from the bootloader, to the kernel+initramfs and
real root however it is "physically" configured inside the image.  Typically
today this is using [systemd](https://systemd.io/) in both the initramfs
and at runtime; but this is up to how you build the image.

### `ENV` (OCI: `Env`)

Ignored by bootc; to configure the global system environment you can
change the systemd configuration.  (Though this is generally not a good idea;
instead it's usually better to change the environment of individual services)

### `EXPOSE` (OCI: `exposedPorts`)

Ignored by bootc; it is agnostic to how the system firewall and network
function at runtime.

### `USER` (OCI: `User`)

Ignored by bootc; typically you should configure individual services inside
the bootc container to run as unprivileged users instead.

### `HEALTHCHECK` (OCI: *no equivalent*)

This is currently a Docker-specific metadata, and did not make it into the
OCI standards.  (Note [podman healthchecks](https://developers.redhat.com/blog/2019/04/18/monitoring-container-vitality-and-availability-with-podman#))

It is important to understand again is that there is no "outer container runtime" when a
bootc container is deployed on a host.  The system must perform health checking on itself (or have an external
system do it).

Relevant links:

- [bootc rollback](../man/bootc-rollback.8.md)
- [CentOS Automotive SIG unattended updates](https://sigs.centos.org/automotive/building/unattended_updates/#watchdog-in-qemu)
  (note that as of right now, greenboot does not yet integrate with bootc)
- <https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT/>


## Kernel

When run as a container, the Linux kernel binary in
`/usr/lib/modules/$kver/vmlinuz` is ignored.  It
is only used when a bootc container is deployed
to a physical or virtual machine.

## Security properties

When run as a container, the container runtime will by default apply
various Linux kernel features such as namespacing to isolate
the container processes from other system processes.

None of these isolation properties apply when a bootc
system is deployed.

## SELinux

For more on the intersection of SELinux and current bootc (OSTree container)
images, see [bootc images - SELinux](../bootc-compatible-images.7.md#SELinux).
