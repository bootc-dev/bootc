# bootc

Transactional, in-place operating system updates using OCI/Docker container images.
bootc is the key component in a broader mission of [bootable containers](https://containers.github.io/bootable/).

The original Docker container model of using "layers" to model
applications has been extremely successful.  This project
aims to apply the same technique for bootable host systems - using
standard OCI/Docker containers as a transport and delivery format
for base operating system updates.

The container image includes a Linux kernel (in e.g. `/usr/lib/modules`),
which is used to boot.  At runtime on a target system, the base userspace is
*not* itself running in a container by default.  For example, assuming
systemd is in use, systemd acts as pid1 as usual - there's no "outer" process.

# Status

The CLI and API for bootc are now considered stable. Every existing system
can be upgraded in place seamlessly across any future changes.

However, the core underlying code uses the [ostree](https://github.com/ostreedev/ostree)
project which has been powering stable operating system updates for
many years.  The stability here generally refers to the surface
APIs, not the underlying logic.
