# bootc

Transactional, in-place operating system updates using OCI/Docker container images.

## Motivation

The original Docker container model of using "layers" to model
applications has been extremely successful.  This project
aims to apply the same technique for bootable host systems - using
standard OCI/Docker containers as a transport and delivery format
for base operating system updates.

The container image includes a Linux kernel (in e.g. `/usr/lib/modules`),
which is used to boot.  At runtime on a target system, the base userspace is
*not* itself running in a "container" by default. For example, assuming
systemd is in use, systemd acts as pid1 as usual - there's no "outer" process.
More about this in the docs; see below.

## Status

NOTE: At the current time, bootc has not reached 1.0, and it is possible
that some APIs and CLIs may change.

## Documentation

See the [project documentation](https://containers.github.io/bootc/); there
are also operating systems and distributions using bootc; here are some examples:

- https://docs.fedoraproject.org/en-US/bootc/
- https://www.heliumos.org/

## Developing bootc

Are you interested in working on bootc?  Great!  See our [HACKING.md](HACKING.md) guide.

