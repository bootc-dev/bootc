# Relationship with systemd "particles"

There is an excellent [vision blog entry](https://0pointer.net/blog/fitting-everything-together.html)
that puts together a coherent picture for how a systemd (and [uapi-group.org](https://uapi-group.org/))
oriented Linux based operating system can be put together, and the rationale for doing so.

The "bootc vision" aligns with parts of this, but differs in emphasis and also some important technical details - and some of the emphasis and details have high level ramifications.  Simply stated: related but different.

## System emphasis

The "particle" proposal mentions that the desktop case is most
interesting; the bootc belief is that servers are equally
important and interesting.  In practice, this is not a real point
of differentiation, because the systemd project has done an excellent
job in catering to all use cases (desktop, embedded, server) etc.

An important aspect related to this is that the bootc project exists and must
interact with many ecosystems, from "systemd-oriented Linux" to Android and
Kubernetes. Hence, we would not explicitly compare with just ChromeOS, but also
with e.g. [Kairos](https://kairos.io/) and many others.

## Design goals

Many of the toplevel design goals do overall align. It is clear that e.g.
[Discoverable Disk Images](https://uapi-group.org/specifications/specs/discoverable_disk_image/)
and [OCI images](https://github.com/opencontainers/image-spec) align on managing
systems in an image-oriented fashion.

### A difference on goal 11

Goal 11 states:

> Things should not require explicit installation. i.e. every image should be a live image. For installation it should be sufficient to dd an OS image onto disk.

The `bootc install` approach is explicitly intending to support things such
as e.g. static IP addresses provisioned via kernel arguments at install time;
it is not a goal for installations to be equivalent to `dd`.  The bootc creator has experience with systems that install this way, and it creates practical problems in nontrivial scenarios such as ["Advanced Format"](https://en.wikipedia.org/wiki/Advanced_Format) disk drives, etc.

### New Goal: An explicit alignment with cloud-native

The bootc project has an explicit goal to to take formats, cues and inspiration
from the container and cloud-native ecosystem.  More on this in several sections below.

### New Goal: Continued explicit support for "unlocked" systems

A strong emphasis of the particle approach is "sealed" systems that chain from Secure Boot.
bootc aims to support the same.  And in practice, nothing in "particles" strictly
requires Secure Boot etc.

However, bootc has a stronger emphasis on continuing to support "unlocked"
systems into the foreseeable future in which key (even root level) operating system
changes can be that are outside of an explicit signed state and feel
*equally* first class, not just "developer system extensions".

Or stated more simply, it will be explicitly supported to create bootc-based
operating systems that boot as e.g. a cloud instance or as desktop machine that defaults to an unlocked state and provides good ergonomics in this scenario for managing user owned
state across operating system upgrades too.

## Hermetic `/usr`

One of the biggest differences starts with this.  The idea of having
the entire operating system self-contained in `/usr` is a good one.  However,
there is an immense amount of prior history and details that make this
hard to support in many generalized cases.

[This tracking issue](https://github.com/uapi-group/specifications/issues/76) is a good starting point - it's mostly about `/etc` (see below).

### bootc design: Carve out sub mounts

Instead, the bootc model allows arbitrary directory roots starting from `/`
to be included in the base operating system image.

This first notable difference is rooted in bootc taking a stronger cue from the [opencontainers](https://github.com/opencontainers) ecosystem (including docker/podman/Kubernetes).
There are no restrictions on application container filesystem layout (everything
is ephemeral by default, and persistence must be explicit); bootc aims to be closer
to this.

There is still alignment: bootc design does *strongly encourage* operating
system state to live underneath `/usr` - it should be the default place for all
operating system executable binaries and default configuration. It should be
read-only by default.

### `/etc`

Today, the bootc project uses [ostree](https://github.com/ostreedev/ostree/) as a backend,
and a key semantic ostree provides for `/etc` is a "3 way merge".

This has several important differences.  First, it means that `/etc` does get updated
by default for unchanged configuration files.

The default proposal for "particle" OSes to deal with "legacy" config files in
`/etc` is to copy them on first OS install (e.g. `/usr/share/factory`).

This creates serious problems for all the software (for example, OpenSSH) that put config
files there; - having the default configuration updated (e.g. for a security issue) for a package manager but not an image based update is not viable.

However a key point of alignment between the two is that we still aim to
have `/etc` exist and be useful!  Writing files there, whether from `vi`
or config management tooling must continue to work.  Both bootc and systemd "particle"
systems should still Feel Like Unix - in contrast to e.g. Android.

At the current time, this is implemented in ostree; as bootc moves
towards stronger integration with podman, it is likely that this logic
will simply be moved into bootc instead on top of podman.
Alternatively perhaps, podman itself may grow some support for
specifying this merge semantic for containers.

### Other persistent state: `/var`

Supporting arbitrary toplevel files in `/` on operating system
updates conflicts with a desire to have e.g. `/home` be persistent by default.

Hence, bootc emphasizes having e.g. `/home` → `/var/home` as
a default symlink in base images.

Aside from `/home` and `/etc`, it is common on most Linux systems to
have most persistent state under `/var`, so this is not a major point
of difference otherwise.

### Other toplevel files/directories

Even the operating systems have completed "UsrMerge" still have
legacy compatibility symlinks required in `/`, e.g. `/bin` → `/usr/bin`.
We still need to support shipping these for many cases, and they
are an important part of operating system state.  Having them
not be explicitly managed by OS updates is hence suboptimal.

Related to this, bootc will continue to support operating systems that have
not completed UsrMerge.

## Discoverable Disk images and booting

The bootc project will not use
[Discoverable Disk Images](https://uapi-group.org/specifications/specs/discoverable_disk_image/).
Instead, we orient as strongly around
[opencontainers/image-spec](https://github.com/opencontainers/image-spec) i.e.
OCI/Docker images.

This is the biggest technical difference that strongly influences
many other aspects of operating system design and experience.

It is an explicit goal of the bootc project that it should feel as
natural as possible for someone familiar with "application containers"
from podman/Docker/Kubernetes to take their tools and knowledge
and apply that to the base operating system too.

### Technical heart: composefs

There is a very strong security rationale behind much of the design proposal
of "particles" and DDIs.  It is absolutely true today, quoting the blog:

> That said, I think \[OCI has\] relatively weak properties, in particular when it comes to security, since immutability/measurements and similar are not provided. This means, unlike for system extensions and portable services a complete trust chain with attestation and per-app cryptographically protected data is much harder to implement sanely.

The [composefs project](https://github.com/containers/composefs/) aims to close
this gap, and the bootc project will use it, and has an explicit goal
to align with e.g. [podman](https://github.com/containers/podman) in using it too.

Effectively, everywhere one might use a DDI, bootc will usually support a container
image.  (However for some things like system configuration files, bootc may
aim to instead support e.g. plain ConfigMap files which are signed for example).

## System booting

### The bootloader

The strong emphasis of the UAPI-group is on
[UEFI](https://en.wikipedia.org/wiki/UEFI). However, the world is a bit broader
than that; the bootc project also will explicitly continue to support:

- [GNU Grub](https://www.gnu.org/software/grub/) for multiple reasons; among them that unfortunately x86 BIOS systems will not disappear entirely in the next 10 years even.
- Android Boot - because some hardware manufacturers ship it, and we want to support operating systems that must work on this hardware.
- [zipl](https://www.ibm.com/docs/en/linux-on-z?topic=bs-zipl-initial-program-loader) because it's how things work on s390x, and there is significant alignment in terms of emphasizing a "unified kernel" style flow.

#### Boot loader configs

bootc aims to align with the idea of generic bootloader-independent config files where possible; today it uses ostree.  For more on this, see [ostree and bootloaders](https://github.com/ostreedev/ostree/blob/main/docs/bootloaders.md).

### The kernel and initramfs

There is agreement that in order to achieve integrity, there must be a strong link
between the kernel and the first userspace code that executes in the initial RAM
disk.

Building on the bootloader statement above: bootc will support [UKI](https://uapi-group.org/specifications/specs/unified_kernel_image/), but not require it.

### The root filesystem

In the bootc model, the root filesystem defaults to a single physical Linux filesystem (e.g. `xfs`, `ext4`, `btrfs` etc.).  It is of course supported to mount other partitions and filesystems; doing so is encouraged even for `/var`.  , where one ends up with some space constraints around the OS `/usr` partition due to dm-verity.

This is a rather large difference already from particles; the root filesystem contains the operating system too; it is not a separate partition.  One thing this helps significantly with is dealing with the "space management" problems that dm-verity introduces (need for
a partition to have unused empty space to grow, and also a fixed-size ultimate capacity limit).

#### Locating the root

bootc does not mandate or emphasize any particular way to locate the root filesystem;
parts of the [discoverable partitions specification](https://uapi-group.org/specifications/specs/discoverable_partitions_specification/) specifically the "root partition" may be
used.  Or, the root filesystem can be found the traditional way, via a local `root=`
kernel argument.

Another point of contrast from the particle emphasis is that while we encourage encrypting the root filesystem, it is not required.  Particularly some use cases in cloud environments perform encryption at the hypervisor level and do not want additional
overhead of doing so per virtual machine.

#### Locating the base container image

Until this point, we have been operating under external constraints; no one is creating
a bootloader that directly understands how to start a container image, for example.
We've gotten as far as running a Linux userspace in the initial RAM disk, and the
physical root filesystem is mounted.

Here, we circle back to [composefs](https://github.com/containers/composefs).  One can
think of composefs as effectively a way to manage something like dm-verity, but using
files.

What bootc builds on top of that is to target a specific container image rootfs
that is part of the "physical" root.  Today, this is implemented again using ostree, via the `ostree=` kernel commandline argument.  In the future, it is likely to be a `bootc.image`.
However, integration with other bootloaders (such as Android Boot) require us to interact
with externally-specified fixed kernel arguments.  

Ultimately, the initramfs will contain logic to find the desired root container, which
again is just a set of files stored in the "physical" root filesystem.

#### Chaining integrity from the initramfs

One can think of composefs as effectively a way to manage something like dm-verity, but
supporting multiple ones stored inside a standard Linux filesystem.

For "sealed" systems, the bootc project suggests a default model where there is an "ephemeral key" that binds the UKI (or equivalent) and the real root.  For a bit more on this, see [ostree and composefs](https://ostreedev.github.io/ostree/composefs/#injecting-composefs-digests).  Effectively, at image build time an "ephemeral" key is generated which signs the composefs digest of the container image.  The public half
of this key is injected into the UKI, which is itself signed e.g. for Secure Boot.

At boot time, the initramfs will use its embedded public key to verify the composefs
digest of the target root - and from there, overlayfs in the Linux kernel combined
with fs-verity will continually verify the integrity of all operating system root
files we use.

At the current time, there is not one single standardized approach for signing composefs
images.  Ultimately, a composefs image has a digest, and signing and verification
of that digest can be done via any signing tool.  For more on this, see
[this issue](https://github.com/containers/composefs/issues/151).

bootc itself will not mandate one mechanism currently.  However, it is very likely
that we will ship an optionally-enabled opinionated mechanism that uses basic ed25519
signatures for example.

This is effectively equivalent to the particle approach of embedding a verity root hash into the kernel commandline - it means that the booted Linux kernel will *only* be capable
of mounting that one specific root filesystem.  Note that this model is effectively
the same as e.g. Fedora uses to sign kernel modules.

However, an "ephemeral key" is not the only valid way to do things; for some operating
system creators it may be very desirable to continue to be able to make root OS image
changes without changing the UKI (and hence re-signing it).  Instead, another valid
approach is to simply maintain a persistent public/private keypair.  This allows
disconnecting the build of userspace and kernel, but also means that there is less
strict verification between kernel and userspace (e.g. downgrade attacks become possible).

#### Chaining integrity to configuration and application containers

composefs is explicitly designed to be useful as a backend for "application" containers (e.g. podman).  There is again not one single mechanism for signing and verification; in some use cases, it may be enough to boot the operating system enough to implement "network as source of truth" - for example, the public keys for verification of application containers
might be fetched from a remote server.  Then before any application containers are run,
we dynamically fetch the relevant keys from a server which was trusted.

The bootc project will align with podman in general, and make it easy to implement
a mechanism that chains keys stored alongside the operating system into composefs-signed
application containers.

Configuration (effectively starting from `/etc` and the kernel commandline) in a "sealed" system is a complex topic.  Many operating system builds will want to disable the default "etc merge" and make `/etc` always lifecycle bound with the OS: commonly writable but ephemeral.

This topic is covered more in the next section.

## Modularity

A goal of "particles" is to add integrity into "general purpose" Linux OSes and distributions - supporting a world where there are a lot of users that simply directly install an OS from an upstream OS such as Debian or Fedora.  This has a lot of implications; among them that e.g. the Secure Boot signatures etc. are made by the OS creator, not the user.

A big emphasis for the bootc project in contrast a design where it is normal and expected for many users to *derive* (via standard container build technology) from the base image produced by the OS upstream.

This is just a difference in emphasis: "particles" can clearly be built fully customized by the end customer, and bootc fully supports booting "stock" images.  

But still: the bootc project will again much more strongly push any scenario that desires truly strong integrity towards making and managing custom derived builds.

### Extensions and security

In "unlocked" scenarios, the bootc project will continue to support a "traditional Unix" feeling where persistent changes to `/etc` can be written and maintained.  Similarly, it will continue to be supported to have machine-local kernel arguments.
There is significant value in migrating "package based" systems to "image based" systems, even if they are still "unsigned" or "unlocked".

The particle model calls for tools like [confext](https://uapi-group.org/specifications/specs/extension_image/#confext-configuration-extension) that use DDIs.  The "backend" of this (managing merged dynamic filesystem trees with overlayfs) and its relationship with systemd units is still relevant, but the bootc approach will again not expose DDIs to the user.  Instead, our approach will take cues from the cloud-native world and use e.g. [Kubernetes ConfigMap](https://github.com/bootc-dev/bootc/issues/22) and support signatures on these.

## More Modularity: Secondary OS installs

This uses OCI containers, which will work the same as the host.

## Developer Mode

This topic heavily diverges between the "unlocked" and "sealed" cases.  In the unlocked case, the bootc project aims to still continue to make it feel very "first class" to perform arbitrary machine-local mutations.  Instead of managing overlay DDIs, `bootc` will make it trivial and obvious to use local container builds using any standard container build tooling.

### Package managers

In order to ease the transition for users coming from package systems, the bootc project suggests that package managers like `apt` and `dnf` etc. learn how to become a frontend for "local" container builds too.  In other words, `apt|dnf install foo` would become shorthand for a container build like:

```
FROM <localhost>
RUN apt|dnf install foo
```

### Transitioning from unlocked, mutable local state to server-built images

Building on the above, a key point of `bootc` is to make it easy and obvious how to go from an "unlocked" system with potential unmanaged state towards a system built and managed using standard OCI container image build systems and tooling.  For example, there should be a command like `apt|dnf print-containerfile`.  (The problem is more complex than this of course, as we would likely want to capture some changes from `/etc` - but also some of those changes may include secrets, which are their own sub-topic)

## Democratizing Code Signing

Strong alignment here.

## Running the OS itself in a container

This is equally obvious to do when the host and the linked container runtime (e.g. podman) again use the same tools.

## Parameterizing Kernels

In "unlocked" scenarios (per above) we will continue to use bootloader configuration that is unsigned.

We will not (in contrast to particles) try to strongly support a "partially sealed, general purpose" model.  More on this below.

Most cases for "sealed" systems will want to entirely lock the kernel commandline, not even using a bootloader at all and hence there is no mechanism to configure it locally at all.  However, as discussed in various venues around UKI, "sealed" systems can become complex to deploy where there is a need for machine (or machine-type) specific kernel arguments:

- Deploying the RT kernel often wants to use [isolcpus=](https://access.redhat.com/solutions/480473).
- Setting static IP addresses on the kernel commandline to enable [network bound disk encryption](https://access.redhat.com/articles/6987053) for the rootfs

The bootc project default approach for this is to lean into the container-native world, using derivation to create a machine-independent "base image", then create derived, machine (or machine-class) specific images that are in turn signed.

## Updating Images

A big differentiation here is that bootc will reuse container technology for fetching updates.  The operating system and application containers will be signed with e.g. [sigstore](https://www.sigstore.dev/) or similar for network fetching.  The signature will cover the composefs digest, which enables continuous verification.

Managing storage of container images using composefs is more complex than `systemd-sysupdate` writing to a partition, but significantly more flexible.  For more on this, see [upstream composefs](https://github.com/containers/composefs).

### Kernel in images

The bootc and particle approaches are aligned on storing the kernel binary in `/usr/lib/modules/$kver`.  On the bootc side, a key bit here is that bootc will extract the kernel and initramfs (or just UKI) and put it in the appropriate place - this is implemented as a transactional operation.  There are significant details that can vary for how this works (because unlike particles, bootc aims to support non-EFI setups as well), but the high level idea is similar.

## Boot Counting + Assessment

This topic relates to the previous one; because of multiple bootloaders, there is not one single approach.  The systemd [automatic boot assessment](https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT) is good where it can be used, but we also will support e.g. Android bootloaders.

## Picking the Newest Version

Because the storage of images is not just files or partitions, bootc will not expose to the user/administrator a semantic of `strvercmp` or package-manager oriented versioning semantics.  Instead, the implementation of "latest" will be implemented in a more Kubernetes-oriented fashion of having "local" API objects with spec and status.  This makes it easy and obvious for higher level management (e.g. cluster)
tooling to orchestrate updates in a Kubernetes-style fashion.

## Home Directory Management

The bootc project will not do anything with this.  We will support [systemd-homed](https://www.freedesktop.org/software/systemd/man/systemd-homed.service.html) where users want it, but in many dedicated servers and managed devices the idea of persistent user "home directories" are more of an anti-pattern.

## Partition Setup

The biggest difference again here is that bootc is oriented closer to a single root partition by default that includes the OS, system/app containers and persistent local state all as one unit.

## Trust chain

In contrast to particles, the bootc project does not aim to by default emphasize a model of using sysexts from the initramfs because its primary use case occurs when using a "partially sealed" system.  And per above (re kernels) it is insufficient for other cases.

Without this in the mix then, the trust chain is simple to describe: the
kernel+initramfs are verified by the bootloader, the initramfs contains the key
and logic necessary to verify the composefs digest of the root, and the root
starts to verify everything else.

## File System Choice

As mentioned above, any Linux filesystem is valid for the root.  For "sealed" systems using composefs will cover integrity and there is not a distinct need for dm-integrity.

## OS Installation vs. OS Instantiation

The bootc project is just less partition-oriented and more towards multiple-composefs-in-root oriented.  However the high level goal is shared of making it easy to "re-provision" and keeping the install-time flow as close as possible.

## Building Images According to this Model

This is a key point of bootc: we aim for operating systems and distributions to ship their own bootc-compatible base images that can be used as a default derivation source.  These images are just OCI images that will follow simple rules (as mentioned above, the kernel is found in `/usr/lib/modules/$kver/vmlinuz`) for example for the extra state to boot.

However in order to enable "sealed" systems (using signed composefs digests), the container build system will need support for this.  But, it is a goal to standardize the composefs metadata needed alongside the OCI, and to support this in the broader container ecosystem of tools (e.g. docker, podman) as well as bootc.

## Final words

This document is obviously very heavily inspired by [the original blog](https://0pointer.net/blog/fitting-everything-together.html).

A point of divergence is that a goal of the bootc project *is* to strongly
influence the existing operating systems and distributions and help them migrate
their customers into an image-based world - and to make practical compromises in
order to aid that goal.

But, the bootc project strongly agrees with the idea of finding common ground (the "50% shared" case).  At a practical level, this project will take a hard dependency on systemd *and* on the container ecosystem, extending bridges where they exist, working on shared standards and approaches between the two.

