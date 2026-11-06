# NAME

bootc-install-mount - Mount an installed deployment into a caller-owned directory

# SYNOPSIS

bootc install mount **--sysroot**=*SYSROOT* **--latest** [**--esp**=*ESP*] [**--read-only**] *TARGET*

# DESCRIPTION

Mount the deployment from an offline physical sysroot, such as one just
created by **bootc install to-filesystem**, at **TARGET**. Both the OSTree
and composefs backends are supported. **TARGET** is an absolute path to a
directory; as with **mount**(8), whatever is there is hidden (bootc warns if
it is not empty).

A deployment selector is required; currently the only one is **--latest**,
which mounts the deployment the default boot entry boots, as the kernel
command line of a booted system would name it. Requiring the selector leaves
room to choose among multiple deployments in the future without changing
what existing invocations mean.

bootc reads the boot entries from *SYSROOT*`/boot` and the ESP. If `/boot`
is a separate partition, mount it at *SYSROOT*`/boot` first, where OSTree
also expects it. The ESP is **--esp** if given. Otherwise, on architectures
that use an ESP, it is *SYSROOT*`/efi` or *SYSROOT*`/boot/efi` if either is
mounted (in that order, `/efi` being where **systemd-gpt-auto-generator**(8)
mounts it), or else the ESP bootc discovers from the block device(s) backing
*SYSROOT*, as **bootc-install**(8) does, mounting it while reading the
entries. The entries are ordered as **bootc-status**(8) orders them.
For GRUB, the default entry is the first of `grub2/user.cfg` (UKIs) or else
the Type 1 entry whose file name sorts last; for systemd-boot, the first
Type 1 entry on the ESP (or in `/boot`) in Boot Loader Specification order.
If that entry boots an OSTree deployment, the deployment is OSTree's default,
the first in its own order. Staged entries, EFI variables (such as a one-time boot
entry), boot counting and a configured default are not considered. When no
boot entries are found at all, the sysroot must contain exactly one
deployment, as it does right after installation.

The mount remains in the caller's mount namespace after this command exits;
bootc does not create a container, chroot, or private mount namespace.

The root follows what the initramfs does at boot. For composefs it is the
deployment's image. For OSTree it is the deployment's composefs image
(`.ostree.cfs`), mounted as **ostree-prepare-root**(1) does, unless
`prepare-root.conf` sets `composefs.enabled = no` or the deployment has no
image, in which case it is the deployment directory itself. Unlike
ostree-prepare-root, bootc also uses the image when `composefs.enabled` is
unset, does not consult kernel arguments, and for `signed` only requires
fs-verity without checking the commit signature.

The deployment root and `/usr` are always read-only. The persistent `/etc`
and `/var` are writable, unless **--read-only** is specified. The caller owns
the resulting mount tree and should clean it up recursively with **umount -R**.

`/etc` and `/var` are set up the way the deployment's root setup will mount
them at boot: for composefs as configured by **bootc-setup-root-conf**(5), and
for OSTree following `etc.transient` in `prepare-root.conf`. A transient
`/etc` is a fresh overlay of the image's `/etc`, so changes to it are
discarded on unmount, just as they would be on reboot. A transient root
(`root.transient`) is not applied; the root stays read-only.

`/var` is always the deployment's state directory on **SYSROOT**. bootc does
not look in the image or its configuration (such as `/etc/fstab` or systemd
mount units) for a separate `/var` filesystem, and does not consider kernel
arguments such as `systemd.volatile`. If the installation puts `/var` on its
own partition, mount that on top of *TARGET*`/var` yourself.

Plain **chroot**(1) into *TARGET* is not enough to run programs from the
deployment: it sets up no `/proc`, `/sys`, `/dev` or `/run`. Use a tool
that provides those, such as `bwrap`, `podman run --rootfs`, or
**systemd-nspawn**(1).

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
**TARGET**

    Directory receiving the deployment mount

    This argument is required.

**--sysroot**=*SYSROOT*

    Offline target sysroot

**--latest**

    Mount the deployment the default boot entry boots

**--esp**=*ESP*

    The mounted EFI System Partition, where systemd-boot keeps its boot entries

**--read-only**

    Mount /etc and /var read-only too. The deployment root is always read-only

<!-- END GENERATED OPTIONS -->

# EXAMPLES

Mount an installation and modify its persistent configuration and state:

```bash
mkdir /mnt/installed
bootc install mount --sysroot /mnt/sysroot --latest /mnt/installed
install -D -m 0644 hostname /mnt/installed/etc/hostname
umount -R /mnt/installed
```

# SEE ALSO

**bootc**(8), **bootc-install**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
