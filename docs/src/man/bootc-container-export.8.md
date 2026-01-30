# NAME

bootc-container-export - Export container filesystem as a tar archive

# SYNOPSIS

bootc container export [OPTIONS] TARGET

# DESCRIPTION

Export container filesystem as a tar archive.

This command exports a container filesystem in a format suitable for
unpacking onto a target system. The output includes proper SELinux
labeling (if available) and can optionally relocate the kernel to /boot
for compatibility with legacy installers like Anaconda's `liveimg` command.

The primary use case is enabling container-built OS images to be installed
via traditional installer mechanisms that don't natively support OCI containers.

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
**TARGET**

    Path to the container filesystem root

    This argument is required.

**--format**=*FORMAT*

    Format for export output

    Possible values:
    - tar

    Default: tar

**-o**, **--output**=*OUTPUT*

    Output file (defaults to stdout)

**--kernel-in-boot**

    Copy kernel and initramfs from /usr/lib/modules to /boot for legacy compatibility. This is useful for installers that expect the kernel in /boot

**--disable-selinux**

    Disable SELinux labeling in the exported archive

<!-- END GENERATED OPTIONS -->

# EXAMPLES

Export a mounted container image to a tar file:

    bootc container export /run/target -o /output/rootfs.tar

Export to stdout and pipe to another command:

    bootc container export /run/target | tar -C /mnt -xf -

Export with kernel relocation for legacy installers:

    bootc container export --kernel-in-boot /run/target -o rootfs.tar

Using podman to mount and export an image:

    podman run --rm \
        --mount=type=image,source=quay.io/fedora/fedora-bootc:42,target=/run/target \
        quay.io/fedora/fedora-bootc:42 \
        bootc container export --kernel-in-boot -o /output/rootfs.tar /run/target

# ANACONDA LIVEIMG INTEGRATION

The tar export can be used with Anaconda's `liveimg` kickstart command to install
bootc-built images on systems without native bootc support in the installer.

## Important Considerations

**This creates a traditional filesystem install, NOT a full bootc system.**
The installed system will:

- Have the filesystem contents from the container image
- Boot with a standard GRUB setup
- NOT have ostree/bootc infrastructure for atomic updates

For full bootc functionality, use `bootc install` or Anaconda's native `bootc`
kickstart command (available in Fedora 43+).

## Required Kickstart Configuration

When using the exported tar with Anaconda's `liveimg`, several kickstart
options are required for a successful installation:

### Bootloader Handling

Anaconda's bootloader installation doesn't work correctly with bootc images.
Use `bootloader --location=none` to skip Anaconda's bootloader setup, then
install the bootloader via bootupd in a %post script:

```
bootloader --location=none

%post --erroronfail
# Install bootloader via bootupd (the bootc way)
BOOT_DISK=$(lsblk -no PKNAME $(findmnt -no SOURCE /) | head -1)
bootupctl backend install --auto --write-uuid --device /dev/$BOOT_DISK /
%end
```

### Installer Boot Options

Add these to the installer kernel command line:

- `inst.nosave=all_ks` - Prevents Anaconda from writing to /root (which may not exist)
- `inst.ks=cdrom:/kickstart.ks` - Path to kickstart on the installation media

## Example Kickstart

Here is a complete example kickstart for installing a bootc image via liveimg.
This assumes the tar file is accessible at a URL (adjust for your environment):

```
# Install from bootc-exported tar
liveimg --url=http://example.com/bootc-export.tar

# Basic configuration  
rootpw --plaintext changeme
keyboard us
timezone UTC

# Skip Anaconda bootloader - use bootupd in %post
bootloader --location=none
zerombr
clearpart --all --initlabel

# UEFI partitioning
part /boot/efi --fstype=efi --size=600
part /boot --fstype=xfs --size=1024
part / --fstype=xfs --grow

reboot

%post --erroronfail
set -euo pipefail

# Install bootloader via bootupd
BOOT_DISK=$(lsblk -no PKNAME $(findmnt -no SOURCE /) | head -1)
if [ -z "$BOOT_DISK" ]; then
    BOOT_DISK="sda"
fi
bootupctl backend install --auto --write-uuid --device /dev/$BOOT_DISK /

# Create BLS entries for installed kernels
mkdir -p /boot/loader/entries
ROOT_UUID=$(findmnt -no UUID /)

if [ ! -f /etc/machine-id ] || [ ! -s /etc/machine-id ]; then
    systemd-machine-id-setup
fi
MACHINE_ID=$(cat /etc/machine-id)

for VMLINUZ in /boot/vmlinuz-*; do
    [ -f "$VMLINUZ" ] || continue
    KVER=$(basename "$VMLINUZ" | sed 's/vmlinuz-//')
    INITRAMFS="/boot/initramfs-${KVER}.img"
    [ -f "$INITRAMFS" ] || continue
    
    cat > "/boot/loader/entries/${MACHINE_ID}-${KVER}.conf" << EOF
title Fedora Linux ($KVER)
version $KVER
linux /vmlinuz-$KVER
initrd /initramfs-${KVER}.img
options root=UUID=$ROOT_UUID ro
EOF
done
%end
```

# SEE ALSO

**bootc**(8), **bootc-container**(8), **bootc-install**(8), **bootupctl**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
