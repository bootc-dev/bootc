# NAME

system-reinstall-bootc - Reinstall the current system with a bootc image

# SYNOPSIS

**system-reinstall-bootc** <*BOOTC_IMAGE*>

# DESCRIPTION

**system-reinstall-bootc** is a utility that allows you to reinstall your current system using a bootc container image. This tool provides an interactive way to replace your existing system with a new bootc-based system while preserving SSH access and making the previous root filesystem (including user data) available in `/sysroot`.

The utility will:
- Pull the specified bootc container image
- Collect SSH keys for root access after reinstall
- Execute a bootc install to replace the current system
- Reboot into the new system

After reboot, the previous root filesystem will be available in `/sysroot`, and some automatic cleanup of the previous root will be performed. Note that existing mounts will not be automatically mounted by the bootc system unless they are defined in the bootc image.

This is primarily intended as a way to "take over" cloud virtual machine images, effectively using them as an installer environment.

# ARGUMENTS

**BOOTC_IMAGE**

    The bootc container image to install (e.g., quay.io/fedora/fedora-bootc:41)

    This argument is required.

# EXAMPLES

Reinstall with a custom bootc image:
```
system-reinstall-bootc registry.example.com/my-bootc:latest
```

# ENVIRONMENT

**BOOTC_REINSTALL_CONFIG**

    This variable is deprecated.

# SEE ALSO

**bootc**(8), **bootc-install**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
