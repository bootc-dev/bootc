# Upgrade/rollback failure detection in bootc

This document describes how to detect when a reboot failed to enable the staged image in bootc.

## Overview

bootc uses different mechanisms to detect boot failures depending on the backend (OSTree vs. composefs+UKI) and the specific point of failure. Understanding these mechanisms is crucial for system administrators and automated tooling that needs to detect failed updates.

## OSTree Backend Boot Failure Detection

For systems using the traditional OSTree backend, bootc relies on OSTree's built-in boot failure detection mechanisms.

### Key Services

1. **`ostree-finalize-staged.service`** - Runs during shutdown to finalize staged deployments
2. **`ostree-boot-complete.service`** - Runs early in boot to detect finalization failures

When `ostree-finalize-staged.service` fails during shutdown/reboot, this will create
a stamp file in `/boot`, and then on a subsequent reboot the `ostree-boot-complete.service`
service will detect it, and then itself exit with a failure mode.

You can monitor the success of both services, though for `ostree-finalize-staged.service`
note that the failure occurred during the previous boot's shutdown.


## Composefs Backend Boot Failure Detection

### Key Services

There is a `bootc-finalize-staged.service` which is similar to `ostree-finalize-staged.service`,
but there is not currently a similar `-boot-complete.service`. There is also a `bootc-root-setup.service`
that runs during initramfs to mount the composefs image and set up `/etc` and `/var` - but if this
service fails, the system will not boot at all (emergency mode or hang).

At the current time then, it is recommended to check the journal for failures from the previous boot:

```bash
# Check for finalization failures from previous boot
journalctl -u bootc-finalize-staged.service -b -1
```

### Systemd Boot Assessment Integration

As of a recent OSTree with [this commit](https://github.com/ostreedev/ostree/commit/08487091256b93493f8d692e37ab3d892c758da1)
it is possible to configure the boot loader entry counting.

At the current time, the composefs backend does not configure boot entry counting, this is likely to be added in the future.

## See Also

- [systemd Automatic Boot Assessment](https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT/)
- [OSTree Manual](https://ostreedev.github.io/ostree/)
- [bootc-rollback(8)](man/bootc-rollback.8.md)
- [bootc-status(8)](man/bootc-status.8.md)
