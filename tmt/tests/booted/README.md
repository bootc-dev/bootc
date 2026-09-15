# Booted tests

These are intended to run via tmt.

## Composefs EROFS V1/V2 regression coverage

The existing `BOOTC_erofs_version` configuration selects the format while the
image is built and is forwarded to tmt by `just test-tmt-nobuild`. It is not
an install flag: installation consumes the UKI already present in the image.
Use the same control for the base and synthetic upgrade images:

```console
export BOOTC_variant=composefs BOOTC_bootloader=systemd
export BOOTC_boot_type=uki BOOTC_seal_state=sealed
BOOTC_erofs_version=v1 just test-tmt readonly image-upgrade-reboot
BOOTC_erofs_version=v2 just test-tmt readonly image-upgrade-reboot
```

`readonly/046-test-erofs-version.nu` checks the booted root identity. Its V1
assertion requires the V2 fallback argument, and explicit V2 requires only the
legacy argument. This is a format regression check, not an old-client bridge
test. `image-upgrade-reboot` builds its derived UKI with the same selected
format and verifies current-client-to-current-client upgrade behavior.

`composefs-1-16-bridge` is opt-in historical-client coverage, restricted to
the bootc 1.16.0 fixture. It requires a read-only shared container store and
the three prebuilt fixture images supplied by the coordinator; it does not
build, copy, or SCP images. Run one case at a time:

```console
cargo xtask run-tmt "$BOOTC_1160_STAGER_IMAGE" composefs-1-16-bridge \
  --composefs-backend --bootloader systemd --boot-type uki --seal-state sealed \
  --context composefs_bridge=true \
  --env BOOTC_composefs_bridge_mode=old-stager \
  --env BOOTC_1160_bootc_sha256="$BOOTC_1160_BOOTC_SHA256" \
  --bridge-image "$BOOTC_CURRENT_DUAL_UKI_IMAGE" \
  --upgrade-image "$BOOTC_CURRENT_DUAL_UKI_UPGRADE_IMAGE"

cargo xtask run-tmt "$BOOTC_CURRENT_STAGER_IMAGE" composefs-1-16-bridge \
  --composefs-backend --bootloader systemd --boot-type uki --seal-state sealed \
  --context composefs_bridge=true \
  --env BOOTC_composefs_bridge_mode=old-initramfs \
  --bridge-image "$BOOTC_1160_INITRAMFS_AUTO_V2_CURRENT_USERSPACE_IMAGE"
```

Required fixture labels are `bootc.test.fixture=bootc-1.16.0-stager`,
`bootc.test.fixture=current-dual-uki`,
`bootc.test.fixture=current-dual-uki-upgrade`, and
`bootc.test.fixture=bootc-1.16.0-initramfs-auto-v2-current-userspace`.
The coordinator supplies the matching pullspecs through the variables above.
For the old-stager case it also supplies the required
`BOOTC_1160_BOOTC_SHA256` value from the pinned fixture build; the test records
the exact `bootc --version`, RPM NEVRA, and `/usr/bin/bootc` checksum before it
stages the bridge image.

The test checks the public status schema, `/proc/cmdline`, repository image
and deployment-state directories, and `/etc` and `/var` sentinels. There is no
stable public inspection API that labels an on-disk EROFS image as V1 or V2
independently of its UKI argument, so it does not infer that from filenames.
It performs rollback and `composefs-gc --assert-no-op` only after booting a
current client; no old 1.16 rollback or GC command is assumed.
