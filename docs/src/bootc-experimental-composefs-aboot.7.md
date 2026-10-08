# Experimental composefs aboot support

This page covers booting the composefs backend with an Android-style A/B boot
image. For the repository layout, fsverity modes, and general composefs
installation model, see [the composefs backend documentation](bootc-composefs.7.md).
Both the aboot integration and its on-disk state format are experimental.

## Boot layouts

There are two supported ways to consume a `/boot/aboot-<kernel-version>.img` artifact:

| Artifact encoding | Bootloader and boot partitions |
| --- | --- |
| Android boot image v2 | `none`; Android `boot_a` and `boot_b`, with no ESP |
| ukiboot image | `ukiboot`; ESP with ukiboot, plus A/B boot images |

The real Android layout deliberately has **no ESP**. For that payload, bootc infers
bootloader `none` and does not install an EFI bootloader; the platform firmware and
`aboot-deploy` manage the A/B boot partitions. Both layouts use the composefs backend
for the root filesystem. They cannot be switched in place to or from the BLS/UKI
layouts managed by GRUB or systemd-boot. Android and ukiboot layouts also cannot
be switched in place.

## Building an image

`bootc container aboot` computes the V1 and V2 composefs digests of the rootfs,
adds both to the kernel command line, and invokes `aboot-update` to create the
artifact. See [EROFS formats](bootc-composefs.7.md#erofs-formats) for why
both digests are included. `/etc/aboot.cfg` controls whether `aboot-update`
emits an Android boot image or a ukiboot image (as well as other details). As
with [building a composefs UKI](building/bootc-sealed-images.7.md#building-sealed-images),
split the kernel and initramfs from the rootfs before generating the boot
artifact, then copy the generated `aboot-<kernel-version>.img` into the final
image's `/boot`.

```sh
bootc container aboot --rootfs /target \
  --kernel-dir /kernel/KVER --out /out
```

The command checks that the generated artifact contains both expected composefs
arguments. It requires `aboot-update` in the build environment; the installed
system needs `aboot-deploy` for updates and rollbacks. If the root filesystem
cannot enforce fsverity, pass `--allow-missing-verity` when building the artifact.
This produces an **unsealed** image, as explained in
[composefs integrity modes](bootc-composefs.7.md#overview).

Bootc automatically selects the native composefs backend, and bootloader `none` from an Android boot
v2 payload and `ukiboot` from a ukiboot payload. An explicit bootloader setting is
optional, but must agree with the payload.
`bootc container inspect --json` reports `"type": "aboot"` for Android payloads
and `"type": "aboot-efi"` for ukiboot payloads; image-builder uses this to
select UEFI boot mode for ukiboot without a bootloader configuration file.

Modern aboot artifacts are discovered only under `/boot`. An `aboot.img` under
`/usr/lib/modules/<kernel-version>` belongs to the legacy OSTree integration and
does not select this backend. A matching `vbmeta-<kernel-version>.img` may accompany
an Android payload. ukiboot payloads do not use vbmeta.

When installing the running container image, `bootc install to-disk` selects the
backend and layout from its boot artifact and reads repart definitions from that
same container. With `--source-imgref`, the source image's root filesystem is not
available during preparation, so no aboot disk layout is inferred. The normally
pulled image must match the selected encoding.
Supplied repart definitions must match the artifact's slot labels and partition
type GUIDs; otherwise bootc creates a default layout. Android uses `boot_a`,
`boot_b`, `vbmeta_a`, and `vbmeta_b`; ukiboot uses `ukiboot_a`, `ukiboot_b`,
`ukibootctl`, and an ESP. Both layouts include a root filesystem and initialize
both boot slots. Platform-specific sizing, device trees, and `/etc/aboot.cfg`
settings remain the image builder's responsibility.

Prebuilt aboot command lines are immutable. Additional installation `--karg`
arguments are rejected; include them when building the artifact.

## Updates, rollback, and recovery

An update stores the new boot image (and optional vbmeta image) under
`/state/deploy/<deployment-id>/aboot/`. A persistent pending record under
`/state/boot/aboot/` tracks those artifacts and their hashes. Staging does not write
either boot partition. At shutdown, bootc verifies the artifacts, records the attempt, and
requires an unambiguous booted slot and calls `aboot-deploy` to flash the inactive slot.

On the next boot, bootc records the observed `androidboot.slot_suffix` kernel commandline
option and reconciles the attempted deployment. The previous slot becomes the rollback
deployment; `bootc rollback` queues it through `aboot-deploy --rollback`.  `bootc status`
indicates when a rollback is queued. A failed boot is **not** automatically retried: bootc
retains the attempted update for inspection and will not stage another update until that
state is resolved.

The firmware's slot-selection and success-marking behavior is outside bootc.  For example,
the ukiboot enables `ukiboot-set-success.service` to mark a successful boot. Validate that
behavior on the target hardware before relying on automatic fallback.
