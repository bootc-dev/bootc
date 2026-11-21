# NAME

bootc-root-setup.service

# DESCRIPTION

A oneshot systemd service that runs in the initramfs to set up the root
filesystem when the composefs backend is active.  It is gated on the
`composefs=` or `composefs.digest=` kernel command line argument and on
`ConditionPathExists=/etc/initrd-release`, so it only runs inside an initramfs.

The service is ordered after `sysroot.mount` and before
`initrd-root-fs.target`.  It performs the following steps:

1. Opens the composefs repository at `/sysroot/composefs`.
2. Mounts the EROFS image `images/<digest>` named by the `composefs=<digest>`
   or `composefs.digest=` kernel argument. fs-verity is required unless the
   digest is preceded by `?`, whatever the repository metadata says; see
   **bootc-composefs(7)**. Two arguments that name different images of the
   same EROFS format are refused.
3. Optionally wraps the root in a transient tmpfs overlay
   (see `root.transient` in **bootc-setup-root-conf.toml(5)**).
4. Bind-mounts or overlays `/etc` and `/var` from the per-deployment state
   directory at `/sysroot/state/deploy/<digest>/`.
5. Replaces `/sysroot` with the fully assembled root, ready for switch-root.

# FAILURE

`initrd-root-fs.target` requires this service, so if it fails the target
fails with it and the initramfs never switches root: the boot stops rather
than continue into a `/sysroot` whose composefs image was not mounted or
verified. As with any failed initramfs unit, `emergency.target` is started;
if the emergency shell exits (or cannot start, for example because root is
locked), starting the default target again runs this service again, and the
boot continues only if it then succeeds. With `rd.shell=0` dracut offers no
shell and powers off instead, or does what `rd.emergency=` names (see
**dracut.cmdline(7)**); sealed images will usually want both.

# CONFIGURATION

Behaviour is controlled by an optional TOML file installed into the initramfs:

`/usr/lib/composefs/setup-root-conf.toml`

See **bootc-setup-root-conf.toml(5)** for the full option reference.

# INSTALLATION

The service and its binary (`/usr/lib/bootc/initramfs-setup`) are installed
into the initramfs by the `51bootc` dracut module.  The module also installs
`/usr/lib/composefs/setup-root-conf.toml` when it is present on the host image,
so image authors do not need manual `dracut --include` invocations.

The `51bootc` module is *not* enabled by default (so that e.g. `apt|dnf install bootc`
don't pull it in). It's recommended for base images to enable it via a config file
in e.g. `/usr/lib/dracut/dracut.conf.d`.

# SEE ALSO

**bootc-setup-root-conf.toml(5)**, **bootc(8)**, **dracut.cmdline(7)**

# VERSION

<!-- VERSION PLACEHOLDER -->
