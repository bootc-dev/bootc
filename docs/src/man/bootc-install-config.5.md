# NAME

bootc-install-config.toml

# DESCRIPTION

The `bootc install` process supports some basic customization.  This configuration file
is in TOML format, and will be discovered by the installation process in via "drop-in"
files in `/usr/lib/bootc/install` that are processed in alphanumerical order.

The individual files are merged into a single final installation config, so it is
supported for e.g. a container base image to provide a default root filesystem type,
that can be overridden in a derived container image.

# install

This is the only defined toplevel table.

The `install` section supports these subfields:

- `block`: An array of supported `to-disk` backends enabled by this base container image;
   if not specified, this will just be `direct`.  The only other supported value is `tpm2-luks`.
   The first value specified will be the default.  To enable both, use `block = ["direct", "tpm2-luks"]`.
- `filesystem`: See below.
- `kargs`: An array of strings; this will be appended to the set of kernel arguments.
- `match_architectures`: An array of strings; this filters the install config.
- `ostree`: See below.
- `stateroot`: The stateroot name to use. Defaults to `default`.
- `root-mount-spec`: A string specifying the root filesystem mount specification.
   For example, `UUID=2e9f4241-229b-4202-8429-62d2302382e1` or `LABEL=rootfs`.
   If not provided, the UUID of the target filesystem will be used.
   An empty string signals to omit boot mount kargs entirely.
- `boot-mount-spec`: A string specifying the /boot filesystem mount specification.
   If not provided and /boot is a separate mount, its UUID will be used.
   An empty string signals to omit boot mount kargs entirely.

# filesystem

There is one valid field:

- `root`: An instance of "filesystem-root"; see below

# filesystem-root

There is one valid field:

`type`: This can be any basic Linux filesystem with a `mkfs.$fstype`.  For example, `ext4`, `xfs`, etc.

# ostree

Configuration options for the ostree repository. There is one valid field:

- `bls-append-except-default`: A string of kernel arguments that will be appended to
  Boot Loader Spec entries, except for the default entry. This is useful for configuring
  arguments that should only apply to non-default deployments.

# Examples

```toml
[install.filesystem.root]
type = "xfs"

[install]
kargs = ["nosmt", "console=tty0"]
stateroot = "myos"
root-mount-spec = "LABEL=rootfs"
boot-mount-spec = "UUID=abcd-1234"

[install.ostree]
bls-append-except-default = 'grub_users=""'
```

# SEE ALSO

**bootc(1)**

# VERSION

<!-- VERSION PLACEHOLDER -->
