% bootc-install-config(5)

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

The `install` section supports two subfields:

- `block`: An array of supported `to-disk` backends enabled by this base container image;
   if not specified, this will just be `direct`.  The only other supported value is `tpm2-luks`.
   The first value specified will be the default.  To enable both, use `block = ["direct", "tpm2-luks"]`.
- `filesystem`: See below.
- `kargs`: An array of strings; this will be appended to the set of kernel arguments.
- `match_architectures`: An array of strings; this filters the install config.

# filesystem

There is one valid field:

- `root`: An instance of "filesystem-root"; see below

# filesystem-root

There is one valid field:

`type`: This can be any basic Linux filesystem with a `mkfs.$fstype`.  For example, `ext4`, `xfs`, etc.

# Examples

```toml
[install.filesystem.root]
type = "xfs"
[install]
kargs = ["nosmt", "console=tty0"]
```

# SEE ALSO

**bootc(1)**

# VERSION

<!-- VERSION PLACEHOLDER -->
