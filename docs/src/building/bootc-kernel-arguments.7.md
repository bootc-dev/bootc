# Kernel arguments

The default bootc model uses ["type 1" bootloader config](https://uapi-group.org/specifications/specs/boot_loader_specification/)
files stored in `/boot/loader/entries`, which define arguments
provided to the Linux kernel. 

The set of kernel
arguments can be machine-specific state, but can also
be managed via container updates.

The bootloader entries are currently written by the OSTree backend.

More on Linux kernel arguments: <https://docs.kernel.org/admin-guide/kernel-parameters.html>

## /usr/lib/bootc/kargs.d

Many bootc use cases will use generic "OS/distribution" kernels.
In order to support injecting kernel arguments, bootc supports
a small custom config file format in `/usr/lib/bootc/kargs.d` in
TOML format, that have the following form:

```
# /usr/lib/bootc/kargs.d/10-example.toml
kargs = ["mitigations=auto,nosmt"]
```

There is also support for making these kernel arguments
architecture specific via the `match-architectures` key:

```
# /usr/lib/bootc/kargs.d/00-console.toml
kargs = ["console=ttyS0,115200n8"]
match-architectures = ["x86_64"]
```

NOTE: The architecture matching here accepts values defined
by the [Rust standard library](https://doc.rust-lang.org/std/env/consts/constant.ARCH.html)
(using the architecture of the `bootc` binary itself).

In some cases for Linux, this matches the value of `uname -m`, but
definitely not all. For example, on Fedora derivatives there is `ppc64le`,
but in Rust only `powerpc64`. A common discrepancy is that
Debian derivatives use `amd64`, whereas Rust (and Fedora derivatives)
use `x86_64`.

### Changing kernel arguments post-install via kargs.d

Changes to `kargs.d` files included in a container build
are honored post-install; the difference between the set of
kernel arguments is applied to the current bootloader
configuration. This will preserve any machine-local
kernel arguments.

## Kernel arguments injected at installation time

The `bootc install` flow supports a `--karg` to provide
install-time kernel arguments. These become machine-local
state. 

Higher level install tools (ideally at least using `bootc install to-filesystem`
can inject kernel arguments this way) too; for example,
the [Anaconda installer](https://github.com/rhinstaller/anaconda)
has a `bootloader` verb which ultimately uses an API
similar to this.

Post-install, it is supported for any tool to edit
the `/boot/loader/entries` files, which are in a standardized
format. 

Typically, `/boot` is mounted read-only to limit
the set of tools which write to this filesystem. It is not
"physically" read-only by default. One approach to edit
them is to run a tool under a new mount namespace, e.g.

```bash
unshare -m
mount -o remount,rw /boot
# tool to edit /boot/loader/entries
```

At the current time, `bootc` does not itself offer
an API to manipulate kernel arguments maintained per-machine.

Other projects such as `rpm-ostree` do, via e.g. `rpm-ostree kargs`,
which is just a frontend for editing the bootloader configuration
files. Note an important detail is that `rpm-ostree kargs` always
creates a new deployment.

`rpm-ostree kargs` and bootc will interoperate as they both
use the ostree backend today, and any kernel arguments changed
via that mechanism will persist across upgrades.

It is currently undefined behavior to remove kernel arguments
locally that are included in the base image via
`/usr/lib/bootc/kargs.d`.

## Injecting default arguments into custom kernels

The Linux kernel supports building in arguments into the kernel
binary, at the time of this writing via the `config CMDLINE`
build option. If you are building a custom kernel, then
it often makes sense to use this instead of `/usr/lib/bootc/kargs.d`
for example.
