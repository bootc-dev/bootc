# Packaging and Integration

This document describes how to build and package bootc for distribution in operating systems.

### Build Requirements

- Rust toolchain (see `rust-toolchain.toml` for the version)
- `coreutils` and `make`

### Basic Build Commands

The primary build targets are:

```bash
make all
```

This builds:
- Binary artifacts (`cargo build --release`)
- Man pages (via `cargo xtask manpages`)

The built binaries are placed in `target/release/`:
- `bootc` - The main bootc CLI
- `system-reinstall-bootc` - System reinstallation tool
- `bootc-initramfs-setup` - Initramfs setup utility

### Installation

The `install` target supports the standard `DESTDIR` variable for staged installations, which is essential for packaging:

```bash
make install DESTDIR=/path/to/staging/root
```


The install target handles:
- Binary installation to `$(prefix)/bin`
- Man pages to `$(prefix)/share/man/man{5,8}`
- systemd units to `$(prefix)/lib/systemd/system`
- Documentation and examples to `$(prefix)/share/doc/bootc`
- Dracut module to `/usr/lib/dracut/modules.d/51bootc`
- Base image configuration files

### Optional Installation Targets

#### install-ostree-hooks

For distributions that need bootc to provide compatibility with `ostree container` commands:

```bash
make install-ostree-hooks DESTDIR=/tmp/stage
```

This creates symbolic links in `$(prefix)/libexec/libostree/ext/` for:
- `ostree-container`
- `ostree-ima-sign`
- `ostree-provisional-repair`

## Source Packaging

### Vendored Dependencies

bootc is written in Rust and has numerous dependencies. For distribution packaging, we recommend using a vendored tarball of Rust crates to ensure reproducible builds and avoid network access during the build process.

#### Generating the Vendor Tarball

Use the `cargo xtask package` command to generate both source and vendor tarballs:

```bash
cargo xtask package
```

This creates two files in the `target/` directory:
- `bootc-<version>.tar.zstd` - Source tarball with git archive contents
- `bootc-<version>-vendor.tar.zstd` - Vendored Rust dependencies

The source tarball includes a `.cargo/vendor-config.toml` file that configures cargo to use the vendored dependencies.

#### Using Vendored Dependencies in Builds

When building with vendored dependencies:

1. Extract both tarballs into your build directory
2. Extract the vendor tarball to create a `vendor/` directory
3. Ensure `.cargo/vendor-config.toml` is in place (included in source tarball)
4. Build normally with `make all`

The cargo build will automatically use the vendored crates instead of fetching from crates.io.

### Version Management

The version is derived from git tags. The `cargo xtask package` command automatically determines the version:
- If the current commit has a tag: uses the tag (e.g., `v1.0.0` becomes `1.0.0`)
- Otherwise: generates a timestamp-based version with commit hash (e.g., `202501181430.g1234567890`)

This ensures that development snapshots have monotonically increasing version numbers.

## Cargo Features

The build respects the `CARGO_FEATURES` environment variable. By default, the Makefile auto-detects whether to enable the `rhsm` (Red Hat Subscription Manager) feature based on the build environment's `/usr/lib/os-release`.

To explicitly control features:

```bash
make all CARGO_FEATURES="rhsm"
```

The `selinux` feature is enabled by default and links against libselinux.
Distributions that do not use SELinux can build without the default
features and add back the others they want (`pre-6.15` is only needed to
boot composefs systems on kernels older than 6.15):

```bash
make bin CARGO_OPTIONS='--no-default-features --features "install-to-disk pre-6.15"'
```

Such a build treats SELinux as disabled on the host, whatever the kernel
says: it never reads selinuxfs, doesn't try to enter the `install_t` domain
and doesn't parse SELinux contexts, so it is not suitable for hosts that run
SELinux. Note that libostree may still link libselinux itself, depending on
how it was built, and that the unit test targets (`make install-unit-tests`)
always use the default features.

## Integration Testing

For distributions that want to include integration tests, use:

```bash
make install-all DESTDIR=/tmp/stage
```

This installs:
- Everything from `make install`
- Everything from `make install-ostree-hooks`
- The integration test binary as `bootc-integration-tests`

## Base image content

Alongside building the binary here, you may also want to prepare
a base image. For that, see [bootc-images](bootc-images.md).

## Additional Resources

- See `Makefile` for all available targets and variables
- See `crates/xtask/src/xtask.rs` for cargo xtask implementation details
- See `contrib/packaging/bootc.spec` for an example RPM spec file that
  uses all of the above.

