# Integration tests crate

This crate holds integration tests (as distinct from the regular
Rust unit tests run as part of `cargo test`).

## Building and running

`cargo run -p tests-integration`
will work.  Note that at the current time all test suites target
an externally built bootc-compatible container image.  See
how things are set up in e.g. Github Actions, where we first
run a `podman build` with the bootc git sources.

## Available suites

### `booted composefs-verity`

Run as root on a test host with composefs support:

```sh
bootc-integration-tests booted composefs-verity
```

This also runs through the `composefs-verity` TMT plan. It creates disposable
repositories in `/var/tmp` and mounts them in a private mount namespace. It
checks strict image verification, compatibility with unprotected repository
metadata, rejection of substituted image refs, and `EIO` when reading tampered
data objects. An explicitly relaxed mount is tested separately. The test skips
filesystems without fs-verity support; it does not modify the host's repository
or boot files.

### `composefs-bcvk`

Intended only right now to be used with a sealed UKI image,
and sanity checks the composefs backend.

### `host-privileged`

This suite will run the target container image in a way that expects
full privileges, but is *not* destructive.

### `install-alongside`

This suite is *DESTRUCTIVE*, executing the bootc `install to-existing-root`
style flow using the host root.  Run it in a transient virtual machine.

### `system-reinstall`

This suite is *DESTRUCTIVE*, executing the `system-reinstall-bootc`
tests.  Run it in a transient virtual machine.
