# Security and threat model

This page describes bootc's trust boundaries and how to configure
stronger guarantees than the defaults. If you believe you've found a
valid vulnerability, see [SECURITY.md](https://github.com/bootc-dev/bootc/blob/main/SECURITY.md)
for how to report it.

## Privileges

bootc is a binary that is intended to be run with full privileges.
It does not expose a service (socket, HTTP endpoint) by default;
that's the role of higher level tooling.

All inputs (CLI arguments, etc) are hence considered fully trusted
by default.

## Container image verification

bootc honors the default `/etc/containers/policy.json` when fetching
images. The upstream default at the time of this writing
does not require signatures for generic images.

It is not a vulnerability in bootc that signatures are not required
by default.

It is however a very good idea for bootc users to enable signatures
for their images.

## On-disk integrity vs. pull-time verification

The default backend is ostree (with a composefs mount), but
fsverity is not enabled by default.

The composefs backend enables fsverity by default if available,
but does not verify the composefs image (because there's nothing
to verify it against by default).

The composefs backend with sealed UKIs does verify the composefs
mount. With composefs + sealed UKIs, it is a vulnerability if
e.g. an attacker can mutate a file in the image store, have
that persist across a re-mount without it resulting in an `EIO`
error (default for Linux kernel fsverity).
