
# Varlink IPC interface

This is an experimental feature; tracking issue: <https://github.com/bootc-dev/bootc/issues/522>

bootc exposes a [varlink](https://varlink.org/) interface for programmatic
access. This is intended for building higher-level tooling (such as desktop
update managers or orchestration systems) on top of bootc without parsing
CLI output or relying on the `--progress-fd` pipe protocol.

## Usage via subprocess

bootc serves varlink via [socket activation](https://varlink.org/#activation).
The simplest way to use it is via `varlinkctl exec:`, which spawns bootc
as a subprocess, passes a connected socket on fd 3, and sends a single call:

```bash
varlinkctl call exec:bootc containers.bootc.GetStatus
```

This returns the same JSON structure as `bootc status --json`.

## Introspecting the interface

To see the methods, types, and errors exposed by the running binary:

```bash
varlinkctl introspect exec:bootc containers.bootc
varlinkctl introspect exec:bootc containers.bootc.update
varlinkctl introspect exec:bootc containers.bootc.install
```

## Interfaces

### `containers.bootc`

Read-only queries about the host.

| Method | Description |
|--------|-------------|
| `GetStatus` | Returns the full host status (same schema as `bootc status --json`). |
| `GetStatusForSysroot(sysroot_path)` | Query the status of a sysroot at an arbitrary path (e.g. after install). |

Example -- querying the running host:

```bash
$ varlinkctl call exec:bootc containers.bootc.GetStatus
{
  "status": {
    "apiVersion": "org.containers.bootc/v1",
    "kind": "BootcHost",
    "metadata": { "name": "host" },
    "spec": { ... },
    "status": { "staged": ..., "booted": ..., "rollback": ... }
  }
}
```

Example -- querying a freshly installed sysroot:

```bash
$ varlinkctl call exec:bootc containers.bootc.GetStatusForSysroot \
    '{"sysroot_path": "/mnt/installed-root"}'
```

This returns the same `Host` schema, with `booted` and `staged` set
to `null` and all deployments listed in `otherDeployments`.  This is
intended for install API consumers (Anaconda, osbuild, custom tooling)
that need to discover deployment paths, image digests, stateroot names,
etc. immediately after installation without rebooting.

### `containers.bootc.update`

Mutating operations with streaming progress.

| Method | Description |
|--------|-------------|
| `Upgrade` | Upgrade to the latest version of the current image. |
| `Switch(target)` | Switch to a different container image. |

These methods are designed to use varlink's `more`/`continues` streaming
for progress notifications (see below). They currently require a booted
host system and will return a `NotBooted` error when run inside a
container.

### `containers.bootc.install`

Installation operations. These are the varlink equivalents of the
`bootc install` subcommands.

| Method | Description |
|--------|-------------|
| `GetConfiguration` | Returns the merged install configuration (same as `bootc install print-configuration --all`). |
| `ToDisk(opts)` | Install to a block device or loopback file (`bootc install to-disk`). |
| `ToFilesystem(opts)` | Install to a pre-mounted filesystem (`bootc install to-filesystem`). |
| `ToExistingRoot(opts)` | Install alongside an existing root (`bootc install to-existing-root`). |

Example -- querying the install configuration:

```bash
$ varlinkctl call exec:bootc containers.bootc.install.GetConfiguration
{
  "config": {
    "root-fs-type": null,
    "filesystem": null,
    "kargs": null,
    ...
  }
}
```

The install methods accept a structured `opts` object. Use
`varlinkctl introspect exec:bootc containers.bootc.install` to see the
full schema. For example, `ToDisk` accepts:

```json
{
  "opts": {
    "device": "/dev/vda",
    "viaLoopback": false,
    "genericImage": true,
    "disableSelinux": false,
    "composefsBackend": false,
    "kargs": ["console=ttyS0,115200n8"]
  }
}
```

These operations are destructive and require appropriate privileges
(typically running inside a privileged container with device access).

## Progress via varlink streaming

The `Upgrade`, `Switch`, and install methods support varlink's native
streaming protocol, which subsumes the
[`--progress-fd`](experimental-progress-fd.md) pipe-based API.

When a client sends `{"more": true}` with a call, the server replies
multiple times:

- **Intermediate replies** (`"continues": true`) carry a `progress` field
  with byte-level or step-level progress events.
- **The final reply** (no `continues`) carries a `result` field with the
  operation outcome.

This maps to the same three deployment stages as `--progress-fd` (pulling,
importing, staging) but uses varlink's built-in framing instead of JSON
Lines over a raw pipe.

### Progress event types

**`ProgressBytes`** -- byte-level transfer progress (e.g. pulling layers):

```json
{
  "progress": {
    "type": "bytes",
    "task": "pulling",
    "description": "Pulling image",
    "id": "quay.io/centos-bootc/centos-bootc:stream10",
    "bytesCached": 0,
    "bytes": 104857600,
    "bytesTotal": 524288000,
    "stepsCached": 0,
    "steps": 3,
    "stepsTotal": 7,
    "subtasks": [
      {
        "subtask": "ostree_derived",
        "description": "Derived Layer:",
        "id": "sha256:abc123...",
        "bytesCached": 0,
        "bytes": 52428800,
        "bytesTotal": 104857600
      }
    ]
  }
}
```

**`ProgressSteps`** -- discrete operation phases (e.g. staging):

```json
{
  "progress": {
    "type": "steps",
    "task": "staging",
    "description": "Staging deployment",
    "id": "staging",
    "stepsCached": 0,
    "steps": 1,
    "stepsTotal": 4,
    "subtasks": [
      {
        "subtask": "deploying",
        "description": "Deploying",
        "id": "deploying",
        "completed": false
      }
    ]
  }
}
```

### Final result

```json
{
  "result": {
    "staged": true,
    "noChange": false,
    "message": "Queued for next boot: quay.io/centos-bootc/centos-bootc:stream10"
  }
}
```

## Programmatic use from Rust

The [zlink](https://docs.rs/zlink) crate provides typed proxy traits.
A client can connect via a Unix socketpair (the same pattern used by
`varlinkctl exec:`):

```rust,ignore
use zlink::unix;

// Connect to a running bootc varlink service
let mut conn = unix::connect("/run/bootc.varlink").await?;

// Or spawn bootc with socket activation (socketpair on fd 3)
// and use the connection directly -- see the integration tests
// for the full pattern.
```

## Relationship with `--progress-fd`

The varlink streaming progress is intended to eventually replace the
`--progress-fd` API. The progress event structure is intentionally
similar, but varlink provides several advantages:

- **Framing**: varlink handles message framing (NUL-delimited JSON)
  instead of requiring newline-delimited JSON Lines.
- **Bidirectional**: clients can cancel or query state mid-operation.
- **Typed**: the interface is self-describing via `varlinkctl introspect`.
- **Composable**: the same socket carries both the request and all
  progress replies, rather than needing a separate file descriptor.

Both APIs will coexist during the experimental period.
