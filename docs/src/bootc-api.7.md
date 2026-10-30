# Using bootc via API

At the current time, bootc is primarily intended to be
driven via a fork/exec model. The core CLI verbs
are stable and will not change.

## Using `bootc edit` and `bootc status --json`

While bootc does not depend on Kubernetes, it does currently
also offer a Kubernetes *style* API, especially oriented
towards the [spec and status and other conventions](https://kubernetes.io/docs/reference/using-api/api-concepts/).

In general, most use cases of driving bootc via API are probably
most easily done by forking off `bootc upgrade` when desired,
and viewing `bootc status --json --format-version=1`.

## JSON Schema

The current API `org.containers.bootc/v1` is stable.
In order to support the future introduction of a v2
or newer format, please change your code now to explicitly
request `--format-version=1` as referenced above. (Available
since bootc 0.1.15, `--format-version=0` in bootc 0.1.14).

There is a [JSON schema](https://json-schema.org/) generated from
the Rust source code available here: [host-v1.schema.json](host-v1.schema.json).

A common way to use this is to run a code generator such as
[go-jsonschema](https://github.com/omissis/go-jsonschema) on the
input schema.
