# NAME

bootc-status - Display status

# SYNOPSIS

**bootc status** \[*OPTIONS...*\]

# DESCRIPTION

Display status.

If standard output is a terminal, this will output a description of the bootc system state.
If standard output is not a terminal, output a YAML-formatted object using a schema
intended to match a Kubernetes resource that describes the state of the booted system.

## Parsing output via programs

Either the default YAML format or `--format=json` can be used. Do not attempt to
explicitly parse the output of `--format=humanreadable` as it will very likely
change over time.

## Programmatically detecting whether the system is deployed via bootc

Invoke e.g. `bootc status --json`, and check if `status.booted` is not `null`.

### Detecting rpm-ostree vs bootc

There is no "bootc runtime". When used with the default ostree backend, bootc
and tools like rpm-ostree end up sharing the same code and doing effectively the same thing.
Hence, there isn't a mechanism to detect if a system "is bootc" or "is rpm-ostree".

However, if the `incompatible` flag is set on a deployment, then there are layered packages and
`rpm-ostree` must be used for mutation.

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
**--format**=*FORMAT*

    The output format

    Possible values:
    - humanreadable
    - yaml
    - json

**--format-version**=*FORMAT_VERSION*

    The desired format version. There is currently one supported version, which is exposed as both `0` and `1`. Pass this option to explicitly request it; it is possible that another future version 2 or newer will be supported in the future

**--booted**

    Only display status for the booted deployment

**-v**, **--verbose**

    Include additional fields in human readable format

<!-- END GENERATED OPTIONS -->

# EXAMPLES

Show current system status:

    bootc status

Show status in JSON format:

    bootc status --format=json

Show detailed status with verbose output:

    bootc status --verbose

Show only booted deployment status:

    bootc status --booted

# SEE ALSO

**bootc**(8), **bootc-upgrade**(8), **bootc-switch**(8), **bootc-rollback**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
