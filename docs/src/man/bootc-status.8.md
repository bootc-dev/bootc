# NAME

bootc-status - Display status

# SYNOPSIS

**bootc status** [*OPTIONS*]

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

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
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
