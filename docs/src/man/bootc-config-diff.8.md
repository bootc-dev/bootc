# NAME

bootc-config-diff - Diff current /etc configuration versus default

# SYNOPSIS

bootc config-diff

# DESCRIPTION

On systems booted with the Composefs backend, show differences between the
current `/etc` and the pristine `/etc` from the booted image. The command
reports paths that were added, modified, or removed; differences can include
file contents and metadata. It does not modify configuration.

The Composefs backend is selected by the booted image. This command is not
supported on systems booted with the OSTree backend.

<!-- BEGIN GENERATED OPTIONS -->
<!-- END GENERATED OPTIONS -->

# EXAMPLES

As root on a Composefs system, create a local-only file and inspect the
differences:

    printf '%s\n' 'local test setting' > /etc/bootc-config-diff-example
    bootc config-diff

The output includes:

    Added "bootc-config-diff-example"

`Added` means the path exists in the current `/etc` but not in the booted
image's pristine `/etc`. The output may also include machine-generated
differences, such as SSH host keys or `machine-id`; not every difference
necessarily represents an administrator change.

For information about `/etc` state and the related OSTree command, see
[Filesystem: `/etc`](../bootc-filesystem.7.md#etc). For backend selection, see
[Installing bootc-compatible images](../bootc-installation.7.md#the-storage-backend)
and [Composefs backend](../bootc-composefs.7.md).

# SEE ALSO

**bootc**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
