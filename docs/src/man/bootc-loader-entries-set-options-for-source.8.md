# NAME

bootc-loader-entries-set-options-for-source - Set or update the kernel arguments owned by a specific source

# SYNOPSIS

bootc loader-entries set-options-for-source **--source** *NAME* [**--options** *"KARGS"*]

# DESCRIPTION

Set or update the kernel arguments owned by a specific source. Each
source's arguments are tracked via `x-options-source-<name>` extension
keys in BLS config files on `/boot`. The `options` line is recomputed
as the merge of all tracked sources plus any untracked (pre-existing)
options.

This command stages a new deployment with the updated kernel arguments.
Changes take effect on the next reboot.

When a staged deployment already exists (e.g. from `bootc upgrade`),
it is replaced using the staged deployment's commit and origin,
preserving the pending upgrade while layering the kargs change on top.

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
**--source**=*SOURCE*

    The name of the source that owns these kernel arguments

**--options**=*OPTIONS*

    The kernel arguments to set for this source

<!-- END GENERATED OPTIONS -->

# REQUIREMENTS

This command requires ostree >= 2026.1 with `bootconfig-extra` support
for preserving extension BLS keys through staged deployment roundtrips.
On older ostree versions, the command will exit with an error.

# EXAMPLES

Add TuneD kernel arguments:

    bootc loader-entries set-options-for-source --source tuned \
        --options "isolcpus=1-3 nohz_full=1-3"

Update TuneD kernel arguments (replaces previous values):

    bootc loader-entries set-options-for-source --source tuned \
        --options "isolcpus=0-7"

Remove all kernel arguments owned by TuneD:

    bootc loader-entries set-options-for-source --source tuned

Multiple sources can coexist independently:

    bootc loader-entries set-options-for-source --source tuned \
        --options "nohz=full isolcpus=1-3"
    bootc loader-entries set-options-for-source --source dracut \
        --options "rd.driver.pre=vfio-pci"

# KNOWN LIMITATIONS

Source keys set by prior calls in the same boot cycle (before any reboot)
are discovered by reading the staged deployment data file at
`/run/ostree/staged-deployment`. If this file is missing or cannot be
parsed, sources from prior calls may not be discovered, potentially
orphaning their kargs. In practice this should not occur, as the file is
managed by ostree and always present when a staged deployment exists.

# SEE ALSO

**bootc**(8), **bootc-loader-entries**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
