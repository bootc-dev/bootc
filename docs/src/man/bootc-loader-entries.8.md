# NAME

bootc-loader-entries - Operations on Boot Loader Specification (BLS) entries

# SYNOPSIS

bootc loader-entries *COMMAND*

# DESCRIPTION

Manage kernel arguments from multiple independent sources by tracking
argument ownership via `x-options-source-<name>` extension keys in BLS
config files.

This solves the problem of kernel argument accumulation on bootc systems
with transient `/etc`, where tools like TuneD lose their state files on
reboot and cannot track which kargs they previously set.

<!-- BEGIN GENERATED OPTIONS -->
<!-- END GENERATED OPTIONS -->

# COMMANDS

**set-options-for-source**
:   Set or update the kernel arguments owned by a specific source.

# SEE ALSO

**bootc**(8), **bootc-loader-entries-set-options-for-source**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
