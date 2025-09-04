# NAME

bootc-config - Configuration file format for bootc

# SYNOPSIS

**/etc/bootc/config.toml**

# DESCRIPTION

The bootc configuration file uses TOML format to specify various
settings for bootc operation.

# FILE FORMAT

The configuration file is in TOML format with the following sections:

## [core]

Core configuration options.

**auto_updates** = *boolean*
    Enable or disable automatic updates. Default: false

**update_interval** = *string*
    Update check interval (e.g., "daily", "weekly"). Default: "weekly"

## [storage]

Storage-related configuration.

**root** = *path*
    Root storage path. Default: "/sysroot/ostree"

# EXAMPLES

A basic configuration file:

    [core]
    auto_updates = true
    update_interval = "daily"
    
    [storage]
    root = "/var/lib/bootc"

# FILES

**/etc/bootc/config.toml**
    System-wide configuration file

# SEE ALSO

**bootc**(8), **toml**(5)

# VERSION

<!-- VERSION PLACEHOLDER -->