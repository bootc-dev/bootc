# NAME

bootc-container-lint - Perform relatively inexpensive static analysis
checks as part of a container build

# SYNOPSIS

**bootc container lint** \[**\--rootfs**\] \[**\--fatal-warnings**\]
\[**\--list**\] \[**\--skip**\] \[**-h**\|**\--help**\]

# DESCRIPTION

Perform relatively inexpensive static analysis checks as part of a
container build.

This is intended to be invoked via e.g. \`RUN bootc container lint\` as
part of a build process; it will error if any problems are detected.

# OPTIONS

**\--rootfs**=*ROOTFS* \[default: /\]

:   Operate on the provided rootfs

**-v**, **\--verbose**

:   Increase logging verbosity

    Use `-vv`, `-vvv` to increase verbosity more.

**\--fatal-warnings**

:   Make warnings fatal

**\--list**

:   Instead of executing the lints, just print all available lints. At
    the current time, this will output in YAML format because its
    reasonably human friendly. However, there is no commitment to
    maintaining this exact format; do not parse it via code or scripts

**\--skip**=*SKIP*

:   Skip checking the targeted lints, by name. Use \`\--list\` to
    discover the set of available lints.

    Example: \--skip nonempty-boot \--skip baseimage-root

**-h**, **\--help**

:   Print help (see a summary with -h)

# VERSION

v1.1.6
