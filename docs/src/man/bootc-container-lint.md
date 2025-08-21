# NAME

bootc-container-lint - Perform relatively inexpensive static analysis
checks as part of a container build

# SYNOPSIS

**bootc container lint** \[**\--rootfs**\] \[**\--fatal-warnings**\]
\[**\--list**\] \[**\--skip**\] \[**\--no-truncate**\]
\[**-h**\|**\--help**\]

# DESCRIPTION

Perform relatively inexpensive static analysis checks as part of a
container build.

This is intended to be invoked via e.g. \`RUN bootc container lint\` as
part of a build process; it will error if any problems are detected.

# OPTIONS

**\--rootfs** *\<ROOTFS\>* \[default: /\]

:   Operate on the provided rootfs

**\--fatal-warnings**

:   Make warnings fatal

**\--list**

:   Instead of executing the lints, just print all available lints. At
    the current time, this will output in YAML format because it\'s
    reasonably human friendly. However, there is no commitment to
    maintaining this exact format; do not parse it via code or scripts

**\--skip** *\<SKIP\>*

:   Skip checking the targeted lints, by name. Use \`\--list\` to
    discover the set of available lints.

    Example: \--skip nonempty-boot \--skip baseimage-root

**\--no-truncate**

:   Don\'t truncate the output. By default, only a limited number of
    entries are shown for each lint, followed by a count of remaining
    entries

**-h**, **\--help**

:   Print help (see a summary with \'-h\')

# VERSION

v1.7.0
