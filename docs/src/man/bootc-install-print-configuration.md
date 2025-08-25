# NAME

bootc-install-print-configuration - Output JSON to stdout that contains
the merged installation configuration as it may be relevant to calling
processes using \`install to-filesystem\` that in particular want to
discover the desired root filesystem type from the container image

# SYNOPSIS

**bootc install print-configuration** \[**-h**\|**\--help**\]

# DESCRIPTION

Output JSON to stdout that contains the merged installation
configuration as it may be relevant to calling processes using \`install
to-filesystem\` that in particular want to discover the desired root
filesystem type from the container image.

At the current time, the only output key is \`root-fs-type\` which is a
string-valued filesystem name suitable for passing to \`mkfs.\$type\`.

# OPTIONS

**-h**, **\--help**

:   Print help (see a summary with \'-h\')

# VERSION

v1.8.0
