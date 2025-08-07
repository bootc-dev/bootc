# NAME

bootc-install-ensure-completion - Intended for use in environments that
are performing an ostree-based installation, not bootc

# SYNOPSIS

**bootc install ensure-completion** \[**-h**\|**\--help**\]

# DESCRIPTION

Intended for use in environments that are performing an ostree-based
installation, not bootc.

In this scenario the installation may be missing bootc specific features
such as kernel arguments, logically bound images and more. This command
can be used to attempt to reconcile. At the current time, the only
tested environment is Anaconda using \`ostreecontainer\` and it is
recommended to avoid usage outside of that environment. Instead, ensure
your code is using \`bootc install to-filesystem\` from the start.

# OPTIONS

**-h**, **\--help**

:   Print help (see a summary with \'-h\')

# VERSION

v1.6.0
