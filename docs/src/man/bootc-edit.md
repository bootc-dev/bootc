# NAME

bootc-edit - Apply full changes to the host specification

# SYNOPSIS

**bootc edit** \[**-f**\|**\--filename**\] \[**\--quiet**\]
\[**-h**\|**\--help**\]

# DESCRIPTION

Apply full changes to the host specification.

This command operates very similarly to \`kubectl apply\`; if invoked
interactively, then the current host specification will be presented in
the system default \`\$EDITOR\` for interactive changes.

It is also possible to directly provide new contents via \`bootc edit
\--filename\`.

Only changes to the \`spec\` section are honored.

# OPTIONS

**-f**, **\--filename** *\<FILENAME\>*

:   Use filename to edit system specification

**\--quiet**

:   Don\'t display progress

**-h**, **\--help**

:   Print help (see a summary with \'-h\')

# VERSION

v1.7.0
