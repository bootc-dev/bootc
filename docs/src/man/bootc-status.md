# NAME

bootc-status - Display status

# SYNOPSIS

**bootc status** \[**\--format**\] \[**\--format-version**\]
\[**\--booted**\] \[**-v**\|**\--verbose**\] \[**-h**\|**\--help**\]

# DESCRIPTION

Display status

If standard output is a terminal, this will output a description of the
bootc system state. If standard output is not a terminal, output a
YAML-formatted object using a schema intended to match a Kubernetes
resource that describes the state of the booted system.

\## Parsing output via programs

Either the default YAML format or \`\--format=json\` can be used. Do not
attempt to explicitly parse the output of \`\--format=humanreadable\` as
it will very likely change over time.

\## Programmatically detecting whether the system is deployed via bootc

Invoke e.g. \`bootc status \--json\`, and check if \`status.booted\` is
not \`null\`.

# OPTIONS

**\--format**=*FORMAT*

:   The output format\

    \
    *Possible values:*

    -   humanreadable: Output in Human Readable format

    -   yaml: Output in YAML format

    -   json: Output in JSON format

**\--format-version**=*FORMAT_VERSION*

:   The desired format version. There is currently one supported
    version, which is exposed as both \`0\` and \`1\`. Pass this option
    to explicitly request it; it is possible that another future version
    2 or newer will be supported in the future

**\--booted**

:   Only display status for the booted deployment

**-v**, **\--verbose**

:   Include additional fields in human readable format

**-h**, **\--help**

:   Print help (see a summary with \'-h\')

# VERSION

v1.4.0
