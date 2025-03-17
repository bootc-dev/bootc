# NAME

bootc-upgrade - Download and queue an updated container image to apply

# SYNOPSIS

**bootc upgrade** \[**\--quiet**\] \[**\--check**\] \[**\--apply**\]
\[**-h**\|**\--help**\]

# DESCRIPTION

Download and queue an updated container image to apply.

This does not affect the running system; updates operate in an \"A/B\"
style by default.

A queued update is visible as \`staged\` in \`bootc status\`.

Currently by default, the update will be applied at shutdown time via
\`ostree-finalize-staged.service\`. There is also an explicit \`bootc
upgrade \--apply\` verb which will automatically take action (rebooting)
if the system has changed.

However, in the future this is likely to change such that reboots
outside of a \`bootc upgrade \--apply\` do \*not\* automatically apply
the update in addition.

# OPTIONS

**\--quiet**

:   Dont display progress

**-v**, **\--verbose**

:   Increase logging verbosity

    Use `-vv`, `-vvv` to increase verbosity more.

**\--check**

:   Check if an update is available without applying it.

    This only downloads an updated manifest and image configuration
    (i.e. typically kilobyte-sized metadata) as opposed to the image
    layers.

**\--apply**

:   Restart or reboot into the new target image.

    Currently, this option always reboots. In the future this command
    will detect the case where no kernel changes are queued, and perform
    a userspace-only restart.

**-h**, **\--help**

:   Print help (see a summary with -h)

# VERSION

v1.1.6
