# NAME

bootc-rollback - Change the bootloader entry ordering; the deployment
under \`rollback\` will be queued for the next boot, and the current
will become rollback. If there is a \`staged\` entry (an unapplied,
queued upgrade) then it will be discarded

# SYNOPSIS

**bootc rollback** \[**\--apply**\] \[**-h**\|**\--help**\]

# DESCRIPTION

Change the bootloader entry ordering; the deployment under \`rollback\`
will be queued for the next boot, and the current will become rollback.
If there is a \`staged\` entry (an unapplied, queued upgrade) then it
will be discarded.

Note that absent any additional control logic, if there is an active
agent doing automated upgrades (such as the default
\`bootc-fetch-apply-updates.timer\` and associated \`.service\`) the
change here may be reverted. It\'s recommended to only use this in
concert with an agent that is in active control.

A systemd journal message will be logged with
\`MESSAGE_ID=26f3b1eb24464d12aa5e7b544a6b5468\` in order to detect a
rollback invocation.

# OPTIONS

**\--apply**

:   Restart or reboot into the rollback image.

    Currently, this option always reboots. In the future this command
    will detect the case where no kernel changes are queued, and perform
    a userspace-only restart.

**-h**, **\--help**

:   Print help (see a summary with \'-h\')

# EXTRA

Note on Rollbacks and the \`/etc\` Directory:

When you perform a rollback (e.g., with \`bootc rollback\`), any changes
made to files in the \`/etc\` directory won\'t carry over to the
rolled-back deployment. The \`/etc\` files will revert to their state
from that previous deployment instead.

This is because \`bootc rollback\` just reorders the existing
deployments. It doesn\'t create new deployments. The \`/etc\` merges
happen when new deployments are created.

# VERSION

v1.7.0
