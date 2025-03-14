# NAME

bootc-rollback - Change the bootloader entry ordering; the deployment
under \`rollback\` will be queued for the next boot, and the current
will become rollback. If there is a \`staged\` entry (an unapplied,
queued upgrade) then it will be discarded

# SYNOPSIS

**bootc rollback** \[**-h**\|**\--help**\]

# DESCRIPTION

Change the bootloader entry ordering; the deployment under \`rollback\`
will be queued for the next boot, and the current will become rollback.
If there is a \`staged\` entry (an unapplied, queued upgrade) then it
will be discarded.

Note that absent any additional control logic, if there is an active
agent doing automated upgrades (such as the default
\`bootc-fetch-apply-updates.timer\` and associated \`.service\`) the
change here may be reverted. Its recommended to only use this in concert
with an agent that is in active control.

A systemd journal message will be logged with
\`MESSAGE_ID=26f3b1eb24464d12aa5e7b544a6b5468\` in order to detect a
rollback invocation.

# OPTIONS

**-h**, **\--help**

:   Print help (see a summary with -h)

# Note on Rollbacks and the /etc Directory

When you perform a rollback (e.g., with bootc rollback), any changes made to files in the `/etc` directory won’t carry over to the rolled-back deployment.
The /etc files will revert to their state from that previous deployment instead.

This is because `bootc rollback` just reorders the existing deployments. It doesn't create new deployments. The /etc merges happen when new deployments are created.

If you want to save a modified /etc file for use after the rollback:
You can copy it to a directory under `/var`, like /var/home/User (for a specific user) or /var/root/ (for the root user).
These directories aren’t affected by the rollback as it is user content.

Going back to the original state from either through a temporary rollback or another `bootc rollback`, the `/etc` directory will restore to its state from that original deployment.

Another option if one is sure the situation you are rolling back for is not the config files i.e content in /etc/ and you want to go to an older deployment you can `bootc switch`
to that older image, this will perform the /etc merge and deploy the previous version of the software.

# VERSION

v1.1.6
