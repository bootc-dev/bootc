% bootc-fetch-apply-updates(5)

# NAME

bootc-fetch-apply-updates.service

# DESCRIPTION

This service causes `bootc` to perform the following steps:

- Check the source registry for an updated container image
- If one is found, download it
- Reboot

This service also comes with a companion `bootc-fetch-apply-updates.timer`
systemd unit.  The current default systemd timer shipped in the upstream
project is enabled for daily updates.

However, it is fully expected that different operating systems
and distributions choose different defaults.

# CUSTOMIZING UPDATES

Note that all three of these steps can be decoupled; they
are:

- `bootc upgrade --check`
- `bootc upgrade`
- `bootc upgrade --apply`

# SEE ALSO

**bootc(1)**

# VERSION

<!-- VERSION PLACEHOLDER -->