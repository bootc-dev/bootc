# NAME

bootc-uki-addon-list - List all installed UKI Addons

# SYNOPSIS

**bootc uki-addon list** \[*OPTIONS...*\]

# DESCRIPTION

**This command is experimental and subject to change.**

List all installed UKI addons on the EFI System Partition, including both
scoped (per-deployment) and global addons.

By default, output is human-readable with one addon per line. Use `--json`
for machine-readable output suitable for scripting.

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
**--json**

    Output in JSON format

<!-- END GENERATED OPTIONS -->

# EXAMPLES

List all installed addons:

    bootc uki-addon list

List addons in JSON format:

    bootc uki-addon list --json

Example JSON output:

```json
[
  {
    "name": "debug",
    "addon_type": { "type": "scoped", "depl_id": "a1b2c3..." }
  },
  {
    "name": "site-config",
    "addon_type": { "type": "global" }
  }
]
```

# SEE ALSO

**bootc-uki-addon**(8), **bootc-uki-addon-add**(8), **bootc-uki-addon-remove**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
