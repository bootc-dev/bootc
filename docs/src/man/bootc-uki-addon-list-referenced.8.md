# NAME

bootc-uki-addon-list-referenced - List all referenced UKI Addons across all deployments

# SYNOPSIS

**bootc uki-addon list-referenced** \[*OPTIONS...*\]

# DESCRIPTION

**This command is experimental and subject to change.**

List all UKI addons referenced by EROFS images across all deployments. This
shows which addons each deployment's container image ships, regardless of
whether those addons are currently installed on the ESP.

This is primarily useful for debugging and understanding which addons are
available in each deployed image. Garbage collection uses this information
internally to determine which global addons can be safely removed.

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
**--json**

    Output in JSON format

<!-- END GENERATED OPTIONS -->

# EXAMPLES

List all referenced addons:

    bootc uki-addon list-referenced

Example output:

    Deployment cb82031a...:
      fav-cmdline (global)
      cmdline-extend (scoped (deployment cb82031a...))
    Deployment 1913e6ed...:
      berserk (scoped (deployment 1913e6ed...))

List referenced addons in JSON format:

    bootc uki-addon list-referenced --json

# SEE ALSO

**bootc-uki-addon**(8), **bootc-uki-addon-list**(8), **bootc-uki-addon-add**(8), **bootc-uki-addon-remove**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
