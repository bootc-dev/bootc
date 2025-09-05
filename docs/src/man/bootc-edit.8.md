# NAME

bootc-edit - Apply full changes to the host specification

# SYNOPSIS

**bootc edit** [*OPTIONS*]

# DESCRIPTION

Apply full changes to the host specification.

This command operates very similarly to `kubectl apply`; if invoked
interactively, then the current host specification will be presented in
the system default `\$EDITOR` for interactive changes.

It is also possible to directly provide new contents via `bootc edit
\--filename`.

Only changes to the `spec` section are honored.

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
<!-- END GENERATED OPTIONS -->

# VERSION

<!-- VERSION PLACEHOLDER -->

