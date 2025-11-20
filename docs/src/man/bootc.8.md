# NAME

bootc - Deploy and transactionally in-place with bootable container
images

# SYNOPSIS

**bootc** \[*OPTIONS...*\] <*SUBCOMMAND*>

# DESCRIPTION

Deploy and transactionally in-place with bootable container images.

The `bootc` project currently uses ostree-containers as a backend to
support a model of bootable container images. Once installed, whether
directly via `bootc install` (executed as part of a container) or via
another mechanism such as an OS installer tool, further updates can be
pulled and `bootc upgrade`.

<!-- BEGIN GENERATED OPTIONS -->
<!-- END GENERATED OPTIONS -->

# SUBCOMMANDS

<!-- BEGIN GENERATED SUBCOMMANDS -->
| Command | Description |
|---------|-------------|
| **bootc upgrade** | Download and queue an updated container image to apply |
| **bootc switch** | Target a new container image reference to boot |
| **bootc rollback** | Change the bootloader entry ordering; the deployment under `rollback` will be queued for the next boot, and the current will become rollback.  If there is a `staged` entry (an unapplied, queued upgrade) then it will be discarded |
| **bootc edit** | Apply full changes to the host specification |
| **bootc status** | Display status |
| **bootc usr-overlay** | Add a transient writable overlayfs on `/usr` |
| **bootc install** | Install the running container to a target |
| **bootc container** | Operations which can be executed as part of a container build |
| **bootc composefs-finalize-staged** |  |

<!-- END GENERATED SUBCOMMANDS -->

# VERSION

<!-- VERSION PLACEHOLDER -->

