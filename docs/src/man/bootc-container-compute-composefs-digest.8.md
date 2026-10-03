# NAME

bootc-container-compute-composefs-digest - Output the bootable composefs
digest for a directory

# SYNOPSIS

bootc container compute-composefs-digest [OPTIONS] [PATH]

# DESCRIPTION

Output the bootable composefs digest for a directory

This is the digest that `bootc container ukify` embeds in the kernel
command line of a UKI. It is a 128-character SHA-512 hex string that
identifies the filesystem contents. Most image builds should use
**bootc-container-ukify**(8), which computes it internally; this command is
useful for scripting and debugging outside of that flow.

The digest depends on the EROFS format; see `--erofs-version`. It must be
run against a separate mount of the root filesystem, not the running root.

# OPTIONS

<!-- BEGIN GENERATED OPTIONS -->
**PATH**

    Path to the filesystem root

**--write-dumpfile-to**=*WRITE_DUMPFILE_TO*

    Additionally generate a dumpfile for the preferred digest, written to the target path

**--erofs-version**=*EROFS_VERSION*

    EROFS format version to use when computing the composefs digest

    Possible values:
    - v1
    - v2

    Default: v1

<!-- END GENERATED OPTIONS -->

# EXAMPLES

Compute the digest of a root filesystem mounted at `/target`:

    bootc container compute-composefs-digest /target

Also write a composefs dumpfile, to compare against another build:

    bootc container compute-composefs-digest --write-dumpfile-to /tmp/rootfs.dump /target

# SEE ALSO

**bootc**(8), **bootc-container-ukify**(8)

# VERSION

<!-- VERSION PLACEHOLDER -->
