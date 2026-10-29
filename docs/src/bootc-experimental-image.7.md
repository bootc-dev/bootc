# bootc image

Experimental features are subject to change or removal. Please
do provide feedback on them.

Tracking issue: <https://github.com/bootc-dev/bootc/issues/690>

## Using `bootc image copy-to-storage`

This experimental command is intended to aid in [booting local builds](bootc-local-builds.7.md).

Invoking this command will default to copying the booted container image into the `containers-storage:`
area as used by e.g. `podman`, under the image tag `localhost/bootc` by default. It can
then be managed independently; used as a base image, pushed to a registry, etc.

Run `bootc image copy-to-storage --help` for more options.

## Mounting deployment image content

`bootc image mount` exposes a path from the locally available booted or staged
deployment image at an existing empty directory. The source must be a directory;
`--source /` selects the image root. It refuses target paths with symlink
components and targets that are already mountpoints. It does not pull an image
or merge deployment state: `/var` is never mounted from host state, and OSTree
checkout fallbacks use the image's pristine `/usr/etc` rather than deployment-local
`/etc`. The target is checked immediately before attachment; callers must prevent
concurrent changes to the target directory while the command runs.

```sh
bootc image mount --deployment booted --source /usr --target /mnt/booted-usr
bootc image unmount /mnt/booted-usr
```

Use `--deployment staged` to select the pending deployment from the active
backend: OSTree selects its staged deployment, while composefs reads the
existing `/run/composefs/staged-deployment` selector. Staged selection does not
discover transitions across backends. If the active backend has no staged
deployment, the command fails instead of guessing an image. This lookup does
not initialize storage, migrate repository metadata, configure the ESP, or
change mount namespaces.

The mounted content is read-only, `nosuid`, and `nodev`. It intentionally
remains executable: the mount does not use `noexec`, so direct executable
paths in the mounted image can be run. The image root itself (`--source /`) is
a valid directory source. Read-only, `nosuid`, `nodev`, and `nosymfollow` do not
disable execution. However, `nosymfollow` prevents following symlinks in the
mounted tree, so a symlink path to an executable will not resolve, even when
its target is also inside the image. The requested source path itself must
also contain no symlink components; this prevents source lookup from escaping
the image before the mount is created. Unmount is non-recursive and operates on
the opened target; it fails if the target is not a mount root or if child mounts
prevent a safe unmount. `bootc image unmount TARGET` is a general-purpose
`umount TARGET`: it unmounts the named non-root mount, whether or not bootc
created it. It does not track or verify bootc provenance, so take care to name
only the mount you intend to remove. Mount attachment follows the propagation
behavior of the target mount namespace; use a private mount namespace if
propagation is undesired.

Example workflow:

```
$ bootc image copy-to-storage
$ cat Containerfile
FROM localhost/bootc
...
$ podman build -t localhost/bootc-custom .
$ bootc switch --transport containers-storage localhost/bootc-custom
```
