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

Example workflow:

```
$ bootc image copy-to-storage
$ cat Containerfile
FROM localhost/bootc
...
$ podman build -t localhost/bootc-custom .
$ bootc switch --transport containers-storage localhost/bootc-custom
```

