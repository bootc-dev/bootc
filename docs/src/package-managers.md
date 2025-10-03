# Package manager integration

A toplevel goal of bootc is to encourage a default model
where Linux systems are built and delivered as (container) images.
In this model, the default usage of package managers such as `apt` and `dnf`
will be at container build time.

However, one may end up shipping the package manager tooling onto
the end system. In some cases this may be desirable even, to allow
workflows with transient overlays using e.g. `bootc usroverlay`.

## Detecting image-based systems

bootc is not the only image based system; there are many. A common
emphasis is on having the operating system content in `/usr`,
and for that filesystem to be mounted read-only at runtime.

A first recommendation here is that package managers should
detect if `/usr` is read-only, and provide a useful error
message referring users to documentation guidance.

An example of a non-bootc case is "Live CD" environments,
where the *physical media* is readonly. Some Live operating system environments end 
up mounting a transient writable overlay (whether via e.g. devicemapper or overlayfs)
that make the system appear writable, but it's arguably clearer not to do so by
default. Detecting `/usr` as read-only here and providing the same information
would make sense.

To specifically detect if bootc is in use, you can parse its JSON status
(if the binary is present) to tell if a system is tracking an image.
The following command succeeds if an image is *not* being tracked:
`test $(bootc status --format=json | jq .spec.image) = null`.

### The `/run/ostree-booted` file

This is created by ostree, and hence created by bootc (with the ostree)
backend. You can use it to detect ostree. However, *most* cases
should instead detect via one of the recommendations above.

### Running a read-only system via podman/docker

The historical default for docker (inherited into podman) is that
the `/` is a writable (but transient) overlayfs. However, e.g. `podman`
supports a `--read-only` flag, and [Kubernetes pods](https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/) offer a
`securityContext.readOnlyRootFilesystem` flag.

Running containers in production in this way is a good idea,
for exactly the same reasons that bootc defaults to mounting
the system read-only.

Ensure that your package manager offers a useful error message
in this mode. Today for example:

```
$ podman run --read-only --rm -ti debian apt update
Reading package lists... Done
E: List directory /var/lib/apt/lists/partial is missing. - Acquire (30: Read-only file system)
$ podman run --read-only --rm -ti quay.io/fedora/fedora:40 dnf -y install strace
Config error: [Errno 30] Read-only file system: '/var/log/dnf.log': '/var/log/dnf.log'
```

However note that both of these fail on `/var` being read-only; in a default bootc
model, it won't be. A more accurate check is thus closer to:

```
$ podman run --read-only --rm -ti --tmpfs /var quay.io/fedora/fedora:40 dnf -y install strace
...
Error: Transaction test error:
  installing package strace-6.9-1.fc40.x86_64 needs 2MB more space on the / filesystem
```

```
$ podman run --read-only --rm --tmpfs /var -ti debian /bin/sh -c 'apt update && apt -y install strace'
...
dpkg: error processing archive /var/cache/apt/archives/libunwind8_1.6.2-3_amd64.deb (--unpack):
 unable to clean up mess surrounding './usr/lib/x86_64-linux-gnu/libunwind-coredump.so.0.0.0' before installing another version: Read-only file system
```

These errors message are misleading and confusing for the user. A more useful error may look like e.g.:

```
$ podman run --read-only --rm --tmpfs /var -ti debian /bin/sh -c 'apt update && apt -y install strace'
error: read-only /usr detected, refusing to operate. See `man apt-image-based` for more information.
```


## Transient overlays

Today there is a simple `bootc usroverlay` command that adds a transient writable overlayfs for `/usr`.
This makes many package manager operations work; conceptually it is similar
to the writable overlay that many "Live CDs" use. However, one cannot change the kernel
this way for example.

An optional integration that package managers can do is to detect this transient overlay
situation and inform the user that the changes will be ephemeral.

## Persistent changes

A bootc system by default *does* have a writable, persistent data store that holds
multiple container image versions (more in [filesystem](filesystem.md)).

Systems such as [rpm-ostree](https://github.com/coreos/rpm-ostree/) implement
a "hybrid" mechanism where packages can be persistently layered and re-applied;
the system effectively does a "local build", unioning the intermediate filesystems.

One aspect of how rpm-ostree implements this is by caching individual unpacked RPMs as ostree commits
in the ostree repo.

This section will be expanded later; you may also be able to find more information in [booting local builds](booting-local-builds.md).


