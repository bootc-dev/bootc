# Generic guidance for building images

The bootc project intends to be operating system and distribution independent as possible,
similar to its related projects [podman](http://podman.io/) and [systemd](https://systemd.io/),
etc.

The recommendations for creating bootc-compatible images will in general need to
be owned by the OS/distribution - in particular the ones who create the default
bootc base image(s). However, some guidance is very generic to most Linux
systems (and bootc only supports Linux).

Let's however restate a base goal of this project:

> The original Docker container model of using "layers" to model
> applications has been extremely successful.  This project
> aims to apply the same technique for bootable host systems - using
> standard OCI/Docker containers as a transport and delivery format
> for base operating system updates.

Every tool and technique for creating application base images
should apply to the host Linux OS as much as possible.

## Understanding mutability

When run as a container (particularly as part of a build), bootc-compatible
images have all parts of the filesystem (e.g. `/usr` in particular) as fully
mutable state, and writing there is encouraged (see below).

When "deployed" to a physical or virtual machine, the container image
files are read-only by default; for more, see [filesystem](../filesystem.md).

## Installing software

For package management tools like `apt`, `dnf`, `zypper` etc.
(generically, `$pkgsystem`) it is very much expected that
the pattern of

`RUN $pkgsystem install somepackage && $pkgsystem clean all`

type flow Just Works here - the same way as it does
"application" container images.  This pattern is really how
Docker got started.

There's not much special to this that doesn't also apply
to application containers; but see below.

### Nesting OCI containers in bootc containers

The [OCI format](https://github.com/opencontainers/image-spec/blob/main/spec.md) uses
"whiteouts" represented in the tar stream as special `.wh` files, and typically
consumed by the Linux kernel `overlayfs` driver as special `0:0` character
devices.  Without special work, whiteouts cannot be nested.

Hence, an invocation like

```
RUN podman pull quay.io/exampleimage/someimage
```

will create problems, as the `podman` runtime will create whiteout files
inside the container image filesystem itself.

Special care and code changes will need to be made to container
runtimes to support such nesting.  Some more discussion in
[this tracker issue](https://github.com/bootc-dev/bootc/issues/128).

## systemd units

The model that is most popular with the Docker/OCI world
is "microservice" style containers with the application as
pid 1, isolating the applications from each other and
from the host system - as opposed to "system containers"
which run an init system like systemd, typically also
SSH and often multiple logical "application" components
as part of the same container.

The bootc project generally expects systemd as pid 1,
and if you embed software in your derived image, the
default would then be that that software is initially
launched via a systemd unit.

```dockerfile
RUN dnf -y install postgresql && dnf clean all
```

Would typically also carry a systemd unit, and that
service will be launched the same way as it would
on a package-based system.

## Users and groups

Note that the above `postgresql` today will allocate a user;
this leads to the topic of [users, groups and SSH keys](users-and-groups.md).

## Configuration

A key aspect of choosing a bootc-based operating system model
is that *code* and *configuration* can be strictly "lifecycle bound"
together in exactly the same way.

(Today, that's by including the configuration into the base
 container image; however a future enhancement for bootc
 will also support dynamically-injected ConfigMaps, similar
 to kubelet)

You can add configuration files to the same places they're
expected by typical package systems on Debian/Fedora/Arch
etc. and others - in `/usr` (preferred where possible)
or `/etc`.  systemd has long advocated and supported
a model where `/usr` (e.g. `/usr/lib/systemd/system`)
contains content owned by the operating system image.

`/etc` is machine-local state.  However, per [filesystem.md](../filesystem.md)
it's important to note that the underlying OSTree
system performs a 3-way merge of `/etc`, so changes you
make in the container image to e.g. `/etc/postgresql.conf`
will be applied on update, assuming it is not modified
locally.

### Prefer using drop-in directories

These "locally modified" files can be a source of state drift.  The best
pattern to use is "drop-in" directories that are merged dynamically by
the relevant software.  systemd supports this comprehensively; see
[drop-ins](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html)
for example in units.

And instead of modifying `/etc/sudoers.conf`, it's best practice to add
a file into `/etc/sudoers.d` for example.

Not all software supports this, however; and this is why there
is generic support for `/etc`.

### Configuration in /usr vs /etc

Some software supports generic configuration both `/usr` and `/etc` - systemd,
among others.  Because bootc supports *derivation* (the way OCI
containers work) - it is supported and encouraged to put configuration
files in `/usr` (instead of `/etc`) where possible, because then
the state is consistently immutable.

One pattern is to replace a configuration file like
`/etc/postgresql.conf` with a symlink to e.g. `/usr/postgres/etc/postgresql.conf`
for example, although this can run afoul of SELinux labeling.

### Secrets

There is a dedicated document for [secrets](secrets.md),
which is a special case of configuration.

## Handling read-only vs writable locations

The high level pattern for bootc systems is summarized again
this way:

- Put read-only data and executables in `/usr`
- Put configuration files in `/usr` (if they're static), or `/etc` if they need to be machine-local
- Put "data" (log files, databases, etc.) underneath `/var`

However, some software installs to `/opt/examplepkg` or another
location outside of `/usr`, and may include all three types of data
undernath its single toplevel directory.  For example, it
may write log files to `/opt/examplepkg/logs`.  A simple way to handle
this is to change the directories that need to be writable to symbolic links
to `/var`:

```dockerfile
RUN apt|dnf install examplepkg && \
    mv /opt/examplepkg/logs /var/log/examplepkg && \
    ln -sr /var/log/examplepkg /opt/examplepkg/logs
```

The [Fedora/CentOS bootc puppet example](https://gitlab.com/fedora/bootc/examples/-/tree/main/opt-puppet)
is one instance of this.

Another option is to configure the systemd unit launching the service to do these mounts
dynamically via e.g.

```
BindPaths=/var/log/exampleapp:/opt/exampleapp/logs
```
