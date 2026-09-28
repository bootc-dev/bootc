
# Users and groups

This is one of the more complex topics. Generally speaking, bootc has nothing to
do directly with configuring users or groups; it is a generic OS
update/configuration mechanism. (There is currently just one small exception in
that `bootc install` has a special case `--root-ssh-authorized-keys` argument,
but it's very much optional).

## Generic base images

Commonly OS/distribution base images will be generic, i.e.
without any configuration.  It is *very strongly recommended*
to avoid hardcoded passwords and ssh keys with publicly-available
private keys (as Vagrant does) in generic images.

### Injecting SSH keys via systemd credentials

The systemd project has documentation for [credentials](https://systemd.io/CREDENTIALS/)
which can be used in some environments to inject a root
password or SSH authorized_keys.  For many cases, this
is a best practice.

At the time of this writing this relies on SMBIOS which
is mainly configurable in local virtualization environments.
(qemu).

### Injecting users and SSH keys via cloud-init, etc.

Many IaaS and virtualization systems are oriented towards a "metadata server"
(see e.g. [AWS instance metadata](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html))
that are commonly processed by software such as [cloud-init](https://cloud-init.io/)
or [Ignition](https://github.com/coreos/ignition) or equivalent.

The base image you're using may include such software, or you
can install it in your own derived images.

In this model, SSH configuration is managed outside of the bootable
image.  See e.g. [GCP oslogin](https://cloud.google.com/compute/docs/oslogin/)
for an example of this where operating system identities are linked
to the underlying Google accounts.

### Adding users and credentials via custom logic (container or unit)

Of course, systems like `cloud-init` are not privileged; you
can inject any logic you want to manage credentials via
e.g. a systemd unit (which may launch a container image)
that manages things however you prefer.  Commonly,
this would be a custom network-hosted source.  For example,
[FreeIPA](https://www.freeipa.org/page/Main_Page).

Another example in a Kubernetes-oriented infrastructure would
be a container image that fetches desired authentication
credentials from a [CRD](https://kubernetes.io/docs/tasks/extend-kubernetes/custom-resources/custom-resource-definitions/)
hosted in the API server.  (To do things like this
it's suggested to reuse the kubelet credentials)

### System users and groups (added via packages, etc)

It is common for packages (deb/rpm/etc) to allocate system users
or groups as part of e.g `apt|dnf install <server package>` such as Apache or MySQL,
and this is often done by directly invoking `useradd` or `groupadd` as part
of package pre/post installation scripts.

With the`shadow-utils` implementation of `useradd` and the default glibc `files` this will
result in changes to the traditional `/etc/passwd` and `/etc/shadow` files
as part of the container build.

#### System drift from local /etc/passwd modifications

When the system is initially installed, the `/etc/passwd` in the container image will be
applied and contain desired users.

By default (without `etc = transient`, see below), the `/etc` directory is machine-local
persistent state. If subsequently `/etc/passwd` is modified local to the machine
(as is common for e.g. setting a root password) then any new changes in the container
image (such as users from new packages) *will not appear* on subsequent updates by default (they will be
in `/usr/etc/passwd` instead - the default image version).

The general best fix for this is to use `systemd-sysusers` instead of allocating
a user/group at build time at all.

##### Using systemd-sysusers

See [systemd-sysusers](https://www.freedesktop.org/software/systemd/man/latest/systemd-sysusers.html).
For example in your derived build:

```
COPY mycustom-user.conf /usr/lib/sysusers.d
```

A key aspect of how this works is that `sysusers` will make changes
to the traditional `/etc/passwd` file as necessary on boot instead
of at build time. If `/etc` is persistent, this can avoid uid/gid drift (but
in the general case it does mean that uid/gid allocation can
depend on how a specific machine was upgraded over time).

Note that the default `sysusers` design is that users are allocated on the client
side (per machine). Avoid having non-root owned files managed by `sysusers`
inside your image, especially underneath `/usr`. With the exception of
`setuid` or `setgid` binaries (which should also be strongly avoided), there is
generally no valid reason for having non-root owned files in `/usr` or other
runtime-immutable directories.

#### User and group home directories and `/var`

For systems configured with persistent `/home` → `/var/home`, any changes to `/var` made
in the container image after initial installation *will not be applied on subsequent updates*.  If for example you inject `/var/home/someuser/.ssh/authorized_keys`
into a container build, existing systems will *not* get the updated authorized keys file.

#### Using DynamicUser=yes for systemd units

For "system" users it's strongly recommended to use systemd [DynamicUser=yes](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#DynamicUser=) where
possible.

This is significantly better than the pattern of allocating users/groups
at "package install time" (e.g. [Fedora package user/group guidelines](https://docs.fedoraproject.org/en-US/packaging-guidelines/UsersAndGroups/)) because
it avoids potential UID/GID drift (see below).

#### Using systemd JSON user records

See [JSON user records](https://systemd.io/USER_RECORD/).  Unlike `sysusers`,
the canonical state for these live in `/usr` - if a subsequent
image drops a user record, then it will also vanish
from the system - unlike `sysusers.d`.

#### nss-altfiles

The [nss-altfiles](https://github.com/aperezdc/nss-altfiles) project
(long) predates systemd JSON user records.  It aims to help split
"system" users into `/usr/lib/passwd` and `/usr/lib/group`.  It's
very important to understand that this aligns with the way
the OSTree project handles the "3 way merge" for `/etc` as it
relates to `/etc/passwd`.  Currently, if the `/etc/passwd` file is
modified in any way on the local system, then subsequent changes
to `/etc/passwd` in the container image *will not be applied*.

Some base images may have `nss-altfiles` enabled by default;
this is currently the case for base images built by
[rpm-ostree](https://github.com/coreos/rpm-ostree).

Commonly, base images will have some "system" users pre-allocated
and managed via this file again to avoid uid/gid drift.

In a derived container build, you can also append users
to `/usr/lib/passwd` for example.  (At the time of this
writing there is no command line to do so though).

Typically it is more preferable to use `sysusers.d`
or `DynamicUser=yes`.

##### Modifying or adding members to system groups

`groupmod`, `gpasswd`, and `libuser`'s `lgroupadd` operate on `/etc/group`.
Many system groups also have an entry there (for example `wheel`) and are
managed normally. But some — typically hardware/device groups such as `cdrom`
or `dialout` — exist *only* in `/usr/lib/group`. Such a group resolves through
`getent group` yet is absent from `/etc/group`, so these tools fail or
silently do nothing:

- `groupmod -g <gid> cdrom` reports `group 'cdrom' does not exist in
  /etc/group`.
- `gpasswd -a <user> cdrom` and `lgroupadd` report the group does not exist
  in `/etc/group`.
- `usermod -aG cdrom <user>` exits `0` but does **not** add the member.

This is expected behavior of the split, not a bug. Check where a group lives
before managing it:

```console
$ grep '^cdrom:' /etc/group    # no output => the group is only in /usr/lib/group
$ getent group cdrom           # still resolves, via nss-altfiles
```

For a group that exists only in `/usr/lib/group`, add its line to `/etc/group`
(writable machine-local state) first, then manage it normally:

```console
$ getent group cdrom >> /etc/group
$ gpasswd -a <user> cdrom
```

Do **not** do this for a group that is already in `/etc/group` (such as
`wheel`): a duplicate entry breaks these tools (`Multiple entries named
'wheel' in /etc/group`). The membership added this way is machine-local; to
make it part of the image instead, add it as image content (a `sysusers.d`
`m <user> <group>` line, or by editing `/usr/lib/group` in the build). To
change a system group's GID, see
[Reusing a UID/GID reserved by the base image](#reusing-a-uidgid-reserved-by-the-base-image).

### Machine-local state for users

At this point, it is important to understand the [filesystem](../bootc-filesystem.7.md)
layout - the default is up to the base image.

The default Linux concept of a user has data stored in both `/etc` (`/etc/passwd`, `/etc/shadow` and groups)
and `/home`.  The choice for how these work is up to the base image, but
a common default for generic base images is to have both be machine-local persistent state.
In this model `/home` would be a symlink to `/var/home/someuser`.

#### Injecting users and SSH keys via at system provisioning time

For base images where `/etc` and `/var` are configured to persist by default, it
will then be generally supported to inject users via "installers" such
as [Anaconda](https://github.com/rhinstaller/anaconda/) (interactively or
via kickstart) or any others.

Typically generic installers such as this are designed for "one time bootstrap"
and again then the configuration becomes mutable machine-local state
that can be changed "day 2" via some other mechanism.

The simple case is a user with a password - typically the installer helps
set the initial password, but to change it there is a different in-system
tool (such as `passwd` or a GUI as part of [Cockpit](https://cockpit-project.org/), GNOME/KDE/etc).

It is intended that these flows work equivalently in a bootc-compatible
system, to support users directly installing "generic" base images, without
requiring changes to the tools above.

#### Transient home directories

Many operating system deployments will want to minimize persistent,
mutable and executable state - and user home directories are that

But it is also valid to default to having e.g. `/home` be a `tmpfs`
to ensure user data is cleaned up across reboots (and this pairs particularly
well with a transient `/etc` as well):

In order to set up the user's home directory to e.g. inject SSH `authorized_keys`
or other files, a good approach is to use systemd `tmpfiles.d` snippets:

```
f~ /home/someuser/.ssh/authorized_keys 600 someuser someuser - <base64 encoded data>
```
which can be embedded in the image as `/usr/lib/tmpfiles.d/someuser-keys.conf`.

Or a service embedded in the image can fetch keys from the network and write
them; this is the pattern used by cloud-init and [afterburn](https://github.com/coreos/afterburn).

### UID/GID drift

Any invocation of `useradd` or `groupadd` that does not allocate a *fixed* UID/GID may
be subject to "drift" in subsequent rebuilds by default.

One possibility is to explicitly force these user/group allocations into a static
state, via `systemd-sysusers` (per above) or explicitly adding the users with
static IDs *before* a dpkg/RPM installation script operates on it:

```
RUN <<EORUN
set -xeuo pipefail
groupadd -g 10044 mycustom-group
useradd -u 10044 -g 10044 -d /dev/null -M mycustom-user
dnf install -y mycustom-package.rpm
bootc container lint
EORUN
```

Ultimately the `/etc/passwd` and similar files are a mapping
between names and numeric identifiers.  A problem then becomes
when this mapping is dynamic and mixed with "stateless"
container image builds.

For example today the CentOS Stream 9 `postgresql` package
allocates a [static uid of `26`](https://gitlab.com/redhat/centos-stream/rpms/postgresql/-/blob/a03cf81d4b9a77d9150a78949269ae52a0027b54/postgresql.spec#L847).

This means that
```
RUN dnf -y install postgresql
```

will always result in a change to `/etc/passwd` that allocates uid 26
and data in `/var/lib/postgres` will always be owned by that UID.

However in contrast, the cockpit project allocates
[a floating cockpit-ws user](https://gitlab.com/redhat/centos-stream/rpms/cockpit/-/blob/1909236ad28c7d93238b8b3b806ecf9c4feb7e46/cockpit.spec#L506).

This means that each container image build (without additional work, unlike the
example at the beginning of this section),may (due to RPM installation 
ordering or other reasons) result in the uid changing.

This can be a problem if that user maintains persistent state.
Such cases are best handled by being converted to use `sysusers.d`
(see [Fedora change](https://fedoraproject.org/wiki/Changes/Adopting_sysusers.d_format)) - or again even better, using `DynamicUser=yes` (see above).

### Reusing a UID/GID reserved by the base image

Sometimes a local group or an application needs a specific numeric GID (or
UID) that a package in the base image already reserves. For example a fleet
has historically used GID `17` for a `developers` group, but the base image
ships a system group on GID `17`.

The obvious commands fail. `groupadd -g 17 developers` reports `GID '17'
already exists`, because the base group is a "system" entry served by
[nss-altfiles](#nss-altfiles) from `/usr/lib/group` and answers the lookup for
that GID; and `groupmod`/`gpasswd` cannot edit it there (see
[Modifying or adding members to system groups](#modifying-or-adding-members-to-system-groups)).
`systemd-sysusers` will not force an already-used GID either; given a conflict
it allocates a different one.

You do **not** need to remove the package that owns the group. There are two
supported approaches.

#### Prefer a non-conflicting GID

If the application refers to the group **by name**, the numeric value does not
matter to it; give the local group any free GID. Numbers below the
distribution's `SYS_GID_MAX` (see `/etc/login.defs`) are reserved for system
allocation, so choose from the free range and allocate it statically, e.g. via
[`sysusers.d`](#using-systemd-sysusers) or by appending to `/usr/lib/group`.
`getent group <gid>` on the base image confirms whether a number is free.

This avoids changing anything in the base image and is the right choice
whenever the specific number is not an external requirement.

#### Reassigning the base group's GID

When a specific reserved number really must be reused (a legacy assignment
already baked into a fleet's file ownership, for instance), reassign the base
group to a different free GID in your derived build. This is a configuration
change, not a package removal, and it must happen at build time — before the
allocation reaches a running machine's files. The group is defined in two
places that both have to agree:

```Dockerfile
FROM <base image>
RUN set -xeu; \
    # 1. move the base group off the wanted GID in the altfiles source
    sed -i 's/^cdrom:x:17:/cdrom:x:4711:/' /usr/lib/group; \
    # 2. keep systemd-sysusers consistent: a lexically-earlier drop-in wins
    #    over the base package's entry, so it will not try to recreate the
    #    group on the old GID at boot
    printf 'g cdrom 4711\n' > /usr/lib/sysusers.d/00-reassign-cdrom.conf; \
    # 3. allocate the local group at the now-free GID, statically in the image
    echo 'developers:x:17:' >> /usr/lib/group; \
    bootc container lint
```

`cdrom`, `17`, and `developers` are placeholders: substitute the group that
actually holds the GID (`getent group <gid>` names it), the GID you need, and a
free replacement GID from the reserved range. Note that on many bases `cdrom`
is a different GID, so the `sed` above matches nothing unless adapted.

Editing `/usr/lib/group` is necessary because altfiles keeps answering for the
old GID otherwise; the `sysusers.d` drop-in alone is not enough, and
`sysusers.d` alone cannot move an existing entry.

After this, `getent group 17` resolves to `developers`, the base group exists
on its new GID, and the mapping survives reboots and the `/etc` three-way
merge. Everything that referenced the base group **by name** continues to work
because name resolution stays consistent; only code that hardcodes the old
numeric GID would be affected, which is unusual.

Note that adding members to a group that lives in `/usr/lib/group` (such as the
reassigned base group) is itself an altfiles behavior: `gpasswd`/`usermod -aG`
operate on `/etc/group`, so promote the group's line into `/etc/group` first,
or manage the membership as image content.

#### tmpfiles.d use for setting ownership

Systemd's [tmpfiles.d](https://www.freedesktop.org/software/systemd/man/latest/tmpfiles.d.html) provides a way
to define files and directories in a way that will be processes at startup as needed. One way to work around
SELinux security context and user or group ownership of a directory or file can be by using the z or Z directives.

These directives will adjust the access mode, user and group ownership and the SELinux security context as
stated on the doc linked above.

For example, if we need `/var/lib/my_file.conf` to be part of the `tss` group but owned by `root`
we could create a tmpfiles.d entry with:

```
+z /var/lib/my_file 0640 root tss -
```

