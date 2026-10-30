# DNS and `/etc/resolv.conf`

`bootc` does not configure networking or select a DNS resolver. The operating
system in the container image must provide a coherent networking and DNS
policy, just as it must provide a kernel and an init system. Usually that
policy is owned by the distribution or base image.

The recommended approach is to configure DNS through the network management
and resolver services selected by the base image. Do not treat
`/etc/resolv.conf` as a file that should be copied from the container build
environment into the booted system.

## Build-time and boot-time resolver configuration

When an image is built, the container runtime normally provides temporary
`/etc/hostname`, `/etc/hosts`, and `/etc/resolv.conf` files so that `RUN`
instructions have working networking. These files describe the build
environment. They are not the DNS configuration of the machine that will boot
the image.

When the image is installed and booted, there is no outer Podman or other
container runtime to recreate these files. The network stack included in the
image is responsible for generating the booted host's resolver configuration.
See [Container runtime vs bootc runtime](bootc-container-runtime.7.md) for more about this
distinction.

In particular:

- Do not copy the build host's `/etc/resolv.conf` into an image.
- Do not rely on the `/etc/resolv.conf` visible in a networked `RUN`
  instruction. It may be a bind mount owned by Podman or Buildah.
- Do not use an empty regular `/etc/resolv.conf` as a placeholder. `bootc`
  removes it when importing the image (see below).
- Do not add files below `/run` to an image. `/run` is runtime state and is
  recreated on every boot.

The one thing `bootc` does with these files: when importing an image (with the
ostree backend today), it removes `/etc/resolv.conf` and `/etc/hostname` if
they are zero-length regular files, because that is what a container runtime
leaves behind after bind-mounting its own copies during the build (see
[buildah#4242](https://github.com/containers/buildah/issues/4242),
bootc [#1096](https://github.com/bootc-dev/bootc/pull/1096) and
[#1167](https://github.com/bootc-dev/bootc/pull/1167)). Apart from that,
`bootc` never reads or writes `/etc/resolv.conf`.

If a Containerfile step must intentionally replace `/etc/resolv.conf`, run the
step with networking disabled, for example with `RUN --network=none`. This
avoids modifying a container-runtime bind mount. It should only be necessary
when deliberately changing the resolver policy inherited from the base image.

## Follow the base image's resolver policy

A derived image should normally retain its base image's DNS implementation.
Configure DNS servers, search domains, and per-interface behavior through that
implementation rather than replacing `/etc/resolv.conf`.

Common policies include:

- NetworkManager supplies per-link DNS configuration to `systemd-resolved`,
  and `/etc/resolv.conf` points to the local resolver stub.
- NetworkManager writes a regular `/etc/resolv.conf` directly.
- Another network manager or resolver owns the file under a
  distribution-specific policy.

NetworkManager and `systemd-resolved` are not alternatives with the same role.
NetworkManager configures network interfaces and may use `systemd-resolved` as
its DNS backend. The base image must ensure that its selected services, the
type and target of `/etc/resolv.conf`, and its service enablement agree. For
anything beyond that, follow your distribution's networking documentation and
the references in [Further reading](#further-reading).

Environment-specific DNS configuration should generally be supplied when a
machine is provisioned. If DNS configuration is intentionally lifecycle-bound
to an image, include NetworkManager connection profiles or resolver drop-ins
in the image rather than including a generated `/etc/resolv.conf`. This keeps
the configuration declarative and makes its owner clear.

## Base images using `systemd-resolved`

A base image using `systemd-resolved` should ensure that:

- `systemd-resolved` is installed and enabled.
- NetworkManager or the selected network manager is configured to supply DNS
  information to it.
- `/etc/resolv.conf` is a symlink to a resolver file generated below
  `/run/systemd/resolve`, normally
  `../run/systemd/resolve/stub-resolv.conf`.

The upstream `systemd-resolved` package supplies a
[`systemd-tmpfiles`](https://www.freedesktop.org/software/systemd/man/latest/tmpfiles.d.html)
rule that creates the symlink at boot, so it does not need to exist in the
image:

```text
L! /etc/resolv.conf - - - - ../run/systemd/resolve/stub-resolv.conf
```

It does not contain DNS server
addresses; `systemd-resolved` creates the target under `/run` from runtime
network configuration. Base image authors should normally use the rule
provided by the `systemd-resolved` package. A custom distribution integration
can ship an equivalent vendor rule in `/usr/lib/tmpfiles.d`.

Do not disable `systemd-resolved` while retaining this rule and symlink. That
leaves `/etc/resolv.conf` pointing to a runtime file that no enabled service
creates.

### Fedora CoreOS example

Fedora CoreOS uses NetworkManager with `systemd-resolved`. It retains the
resolver stub symlink and configures DNS through NetworkManager connection
profiles. For example, its Butane configuration examples write NetworkManager
keyfiles under `/etc/NetworkManager/system-connections/` and set the `dns` and
`dns-search` properties there.

See the Fedora CoreOS documentation for
[host network configuration](https://docs.fedoraproject.org/en-US/fedora-coreos/sysconfig-network-configuration/)
and Fedora's description of its
[`systemd-resolved` integration](https://fedoraproject.org/wiki/Changes/systemd-resolved).
Fedora CoreOS also has an integration
[test for its resolver policy](https://github.com/coreos/fedora-coreos-config/blob/testing-devel/tests/kola/networking/resolv/systemd-resolved).

This is an example of a complete base-image policy, not a requirement that all
bootc images use `systemd-resolved`.

## Base images using a regular `/etc/resolv.conf`

A base image may instead have NetworkManager or another service write a
regular `/etc/resolv.conf` at runtime, on the booted host; nothing in the
container build produces that file. In that case it should ensure that:

- `systemd-resolved` is not enabled.
- No tmpfiles rule recreates the `systemd-resolved` symlink.
- `/etc/resolv.conf` is absent or is a regular file that the selected service
  is configured to manage.

For Fedora-derived images, removing the `systemd-resolved` package is generally
clearer than only disabling its service: the package also owns the tmpfiles
rule that creates the symlink. Do the removal in a `RUN --network=none` step:
with networking enabled, `/etc/resolv.conf` is the container runtime's bind
mount and the package's uninstall scriptlet fails when it tries to handle it
(package removal needs no network). The inherited stub symlink is left behind
by the removal; remove it in the same step:

```Dockerfile
RUN --network=none dnf -y remove systemd-resolved && rm -f /etc/resolv.conf
```

If the package must remain installed, mask its tmpfiles rule with a symlink to
`/dev/null` at `/etc/tmpfiles.d/systemd-resolve.conf` and disable the service.

Any Containerfile operation that removes the inherited resolver symlink should
use `RUN --network=none`, because a networked build step sees a bind mount at
`/etc/resolv.conf` instead of the image's file.

## `/etc/resolv.conf` is a symlink, managed by tmpfiles.d

Content that the *image* provides for `/etc/resolv.conf` should reach it
through a symlink created by a `systemd-tmpfiles` rule, not as a regular file
in the image: `/etc` is three-way merged across upgrades, and once a regular
file there has been modified locally a later image default no longer takes
effect (see [Filesystem: `/etc`](../bootc-filesystem.7.md#etc)). The target depends on
the policy:

- a file under `/run` when the resolver is dynamic -- this is what the
  `systemd-resolved` rule above does;
- a file under `/usr` when the configuration is truly static (below).

A regular file that a service such as NetworkManager *generates at runtime* is
a different matter: the service owns it and rewrites it on every boot, so it
does not carry image content and the merge behavior does not apply to it.

## Static resolver configuration

Static DNS is configured through the network stack, like any other DNS
setting, and that is the preferred mechanism even when the values never
change:

- NetworkManager: set `ipv4.dns` / `ipv6.dns` on the connection profile
  (with `ipv4.ignore-auto-dns yes` if DHCP must not add servers), typically
  together with a static address.
- `systemd-resolved`: drop-ins in `/etc/systemd/resolved.conf.d/`.

Baking DNS server addresses into the image as a `resolv.conf` file is
discouraged: they are machine or environment configuration, and the file
bypasses whatever the network stack would otherwise manage. If an image must
ship one anyway, put the content under `/usr`, for example
`/usr/lib/resolv.conf`, and point the symlink at it with a rule mirroring the
`systemd-resolved` one:

```text
L /etc/resolv.conf - - - - ../usr/lib/resolv.conf
```

Then mask the vendor `systemd-resolved` rule for the same path (a symlink to
`/dev/null` at `/etc/tmpfiles.d/systemd-resolve.conf`; two rules for one path
are an error in `tmpfiles.d`), configure the network stack not to manage the
file (`dns=none` in the `[main]` section of `NetworkManager.conf`; do not
enable `systemd-resolved`), and use `RUN --network=none` for the build step
that removes an inherited symlink.

## Further reading

Behavior such as `ndots`, timeouts, retries, caching, and split DNS is defined
by the resolver the base image selected, not by `bootc`. See the
[`systemd-resolved` documentation](https://www.freedesktop.org/software/systemd/man/latest/systemd-resolved.html)
and NetworkManager's documentation for
[`NetworkManager.conf`](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/NetworkManager.conf.html)
and
[connection settings](https://networkmanager.dev/docs/api/latest/ref-settings.html).

## Application containers

Application containers and bootc hosts have different runtime behavior. By
default, Podman creates `/etc/hosts`, `/etc/hostname`, and `/etc/resolv.conf`
for each application container. Runtime options such as `podman run --dns`
control that generated file, and `--dns=none` requests use of the image's file.

The DNS options to `podman build` apply to networked `RUN` instructions; they
do not define the DNS policy of a host booted from the completed image. See the
Podman documentation for
[`podman run`](https://docs.podman.io/en/latest/markdown/podman-run.1.html) and
[`podman build`](https://docs.podman.io/en/latest/markdown/podman-build.1.html).
