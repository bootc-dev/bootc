
# Secrets (e.g. container pull secrets)

To have `bootc` fetch updates from registry which requires authentication,
you must include a pull secret in one of `/etc/ostree/auth.json`,
`/run/ostree/auth.json` or `/usr/lib/ostree/auth.json`.

The path to the authentication file differs from that used
by e.g. `podman` by default as some of the file paths used
there are not appropriate for system services (e.g. reading
the `/root` home directory).

Regardless, injecting this data is a good example of a generic
"secret".  The bootc project does not currently include one
single opinionated mechanism for secrets.

## Synchronizing the bootc and podman credentials

See the [containers-auth.json](https://github.com/containers/image/blob/main/docs/containers-auth.json.5.md) man page. In many cases, you will
want to keep both the bootc and podman/skopeo credentials
in sync. One pattern is to symlink the two via e.g. a systemd `tmpfiles.d` fragment.

If you have a process invoking `podman login` (which by default writes to
an ephemeral `$XDG_RUNTIME_DIR/containers/auth.json`) you can then
`ln -s /run/user/0/containers/auth.json /run/ostree/auth.json`.

## Performing an explicit login

If you have automation (or manual processes) performing a login,
you can pass `--authfile` to set the bootc authfile explicitly;
for example

```bash
echo <somepassword> | podman login \
  --authfile /run/ostree/auth.json -u someuser --password-stdin
```

This pattern of using the ephemeral location in `/run` can work
well when the credentials are derived on system start from
an external system. For example, `aws ecr get-login-password --region region`
as suggested by [this document](https://docs.aws.amazon.com/AmazonECR/latest/userguide/Podman.html).

You can also use the machine-local persistent location `/etc/ostree/auth.json`
via this method.

## Using a credential helper

In order to use a credential helper as configured in `registries.conf`
such as `credential-helpers = ["ecr-login"]`, you must currently
also write a "no-op" authentication file with the contents `{}` (i.e. an
empty JSON object, not an empty file) into the pull secret location.

## Embedding in container build

This was mentioned above; you can include secrets in
the container image if the registry server is suitably protected.

In some cases, embedding only "bootstrap" secrets into the container
image is a viable pattern, especially alongside a mechanism for
having a machine authenticate to a cluster.   In this pattern,
a provisioning tool (whether run as part of the host system
or a container image) uses the bootstrap secret to lay down
and keep updated other secrets (for example, SSH keys,
certificates).

## Via cloud metadata

Most production IaaS systems support a "metadata server" or equivalent
which can securely host secrets - particularly "bootstrap secrets".
Your container image can include tooling such as `cloud-init`
or `ignition` which fetches these secrets.

## Embedded in disk images

Another pattern is to embed bootstrap secrets only in disk images.
For example, when generating a cloud disk image (AMI, OpenStack glance image, etc.)
from an input container image, the disk image can contain secrets that
are effectively machine-local state.  Rotating them would
require an additional management tool, or refreshing disk images.

## Injected via baremetal installers

It is common for installer tools to support injecting configuration
which can commonly cover secrets like this.

## Injecting secrets via systemd credentials

The systemd project has documentation for [credentials](https://systemd.io/CREDENTIALS/)
which applies in some deployment methodologies.
