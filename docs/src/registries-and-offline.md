# Accessing registries and disconnected updates

The `bootc` project uses the [containers/image](https://github.com/containers/image)
library to fetch container images (the same used by `podman`) which means it honors almost all
the same configuration options in `/etc/containers`.

## Insecure registries

Container clients such as `podman pull` and `docker pull` have a `--tls-verify=false`
flag which says to disable TLS verification when accessing the registry.  `bootc`
has no such option.  Instead, you can globally configure the option
to disable TLS verification when accessing a specific registry via the
`/etc/containers/registries.conf.d` configuration mechanism, for example:

```
# /etc/containers/registries.conf.d/local-registry.conf
[[registry]]
location="localhost:5000"
insecure=true
```

For more, see [containers-registries.conf](https://github.com/containers/image/blob/main/docs/containers-registries.conf.5.md).

## Private registries

It's common to use a private repository when deploying a fleet of bootc instances.

In addition to registry configuration, if you want to use a private registry, you'll need to address authentication. Place a `auth.json` file in the directory `/etc/ostree/auth.json`.

For more, see [auth.json](https://man.archlinux.org/man/containers-auth.json.5)

## Disconnected and offline updates

It is common (a best practice even) to maintain systems which default
to being disconnected from the public Internet.

### Pulling updates from a local mirror

Everything in the section [remapping and mirroring images](https://github.com/containers/image/blob/main/docs/containers-registries.conf.5.md#remapping-and-mirroring-registries)
applies to bootc as well.

### Performing offline updates via USB

In a usage scenario where the operating system update is in a fully
disconnected environment and you want to perform updates via e.g. inserting
a USB drive, one can do this by copying the desired OS container image to
e.g. an `oci` directory:

```bash
skopeo copy docker://quay.io/exampleos/myos:latest oci:/path/to/filesystem/myos.oci
```

Then once the USB device containing the `myos.oci` OCI directory is mounted
on the target, use

```bash
bootc switch --transport oci /var/mnt/usb/myos.oci
```

The above command is only necessary once, and thereafter will be idempotent.
Then, use `bootc upgrade --apply` to fetch and apply the update from the USB device.

This process can all be automated by creating systemd
units that look for a USB device with a specific label, mount (optionally with LUKS
for example), and then trigger the bootc upgrade.
