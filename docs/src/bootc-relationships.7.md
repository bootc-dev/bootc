# Relationship with other projects

bootc is the key component in a broader mission of [bootable containers](https://containers.github.io/bootable/).
Here's its relationship to other moving parts.

## Relationship with podman

It gets a bit confusing to talk about shipping bootable operating systems in container images.
Again, to be clear: we are reusing container images as:

- A build mechanism (including running *as* a standard OCI container image)
- A transport mechanism

But, actually when a bootc container is booted, podman (or docker, etc.) is not involved.
The storage used for the operating system content is distinct from `/var/lib/containers`.
`podman image prune --all` will not delete your operating system.

That said, a toplevel goal of bootc is alignment with the https://github.com/containers ecosystem,
which includes podman.  But more specifically at a technical level, today bootc uses
[skopeo](https://github.com/containers/skopeo/) and hence indirectly [containers/image](https://github.com/containers/image)
as a way to fetch container images.

This means that bootc automatically also honors many of the knobs available in `/etc/containers` - specifically
things like [containers-registries.conf](https://github.com/containers/image/blob/main/docs/containers-registries.conf.5.md).

In other words, if you configure `podman` to pull images from your local mirror registry, then `bootc` will automatically honor that as well.

The simple way to say it is: A goal of `bootc` is to be the bootable-container analogue for `podman`, which runs application containers.  Everywhere one might run `podman`, one could also consider using `bootc`. 

## Relationship with Image Builder (osbuild)

There is a new [bootc-image-builder](https://github.com/osbuild/bootc-image-builder) project that is dedicated to the intersection of these two!

## Relationship with Kubernetes

Just as `podman` does not depend on a Kubernetes API server, `bootc` will also not depend on one.

However, there are also plans for `bootc` to also understand Kubernetes API types.  See [configmap/secret support](https://github.com/bootc-dev/bootc/issues/22) for example.

Perhaps in the future we may actually support some kind of `Pod` analogue for representing the host state.  Or we may define a [CRD](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/) which can be used inside and outside of Kubernetes.

## Relationship with ostree

OSTree provides many things:
1. a git-like repo for OS data from which you can check out an entire rootfs
2. a bootloader integration layer
3. a transport layer for pulling content over HTTP

With bootc, the OSTree transport layer is not used. Instead, content is pulled
as OCI containers using `skopeo` as mentioned above. However, this content
is then imported into the local OSTree repo to perform a deployment checkout.
The role of OSTree may further shrink in the future, especially as tighter
integration with podman and composefs occurs, but it will remain an important
part of the bootc stack (in particular the bootloader integration layer and
management of deployment roots).

## Relationship with rpm-ostree

As mentioned above, bootc uses OSTree as a backing model, and so does
rpm-ostree. Hence, when using a container source, `rpm-ostree upgrade` and
`bootc upgrade` are effectively equivalent; you can use either command.

### Differences from rpm-ostree

- The ostree project never tried to have an opinionated "install" mechanism,
  but bootc does with `bootc install to-filesystem`
- Bootc has additional features such as `/usr/lib/bootc/kargs.d` and
  [logically bound images](bootc-logically-bound-images.7.md).

### Client side changes

Currently all functionality for client-side changes
such as `rpm-ostree install` or `rpm-ostree initramfs --enable`
continue to work, because of the shared base.

However, as soon as you mutate the system in this way, `bootc upgrade`
will error out as it will not understand how to upgrade
the system.  The bootc project currently takes a relatively
hard stance that system state should come from a container image.

The way kernel argument work also uses ostree on the backend
in both cases, so using e.g. `rpm-ostree kargs` will also work
on a system updating via bootc.

Overall, rpm-ostree is used in several important projects
and will continue to be maintained for many years to come.

However, for use cases which want a "pure" image based model,
using `bootc` will be more appealing.  bootc also does not
e.g. drag in dependencies on `libdnf` and the RPM stack.

bootc also has the benefit of starting as a pure Rust project;
and while it [doesn't have an IPC mechanism today](https://github.com/bootc-dev/bootc/issues/4), the surface
of such an API will be significantly smaller.

Further, bootc does aim to [include some of the functionality of zincati](https://github.com/bootc-dev/bootc/issues/5).

But all this said: *It will be supported to use both bootc and rpm-ostree together*; they are not exclusive.
For example, `bootc status` at least will still function even if packages are layered.

### Future bootc <-> podman binding

All the above said, it is likely that at some point bootc will switch to [hard binding with podman](https://github.com/bootc-dev/bootc/pull/215).
This will reduce the role of ostree, and hence break compatibility with rpm-ostree.
When such work lands, we will still support at least a "one way" transition from an
ostree backend.  But once this happens there are no plans to teach rpm-ostree
to use podman too.

## Relationship with Fedora CoreOS (and Silverblue, etc.)

Per above, it is a toplevel goal to support a seamless, transactional update from existing OSTree based systems, which includes these Fedora derivatives.

For Fedora CoreOS specifically, see [this tracker issue](https://github.com/coreos/fedora-coreos-tracker/issues/1446).

See also [OstreeNativeContainerStable](https://fedoraproject.org/wiki/Changes/OstreeNativeContainerStable).
