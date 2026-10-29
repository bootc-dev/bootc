% ostree-container-auth 5

# NAME
ostree-container-auth description of the registry authentication file

# DESCRIPTION

The OSTree container stack uses the same file formats as **containers-auth(5)** but
not the same locations.

When running as uid 0 (root), the tooling uses `/run/ostree/auth.json` first, then looks
in `/etc/ostree/auth.json`, and finally checks `/usr/lib/ostree/auth.json`.
For any other uid, the file paths used are in `${XDG_RUNTIME_DIR}/ostree/auth.json`.

In the future, it is likely that a path that is supported for both "system podman"
usage and ostree will be added.

## FORMAT

The auth.json file stores, or references, credentials that allow the user to authenticate
to container image registries.
It is primarily managed by a `login` command from a container tool such as `podman login`,
`buildah login`, or `skopeo login`.

For more information, see **containers-auth(5)**.

# SEE ALSO

**containers-auth(5)**, **skopeo-login(1)**, **skopeo-logout(1)**
