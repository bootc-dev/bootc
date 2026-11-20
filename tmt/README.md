# TMT integration tests

In the bootc CI, integration tests are executed via Packit on the Testing Farm.

See [CONTRIBUTING.md](../CONTRIBUTING.md#running-tmt-integration-tests) for
instructions on running them locally.

## Package-mode preserve-var test

Run the package-mode migration test against either supported local VM image.
The command builds the configured `BOOTC_image` (default `localhost/bootc`),
transfers it as an OCI archive from a sanitized snapshot of the current working
tree, and runs the TMT plan without `sudo`. The Fedora test uses
`quay.io/fedora/fedora-bootc:44` and the CentOS test uses
`quay.io/centos-bootc/centos-bootc:stream10`; set `BOOTC_base` to override either
base image explicitly.

```bash
just test-tmt-package-mode fedora-44
just test-tmt-package-mode centos-stream-10
```

The snapshot excludes `.git`, `/target`, `.worktrees`, and local package-mode
archives, while retaining uncommitted source changes. The controller workdir is
created under `$HOME/.cache/bootc-tmt-workdirs` without sudo or symlinks. On a
package-mode guest where `/home` is a real directory, the test stages the full
TMT run directory into the corresponding `/var/home/...` location before
migration; after boot, the normal `/home -> /var/home` view resolves the same
lexical path. Already-persistent `/var` workdirs are not duplicated. The test
checks the persistent path and rejects excluded or nested mounts. TMT run logs
and the testcloud image cache remain under that workdir root.
