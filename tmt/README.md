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
created under `$HOME/.cache/bootc-tmt-workdirs`. TMT 1.69 mirrors it to
the same absolute guest path; on bootc guests `/home/...` resolves to
`/var/home/...`, which is preserved by the migration. The test checks the
resolved path is under preserved `/var` and rejects nested mounts, so it does
not rely on `/var/tmp` or symlinks. TMT run logs and the testcloud image cache
remain under that workdir root.
