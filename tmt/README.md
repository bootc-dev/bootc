# TMT integration tests

In the bootc CI, integration tests are executed via Packit on the Testing Farm.

See [CONTRIBUTING.md](../CONTRIBUTING.md#running-tmt-integration-tests) for
instructions on running them locally.

## Package-mode preserve-var test

Run the package-mode migration test against either supported local VM image.
The command builds the configured `BOOTC_image` (default `localhost/bootc`),
transfers it as an OCI archive, and runs the TMT plan. It does not require
`sudo`:

```bash
just test-tmt-package-mode fedora-44
just test-tmt-package-mode centos-stream-10
```

The controller workdir is created under `$HOME/.cache/bootc-tmt-workdirs`. TMT
1.69 mirrors it to
the same absolute guest path; on bootc guests `/home/...` resolves to
`/var/home/...`, which is preserved by the migration. The test checks the
resolved path is under preserved `/var` and rejects nested mounts, so it does
not rely on `/var/tmp` or symlinks. TMT run logs and the testcloud image cache
remain under that workdir root.
