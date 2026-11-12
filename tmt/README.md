# TMT integration tests

In the bootc CI, integration tests are executed via Packit on the Testing Farm.

See [CONTRIBUTING.md](../CONTRIBUTING.md#running-tmt-integration-tests) for
instructions on running them locally.

## Package-mode preserve-var test

The package-mode migration test can be run against both supported local VM
images:

```bash
just test-tmt-package-mode fedora-44
just test-tmt-package-mode centos-stream-10
```

Each invocation builds the configured `BOOTC_image` (default
`localhost/bootc`), transfers it as an OCI archive, and runs the same TMT plan.
The recipe asks for `sudo` once to create `/var/lib/bootc-tmt-workdirs`; TMT 1.69
syncs to the same absolute path on the guest, where `/var/lib` is covered by
`--preserve-var`. This avoids using the excluded `/var/tmp` tree and avoids
replacing TMT's real run directory with a symlink. TMT run logs and the
testcloud image cache are kept under that workdir root.

If sudo cannot prompt in the current shell, create the root once interactively
and retry:

```bash
sudo install -d -m 1777 /var/lib/bootc-tmt-workdirs
```
