# Run integration tests locally

Integration tests can be run locally on a developer's machine, which is especially valuable for debugging purposes.

## Prerequisites

Install the required tools:
- [tmt](https://tmt.readthedocs.io/en/stable/guide.html#the-first-steps)
- [bcvk](https://github.com/containers/bcvk) for VM management
- podman
- rsync

## Running tests

The recommended way to run tests is using the Justfile:

```bash
# Run all tests
just test-tmt

# Run specific test(s) by name filter
just test-tmt readonly
just test-tmt local-upgrade
```

This will:
1. Generate TLS certificates for the registry (if not already present)
2. Build the base bootc test image
3. Build the registry VM image with TLS support
4. Launch a registry VM to host custom test images
5. Build custom test images from each test's images/ directory
6. Push custom images to the registry VM
7. Run tests using bcvk-provisioned VMs

## Test architecture

### Registry VM

Tests use a **multi-VM architecture** with a persistent registry VM:

- **Registry VM**: Runs a container registry service with TLS enabled
  - Launched once before all tests begin
  - Shared across all test VMs in the run
  - Accessible via hostname `bootc-registry.test:5000`
  - Uses self-signed TLS certificates (see `hack/README-registry-tls.md`)
  - Automatically cleaned up after all tests complete

- **Test VMs**: Individual VMs for each test plan
  - Each test gets its own isolated VM
  - Can pull custom images from the registry VM
  - Cleaned up after the test completes

This architecture ensures:
- Test isolation (each test runs in its own VM)
- Fast image distribution (shared registry)
- Secure TLS communication between VMs
- No test state leakage between plans

### Custom test images

Tests can define custom container images in an `images/` subdirectory. The framework automatically:

1. **Discovers** Containerfiles in `test-*/images/*/Containerfile`
2. **Builds** each image before the test runs
3. **Pushes** to the registry VM
4. **Provides** environment variables to access the images

#### Directory structure

```
tmt/tests/booted/test-20-image-pushpull-upgrade/
├── test.nu                              # Test script
└── images/                              # Custom images for this test
    ├── 01-bootc-derived/
    │   ├── Containerfile                # Base derived image
    │   └── usr/lib/bootc/kargs.d/       # Additional files
    │       └── 05-testkargs.toml
    └── 02-bootc-derived-upgraded/
        ├── Containerfile                # Upgraded image
        └── usr/lib/bootc/kargs.d/
            └── 05-testkargs.toml
```

**Naming convention**:
- Subdirectories under `images/` should use numeric prefixes for build order: `01-name`, `02-name`, etc.
- The framework strips the numeric prefix to create the tag suffix
- Example: `01-bootc-derived` → tag suffix `bootc-derived`

**Build context**:
- Each Containerfile is built with its subdirectory as the build context
- Additional files in the subdirectory can be `COPY`'d into the image

#### Accessing images in tests

The framework provides environment variables for each custom image:

```bash
# Format: BOOTC_TEST_IMAGE_<TAG_SUFFIX>
# Example for images/01-bootc-derived/:
echo $BOOTC_TEST_IMAGE_BOOTC_DERIVED
# Output: bootc-registry.test:5000/test-20-image-pushpull-upgrade-bootc-derived

# Example for images/02-bootc-derived-upgraded/:
echo $BOOTC_TEST_IMAGE_BOOTC_DERIVED_UPGRADED
# Output: bootc-registry.test:5000/test-20-image-pushpull-upgrade-bootc-derived-upgraded
```

**Tag structure**:
- Full tags are namespaced with the test name to avoid collisions
- Format: `<registry-url>/<test-name>-<tag-suffix>`
- Example: `bootc-registry.test:5000/test-20-image-pushpull-upgrade-bootc-derived`

**Usage in test scripts** (Nushell):
```nushell
# Use the pre-built image from the framework
let image = $env.BOOTC_TEST_IMAGE_BOOTC_DERIVED

# Switch to the custom image
bootc switch --transport registry $image
```

**Usage in test scripts** (Bash):
```bash
# Use the pre-built image from the framework
image="$BOOTC_TEST_IMAGE_BOOTC_DERIVED"

# Switch to the custom image
bootc switch --transport registry "$image"
```

### Registry environment variables

When tests run with a registry VM, the following environment variables are available:

- `BOOTC_REGISTRY_IP`: IP address of the registry VM (e.g., `192.168.122.100`)
- `BOOTC_REGISTRY_PORT`: Port the registry is listening on (`5000`)
- `BOOTC_REGISTRY_HOSTNAME`: Hostname for TLS validation (`bootc-registry.test`)
- `BOOTC_REGISTRY_URL`: Full URL to the registry (`bootc-registry.test:5000`)
- `BOOTC_TEST_IMAGE_<TAG_SUFFIX>`: Full image reference for each custom image

**TLS configuration**:
- The registry uses self-signed TLS certificates
- Test VMs automatically trust the registry CA certificate
- Hostname `bootc-registry.test` is configured in `/etc/hosts` to point to `$BOOTC_REGISTRY_IP`
- Most operations work without `--tls-verify=false` (exception: host pushing to registry uses `--dest-tls-verify=false`)

**Example usage**:
```bash
# Custom images are pre-built and available via environment variables
bootc switch --transport registry $BOOTC_TEST_IMAGE_BOOTC_DERIVED

# Manual image operations (if needed)
podman tag localhost/my-image $BOOTC_REGISTRY_URL/my-image
podman push $BOOTC_REGISTRY_URL/my-image  # TLS works automatically
```

## Advanced usage

### Preserving VMs for debugging

Preserve VMs after tests complete for debugging:

```bash
cargo xtask run-tmt --preserve-vm --image localhost/bootc-integration readonly
```

When `--preserve-vm` is used:
- Registry VM and test VMs are not automatically cleaned up
- SSH connection details are printed to the console
- Use `bcvk libvirt rm --stop --force <vm-name>` to manually clean up

### Running without a registry

To run tests without the registry VM (legacy mode, not recommended):

```bash
cargo xtask run-tmt --image localhost/bootc-integration readonly
```

Note: Tests that require custom images will fail without a registry VM.

### Manual provisioning

Provision a VM manually for interactive testing:

```bash
cargo xtask tmt-provision --image localhost/bootc-integration
```

This provisions a VM and prints SSH/TMT connection details for manual test execution.

### See also

- `cargo xtask run-tmt --help` - All available options
- `hack/README-registry-tls.md` - TLS certificate architecture and troubleshooting
- `tmt/tests/booted/README.md` - Test structure and authoring guide
