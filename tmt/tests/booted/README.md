# Booted tests

These are tests that run on booted bootc systems, intended to be executed via TMT (Testing Management Tool).

## Test structure

Tests can be organized in two ways:

### File-based tests (legacy)

Simple tests that don't require custom images:

```
tmt/tests/booted/
└── test-01-readonly.nu          # Test script with metadata
```

### Directory-based tests (recommended)

Tests that need custom container images:

```
tmt/tests/booted/
└── test-20-image-pushpull-upgrade/
    ├── test.nu                    # Test script
    └── images/                    # Custom images for this test
        ├── 01-bootc-derived/
        │   ├── Containerfile      # Image definition
        │   └── usr/...            # Additional files to include
        └── 02-bootc-derived-upgraded/
            └── Containerfile
```

## Writing a new test

### 1. Create test metadata

Every test file (`test.nu` or `test-*.nu`) must include metadata at the top:

```nushell
# number: 30
# tmt:
#   summary: Brief description of what this test does
#   duration: 30m
#
# Optional: Test requires specific features
# tmt:
#   adjust:
#     - when: running_env != image_mode
#       enabled: false
#       because: requires features only available in image mode
```

**Metadata fields**:
- `number`: Test number for ordering (must be unique)
- `summary`: One-line description of the test
- `duration`: Expected test runtime
- `adjust`: Optional conditions to enable/disable the test

### 2. Choose test structure

**Use file-based structure** if:
- Test doesn't need custom container images
- Test only uses the base bootc image

**Use directory-based structure** if:
- Test needs custom container images
- Test needs to include additional files in images
- Test needs multiple image variants

### 3. Create custom images (directory-based tests only)

Create an `images/` subdirectory with numbered subdirectories:

```
test-30-my-test/
└── images/
    ├── 01-base-image/
    │   └── Containerfile
    └── 02-modified-image/
        ├── Containerfile
        └── usr/local/bin/my-script.sh
```

**Naming convention**:
- Use numeric prefix for build order: `01-name`, `02-name`
- Prefix is stripped to create the tag suffix
- Example: `01-bootc-derived` → `BOOTC_TEST_IMAGE_BOOTC_DERIVED`

**Containerfile requirements**:
- Must start with `FROM localhost:5000/bootc` (the base test image from registry)
- Build context is the subdirectory containing the Containerfile
- Can `COPY` files from the subdirectory into the image

**Example Containerfile**:
```dockerfile
FROM localhost:5000/bootc

# Install packages
RUN dnf install -y my-package && dnf clean all

# Add custom files
COPY usr/ /usr/

# Create directories with specific labels
RUN mkdir /mydir && \
    echo "/mydir /somedir" >> /etc/selinux/targeted/contexts/files/file_contexts.subs_dist
```

### 4. Write the test script

**Access custom images via environment variables**:

```nushell
# Use the pre-built image from the framework
let image = $env.BOOTC_TEST_IMAGE_BOOTC_DERIVED

# Switch to the custom image
bootc switch --transport registry $image

# Reboot to activate
tmt-reboot
```

**Environment variables available**:
- `BOOTC_TEST_IMAGE_<TAG_SUFFIX>`: Full reference for each custom image
- `BOOTC_REGISTRY_URL`: Registry hostname and port (e.g., `bootc-registry.test:5000`)
- `BOOTC_REGISTRY_IP`: IP address of registry VM
- `TMT_REBOOT_COUNT`: Current reboot count (0, 1, 2, ...)

**Common patterns**:

```nushell
# Multi-boot test pattern
def main [] {
    match $env.TMT_REBOOT_COUNT? {
        null | "0" => first_boot,
        "1" => second_boot,
        "2" => third_boot,
        $o => { error make { msg: $"Invalid TMT_REBOOT_COUNT ($o)" } },
    }
}

def first_boot [] {
    # Perform setup and switch to new image
    bootc switch --transport registry $env.BOOTC_TEST_IMAGE_BOOTC_DERIVED
    tmt-reboot
}

def second_boot [] {
    # Verify the new image is running
    let st = bootc status --json | from json
    assert ($st.status.booted.image.image | str contains "bootc-derived")
}
```

### 5. Update TMT integration

After creating or modifying tests, regenerate TMT configuration:

```bash
cargo xtask update-integration
```

This will:
- Scan for all test files in `tmt/tests/booted/`
- Discover custom images in `images/` subdirectories
- Generate `tmt/tests/tests.fmf` with test definitions
- Update `tmt/plans/integration.fmf` with test plans

### 6. Test your changes

Run your specific test:

```bash
just test-tmt my-test
```

Or run all tests:

```bash
just test-tmt
```

## Best practices

### Custom images

1. **Clean up after installations**: Remove DNF caches and logs to keep images small
   ```dockerfile
   RUN dnf install -y package && \
       dnf clean all && \
       rm -rf /var/log/dnf* /var/cache/dnf
   ```

2. **Use build order prefixes**: Ensure images build in the correct dependency order
   - `01-base-image/` builds first
   - `02-derived-image/` can reference `01-base-image` if needed

3. **Include only necessary files**: The build context is the subdirectory, so organize files accordingly

4. **Document image purpose**: Add comments in Containerfile explaining what the image tests

### Test scripts

1. **Use assertions liberally**: Verify all expected conditions
   ```nushell
   assert ($condition) "Error message explaining what went wrong"
   ```

2. **Handle multi-boot scenarios**: Use `TMT_REBOOT_COUNT` to track boot state
   ```nushell
   match $env.TMT_REBOOT_COUNT? {
       null | "0" => first_boot,
       "1" => second_boot,
       # ...
   }
   ```

3. **Check preconditions**: Verify required features are available
   ```nushell
   let soft_reboot_capable = "/usr/lib/systemd/system/soft-reboot.target" | path exists
   if not $soft_reboot_capable {
       echo "Skipping, system is not soft reboot capable"
       return
   }
   ```

4. **Clean up state**: Don't leave persistent changes that could affect other tests

5. **Use descriptive test names**: Function names and tap messages should clearly indicate what's being tested

### TMT metadata

1. **Set realistic durations**: Account for image builds, reboots, and test execution

2. **Use adjust conditions**: Disable tests that require specific features
   ```yaml
   adjust:
     - when: running_env != image_mode
       enabled: false
       because: requires features only available in image mode
   ```

3. **Write clear summaries**: Should clearly state what the test verifies

## Debugging tests

### View test output

Test results are stored in TMT's run directory. To see detailed output:

```bash
# Run with verbose output
cargo xtask run-tmt --image localhost/bootc-integration my-test 2>&1 | tee test.log

# After a failure, check the TMT report
tmt run -i <run-id> report -vvv
```

### Preserve VMs for debugging

Keep VMs alive after tests for manual inspection:

```bash
cargo xtask run-tmt --preserve-vm --image localhost/bootc-integration my-test
```

This will print SSH connection details:
```
Test VM name: bootc-tmt-abc123-plan-30-my-test
Test VM SSH port: 12345
Test VM SSH key: target/bootc-tmt-abc123-plan-30-my-test.ssh-key

To connect to test VM via SSH:
  ssh -i target/bootc-tmt-abc123-plan-30-my-test.ssh-key -p 12345 -o IdentitiesOnly=yes root@localhost
```

### Common issues

**Custom image not found**:
- Verify the images/ directory exists and contains Containerfiles
- Run `cargo xtask update-integration` to regenerate TMT configs
- Check that environment variable name matches: `BOOTC_TEST_IMAGE_<TAG_SUFFIX>`

**Image build failures**:
- Check Containerfile syntax
- Verify base image reference is `FROM localhost:5000/bootc`
- Ensure any COPY paths are relative to the subdirectory

**Test VM can't reach registry**:
- Verify registry VM is running (should be automatic)
- Check `$BOOTC_REGISTRY_URL` is set in test environment
- Confirm TLS certificates were generated: `ls hack/.registry-certs/`

## Examples

See existing tests for examples:
- `test-20-image-pushpull-upgrade/` - Multi-image test with upgrade scenario
- `test-25-soft-reboot/` - Multi-boot test with kernel args
- `test-27-custom-selinux-policy/` - SELinux label verification
- `test-29-soft-reboot-selinux-policy/` - SELinux policy modification test
