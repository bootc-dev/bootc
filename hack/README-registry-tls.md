# Secure Registry Setup for TMT Tests

This document explains how the TMT test registry uses TLS with self-signed certificates for secure communication.

## Overview

The TMT test infrastructure uses a registry VM to test image push/pull operations. The registry is now configured with TLS using self-signed certificates to ensure secure communication between the registry and test VMs.

## Certificate Architecture

### Components

1. **CA Certificate** (`ca.pem`): A self-signed Certificate Authority used to sign the registry certificate
2. **Registry Certificate** (`registry-cert.pem`): Server certificate for the registry, signed by the CA
3. **Registry Private Key** (`registry-key.pem`): Private key for the registry certificate

### Certificate Locations

- **Build-time**: Certificates are generated in `hack/.registry-certs/` at project root (git-ignored)
- **Registry VM**: Certificates are stored in `/etc/registry/certs/` and served by the registry container
- **Test VMs**: The CA certificate is installed to `/usr/share/pki/ca-trust-source/anchors/bootc-registry-ca.crt`

## Building Images with TLS Support

### Step 1: Generate Certificates

Before building either the registry image or test images, generate the certificates:

```bash
./hack/setup-registry-certs.sh
```

This script:
- Creates `hack/.registry-certs/` directory at project root
- Generates a self-signed CA certificate
- Generates a registry server certificate signed by the CA
- Certificates are valid for 10 years
- Uses hostname `bootc-registry.test` for TLS validation (instead of hardcoded IPs)
- Test VMs automatically configure `/etc/hosts` to resolve this hostname to the registry's actual IP

The script is idempotent - if certificates already exist, it will skip generation. To regenerate:

```bash
rm -rf hack/.registry-certs
./hack/setup-registry-certs.sh
```

### Step 2: Build the Registry Image

Build the registry image with:

```bash
podman build -f hack/Containerfile.registry -t bootc-registry .
```

This will:
- Copy the pre-generated certificates from `hack/.registry-certs/`
- Install them in `/etc/registry/certs/`
- Configure the registry Quadlet service to use TLS
- Install the CA certificate to the system trust store

### Step 3: Build the Test Image

Build the test image with:

```bash
podman build -f hack/Containerfile -t localhost/bootc-derived .
```

This will:
- Copy the CA certificate from `hack/.registry-certs/ca.pem`
- Install it to the system trust store at `/usr/share/pki/ca-trust-source/anchors/`
- Run `update-ca-trust` to add it to the trusted certificates

## How It Works

### Registry VM

The registry VM runs a Podman Quadlet service defined in `/usr/share/containers/systemd/registry.container`:

```ini
[Container]
Image=quay.io/libpod/registry:2.8.2
PublishPort=5000:5000
Volume=/var/lib/registry:/var/lib/registry:Z
Volume=/etc/registry/certs:/certs:Z,ro
Environment=REGISTRY_HTTP_TLS_CERTIFICATE=/certs/registry-cert.pem
Environment=REGISTRY_HTTP_TLS_KEY=/certs/registry-key.pem
```

The registry container:
- Listens on port 5000 with TLS enabled
- Uses the server certificate and key from `/etc/registry/certs/`
- Certificate is issued for hostname `bootc-registry.test`
- Validates client connections using TLS
- Host uses `--dest-tls-verify=false` when pushing (due to --dest-cert-dir limitations in user namespaces)

### Hostname Resolution

The TLS certificate is issued for hostname `bootc-registry.test` instead of hardcoded IP addresses.
This avoids certificate validation failures when the registry's IP is dynamically assigned.

Test VMs automatically configure hostname resolution during TMT's prepare phase:

1. TMT sets environment variables:
   - `BOOTC_REGISTRY_IP`: The actual IP address of the registry VM
   - `BOOTC_REGISTRY_HOSTNAME`: `bootc-registry.test`
   - `BOOTC_REGISTRY_URL`: `bootc-registry.test:5000`

2. A prepare script adds an entry to `/etc/hosts`:
   ```
   192.168.1.124 bootc-registry.test
   ```

3. When tests use `BOOTC_REGISTRY_URL`, DNS resolves the hostname to the registry's IP,
   and TLS validates the certificate against the hostname.

### Test VMs

Test VMs:
- Have the CA certificate installed in their system trust store
- Automatically configure `/etc/hosts` to resolve `bootc-registry.test` to the registry IP
- Can connect to the registry using HTTPS without `--tls-verify=false`
- Podman and Skopeo automatically trust the registry's certificate

## Testing the Setup

To test the secure registry setup:

```bash
# Generate certificates
./hack/setup-registry-certs.sh

# Build registry image
podman build -f hack/Containerfile.registry -t bootc-registry .

# Build test image
podman build -f hack/Containerfile -t localhost/bootc-derived .

# Run TMT tests with registry
cargo xtask run-tmt --image localhost/bootc-derived --registry-image bootc-registry
```

## Troubleshooting

### Certificate Errors

If you see TLS certificate errors:

1. Ensure certificates were generated before building images:
   ```bash
   ls -la hack/.registry-certs/
   ```

2. Verify the CA certificate is in the test image:
   ```bash
   podman run --rm localhost/bootc-derived ls -la /usr/share/pki/ca-trust-source/anchors/
   ```

3. Check if the certificate is trusted:
   ```bash
   podman run --rm localhost/bootc-derived trust list | grep -i bootc
   ```

### Registry Connection Issues

If the registry is unreachable:

1. Verify the registry service is running in the registry VM:
   ```bash
   ssh <registry-vm> systemctl status registry.service
   ```

2. Check registry logs:
   ```bash
   ssh <registry-vm> podman logs registry
   ```

3. Verify certificates are mounted correctly:
   ```bash
   ssh <registry-vm> ls -la /etc/registry/certs/
   ```

## Security Considerations

### Self-Signed Certificates

These certificates are **self-signed** and intended **only for testing**. They:
- Are not validated by any external Certificate Authority
- Should never be used in production
- Are regenerated for each test environment
- Are automatically trusted only within the test VMs

### Certificate Validity

- Certificates are valid for 10 years from generation
- Certificate is issued for hostname `bootc-registry.test` (not IP addresses)
- Test VMs use `/etc/hosts` to resolve the hostname to the actual registry IP
- The CA private key is stored in `hack/.registry-certs/ca-key.pem` (git-ignored)

### Network Security

- The registry is only accessible on the test network (libvirt bridge)
- TLS encryption protects image data in transit
- No authentication is configured (registry is open to the test network)

## Files Modified

- `hack/setup-registry-certs.sh` - Script to generate certificates
- `hack/Containerfile.registry` - Registry image with TLS support
- `hack/Containerfile` - Test image with CA certificate trust
- `tmt/tests/booted/test-image-pushpull-upgrade.nu` - Removed `--tls-verify=false`
- `crates/xtask/src/tmt.rs` - Removed `--tls-verify=false` from base image push
- `.gitignore` - Added `hack/.registry-certs/` to ignore generated certificates
