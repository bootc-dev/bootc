#!/bin/bash
# Setup certificates for registry before building container images
# This script should be run before building Containerfile.registry
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CERT_DIR="$PROJECT_ROOT/hack/.registry-certs"

# Create certificate directory if it doesn't exist
mkdir -p "$CERT_DIR"

# Check if certificates already exist
if [ -f "$CERT_DIR/ca.pem" ] && [ -f "$CERT_DIR/registry-cert.pem" ] && [ -f "$CERT_DIR/registry-key.pem" ]; then
    echo "Certificates already exist in $CERT_DIR"
    echo "To regenerate, remove the directory and run again: rm -rf $CERT_DIR"
    exit 0
fi

echo "Generating registry certificates in $CERT_DIR..."

# Generate a private key for the CA
openssl genrsa -out "$CERT_DIR/ca-key.pem" 4096 2>/dev/null

# Generate a self-signed CA certificate
openssl req -new -x509 -days 3650 -key "$CERT_DIR/ca-key.pem" \
    -out "$CERT_DIR/ca.pem" \
    -subj "/C=US/ST=Test/L=Test/O=Bootc Test Registry/CN=Bootc Test CA" 2>/dev/null

# Generate a private key for the registry server
openssl genrsa -out "$CERT_DIR/registry-key.pem" 4096 2>/dev/null

# Create a certificate signing request for the registry
# Use a predictable hostname instead of hardcoded IPs
# Test VMs will add this hostname to /etc/hosts pointing to the actual registry IP
cat > "$CERT_DIR/registry-csr.cnf" <<'EOF'
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C = US
ST = Test
L = Test
O = Bootc Test Registry
CN = bootc-registry.test

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = bootc-registry.test
DNS.2 = registry
DNS.3 = localhost
# Localhost IP for local testing
IP.1 = 127.0.0.1
EOF

openssl req -new -key "$CERT_DIR/registry-key.pem" \
    -out "$CERT_DIR/registry.csr" \
    -config "$CERT_DIR/registry-csr.cnf" 2>/dev/null

# Sign the registry certificate with our CA
openssl x509 -req -in "$CERT_DIR/registry.csr" \
    -CA "$CERT_DIR/ca.pem" \
    -CAkey "$CERT_DIR/ca-key.pem" \
    -CAcreateserial \
    -out "$CERT_DIR/registry-cert.pem" \
    -days 3650 \
    -extensions v3_req \
    -extfile "$CERT_DIR/registry-csr.cnf" 2>/dev/null

# Set appropriate permissions
chmod 644 "$CERT_DIR/registry-cert.pem"
chmod 600 "$CERT_DIR/registry-key.pem"
chmod 644 "$CERT_DIR/ca.pem"
chmod 600 "$CERT_DIR/ca-key.pem"

# Create podman cert directory structure for localhost:5000
# Podman expects: <cert-dir>/<hostname:port>/ca.crt
# Client certificates are not needed since the registry doesn't require mTLS
mkdir -p "$CERT_DIR/localhost:5000"
cp "$CERT_DIR/ca.pem" "$CERT_DIR/localhost:5000/ca.crt"
chmod 644 "$CERT_DIR/localhost:5000/ca.crt"

echo "✓ Certificates generated successfully in $CERT_DIR"
echo "  CA certificate: $CERT_DIR/ca.pem"
echo "  Registry certificate: $CERT_DIR/registry-cert.pem"
echo "  Registry key: $CERT_DIR/registry-key.pem"
echo "  Podman cert dir: $CERT_DIR/localhost:5000/ca.crt"
echo ""
echo "These certificates will be used by:"
echo "  - Containerfile.registry: For the registry service TLS"
echo "  - Containerfile: For the test VMs to trust the registry CA"
echo "  - podman push: For pushing to localhost:5000 with --cert-dir"
