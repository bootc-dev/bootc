#!/usr/bin/env python3
# number: 34
# tmt:
#   summary: Verify bootc sends correct User-Agent header to registries
#   duration: 10m
#
"""
Test that bootc sends the correct User-Agent header when pulling images.

This test starts a mock HTTP registry server, configures it as an insecure
registry, and verifies that bootc's requests include "bootc/" in the User-Agent.

Note: The --user-agent-prefix feature requires skopeo >= 1.21.0. If the
installed skopeo doesn't support it, this test will be skipped.

Note: When insecure=true, container tools first attempt TLS then fall back to
plain HTTP. Our HTTP server will receive an invalid TLS handshake first, which
we ignore and continue serving.
"""

import http.server
import json
import os
import subprocess
import sys
import threading

# Global to capture the user agent
captured_user_agent = None
server_ready = threading.Event()
request_received = threading.Event()
# Global to store the dynamically allocated port
allocated_port = None


def skopeo_supports_user_agent_prefix() -> bool:
    """Check if the installed skopeo supports --user-agent-prefix."""
    try:
        result = subprocess.run(
            ["skopeo", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return "--user-agent-prefix" in result.stdout
    except Exception:
        return False


def parse_os_release() -> dict[str, str]:
    """Parse /usr/lib/os-release into a dictionary."""
    os_release = {}
    try:
        with open("/usr/lib/os-release") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    key, _, value = line.partition("=")
                    # Remove quotes if present
                    value = value.strip('"\'')
                    os_release[key] = value
    except FileNotFoundError:
        pass
    return os_release


def distro_requires_user_agent_support() -> bool:
    """Check if the current distro should have skopeo with --user-agent-prefix.

    Returns True if we're on a distro version that ships skopeo >= 1.21.0,
    meaning the test must not be skipped.
    """
    os_release = parse_os_release()
    distro_id = os_release.get("ID", "")
    version_id = os_release.get("VERSION_ID", "")

    try:
        version = int(version_id)
    except ValueError:
        return False

    # Fedora 43+ ships skopeo 1.21.0+
    if distro_id == "fedora" and version >= 43:
        return True

    return False


class RegistryHandler(http.server.BaseHTTPRequestHandler):
    """Mock registry that captures User-Agent and returns 404."""

    def do_GET(self):
        global captured_user_agent
        captured_user_agent = self.headers.get("User-Agent", "")
        print(f"Request: {self.path}", flush=True)
        print(f"User-Agent: {captured_user_agent}", flush=True)

        # Return a registry-style 404
        self.send_response(404)
        self.send_header("Content-Type", "application/json")
        body = json.dumps({
            "errors": [{"code": "NAME_UNKNOWN", "message": "repository not found"}]
        }).encode()
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        # Signal that we received a valid HTTP request
        request_received.set()

    def log_message(self, format, *args):
        print(format % args, flush=True)


class TolerantHTTPServer(http.server.HTTPServer):
    """HTTP server that ignores errors from TLS probe attempts."""

    def handle_error(self, request, client_address):
        # Silently ignore errors - these are typically TLS handshake attempts
        # that we can't handle. The client will retry with plain HTTP.
        print(f"Ignoring error from {client_address} (likely TLS probe)", flush=True)


def run_server():
    """Run the mock registry server on a dynamically allocated port."""
    global allocated_port
    # Bind to port 0 to let the OS allocate an available port
    server = TolerantHTTPServer(("127.0.0.1", 0), RegistryHandler)
    allocated_port = server.server_address[1]
    server.timeout = 30
    server_ready.set()
    # Handle multiple requests - first few may be TLS probes
    for _ in range(20):
        server.handle_request()
        if captured_user_agent:
            # Got a valid HTTP request with User-Agent, we're done
            break


def main():
    # Check if skopeo supports --user-agent-prefix
    if not skopeo_supports_user_agent_prefix():
        # Get skopeo version for the skip message
        try:
            result = subprocess.run(
                ["skopeo", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            version = result.stdout.strip()
        except Exception:
            version = "unknown"

        # On distros that should have new enough skopeo, fail hard
        if distro_requires_user_agent_support():
            print(f"ERROR: skopeo ({version}) does not support --user-agent-prefix", flush=True)
            print("This distro should have skopeo >= 1.21.0", flush=True)
            return 1

        print(f"SKIP: skopeo ({version}) does not support --user-agent-prefix", flush=True)
        print("This feature requires skopeo >= 1.21.0", flush=True)
        # Exit 0 to skip the test gracefully
        return 0

    print("=== User-Agent Header Test ===", flush=True)

    # Start server in background thread (port allocated dynamically)
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    # Wait for server to be ready and get the allocated port
    if not server_ready.wait(timeout=5):
        print("ERROR: Server failed to start", flush=True)
        return 1

    registry = f"127.0.0.1:{allocated_port}"
    print(f"Server listening on {registry}", flush=True)

    # Configure insecure registry
    registries_conf = f"""[[registry]]
location = "{registry}"
insecure = true
"""
    conf_path = "/etc/containers/registries.conf.d/99-test-insecure.conf"
    print(f"Writing registries config to {conf_path}", flush=True)
    with open(conf_path, "w") as f:
        f.write(registries_conf)
    print(registries_conf, flush=True)

    try:

        # Test with bootc
        print("\n=== Testing with bootc ===", flush=True)
        result = subprocess.run(
            ["bootc", "switch", "--transport", "registry", f"{registry}/test:latest"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        print(f"bootc exit code: {result.returncode}", flush=True)
        print(f"bootc stdout: {result.stdout}", flush=True)
        print(f"bootc stderr: {result.stderr}", flush=True)

        # Wait for server to receive the HTTP request (after TLS probes)
        if not request_received.wait(timeout=10):
            print("ERROR: No HTTP request was received by server", flush=True)
            return 1

        # Check result
        if not captured_user_agent:
            print("ERROR: No User-Agent was captured", flush=True)
            return 1

        print(f"\nCaptured User-Agent: {captured_user_agent}", flush=True)

        if "bootc/" not in captured_user_agent:
            print(f"ERROR: User-Agent does not contain 'bootc/'", flush=True)
            return 1

        print("\nSUCCESS: User-Agent contains 'bootc/'", flush=True)
        return 0

    finally:
        # Cleanup
        if os.path.exists(conf_path):
            os.remove(conf_path)


if __name__ == "__main__":
    sys.exit(main())
