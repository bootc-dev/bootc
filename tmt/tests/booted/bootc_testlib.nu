# A simple nushell "library" for the

# This is a workaround for what must be a systemd bug
# that seems to have appeared in C10S
# TODO diagnose and fill in here
export def reboot [] {
    # Allow more delay for bootc to settle
    sleep 120sec

    tmt-reboot
}

# True if we're running in bcvk with `--bind-storage-ro` and
# we can expect to be able to pull container images from the host.
# See xtask.rs
export def have_hostexports [] {
    $env.BCVK_EXPORT? == "1"
}

# Parse the kernel commandline into a list.
# This is not a proper parser, but good enough
# for what we need here.
export def parse_cmdline []  {
    open /proc/cmdline | str trim | split row " "
}

# cstor-dist configuration for authenticated registry testing
# cstor-dist serves images from containers-storage via an authenticated OCI registry endpoint
# https://github.com/ckyrouac/cstor-dist
const CSTOR_DIST_IMAGE = "ghcr.io/ckyrouac/cstor-dist:latest"
const CSTOR_DIST_USER = "testuser"
const CSTOR_DIST_PASS = "testpass"
const CSTOR_DIST_PORT = 8000

# The registry address for cstor-dist
export const CSTOR_DIST_REGISTRY = $"localhost:($CSTOR_DIST_PORT)"

# Start cstor-dist with basic auth on localhost
# Fails if cstor-dist cannot be started
export def start_cstor_dist [] {
    print "Starting cstor-dist with basic auth..."

    # Pull test images that cstor-dist will serve
    print "Pulling test images for cstor-dist to serve..."
    podman pull docker.io/library/alpine:latest
    podman pull docker.io/library/busybox:latest

    # Run cstor-dist container with auth enabled
    # Mount the local containers storage so cstor-dist can serve images from it
    let storage_path = if ("/var/lib/containers/storage" | path exists) {
        "/var/lib/containers/storage"
    } else {
        $"($env.HOME)/.local/share/containers/storage"
    }

    (podman run --privileged --rm -d --name cstor-dist-auth
        -p $"($CSTOR_DIST_PORT):8000"
        -v $"($storage_path):/var/lib/containers/storage"
        $CSTOR_DIST_IMAGE --username $CSTOR_DIST_USER --password $CSTOR_DIST_PASS)

    # Wait for cstor-dist to be ready by testing HTTP connection
    # Loop for up to 20 seconds
    print "Waiting for cstor-dist to be ready..."
    let auth_header = $"($CSTOR_DIST_USER):($CSTOR_DIST_PASS)" | encode base64
    mut ready = false
    for i in 1..20 {
        let result = do { curl -sf -H $"Authorization: Basic ($auth_header)" $"http://($CSTOR_DIST_REGISTRY)/v2/" } | complete
        if $result.exit_code == 0 {
            $ready = true
            break
        }
        print $"Attempt ($i)/20: cstor-dist not ready yet..."
        sleep 1sec
    }

    if not $ready {
        # Show container logs for debugging
        print "cstor-dist failed to start. Container logs:"
        podman logs cstor-dist-auth
        error make { msg: "cstor-dist failed to become ready within 20 seconds" }
    }

    print $"cstor-dist running on ($CSTOR_DIST_REGISTRY)"
}

# Get cstor-dist auth config
export def get_cstor_auth [] {
    # Base64 encode the credentials for auth.json
    let auth_b64 = $"($CSTOR_DIST_USER):($CSTOR_DIST_PASS)" | encode base64
    {
        registry: $CSTOR_DIST_REGISTRY,
        auth_b64: $auth_b64
    }
}

# Configure insecure registry for cstor-dist (no TLS)
export def setup_insecure_registry [] {
    mkdir /etc/containers/registries.conf.d
    (echo $"[[registry]]\nlocation=\"($CSTOR_DIST_REGISTRY)\"\ninsecure=true"
        | save -f /etc/containers/registries.conf.d/99-cstor-dist.conf)
}

# Set up auth.json on the running system with cstor-dist credentials
export def setup_system_auth [] {
    mkdir /run/ostree
    let cstor = get_cstor_auth
    print $"Setting up system auth for cstor-dist at ($cstor.registry)"
    let auth_json = $'{"auths": {"($cstor.registry)": {"auth": "($cstor.auth_b64)"}}}'
    echo $auth_json | save -f /run/ostree/auth.json
}
