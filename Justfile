# Build the container image from current sources
build *ARGS:
    podman build --jobs=4 -t localhost/bootc {{ARGS}} .

# This container image has additional testing content and utilities
build-integration-test-image *ARGS: build
    podman build --jobs=4 -t localhost/bootc-integration -f hack/Containerfile {{ARGS}} .

# Run container integration tests
run-container-integration: build-integration-test-image
    podman run --rm localhost/bootc-integration bootc-integration-tests container

# These tests may spawn their own container images.
run-container-external-tests:
   ./tests/container/run localhost/bootc

unittest *ARGS:
    podman build --jobs=4 --target units -t localhost/bootc-units --build-arg=unitargs={{ARGS}} .

# Update all generated files (man pages and JSON schemas)
#
# This is the unified command that:
# - Auto-discovers new CLI commands and creates man page templates
# - Syncs CLI options from Rust code to existing man page templates  
# - Updates JSON schema files
#
# Use this after adding, removing, or modifying CLI options or schemas.
update-generated:
    cargo run -p xtask update-generated
