# Build the container image from current sources
build *ARGS:
    podman build --jobs=4 -t localhost/bootc {{ARGS}} .

# This container image has additional testing content and utilities
build-integration-test-image *ARGS: build
    podman build --jobs=4 -t localhost/bootc-integration -f hack/Containerfile {{ARGS}} .

# Run container integration tests
run-container-integration: build-integration-test-image
    podman run --rm localhost/bootc-integration bootc-integration-tests container

unittest *ARGS:
    podman build --jobs=4 --target units -t localhost/bootc-units --build-arg=unitargs={{ARGS}} .
