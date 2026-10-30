# bootc is read-only when run in a default container

Currently, running e.g. `podman run <someimage> bootc upgrade` will not work.
There are a variety of reasons for this, such as the basic fact that by
default a `docker|podman run <image>` doesn't know where to update itself;
the image reference is not exposed into the target image (for security/operational
reasons).

## Supported operations

There are only two supported operations in a container environment today:

- `bootc status`: This can reliably be used to detect whether the system is
  actually booted via bootc or not.
- `bootc container lint`: See [man/bootc-container-lint.8.md](man/bootc-container-lint.8.md).

### Testing bootc in a container

Eventually we would like to support having bootc run inside a container environment
primarily for testing purposes. For this, please see the [tracking issue](https://github.com/bootc-dev/bootc/issues/400).
