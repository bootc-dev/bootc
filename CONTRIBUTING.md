# Contributing to bootc

Thanks for your interest in contributing!  At the current time,
bootc is implemented in Rust, and calls out to important components
which are written in Go (e.g. https://github.com/containers/image)
as well as C (e.g. https://github.com/ostreedev/ostree/).  Depending
on what area you want to work on, you'll need to be familiar with
the relevant language.

## Note: Before writing a big patch

If you plan to contribute a large change, please get in touch *before*
submitting a pull request by e.g. filing an issue describing your proposed
change. This will help ensure alignment.

## Development environment

There isn't a single approach to working on bootc; however
the primary developers tend to use Linux host systems,
and test in Linux VMs.  One specifically recommended
approach is to use [toolbox](https://github.com/containers/toolbox/)
to create a containerized development environment
(it's possible, though not necessary to create the toolbox
 dev environment using a bootc image as well).

At the current time most upstream developers use a Fedora derivative
as a base, and the [hack/Containerfile](hack/Containerfile) defaults
to Fedora.  However, bootc itself is not intended to strongly tie to a particular
OS or distribution, and patches to handle others are gratefully
accepted!

## Key recommended ingredients:

- A development environment (toolbox or a host) with a Rust and C compiler, etc.
  While this isn't specific to bootc, you will find the experience of working on Rust
  is greatly aided with use of e.g. [rust-analyzer](https://github.com/rust-lang/rust-analyzer/).
- Install [bcvk](https://github.com/bootc-dev/bcvk).

## Ensure you're familiar with a bootc system

Worth stating: before you start diving into the code you should understand using
the system as a user and how it works.  See the user documentation for that.

## The Justfile

The [Justfile](Justfile) is the primary interface for building and testing bootc.

```bash
just --list           # Show all targets organized by group
just list-variants    # Show available build variants and current config
```

### Building from source

Edit the source code; a simple thing to do is add e.g.
`eprintln!("hello world");` into `run_from_opt` in [crates/lib/src/cli.rs](crates/lib/src/cli.rs).
You can run `make` or `cargo build` to build that locally. However, a key
next step is to get that binary into a bootc container image.

Running `just` defaults to `just build` which will build a container
from the current source code; the result will be named `localhost/bootc`.

### Running an interactive shell in an environment from the container

You can of course `podman run --rm -ti localhost/bootc bash` to get a shell,
and try running `bootc`.

### Running container-oriented integration tests

```bash
just test-container
```

### Running (TMT) integration tests

A common cycle here is you'll edit e.g. `deploy.rs` and want to run the
tests that perform an upgrade:

```bash
just test-tmt local-upgrade-reboot
```

To run a specific test:

```bash
just test-tmt readonly
```

### Faster iteration cycles

The test cycle currently builds a disk image and creates a new ephemeral
VM for each test run.

You can shortcut some iteration cycles by having a more persistent
environment where you run bootc.

#### Upgrading from the container image

One good approach is to create a persistent target virtual machine via e.g.
`bcvk libvirt run` (or a cloud VM), and then after doing a `just build` and getting
a container image, you can directly upgrade to that image.

For the local case, check out [cstor-dist](https://github.com/cgwalters/cstor-dist).
Another alternative is mounting via virtiofs (see e.g. [this PR to bcvk](https://github.com/bootc-dev/bcvk/pull/16)).
If you're using libvirt, see [this document](https://libvirt.org/kbase/virtiofs.html).

#### Running bootc against a live environment

If your development environment host is also a bootc system (e.g. a
workstation or a virtual server) one way to shortcut some cycles is just
to directly run the output of the built binary against your host.

Say for example your host is a Fedora 42 workstation (based on bootc),
then you can `cargo b --release` directly in a Fedora 42 container
or even on your host system, and then directly run e.g. `./target/release/bootc upgrade`
etc.

### Testing with composefs (sealed images)

To build and test with the experimental composefs backend:

```bash
# Build a sealed image with auto-generated test Secure Boot keys
just build-sealed

# Run composefs-specific tests
just test-composefs

# Validate that composefs digests match between build and install views
# (useful for debugging mtime/metadata issues)
just validate-composefs-digest
```

The `build-sealed` target generates test Secure Boot keys in `target/test-secureboot/`
and builds a complete sealed image with UKI. See [experimental-composefs.md](docs/src/experimental-composefs.md)
for more information on sealed images.


### Debugging via lldb

The `hack/lldb` directory contains an example of how to use lldb to debug bootc code.
`hack/lldb/deploy.sh` can be used to build and deploy a bootc VM in libvirt with an lldb-server
running as a systemd service. Depending on your editor, you can then connect to the lldb server
to use an interactive debugger, and set up the editor to build and push the new binary to the VM.
`hack/lldb/dap-example-vim.lua` is an example for neovim.

The VM can be connected to via `ssh test@bootc-lldb` if you have [nss](https://libvirt.org/nss.html)
enabled.

For some bootc install commands, it's simpler to run the lldb-server in a container, e.g.

```bash
sudo podman run --pid=host --network=host --privileged --security-opt label=type:unconfined_t -v /var/lib/containers:/var/lib/containers -v /dev:/dev -v .:/output localhost/bootc-lldb lldb-server platform --listen "*:1234" --server
```

## Code linting

The `make validate` target runs checks locally that we gate on
in CI, currently around `cargo fmt` and `cargo clippy`.

## Running the tests

First, you can run many unit tests with `cargo test`.

### container tests

There's a small set of tests which are designed to run inside a bootc container
and are built into the default container image:

```
$ just test-container
```

## Submitting a patch

The podman project has some [generic useful guidance](https://github.com/containers/podman/blob/main/CONTRIBUTING.md#submitting-pull-requests);
like that project, a "Developer Certificate of Origin" is required.

### Sign your PRs

The sign-off is a line at the end of the explanation for the patch. Your
signature certifies that you wrote the patch or otherwise have the right to pass
it on as an open-source patch. The rules are simple: if you can certify
the below (from [developercertificate.org](https://developercertificate.org/)):

```
Developer Certificate of Origin
Version 1.1

Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
660 York Street, Suite 102,
San Francisco, CA 94110 USA

Everyone is permitted to copy and distribute verbatim copies of this
license document, but changing it is not allowed.

Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

Then you just add a line to every git commit message:

    Signed-off-by: Joe Smith <joe.smith@email.com>

Use your real name (sorry, no pseudonyms or anonymous contributions.)

If you set your `user.name` and `user.email` git configs, you can sign your
commit automatically with `git commit -s`.

### Git commit style

Please look at `git log` and match the commit log style, which is very
similar to the
[Linux kernel](https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git).

You may use `Signed-off-by`, but we're not requiring it.

**General Commit Message Guidelines**:

1. Title
    - Specify the context or category of the changes e.g. `lib` for library changes, `docs` for document changes, `bin/<command-name>` for command changes, etc.
    - Begin the title with the first letter of the first word capitalized.
    - Aim for less than 50 characters, otherwise 72 characters max.
    - Do not end the title with a period.
    - Use an [imperative tone](https://en.wikipedia.org/wiki/Imperative_mood).
2. Body
    - Separate the body with a blank line after the title.
    - Begin a paragraph with the first letter of the first word capitalized.
    - Each paragraph should be formatted within 72 characters.
    - Content should be about what was changed and why this change was made.
    - If your commit fixes an issue, the commit message should end with `Closes: #<number>`.

Commit Message example:

```bash
<context>: Less than 50 characters for subject title

A paragraph of the body should be within 72 characters.

This paragraph is also less than 72 characters.
```

For more information see [How to Write a Git Commit Message](https://chris.beams.io/posts/git-commit/)
