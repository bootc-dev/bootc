# Understanding Makefile vs Justfile:
#
# This file MUST NOT:
# - Spawn podman or virtualization tools
# - Invoke `sudo`
#
# Stated positively, the code invoked from here is only expected to
# operate as part of "a build" that results in a bootc binary
# plus data files. The two key operations are `make`
# and `make install`.
# We expect code run from here is (or can be) inside a container with low
# privileges - running as a nonzero UID even.
#
# Understanding Makefile vs xtask.rs: Basically use xtask.rs if what
# you're doing would turn into a mess of bash code, whether inline here
# or externally in e.g. ./ci/somebashmess.sh etc.

prefix ?= /usr

SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
# https://reproducible-builds.org/docs/archives/
TAR_REPRODUCIBLE = tar --mtime="@${SOURCE_DATE_EPOCH}" --sort=name --owner=0 --group=0 --numeric-owner --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime

# Enable rhsm if we detect the build environment is RHEL-like.
# We may in the future also want to include Fedora+derivatives as
# the code is really tiny.
# (Note we should also make installation of the units conditional on the rhsm feature)
CARGO_FEATURES ?= $(shell . /usr/lib/os-release; if echo "$$ID_LIKE" |grep -qF rhel; then echo rhsm; fi)

all: bin manpages

bin:
	cargo build --release --features "$(CARGO_FEATURES)"

.PHONY: manpages
manpages:
	cargo run --package xtask -- manpages

STORAGE_RELATIVE_PATH ?= $(shell realpath -m -s --relative-to="$(prefix)/lib/bootc/storage" /sysroot/ostree/bootc/storage)
install:
	install -D -m 0755 -t $(DESTDIR)$(prefix)/bin target/release/bootc
	install -D -m 0755 -t $(DESTDIR)$(prefix)/bin target/release/system-reinstall-bootc
	install -d -m 0755 $(DESTDIR)$(prefix)/lib/bootc/bound-images.d
	install -d -m 0755 $(DESTDIR)$(prefix)/lib/bootc/kargs.d
	ln -s "$(STORAGE_RELATIVE_PATH)" "$(DESTDIR)$(prefix)/lib/bootc/storage"
	install -D -m 0755 crates/cli/bootc-generator-stub $(DESTDIR)$(prefix)/lib/systemd/system-generators/bootc-systemd-generator 
	install -d $(DESTDIR)$(prefix)/lib/bootc/install
	install -D -m 0644 -t $(DESTDIR)$(prefix)/share/man/man5 target/man/*.5; \
	install -D -m 0644 -t $(DESTDIR)$(prefix)/share/man/man8 target/man/*.8; \
	install -D -m 0644 -t $(DESTDIR)/$(prefix)/lib/systemd/system systemd/*.service systemd/*.timer systemd/*.path systemd/*.target
	install -d -m 0755 $(DESTDIR)/$(prefix)/lib/systemd/system/multi-user.target.wants
	ln -s ../bootc-status-updated.path $(DESTDIR)/$(prefix)/lib/systemd/system/multi-user.target.wants/bootc-status-updated.path
	ln -s ../bootc-status-updated-onboot.target $(DESTDIR)/$(prefix)/lib/systemd/system/multi-user.target.wants/bootc-status-updated-onboot.target
	install -D -m 0644 -t $(DESTDIR)/$(prefix)/share/doc/bootc/baseimage/base/usr/lib/ostree/ baseimage/base/usr/lib/ostree/prepare-root.conf
	install -d -m 755 $(DESTDIR)/$(prefix)/share/doc/bootc/baseimage/base/sysroot
	cp -PfT baseimage/base/ostree $(DESTDIR)/$(prefix)/share/doc/bootc/baseimage/base/ostree 
	# Ensure we've cleaned out any possibly older files
	rm -vrf $(DESTDIR)$(prefix)/share/doc/bootc/baseimage/dracut
	rm -vrf $(DESTDIR)$(prefix)/share/doc/bootc/baseimage/systemd
	# Copy dracut and systemd config files
	cp -Prf baseimage/dracut $(DESTDIR)$(prefix)/share/doc/bootc/baseimage/dracut
	cp -Prf baseimage/systemd $(DESTDIR)$(prefix)/share/doc/bootc/baseimage/systemd
	# Install fedora-bootc-destructive-cleanup in fedora derivatives 
	ID=$$(. /usr/lib/os-release && echo $$ID); \
	ID_LIKE=$$(. /usr/lib/os-release && echo $$ID_LIKE); \
	if [ "$$ID" = "fedora" ] || [[ "$$ID_LIKE" == *"fedora"* ]]; then \
	ln -s ../bootc-destructive-cleanup.service $(DESTDIR)/$(prefix)/lib/systemd/system/multi-user.target.wants/bootc-destructive-cleanup.service; \
	install -D -m 0755 -t $(DESTDIR)/$(prefix)/lib/bootc contrib/scripts/fedora-bootc-destructive-cleanup; \
	fi

# Run this to also take over the functionality of `ostree container` for example.
# Only needed for OS/distros that have callers invoking `ostree container` and not bootc.
install-ostree-hooks:
	install -d $(DESTDIR)$(prefix)/libexec/libostree/ext
	for x in ostree-container ostree-ima-sign ostree-provisional-repair; do \
	  ln -sf ../../../bin/bootc $(DESTDIR)$(prefix)/libexec/libostree/ext/$$x; \
	done

# Install code in the initramfs, off by default except in builds from git main right now
# Also the systemd unit hardcodes /usr so we give up the farce of supporting $(prefix)
install-initramfs:
	install -D -m 0644 -t $(DESTDIR)/usr/lib/systemd/system crates/initramfs/*.service
	install -D -m 0755 target/release/bootc-initramfs-setup $(DESTDIR)/usr/lib/bootc/initramfs-setup

# Install initramfs files, including dracut module
install-initramfs-dracut: install-initramfs
	install -D -m 0755 -t $(DESTDIR)/usr/lib/dracut/modules.d/51bootc crates/initramfs/dracut/module-setup.sh

# Install the main binary, the ostree hooks, and the integration test suite.
install-all: install install-ostree-hooks
	install -D -m 0755 target/release/tests-integration $(DESTDIR)$(prefix)/bin/bootc-integration-tests

bin-archive: all
	$(MAKE) install DESTDIR=tmp-install && $(TAR_REPRODUCIBLE) --zstd -C tmp-install -cf target/bootc.tar.zst . && rm tmp-install -rf

build-unit-tests:
	cargo t --no-run

# We separate the build of the unit tests from actually running them in some cases
install-unit-tests: build-unit-tests
	cargo t --no-run --frozen
	install -D -m 0755 -t $(DESTDIR)/usr/lib/bootc/units/ $$(cargo t --no-run --message-format=json | jq -r 'select(.profile.test == true and .executable != null) | .executable')
	install -d -m 0755 /usr/bin/
	echo -e '#!/bin/bash\nset -xeuo pipefail\nfor f in /usr/lib/bootc/units/*; do echo $$f && $$f; done' > $(DESTDIR)/usr/bin/bootc-units && chmod a+x $(DESTDIR)/usr/bin/bootc-units

test-bin-archive: all
	$(MAKE) install-all DESTDIR=tmp-install && $(TAR_REPRODUCIBLE) --zstd -C tmp-install -cf target/bootc.tar.zst . && rm tmp-install -rf

# This gates CI by default. Note that for clippy, we gate on
# only the clippy correctness and suspicious lints, plus a select
# set of default rustc warnings.
# We intentionally don't gate on this for local builds in cargo.toml
# because it impedes iteration speed.
CLIPPY_CONFIG = -A clippy::all -D clippy::correctness -D clippy::suspicious -D clippy::disallowed-methods -Dunused_imports -Ddead_code
validate:
	cargo fmt -- --check -l
	cargo test --no-run
	(cd crates/ostree-ext && cargo check --no-default-features)
	(cd crates/lib && cargo check --no-default-features)
	cargo check --features=composefs-backend
	cargo clippy -- $(CLIPPY_CONFIG)
	env RUSTDOCFLAGS='-D warnings' cargo doc --lib
.PHONY: validate
fix-rust:
	cargo clippy --fix --allow-dirty -- $(CLIPPY_CONFIG)
.PHONY: fix-rust

update-generated:
	cargo xtask update-generated
.PHONY: update-generated

vendor:
	cargo xtask $@
.PHONY: vendor

package-rpm:
	cargo xtask $@
.PHONY: package-rpm
