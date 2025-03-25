prefix ?= /usr

SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
# https://reproducible-builds.org/docs/archives/
TAR_REPRODUCIBLE = tar --mtime="@${SOURCE_DATE_EPOCH}" --sort=name --owner=0 --group=0 --numeric-owner --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime

all:
	cargo build --release
    
install:
	install -D -m 0755 -t $(DESTDIR)$(prefix)/bin target/release/bootc
	install -D -m 0755 -t $(DESTDIR)$(prefix)/bin target/release/system-reinstall-bootc
	install -d -m 0755 $(DESTDIR)$(prefix)/lib/bootc/bound-images.d
	install -d -m 0755 $(DESTDIR)$(prefix)/lib/bootc/kargs.d
	ln -s /sysroot/ostree/bootc/storage $(DESTDIR)$(prefix)/lib/bootc/storage
	install -D -m 0755 cli/bootc-generator-stub $(DESTDIR)$(prefix)/lib/systemd/system-generators/bootc-systemd-generator 
	install -d $(DESTDIR)$(prefix)/lib/bootc/install
	# Support installing pre-generated man pages shipped in source tarball, to avoid
	# a dependency on pandoc downstream.  But in local builds these end up in target/man,
	# so we honor that too.
	for d in man target/man; do \
	  if test -d $$d; then \
	    install -D -m 0644 -t $(DESTDIR)$(prefix)/share/man/man5 $$d/*.5; \
	    install -D -m 0644 -t $(DESTDIR)$(prefix)/share/man/man8 $$d/*.8; \
	  fi; \
	  done
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

# Run this to also take over the functionality of `ostree container` for example.
# Only needed for OS/distros that have callers invoking `ostree container` and not bootc.
install-ostree-hooks:
	install -d $(DESTDIR)$(prefix)/libexec/libostree/ext
	for x in ostree-container ostree-ima-sign ostree-provisional-repair; do \
	  ln -sf ../../../bin/bootc $(DESTDIR)$(prefix)/libexec/libostree/ext/$$x; \
	done

# Install the main binary, the ostree hooks, and the integration test suite.
install-all: install install-ostree-hooks
	install -D -m 0755 target/release/tests-integration $(DESTDIR)$(prefix)/bin/bootc-integration-tests 

bin-archive: all
	$(MAKE) install DESTDIR=tmp-install && $(TAR_REPRODUCIBLE) -C tmp-install -cf target/bootc.tar . && rm tmp-install -rf

test-bin-archive: all
	$(MAKE) install-all DESTDIR=tmp-install && $(TAR_REPRODUCIBLE) -C tmp-install -cf target/bootc.tar . && rm tmp-install -rf

test-tmt:
	cargo xtask test-tmt

# This gates CI by default. Note that for clippy, we gate on
# only the clippy correctness and suspicious lints, plus a select
# set of default rustc warnings.
# We intentionally don't gate on this for local builds in cargo.toml
# because it impedes iteration speed.
CLIPPY_CONFIG = -A clippy::all -D clippy::correctness -D clippy::suspicious -Dunused_imports -Ddead_code
validate-rust:
	cargo fmt -- --check -l
	cargo test --no-run
	(cd lib && cargo check --no-default-features)
	cargo clippy -- $(CLIPPY_CONFIG)
	env RUSTDOCFLAGS='-D warnings' cargo doc --lib
.PHONY: validate-rust
fix-rust:
	cargo clippy --fix --allow-dirty -- $(CLIPPY_CONFIG)
.PHONY: fix-rust

validate: validate-rust
	ruff check
.PHONY: validate

update-generated:
	cargo xtask update-generated
.PHONY: update-generated

vendor:
	cargo xtask $@
.PHONY: vendor

package-rpm:
	cargo xtask $@
.PHONY: package-rpm
