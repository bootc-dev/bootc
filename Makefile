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
	install -D -m 0755 crates/cli/bootc-generator-stub $(DESTDIR)$(prefix)/lib/systemd/system-generators/bootc-systemd-generator 
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

# Install the main binary, the ostree hooks, and the integration test suite.
install-all: install install-ostree-hooks
	install -D -m 0755 target/release/tests-integration $(DESTDIR)$(prefix)/bin/bootc-integration-tests 

bin-archive: all
	$(MAKE) install DESTDIR=tmp-install && $(TAR_REPRODUCIBLE) --zstd -C tmp-install -cf target/bootc.tar.zst . && rm tmp-install -rf

test-bin-archive: all
	$(MAKE) install-all DESTDIR=tmp-install && $(TAR_REPRODUCIBLE) --zstd -C tmp-install -cf target/bootc.tar.zst . && rm tmp-install -rf

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
	(cd crates/ostree-ext && cargo check --no-default-features)
	(cd crates/lib && cargo check --no-default-features)
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

# Create a release commit with updated version
# Usage: make release-commit VERSION=1.5.0
release-commit:
	@if [ -z "$(VERSION)" ]; then \
		echo "Error: VERSION is required. Usage: make release-commit VERSION=1.5.0"; \
		exit 1; \
	fi
	@echo "Creating release commit for version $(VERSION)..."
	# Update version in lib/Cargo.toml
	sed -i 's/^version = ".*"/version = "$(VERSION)"/' crates/lib/Cargo.toml
	# Update Cargo.lock with new version
	cargo update --workspace
	# Run cargo xtask update-generated to update generated files
	cargo xtask update-generated
	# Stage all changes
	git add crates/lib/Cargo.toml Cargo.lock
	git add -A  # Add any files updated by cargo xtask update-generated
	# Create commit
	git commit -m "Release $(VERSION)"
	# Create signed tag
	git tag -s -m "Release $(VERSION)" v$(VERSION)
.PHONY: release-commit

# Get the next minor version by bumping the minor version from crates/lib/Cargo.toml
# Outputs the new version string (e.g., "1.3.0" if current version is "1.2.4")
next-minor-version:
	@VERSION=$$(grep '^version' crates/lib/Cargo.toml | sed 's/version = "//;s/"//'); \
	if [ -z "$$VERSION" ]; then \
		echo "Error: Could not find version in crates/lib/Cargo.toml" >&2; \
		exit 1; \
	fi; \
	if ! echo "$$VERSION" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$$' >/dev/null; then \
		echo "Error: Invalid version format in Cargo.toml: $$VERSION" >&2; \
		exit 1; \
	fi; \
	MAJOR=$$(echo "$$VERSION" | cut -d. -f1); \
	MINOR=$$(echo "$$VERSION" | cut -d. -f2); \
	if ! [ "$$MAJOR" -eq "$$MAJOR" ] 2>/dev/null || ! [ "$$MINOR" -eq "$$MINOR" ] 2>/dev/null; then \
		echo "Error: Invalid version numbers in $$VERSION" >&2; \
		exit 1; \
	fi; \
	NEW_MINOR=$$((MINOR + 1)); \
	echo "$$MAJOR.$$NEW_MINOR.0"
.PHONY: next-minor-version
