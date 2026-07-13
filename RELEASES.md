# Release Process

This document describes the release process, versioning strategy, and support policies for bootc.

## Versioning

bootc follows [Semantic Versioning](https://semver.org/) standards:

- **Major releases** (x.0.0): Breaking changes to the CLI, API, or upgrade path
- **Minor releases** (x.y.0): New features, backwards compatible additions
- **Patch releases** (x.y.z): Bug fixes, security patches, backwards compatible

**Note:** Semantic versioning adherence began with version 1.2.0. Versions prior to 1.2.0 may not strictly follow semver standards.

## Stability Guarantees

The bootc CLI and API are considered **stable**. We ensure that every existing system can be upgraded in place seamlessly across any future changes. This means:

- **CLI compatibility**: Commands and flags will not be removed without deprecation warnings
- **API compatibility**: The bootc API maintains backwards compatibility
- **Upgrade path**: Systems can always upgrade from any version to any later version without manual intervention

<!-- OPEN QUESTION: What's the deprecation policy? How many versions advance notice? -->

## Release Cadence

Starting with **v1.16.0** (June 2024), bootc follows a **weekly release cadence**:

- Automated release PRs created every **Monday at 8:00 AM UTC**
- Default: **patch version bump** for weekly releases
- Minor releases: triggered as needed when new features are ready
- Major releases: rare, only for significant breaking changes requiring careful migration

## Release Process

Releases are fully automated using GitHub Actions workflows.

### 1. Scheduled Release PR Creation

**When:** Every Monday at 8:00 AM UTC (or manually triggered)

**What happens:**
1. Automated workflow bumps version in `crates/lib/Cargo.toml`
2. Internal crate versions updated to match (`bootc-internal-utils`, `bootc-internal-mount`, `bootc-internal-blockdev`)
3. Changes committed with GPG signature
4. Pull request created with `release` label
5. PR includes checklist for maintainers to review

**Workflow:** `.github/workflows/scheduled-release.yml`

### 2. Release Review and Merge

**Who:** Project maintainers review the release PR

**Review checklist:**
- [ ] Version bump is correct (patch/minor/major as appropriate)
- [ ] All CI tests pass
- [ ] No blocking issues or regressions
- [ ] Release notes will accurately reflect changes

**Action:** Maintainer merges the release PR

### 3. Automated Release Creation

**Trigger:** Merging a PR with the `release` label

**What happens:**
1. Version extracted from `crates/lib/Cargo.toml`
2. Version format validated (must match `x.y.z` semver)
3. GPG-signed git tag created: `v<version>`
4. Tag pushed to repository
5. Source packaging executed via `cargo xtask package`
6. Draft GitHub release created
7. Release assets uploaded:
   - `bootc-<version>-vendor.tar.zstd` - Vendored Rust dependencies for offline builds
   - `bootc-<version>.tar.zstd` - Source tarball

**Workflow:** `.github/workflows/release.yml`

### 4. Release Finalization

**Who:** Project maintainers

**Actions:**
1. Review auto-generated release notes
2. Add highlights or context if needed
3. Publish the draft release (makes it public)

## Manual Release Triggers

Maintainers can manually trigger releases outside the weekly schedule:

1. Navigate to **Actions** → **"Create Release PR"**
2. Click **"Run workflow"**
3. Select version type:
   - `patch` (default) - Bug fixes only
   - `minor` - New features

**Use cases for manual releases:**
- Critical security patches
- Important bug fixes that can't wait for weekly cycle
- Feature releases ready for announcement

## Release Assets

Each release on [GitHub Releases](https://github.com/bootc-dev/bootc/releases) includes:

### Source Archives

- **`bootc-<version>.tar.zstd`** - Complete source code tarball
  - Use this for packaging bootc in Linux distributions
  - Includes all source files needed to build bootc

- **`bootc-<version>-vendor.tar.zstd`** - Vendored Rust dependencies
  - Pre-downloaded Cargo dependencies for offline builds
  - Required for air-gapped or restricted network environments
  - Ensures reproducible builds with exact dependency versions

### Release Notes

Auto-generated release notes include:
- **Features**: New capabilities and enhancements
- **Bug Fixes**: Issues resolved in this release
- **Contributors**: Community members who contributed
- **Full Changelog**: Link to compare with previous version

Maintainers may add additional context, breaking change warnings, or upgrade notes.

## Release Branches

<!-- OPEN QUESTION: Are release branches created? If so, when and for how long? -->
<!-- Based on workflows, it appears releases are tagged from main, but are there long-lived release/X.Y branches for backports? -->

Currently, releases are tagged directly from the `main` branch. 

<!-- TODO: Document if/when release branches (e.g., release/1.16) are created for long-term support -->

## Support Policy

<!-- OPEN QUESTION: What's the official support policy? -->
<!-- - How long is each version supported? -->
<!-- - Are there different support tiers (Active, Security-only, EOL)? -->
<!-- - Will there be LTS releases? -->

**Current approach:**

The project focuses on the **latest stable release**. Users are encouraged to update to the latest version to receive:
- New features and enhancements
- Bug fixes
- Security patches
- Performance improvements

Given the weekly release cadence and seamless upgrade path, staying current is recommended.

<!-- PLACEHOLDER: As bootc matures, a formal support horizon will be established -->
<!-- Example: "Latest release + previous release" or "3-month support window" -->

## Backporting

<!-- OPEN QUESTION: What's the backporting policy? -->
<!-- - What qualifies for backports? (security only? critical bugs?) -->
<!-- - Which versions receive backports? -->
<!-- - Who approves backports? -->

**Current approach:**

With weekly releases, most fixes are included in the next scheduled release rather than backported.

<!-- PLACEHOLDER: Document criteria for backporting when established -->
<!-- Likely candidates: Security vulnerabilities, data loss bugs, upgrade blockers -->

## Pre-releases

<!-- OPEN QUESTION: Does bootc do pre-releases (alpha, beta, RC)? -->
<!-- The workflows don't show pre-release automation, but that doesn't mean they don't happen -->

Pre-release versions (alpha, beta, release candidates) may be published for testing major features or significant changes:

- **Alpha**: `v<version>-alpha.<n>` - Early testing, unstable
- **Beta**: `v<version>-beta.<n>` - Feature complete, testing in progress  
- **Release Candidate**: `v<version>-rc.<n>` - Final testing before stable release

**When used:**
<!-- OPEN QUESTION: When are pre-releases created? Only for major versions? -->
- Major version releases
- Significant architectural changes
- Features requiring community testing

Pre-releases are **not production-ready** and should only be used for testing.

## Security Releases

For security vulnerabilities:

1. Follow the [Security Policy](./SECURITY.md) to report issues privately
2. Security Response Team assesses severity and impact
3. Fix developed in private
4. **Critical vulnerabilities are fast-tracked** and released immediately (not waiting for weekly cycle)
5. Coordinated disclosure after fix is available

## GPG Signing

All release tags are signed with GPG keys to ensure authenticity and integrity.

**Verification:**
```bash
# Verify a release tag
git verify-tag v1.16.3

# Clone with verification
git clone --branch v1.16.3 https://github.com/bootc-dev/bootc.git
cd bootc
git verify-tag HEAD
```

## Release Team

<!-- OPEN QUESTION: Who are the release managers/approvers? -->
<!-- - Are all maintainers release approvers? -->
<!-- - Is there a designated release manager? -->
<!-- - Rotation schedule? -->

Releases are managed by the project maintainers as defined in [MAINTAINERS.md](./MAINTAINERS.md).

<!-- PLACEHOLDER: Document if there's a release rotation or specific release role -->

## Release History

View all releases at: https://github.com/bootc-dev/bootc/releases

**Recent milestones:**
- **v1.16.0** (June 2024) - Transitioned to weekly release cadence
- **v1.2.0** - Began strict semantic versioning adherence
- **v1.0.0** - First stable release

## Breaking Changes

When breaking changes are necessary:

1. Deprecation warnings announced at least **2 releases in advance**
2. Migration documentation provided
3. Clear upgrade path documented in release notes
4. Major version bump (x.0.0)

**Commitment:** We maintain backwards compatibility wherever possible and only introduce breaking changes when necessary for significant improvements.

## API Stability

The bootc API is considered stable. Changes to the API follow these guidelines:

- **Additions**: New APIs can be added in minor releases
- **Deprecations**: APIs may be marked deprecated but remain functional
- **Removals**: Deprecated APIs removed only in major releases
- **Changes**: Behavior changes only in major releases, with migration guide

## Questions or Issues?

- **Release discussions**: [GitHub Discussions](https://github.com/bootc-dev/bootc/discussions)
- **Release bugs**: [File an issue](https://github.com/bootc-dev/bootc/issues)
- **Security issues**: See [SECURITY.md](./SECURITY.md)

## Future Plans

<!-- OPEN QUESTION: Any planned changes to the release process? -->

As bootc continues to mature, we may introduce:

- Long-term support (LTS) releases
- Extended support periods for specific versions
- More formal release branch strategy
- Pre-release testing programs

Community feedback on release cadence and support needs is welcome via GitHub Discussions.
