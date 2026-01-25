![bootc logo](https://raw.githubusercontent.com/containers/common/main/logos/bootc-logo-full-vert.png)
# bootc


Transactional, in-place operating system updates using OCI/Docker container images.

## Motivation

The original Docker container model of using "layers" to model
applications has been extremely successful.  This project
aims to apply the same technique for bootable host systems - using
standard OCI/Docker containers as a transport and delivery format
for base operating system updates.

The container image includes a Linux kernel (in e.g. `/usr/lib/modules`),
which is used to boot.  At runtime on a target system, the base userspace is
*not* itself running in a "container" by default. For example, assuming
systemd is in use, systemd acts as pid1 as usual - there's no "outer" process.
More about this in the docs; see below.

## Status

The CLI and API are considered stable. We will ensure that every existing system
can be upgraded in place seamlessly across any future changes.

## Documentation

See the [project documentation](https://bootc-dev.github.io/bootc/).

## Versioning

Although bootc is not released to crates.io as a library, version
numbers are expected to follow [semantic
versioning](https://semver.org/) standards.  This practice began with
the release of version 1.2.0; versions prior may not adhere strictly
to semver standards.

## Adopters (base and end-user images)

The bootc CLI is just a client system; it is not tied to any particular
operating system or Linux distribution. You very likely want to actually
start by looking at [ADOPTERS.md](ADOPTERS.md).

## Community discussion

- [Github discussion forum](https://github.com/containers/bootc/discussions) for async discussion
- [#bootc-dev on CNCF Slack](https://cloud-native.slack.com/archives/C08SKSQKG1L) for live chat
- Recurring live meeting hosted on [CNCF Zoom](https://zoom-lfx.platform.linuxfoundation.org/meeting/96540875093?password=7889708d-c520-4565-90d3-ce9e253a1f65) each Friday at 15:30 UTC.

This project is also tightly related to the previously mentioned Fedora/CentOS bootc project,
and many developers monitor the relevant discussion forums there. In particular there's a
Matrix channel and a weekly video call meeting for example: <https://docs.fedoraproject.org/en-US/bootc/community/>.

## Developing bootc

Are you interested in working on bootc?  Great!  See our [CONTRIBUTING.md](CONTRIBUTING.md) guide.
There is also a list of [MAINTAINERS.md](MAINTAINERS.md).

## Governance
See [GOVERNANCE.md](GOVERNANCE.md) for project governance details.

## Badges

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/10113/badge)](https://www.bestpractices.dev/projects/10113)
[![LFX Health Score](https://insights.linuxfoundation.org/api/badge/health-score?project=bootc)](https://insights.linuxfoundation.org/project/bootc)
[![LFX Contributors](https://insights.linuxfoundation.org/api/badge/contributors?project=bootc)](https://insights.linuxfoundation.org/project/bootc)
[![LFX Active Contributors](https://insights.linuxfoundation.org/api/badge/active-contributors?project=bootc)](https://insights.linuxfoundation.org/project/bootc)

### Code of Conduct

The bootc project is a [Cloud Native Computing Foundation (CNCF) Sandbox project](https://www.cncf.io/sandbox-projects/)
and adheres to the [CNCF Community Code of Conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md).

---
The Linux Foundation® (TLF) has registered trademarks and uses trademarks. For a list of TLF trademarks, see [Trademark Usage](https://www.linuxfoundation.org/trademark-usage/).
