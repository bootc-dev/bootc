# Bootc Project Governance

The Bootc project is dedicated to providing transactional, in-place operating system updates using OCI/Docker container images.
This governance explains how the project is run.

- [Values](#values)
- [Maintainers](#maintainers)
- [Becoming a Maintainer](#becoming-a-maintainer)
- [Members](#members)
- [Reviewers](#reviewers)
- [Committers](#committers)
- [Meetings](#meetings)
- [CNCF Resources](#cncf-resources)
- [Code of Conduct Enforcement](#code-of-conduct)
- [Security Response Team](#security-response-team)
- [Voting](#voting)
- [Modifications](#modifying-this-charter)

## Values

The Bootc and its leadership embrace the following values:

* Openness: Communication and decision-making happens in the open and is discoverable for future
  reference. As much as possible, all discussions and work take place in public
  forums and open repositories.

* Fairness: All stakeholders have the opportunity to provide feedback and submit
  contributions, which will be considered on their merits.

* Community over Product or Company: Sustaining and growing our community takes
  priority over shipping code or sponsors' organizational goals.  Each
  contributor participates in the project as an individual.

* Inclusivity: We innovate through different perspectives and skill sets, which
  can only be accomplished in a welcoming and respectful environment.

* Participation: Responsibilities within the project are earned through
  participation, and there is a clear path up the contributor ladder into leadership
  positions.

## Maintainers

There are different levels of maintainership in the Bootc project, each with
different responsibilities and expectations. The contributor ladder is:
[Members](#members), [Reviewers](#reviewers), and [Committers](#committers).

The current maintainers can be found in [MAINTAINERS.md](./MAINTAINERS.md).

Direct pushes to the code is never allowed. All pull requests require review by a maintainer
*other* than the one submitting it. "Large" changes are encouraged to have a tracking
issue filed beforehand and gather consensus from multiple maintainers and interested community.

Maintainers collectively manage the project's resources and contributors.

This privilege is granted with some expectation of responsibility: maintainers
are people who care about the Bootc project and want to help it grow and
improve. A maintainer is not just someone who can make changes, but someone who
has demonstrated their ability to collaborate with the team, get the most
knowledgeable people to review code and docs, contribute high-quality code, and
follow through to fix issues (in code or tests).

A maintainer is a contributor to the project's success and a citizen helping
the project succeed.

The collective team of all Committers is known as the Maintainer Council, which
is the governing body for the project.

### Becoming a Maintainer

The path to maintainership follows the contributor ladder:

  * **Member**: Sponsored by a reviewer or committer. Approval requires a
    simple majority of current committers.
  * **Reviewer**: Proposed by an existing maintainer. Approval requires a
    simple majority of current committers.
  * **Committer**: Proposed by an existing maintainer. Approval requires a
    simple majority of current committers.

See the [Members](#members), [Reviewers](#reviewers), and
[Committers](#committers) sections for specific requirements and
responsibilities of each role.

A new maintainer must be proposed by opening a PR against the
[MAINTAINERS.md](./MAINTAINERS.md), which will prompt a
[gitvote](https://github.com/cncf/gitvote). Maintainer nominations will be
evaluated without prejudice to employer or demographics.

Maintainers who are selected will be granted the necessary GitHub rights.

### Removing a Maintainer

Maintainers may resign at any time if they feel that they will not be able to
continue fulfilling their project duties.

Maintainers may also be removed after being inactive, failure to fulfill their 
Maintainer responsibilities, violating the Code of Conduct, or other reasons.
Inactivity is defined as a period of very low or no activity in the project 
for a year or more, with no definite schedule to return to full Maintainer 
activity.

A Maintainer may be removed at any time by a 2/3 vote of the remaining committers.

Depending on the reason for removal, a Maintainer may be converted to Emeritus
status.  Emeritus Maintainers will still be consulted on some project matters,
and can be rapidly returned to Maintainer status if their availability changes.
This requires two votes from active maintainers.

## Members

A member is an active participant in the community who has shown consistent
involvement in the project. Members attend community meetings, help answer
questions in discussion forums, assist with issue triage, help organize events
or community activities, and contribute to the overall health of the project.

Members are part of the organization but do not have write access or code
review responsibilities. Membership recognizes sustained community engagement
and is the first step on the contributor ladder. Members are not required to
have made code contributions, though they may have. Becoming a member is a
core aspect in the journey to becoming a reviewer.

A new member must be sponsored by an existing reviewer or committer. The
sponsor will open a pull request to the [MAINTAINERS.md](./MAINTAINERS.md)
file adding the candidate. Approval requires a simple majority of current
committers.

## Reviewers

A reviewer is a core maintainer within the project. They share in reviewing
issues and pull requests, and their LGTM counts towards the required LGTM count
to merge a code change into the project.

Reviewers are part of the organization but do not have write access. Becoming a
reviewer is a core aspect in the journey to becoming a committer.

## Committers

A committer is a core maintainer who is responsible for the overall quality and
stewardship of the project. They share the same reviewing responsibilities as
reviewers, but are also responsible for upholding the project bylaws as well as
participating in project level votes.

Committers are part of the organization with write access to all repositories.
Committers are expected to remain actively involved in the project and
participate in voting and discussing of proposed project level changes.

To become a Committer you need to demonstrate the following:

  * commitment to the project:
    * participate in discussions, contributions, code and documentation reviews for 6 months or more,
    * perform reviews for 20 non-trivial pull requests,
    * contribute 10 non-trivial pull requests and have them merged,
  * ability to write quality code and/or documentation,
  * ability to collaborate with the team,
  * understanding of how the team works (policies, processes for testing and code review, etc),
  * understanding of the project's code base and coding and documentation style.

## Meetings

Time zones permitting, Maintainers are expected to participate in the public
developer meeting, which occurs at 15:30 UTC on Fridays via [Zoom](https://zoom-lfx.platform.linuxfoundation.org/meeting/96540875093?password=7889708d-c520-4565-90d3-ce9e253a1f65).

Maintainers will also have closed meetings in order to discuss security reports
or Code of Conduct violations.  Such meetings should be scheduled by any
Maintainer on receipt of a security issue or CoC report.  All current Maintainers
must be invited to such closed meetings, except for any Maintainer who is
accused of a CoC violation.

## CNCF Resources

Any Maintainer may suggest a request for CNCF resources, either in the
[bootc discussions](https://github.com/bootc-dev/bootc/discussions), or during a
meeting.  A simple majority of Maintainers approves the request.  The Maintainers
may also choose to delegate working with the CNCF to non-Maintainer community
members, who will then be added to the [CNCF's Maintainer List](https://github.com/cncf/foundation/blob/main/project-maintainers.csv)
for that purpose.

## Code of Conduct

[Code of Conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md)
violations by community members will be discussed and resolved
by the maintainers privately.  If a Maintainer is directly involved
in the report, the Maintainers will instead designate two Maintainers to work
with the CNCF Code of Conduct Committee in resolving it.

## Security Response Team

The Maintainers will appoint a Security Response Team to handle security reports.
This committee may simply consist of the Maintainer Council themselves.  If this
responsibility is delegated, the Maintainers will appoint a team of at least two 
contributors to handle it.  The Maintainers will review who is assigned to this
at least once a year.

The Security Response Team is responsible for handling all reports of security
holes and breaches according to the [security policy](./SECURITY.md).

## Voting

While most business in Bootc is conducted by "[lazy consensus](https://community.apache.org/committers/lazyConsensus.html)", 
periodically the Maintainers may need to vote on specific actions or changes.
A vote can be taken using [gitvote](https://github.com/cncf/gitvote) or
privately for security or conduct matters. Any Maintainer may demand a vote be taken.

Most votes require a simple majority of all Maintainers to succeed, except where
otherwise noted.  Two-thirds majority votes mean at least two-thirds of all 
existing maintainers.

## Modifying this Charter

Changes to this Governance and its supporting documents may be approved by 
a 2/3 vote of the Maintainers.
