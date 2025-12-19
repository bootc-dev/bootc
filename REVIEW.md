# Code Review Guidelines

These guidelines are derived from analysis of code reviews across the bootc-dev
organization (October–December 2024). They represent the collective expectations
and standards that have emerged from real review feedback.

## Testing

Tests are expected for all non-trivial changes - unit and integration by default.

If there's something that's difficult to write a test for at the current time,
please do at least state if it was tested manually.

### Choosing the Right Test Type

Unit tests are appropriate for parsing logic, data transformations, and
self-contained functions. Use integration tests for anything that involves
running containers or VMs.

Default to table-driven tests instead of having a separate unit test per
case. Especially LLMs like to generate the latter, but it can become
too verbose. Context windows matter to both humans and LLMs reading the
code later (this applies outside of unit tests too of course, but it's
easy to generate a *lot* of code for unit tests unnecessarily).

### Separating Parsing from I/O

A recurring theme is structuring code for testability. Split parsers from data
reading: have the parser accept a `&str`, then have a separate function that
reads from disk and calls the parser. This makes unit testing straightforward
without filesystem dependencies.

### Test Assertions

Make assertions strict and specific. Don't just verify that code "didn't crash"—
check that outputs match expected values. When adding new commands or output
formats, tests should verify the actual content, not just that something was
produced.

## Code Quality

### Parsing Structured Data

Never parse structured data formats (JSON, YAML, XML) with text tools like `grep`
or `sed`.

### Shell Scripts

Try to avoid having shell script longer than 50 lines. This commonly occurs
in build system and tests. For the build system, usually there's higher
level ways to structure things (Justfile e.g.) and several of our projects
use the `cargo xtask` pattern to put arbitrary "glue" code in Rust using
the `xshell` crate to keep it easy to run external commands.

### Constants and Magic Values

Extract magic numbers into named constants. Any literal number that isn't
immediately obvious—buffer sizes, queue lengths, retry counts, timeouts—should
be a constant with a descriptive name. The same applies to magic strings:
deduplicate repeated paths, configuration keys, and other string literals.

When values aren't self-explanatory, add a comment explaining why that specific
value was chosen.

### Don't ignore (swallow) errors

Avoid the `if let Ok(v) = ... { }` in Rust, or `foo 2>/dev/null || true`
pattern in shell script by default. Most errors should be propagated by
default. If not, it's usually appropriate to at least log error messages
at a `tracing::debug!` or equivalent level.

Handle edge cases explicitly: missing data, malformed input, offline systems.
Error messages should provide clear context for diagnosis.

### Code Organization

Separate concerns: I/O operations, parsing logic, and business logic belong in
different functions. Structure code so core logic can be unit tested without
external dependencies.

It can be OK to duplicate a bit of code in a slightly different form twice,
but having it happen in 3 places asks for deduplication.

## Commits and Pull Requests

### Commit Organization

Break changes into logical, atomic commits. Reviewers appreciate being able to
follow your reasoning: "Especially grateful for breaking it up into individual
commits so I can more easily follow your train of thought."

Preparatory refactoring should be separate from behavioral changes. Each commit
should tell a clear story and be reviewable independently. Commit messages should
explain the "why" not just the "what," and use imperative mood ("Add feature"
not "Added feature").

### PR Descriptions

PRs should link to the issues they address using `Closes:` or `Fixes:` with
full URLs. One reviewer noted: "I edited this issue just now to have
`Closes: <URL>` but let's try to be sure we're doing that kind of thing in
general in the future."

Document known limitations and caveats explicitly. When approaches have tradeoffs
or don't fully solve a problem, say so. For complex investigations, use collapsible
`<details>` sections to include debugging notes without cluttering the main
description.

Think about broader implications: "But we'll have this problem across all repos
right?" Consider how your change affects the wider ecosystem.

### Keeping PRs Current

Keep PRs rebased on main. When CI failures are fixed in other PRs, rebase to
pick up the fixes. Reference the fixing PR when noting that a rebase is needed.

### Before Merge

Self-review your diff before requesting review. Catch obvious issues yourself
rather than burning reviewer cycles.

Do not add `Signed-off-by` lines automatically—these require explicit human
action after review. If code was AI-assisted, include an `Assisted-by:` trailer
indicating the tool and model used.


## Architecture and Design

### Workarounds vs Proper Fixes

When implementing a workaround, document where the proper fix belongs and link
to relevant upstream issues. Invest time investigating proper fixes before
settling on workarounds.

### Cross-Project Considerations

Prefer pushing fixes upstream when the root cause is in a dependency. Reduce
scope where possible; don't reimplement functionality that belongs elsewhere.

When multiple systems interact (like Renovate and custom sync tooling), be
explicit about which system owns what and how they coordinate.

### Avoiding Regressions

Verify that new code paths handle all cases the old code handled. When rewriting
functionality, ensure equivalent coverage exists.

### Review Requirements

When multiple contributors co-author a PR, bring in an independent reviewer.

## Rust-Specific Guidance

Prefer rustix over `libc`. All `unsafe` code must be very carefully
justified.

### Dependencies

New dependencies should be justified. Glance at existing reverse dependencies
on crates.io to see if a crate is widely used. Consider alternatives: "I'm
curious if you did any comparative analysis at all with alternatives?"

Prefer well-maintained crates with active communities. Consider `cargo deny`
policies when adding dependencies.

### API Design

When adding new commands or options, think about machine-readable output early.
JSON is generally preferred for that.

Keep helper functions in appropriate modules. Move command output formatting
close to the CLI layer, keeping core logic functions focused on their primary
purpose.
