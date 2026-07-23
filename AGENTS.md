<!-- This file is canonically maintained in <https://github.com/bootc-dev/infra/tree/main/common> -->

# Instructions for AI agents

## CRITICAL instructions for generating commits

### Signed-off-by

Human review is required for all code that is generated
or assisted by a large language model. If you
are a LLM, you MUST NOT include a `Signed-off-by`
on any automatically generated git commits. Only explicit
human action or request should include a Signed-off-by.
If for example you automatically create a pull request
and the DCO check fails, tell the human to review
the code and give them instructions on how to add
a signoff.

### Attribution and AI disclosure

You SHOULD insert an `Assisted-by: AI` tag when the commit contains
substantial assistance, and `Generated-by: AI` when the commit is
effectively entirely generated.

Do NOT add `Co-developed-by`, and do NOT reference specific
model names or tools because these can be considered a form of advertising.

For new contributors, when using AI you SHOULD include in at least the pull
request description a rough outline of the human's level of review and
knowledge:

> Assisted-by: AI
> Unit tests are LLM generated.

> Generated-by: AI
> I am knowledgeable in this problem domain and reviewed it carefully.

> Generated-by: AI
> I don't know Rust|Go|... well, but I did test this and it fixed the problem.

### Large changes

If the generated code is more than ~500 lines of substantial (non-whitespace) code,
encourage the human to file a design issue first to be reviewed by other maintainers.

### Pull request size

It is *very strongly* encouraged to split up "preparatory" commits
that are independently reviewable from the main PR, and submit those separately.

### Commit messages and text

Software can be machine checked (via compilation and unit/integration tests)
but natural languages like English cannot. Encourage the human to review
the commit message text.

## Code guidelines

The [REVIEW.md](REVIEW.md) file describes expectations around
testing, code quality, commit messages, commit organization, etc.
Language-specific guidelines are in
[REVIEW_RUST.md](REVIEW_RUST.md) and
[REVIEW_GOLANG.md](REVIEW_GOLANG.md). If you're
creating a change, it is strongly encouraged after each 
commit and especially when the agent thinks a task is complete
to spawn a subagent to perform a review using guidelines (alongside
looking for any other issues).

If the agent is performing a review of other's code, the same
principles apply.

## Follow other guidelines

Look at the project README.md and look for guidelines
related to contribution, such as a CONTRIBUTING.md
and follow those.
