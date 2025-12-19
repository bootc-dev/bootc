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

### Attribution

When generating substantial amounts of code, you SHOULD
include an `Assisted-by: TOOLNAME (MODELNAME)`. For example,
`Assisted-by: Goose (Sonnet 4.5)`.

## Code guidelines

The [REVIEW.md](REVIEW.md) file describes expectations around
testing, code quality, commit organization, etc. If you're
creating a change, it is strongly encouraged after each 
commit and especially when you think a task is complete
to spawn a subagent to perform a review using guidelines (alongside
looking for any other issues).

If you are performing a review of other's code, the same
principles apply.

## Follow other guidelines

Look at the project README.md and look for guidelines
related to contribution, such as a CONTRIBUTING.md
and follow those.
