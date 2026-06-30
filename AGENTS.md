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

Do NOT add an `Assisted-by`, `Co-developed-by`, or similar commit
trailer crediting an AI tool. Instead, disclose AI assistance in the
**pull request description**. Examples:

- "I used a LLM to generate just unit tests."
- "This code was written in part with the assistance of generative AI."
- "A LLM was used to generate almost all of the code, but I am knowledgeable in this problem domain and reviewed it carefully."
- "This code is generated, I am only partially knowledgeable in this domain."
- "Code is LLM generated; I don't know the programming language but it did fix the problem."

(The closer the commits are to being *entirely* AI, the more likely
 it is that you should submit the PR as a draft, or even file an
 issue first with a proposed design.)

If you're an agent generating a git commit, ensure your human sees
this choice and preferably writes the text on their own.

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
testing, code quality, commit messages, commit organization, etc. If you're
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
