---
description: |
  Draft PR implementation agent. When an issue is labeled 'agent/code',
  this agent reads the issue, explores the repo, implements the change,
  validates it with the repo's own build tooling, and opens a draft pull
  request for human review via the create-pull-request safe-output.

on:
  issues:
    types: [labeled]

if: github.event.label.name == 'agent/code'

permissions:
  contents: read
  issues: read

model: claude-sonnet-4-5-20250929
engine:
  id: claude
tools:
  bash: ["*"]
  github:
    toolsets: [issues]

network:
  allowed:
    - defaults
    - rust

safe-outputs:
  github-app:
    client-id: ${{ vars.GH_AW_APP_CLIENT_ID }}
    private-key: ${{ secrets.GH_AW_APP_PRIVATE_KEY }}
    # Without this, the minted installation token only gets contents/issues/
    # pull-requests, and GitHub server-side rejects any push that touches
    # .github/workflows/* with "refusing to allow a GitHub App to create or
    # update workflow ... without `workflows` permission" - even though the
    # App installation itself has the Workflows permission granted.
    permissions:
      workflows: write
  create-pull-request:
    max: 1
    branch-prefix: agent/
    # Protected files (README.md, workflow definitions, etc.) normally fall
    # back to `request_review`: the PR is opened but flagged for mandatory
    # human review before merge. Applying `agent/workflow-edits-allowed` to
    # the originating issue *before* it's labeled `agent/code` pre-authorizes
    # this specific run to edit them without that gate. This must not become
    # the default — see "Letting the agent edit protected files" in README.md.
    protected-files:
      # case(), not "cond && 'allowed' || 'request_review'": gh-aw's compiler
      # JSON-encodes this string with Go's default HTML-escaping, which turns
      # a literal && into \u0026\u0026 and produces an expression GitHub
      # Actions can't parse (silently breaking the whole workflow file at
      # push time, no job even attempts to run). case() has no &, <, or >,
      # so it survives that encoding intact.
      policy: ${{ case(contains(github.event.issue.labels.*.name, 'agent/workflow-edits-allowed'), 'allowed', 'request_review') }}

# Track that an agent is actively working on this issue via a plain label,
# added/removed by dedicated jobs rather than safe-outputs: removal must
# happen unconditionally (including on agent failure/timeout), which
# safe-outputs' success-gated handlers can't guarantee. See "Tracking active
# agent runs" in README.md.
jobs:
  # Depending on pre_activation (not activation) is what makes gh-aw's compiler
  # automatically thread this job into activation's own needs, so agent (which
  # needs activation) transitively waits for the label to be added first -
  # no separate `jobs.agent.needs:` override required (and if one is added,
  # the compiler silently ignores it for jobs already wired via pre_activation).
  add_working_label:
    needs: pre_activation
    if: needs.pre_activation.outputs.activated == 'true'
    runs-on: ubuntu-latest
    permissions:
      issues: write
    steps:
      - name: Generate App token
        id: app-token
        uses: actions/create-github-app-token@v3.2.0
        with:
          client-id: ${{ vars.GH_AW_APP_CLIENT_ID }}
          private-key: ${{ secrets.GH_AW_APP_PRIVATE_KEY }}
      - name: Add agent/drafter-working label
        # ISSUE_NUMBER/REPO must be passed via env: rather than inlined
        # directly into the run: script below (as `${{ github.* }}`): gh-aw's
        # compiler sanitizes any inline `${{ github.* }}` expressions it
        # finds in run: scripts by extracting them into new env vars, but its
        # extraction pass rebuilds the step's entire env: map from scratch
        # using a type assertion that doesn't match how custom-job steps'
        # env: block is typed by this point in compilation -- so it silently
        # drops GH_TOKEN (and anything else already here) instead of merging.
        # Keeping every `${{ github.* }}` reference out of run: sidesteps the
        # bug entirely, since there's then nothing for that pass to extract.
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}
          ISSUE_NUMBER: ${{ github.event.issue.number }}
          REPO: ${{ github.repository }}
        run: |
          set -euo pipefail
          gh issue edit "$ISSUE_NUMBER" --repo "$REPO" --add-label agent/drafter-working || true
  remove_working_label:
    needs: [pre_activation, activation, agent, detection, safe_outputs]
    # Only tear down the label this same run put up: gating on this run's own
    # pre_activation output (not just "always()") stops a run whose real work
    # never started from clearing an in-progress signal it never set. See
    # review.md/fix.md, which share this exact job pair and label scheme on
    # PRs -- a bare `if: always()` there was found to strip a *different*,
    # still-running workflow's label out from under it.
    if: always() && needs.pre_activation.outputs.activated == 'true'
    runs-on: ubuntu-latest
    permissions:
      issues: write
    steps:
      - name: Generate App token
        id: app-token
        uses: actions/create-github-app-token@v3.2.0
        with:
          client-id: ${{ vars.GH_AW_APP_CLIENT_ID }}
          private-key: ${{ secrets.GH_AW_APP_PRIVATE_KEY }}
      - name: Remove agent/drafter-working label (best-effort)
        # See the "Add agent/drafter-working label" step above for why
        # ISSUE_NUMBER/REPO are passed via env: instead of inlined in run:.
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}
          ISSUE_NUMBER: ${{ github.event.issue.number }}
          REPO: ${{ github.repository }}
        run: |
          gh issue edit "$ISSUE_NUMBER" --repo "$REPO" --remove-label agent/drafter-working || true

timeout-minutes: 15
source: bootc-dev/gh-agentic-workflows@8b8fddc621b42cc44f82f93bc2970dafaeda113a
---

# Drafter

Issue #${{ github.event.issue.number }} has been labeled for draft PR
implementation.

## Your task

1. Retrieve the content of issue #${{ github.event.issue.number }} to
   understand exactly what change is requested.
2. Explore the repository as needed (`ls`, `cat`, `grep`, etc.) to find the
   relevant files.
3. Make the smallest reasonable change that satisfies the issue.
4. Validate your change using whatever the repository actually provides:
   a command explicitly requested by the issue, or — if none is given —
   check for a `Justfile`, `Makefile`, test suite, or other repo-native way
   to check your work (e.g. running a relevant Python module directly). If
   the repo has no such tooling, validate by inspection and, where
   reasonable, a small ad hoc check (e.g. `python3 -c '...'`) instead of
   assuming a command that may not exist.
5. If your change edits any `.github/workflows/*.md` file, recompile the
   lockfiles before opening the pull request: run `just setup && just
   compile` (this recompiles *all* workflows, not just the one you touched —
   every `.lock.yml` must stay in sync with its `.md` source).
6. Check if the originating issue #${{ github.event.issue.number }} has the
   `agent/workflow-edits-allowed` label by reading its labels. If it does,
   you must propagate this label to the pull request so that subsequent
   fix iterations (via `fix.md`) can also push changes to protected files.
7. Once validation passes, open a pull request via the `create-pull-request`
   safe-output. The PR description should summarize the change and state
   how it was validated. If the originating issue has the
   `agent/workflow-edits-allowed` label (checked in step 6), pass it in the
   `labels` parameter when creating the PR.

## Constraints

- Only ever propose changes via `create-pull-request` — never push directly
  to the default branch.
- Open at most one pull request.
- If the issue is not well-scoped enough to implement safely, or if the
  issue's premise doesn't match what's actually in the repository (e.g. it
  references content that doesn't exist), do not open a PR and do not
  fabricate content to match the issue; instead stop without emitting a
  `create-pull-request` safe-output (using `noop` or similar to explain why,
  if available).
