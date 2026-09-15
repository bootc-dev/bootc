---
description: |
  Reviewer agent. Automatically reviews pull requests authored by the code
  agent and signals readiness via labels: 'agent/fixme' when changes are
  needed, 'agent/lgtm' when the PR is ready to merge.

on:
  pull_request:
    types: [opened, synchronize]
  bots: ["${{ vars.GH_AW_APP_BOT_SLUG }}"]

if: startsWith(github.event.pull_request.head.ref, 'agent/')

permissions:
  contents: read
  issues: read
  pull-requests: read

model: claude-sonnet-4-5-20250929
engine:
  id: claude
tools:
  bash: ["*"]
  github:
    toolsets: [default]
    # See drafter.md: trusts our own bot's authored content (e.g. issues it
    # files) so it isn't filtered out by integrity checks on this public repo.
    min-integrity: approved
    trusted-users: ["${{ vars.GH_AW_APP_BOT_SLUG }}"]

safe-outputs:
  github-app:
    client-id: ${{ vars.GH_AW_APP_CLIENT_ID }}
    private-key: ${{ secrets.GH_AW_APP_PRIVATE_KEY }}
  submit-pull-request-review:
    max: 1
  add-labels:
    max: 1
    allowed: ["agent/fixme", "agent/lgtm"]
  remove-labels:
    max: 2
    allowed: ["agent/fixme", "agent/lgtm"]

# See drafter.md for why this is a plain job pair instead of safe-outputs.
jobs:
  # See drafter.md: depending on pre_activation (not activation) makes gh-aw's
  # compiler automatically thread this job into activation's own needs, so
  # agent transitively waits for the label to be added first.
  add_working_label:
    needs: pre_activation
    if: needs.pre_activation.outputs.activated == 'true'
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - name: Generate App token
        id: app-token
        uses: actions/create-github-app-token@v3.2.0
        with:
          client-id: ${{ vars.GH_AW_APP_CLIENT_ID }}
          private-key: ${{ secrets.GH_AW_APP_PRIVATE_KEY }}
      - name: Add agent/review-working label
        # PR_NUMBER/REPO must be passed via env: rather than inlined
        # directly into the run: script below (as `${{ github.* }}`): see
        # drafter.md's equivalent step for why -- gh-aw's compiler silently
        # drops GH_TOKEN (and anything else already in this env: block)
        # when it sanitizes an inline `${{ github.* }}` expression it finds
        # in run:, due to a type-assertion bug in that compiler pass.
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}
          PR_NUMBER: ${{ github.event.pull_request.number }}
          REPO: ${{ github.repository }}
        run: |
          set -euo pipefail
          gh pr edit "$PR_NUMBER" --repo "$REPO" --add-label agent/review-working || true
  remove_working_label:
    needs: [pre_activation, activation, agent, detection, safe_outputs]
    # Only tear down the label this same run put up: gating on this run's own
    # pre_activation output (not just "always()") stops a run whose real work
    # never started from clearing an in-progress signal it never set. See
    # fix.md's equivalent job for the live incident this defends against.
    if: always() && needs.pre_activation.outputs.activated == 'true'
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - name: Generate App token
        id: app-token
        uses: actions/create-github-app-token@v3.2.0
        with:
          client-id: ${{ vars.GH_AW_APP_CLIENT_ID }}
          private-key: ${{ secrets.GH_AW_APP_PRIVATE_KEY }}
      - name: Remove agent/review-working label (best-effort)
        # See the "Add agent/review-working label" step above for why
        # PR_NUMBER/REPO are passed via env: instead of inlined in run:.
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}
          PR_NUMBER: ${{ github.event.pull_request.number }}
          REPO: ${{ github.repository }}
        run: |
          gh pr edit "$PR_NUMBER" --repo "$REPO" --remove-label agent/review-working || true

timeout-minutes: 15
source: bootc-dev/gh-agentic-workflows@8b8fddc621b42cc44f82f93bc2970dafaeda113a
---

# PR Review Agent

The code agent has opened or updated a pull request
#${{ github.event.pull_request.number }}.

## Your task

1. Look at the PR's diff and the full context of any files it touches.
2. Review it for correctness, quality, safety, and adherence to repository
   conventions.
3. Decide on exactly one of two outcomes:
   - **Needs more work**: remove the `agent/lgtm` label if present, submit a
     `submit-pull-request-review` with `event: COMMENT` and concrete,
     actionable feedback describing exactly what needs to change, then add
     the `agent/fixme` label.
   - **Looks good, ready to merge**: remove the `agent/fixme` label if
     present, submit a `submit-pull-request-review` with `event: COMMENT`
     noting what you checked and that it looks good, then add the
     `agent/lgtm` label.

   Always use `event: COMMENT` for the review itself — never
   `REQUEST_CHANGES` or `APPROVE`. GitHub silently downgrades both of those
   to `COMMENT` whenever the reviewing identity matches the PR author's
   identity (as it does here, since both this workflow and `drafter.md`
   act as the same bot account), so requesting either would be misleading
   about what actually happens. The labels below are what
   actually carry the fix/merge decision.

## Constraints

- Submit exactly one review via `submit-pull-request-review`, always with
  `event: COMMENT`.
- `agent/fixme` and `agent/lgtm` are mutually exclusive — the PR must have
  exactly one of them applied after you finish, never both and never
  neither. Always remove the other one first (removal of a label that
  isn't present is a harmless no-op).
- Be specific in your feedback when applying `agent/fixme` — it will be read
  by another agent (`fix.md`) that will attempt to address it
  automatically.
- Don't apply `agent/fixme` solely over the wording of an existing commit
  message on this branch. `merge.yml` squashes every commit using this PR's
  title and body, not the raw commit log, so individual commit messages
  never appear in the final history — review the code and the PR
  description, not commit-by-commit hygiene. (`fix.md` also has no way to
  reword an existing commit without a real file change to attach it to, so
  this kind of feedback would be a dead end anyway.)
