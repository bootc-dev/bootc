---
description: |
  Fix-iteration agent. When review.md flags a pull request
  with the 'agent/fixme' label, this agent reads the reviewer's feedback and
  pushes follow-up commits to the same branch, closing the
  code -> review -> fix loop.

on:
  pull_request:
    types: [labeled]
  bots: ["${{ vars.GH_AW_APP_BOT_SLUG }}"]

if: |
  github.event.label.name == 'agent/fixme'

# gh-aw's default `pull_request`-triggered concurrency group is keyed only by
# workflow name + PR number, not by which label fired the run. That's fine
# for gh-aw's own `label_command:`/label-trigger-shorthand triggers (which
# thread the label name into the group automatically) but this workflow uses
# a plain `pull_request: types: [labeled]` trigger instead (see the "Your
# task" note below for why), so it doesn't get that treatment. The `on:
# labeled` trigger above fires at the Actions level on *any* label change to
# the PR -- the `if:` above only filters which runs actually do real work,
# after the run has already started -- so add_working_label's own
# `--add-label agent/fix-working` call is itself a `labeled` event that
# starts a second run in the *same* default concurrency group. Confirmed
# live: that second run's job-level `if:` conditions correctly evaluate
# false and skip real work, but `cancel-in-progress: true` on the shared
# group cancels the first run's in-progress `activation`/`agent` jobs
# (mid-LLM-fix) the instant the second run starts, regardless of what the
# second run's own conditions decide -- observed via the GitHub API as the
# first run's `agent` job showing `conclusion: cancelled` with
# `started_at == completed_at`. Keying the group on the triggering label
# name isolates the two: a real `agent/fixme` run and its own
# self-retriggered `agent/fix-working` run land in different groups and
# never cancel each other. `|| github.run_id` on the label term (not just
# the PR-number term) keeps any non-label-triggered run of this workflow,
# should one ever exist, out of every label-keyed group instead of
# colliding on an empty string.
concurrency:
  group: "gh-aw-${{ github.workflow }}-${{ github.event.pull_request.number || github.ref || github.run_id }}-${{ github.event.label.name || github.run_id }}"
  cancel-in-progress: true

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

network:
  allowed:
    - defaults
    - rust

safe-outputs:
  github-app:
    client-id: ${{ vars.GH_AW_APP_CLIENT_ID }}
    private-key: ${{ secrets.GH_AW_APP_PRIVATE_KEY }}
    # See drafter.md: needed so pushes touching .github/workflows/* (e.g. an
    # override-labeled fix commit) aren't rejected server-side for lacking
    # the `workflows` permission on the minted token.
    permissions:
      workflows: write
  add-comment:
    max: 1
  remove-labels:
    max: 1
    allowed: ["agent/fixme"]
  push-to-pull-request-branch:
    max: 1
    # Mirrors drafter.md's override: if the PR itself carries
    # `agent/workflow-edits-allowed` (e.g. the drafter PR was opened under
    # the override, or a human added it afterwards), fix commits may also
    # touch protected files without the request_review gate. See "Letting
    # the agent edit protected files" in README.md.
    protected-files:
      # See drafter.md for why this uses case() instead of the more common
      # "cond && 'allowed' || 'request_review'" ternary idiom: gh-aw's
      # compiler HTML-escapes && to \u0026\u0026 when JSON-encoding this
      # value, which breaks GitHub Actions' expression parser.
      policy: ${{ case(contains(github.event.pull_request.labels.*.name, 'agent/workflow-edits-allowed'), 'allowed', 'request_review') }}

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
      - name: Add agent/fix-working label
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
          gh pr edit "$PR_NUMBER" --repo "$REPO" --add-label agent/fix-working || true
  remove_working_label:
    needs: [pre_activation, activation, agent, detection, safe_outputs]
    # Only tear down the label this same run put up: gating on this run's own
    # pre_activation output (not just "always()") stops a run whose real work
    # never started from clearing an in-progress signal it never set. Found
    # live: fix.md's cleanup removed review.md's own agent/review-working
    # label 11 seconds after review.md set it, while review.md's real agent
    # job kept running ~8 more minutes -- back when both workflows shared a
    # single agent/working label, a run whose job-level `if:` had skipped
    # real work still unconditionally stripped whatever the *other*
    # workflow's still-active run had just set. Per-workflow label names
    # (see above) remove the cross-workflow collision; this condition is
    # defense-in-depth against the same class of bug recurring.
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
      - name: Remove agent/fix-working label (best-effort)
        # See the "Add agent/fix-working label" step above for why
        # PR_NUMBER/REPO are passed via env: instead of inlined in run:.
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}
          PR_NUMBER: ${{ github.event.pull_request.number }}
          REPO: ${{ github.repository }}
        run: |
          gh pr edit "$PR_NUMBER" --repo "$REPO" --remove-label agent/fix-working || true

timeout-minutes: 15
source: bootc-dev/gh-agentic-workflows@8b8fddc621b42cc44f82f93bc2970dafaeda113a
---

# PR Fix Agent

The `agent/fixme` label was applied to pull request
#${{ github.event.pull_request.number }} by the review agent (`review.md`),
meaning it found something that needs to change.

Note: this workflow uses a plain `pull_request: types: [labeled]` trigger
rather than gh-aw's `label_command:` trigger to maintain manual label
consumption and prevent duplicate re-triggers. The label must be consumed
manually: this workflow removes `agent/fixme` itself via `remove-labels`
(step 1 below) so it can't cause a duplicate re-trigger.

## Your task

1. Remove the `agent/fixme` label from this PR via the `remove-labels`
   safe-output, so it's consumed and can't re-trigger this workflow.
2. **Enforce the iteration cap.** Run
   `gh pr view ${{ github.event.pull_request.number }} --json commits --jq '.commits | length'`
   to count the commits on this PR — comparing the count before and after
   a fix attempt is how to detect whether a new commit was actually
   pushed, via the GitHub API rather than a raw `git fetch`. Use `gh`/the API for
   this, not `git fetch`: in the sandboxed agent job, a raw `git fetch`
   against this (private) repo is not guaranteed to have working
   credentials, whereas `gh`/`GH_TOKEN` is always set up for you.
   If the count is already 3 or more, the cap has been reached:
   - Do not make any code changes and do not emit a
     `push-to-pull-request-branch` safe-output.
   - Emit an `add-comment` safe-output on this PR whose body says: the
     automated fix loop has reached its iteration limit (3) and automated
     fixing has stopped; a human needs to review the PR and either push a
     fix commit and apply `agent/lgtm` directly once satisfied, or close the
     PR. Explicitly note that re-applying `agent/fixme` will **not** give the
     loop another attempt: this cap is simply the total commit count on
     the branch, which only grows, so relabeling will immediately hit the
     same cap again without attempting a fix (the only way to actually
     continue the automated loop is to reduce the branch's commit count,
     e.g. by squashing, below 3 first).
   - Stop here. Do not proceed to the remaining steps.

   This caps the loop at 2 fix iterations, on the assumption that
   `drafter.md` pushes exactly one initial commit before this workflow
   ever runs. If a drafter ever pushes more than one initial commit, the
   cap will trip slightly earlier than 2 true fix iterations — an accepted
   trade-off for not depending on `git fetch` credentials that may not be
   present in the sandbox.
3. Otherwise (cap not reached), determine the PR's branch name by running
   `gh pr view ${{ github.event.pull_request.number }} --json headRefName --jq .headRefName`.
4. Read the reviewer's feedback: run
   `gh pr view ${{ github.event.pull_request.number }} --json reviews` (or
   `gh api repos/${{ github.repository }}/pulls/${{ github.event.pull_request.number }}/reviews`)
   and use the body of the most recent review to see what needs fixing.
5. Check out the PR branch and make the smallest change that addresses the
   feedback.
6. Validate your change using whatever the repo actually provides (tests,
   a lint command, or a small ad hoc check) — do not assume tooling that
   may not exist.
7. If your change edits any `.github/workflows/*.md` file, recompile the
   lockfiles: run `just setup && just compile` (this recompiles *all*
   workflows, not just the one you touched — every `.lock.yml` must stay in
   sync with its `.md` source). Include the resulting `.lock.yml` changes in
   your commit.
8. Push your fix as a new commit on the same branch via the
   `push-to-pull-request-branch` safe-output. Do not open a new PR.

## Constraints

- Only ever modify the existing PR branch via `push-to-pull-request-branch`
  — never push directly to `main` and never open a new PR.
- Always add a new commit; never `git commit --amend` an existing commit on
  this branch. `push-to-pull-request-branch` can only convey new file
  changes — an amend that only changes a commit message (no file diff) has
  nothing in it for that mechanism to push, and will silently look
  successful while the branch stays exactly as it was. (This should be rare
  in practice: see review.md, which doesn't request fixes purely over
  commit message wording, since messages don't survive the final squash
  merge anyway.)
- Respect the iteration cap in step 2 without exception.
- Always remove `agent/fixme` (step 1), even if the iteration cap causes you
  to stop before making any code changes.
- When the iteration cap is reached, never emit `add-labels` for
  `agent/fixme` or `agent/lgtm` — an unlabeled PR with the cap-reached comment
  is the intended "stuck, needs a human" signal. Only emit the
  `add-comment` safe-output described in step 2.
