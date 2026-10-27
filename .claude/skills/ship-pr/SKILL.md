---
name: ship-pr
description: Open a PR for the current branch and drive it to merge — watch CI and review comments, fix failures and findings as they arrive, request up to 3 `@claude` review rounds (always on large PRs over 2k changed lines, and on any PR to review fixes the automatic review skips), and squash-merge once everything is green and resolved. Use when asked to "ship", "open and merge", or "land" a branch.
---

# Ship a PR

Take the current branch from "committed" to "merged on `main`" without
handing back in between, unless a stop condition below is hit.

## Repo facts this relies on

Verify them if something behaves unexpectedly, because they can drift:

- **Nothing on `main` is enforced by GitHub.** The repo is private on a free
  plan, so it has no rulesets, branch protection or required checks. The
  merge conditions in §4 are this skill's own discipline. Treat them as if
  GitHub enforced them. The repo allows every merge method, but
  `CONTRIBUTING.md` says PRs land by **squash**. Merged branches are **not**
  deleted automatically.
- **No build CI exists yet.** Until R1 picks a toolchain, the repo holds
  design and process documents only, and `claude-review` is the only check.
  When `CONTRIBUTING.md` §Running the gates lists real gates, they apply
  here too.
- **Nyyrikki is a security component** (`CLAUDE.md`). A review finding that
  points to a way a request could run without approval, a credential could
  reach the agent, or a failure could end in allow is the most serious kind
  of finding there is.
- **`claude-review`** (`.github/workflows/claude-code-review.yml`) runs
  automatically on `opened`/`synchronize`/`reopened`, but **don't count
  on it reviewing more than once**. It posts inline comments for findings,
  or a `## Code review` summary ("No issues found…") when the review is
  clean. A later run usually stops once it sees that Claude has already
  commented on the PR, and the check still goes green. Now and then one
  reviews anyway. Commits pushed after the first review, including the
  fixes for its findings, are therefore **not reliably reviewed
  automatically** (see §3 and §4). A later automatic review that does post
  counts as a review of its run's head, found as in §3.
- **`@claude`** (`.github/workflows/claude.yml`) answers a PR comment that
  mentions it. The comment must come from a writer or `tuhokuutio[bot]`. The
  reply is an issue comment from `claude[bot]` that starts with
  "**Claude finished …**" and links the job.
- **A PR that changes `claude-code-review.yml` or `claude.yml` is never
  reviewed, and the check still goes green.** The action refuses to run
  unless both files are identical to `main`'s, logs "Workflow validation
  failed", and exits with success. `@claude` rounds are skipped the same
  way. Land workflow changes in a PR of their own, reviewed by the owner,
  and keep them out of PRs that need a Claude review. When a
  `claude-review` run finishes in seconds, read its log before trusting
  it.
- Only checks for the **current head SHA** count.

## 1. Open the PR

1. Make sure the work is committed, and rebase on `origin/main` if it is
   behind. Run the gates in `CONTRIBUTING.md` §Running the gates, if it
   lists any. Don't commit application code without a design doc behind it
   (`CLAUDE.md`).
2. Push with `git push -u origin HEAD`.
3. Write a **Conventional Commits** title. The squash makes it the commit
   on `main`, so get the type and scope right (`CONTRIBUTING.md`).
   The body follows `.github/pull_request_template.md`: What and why,
   Verification, Security and the Checklist, filled in honestly. Leave a
   checklist box unticked rather than tick one that doesn't apply. End it
   with the attribution line from the session's instructions, if any.
4. Run `gh pr create --base main --title … --body-file …`. If the host
   offers a PR-linking tool, link the PR.
5. Measure the size, leaving out lockfiles (none exist yet, but the filter
   is ready for when code arrives):

   ```sh
   gh api --paginate repos/{owner}/{repo}/pulls/<N>/files --jq '.[]
     | select(.filename | test("(package-lock\\.json|Cargo\\.lock|go\\.sum)$") | not)
     | .additions + .deletions' | awk '{s+=$1} END {print s+0}'
   ```

   Use the paginated API. `gh pr view --json files` stops at 100 files and
   undercounts a large PR.

   **Large = more than 2000.** Measure again after big fix pushes, because a
   PR can cross the line.

## 2. Wait, then react

Wait for events. Don't spin:

- If the host has a PR-watch tool (for example `watch_pull_request`), use
  it and end the turn. It wakes you on check, review and comment events.
- Otherwise, run `gh pr checks <N> --watch --interval 60` in the
  background and get notified when it exits. Then read the comments.

Each time you wake, collect **everything new** before changing anything,
then fix it all in one batch, so one push follows one round of findings:

```sh
gh pr checks <N>                                          # check states for the head SHA
gh api --paginate repos/{owner}/{repo}/pulls/<N>/comments   # inline review comments
gh api --paginate repos/{owner}/{repo}/issues/<N>/comments  # summary + @claude replies
gh api graphql -f query='query{repository(owner:"Tuhis",name:"Nyyrikki"){pullRequest(number:<N>){
  reviewThreads(first:100){pageInfo{hasNextPage} nodes{id isResolved comments(first:20){nodes{author{login} body path line}}}}}}}'
```

If `hasNextPage` is true, a thread may be missing from the list. Stop and
report rather than merge on a partial list.

### Waited 30 minutes? Investigate, don't keep waiting

A wake is not guaranteed: a watch fires on events, and a stuck check or a
review job that never answers produces none. So whenever you start waiting
(a push, a rerun, an `@claude` request), also start a **30-minute timer** in
the background (`sleep 1800` with `run_in_background`, never a foreground
wait) and note the time. When it fires, or when you wake for any reason
and the thing you are waiting for is older than 30 minutes, investigate
before waiting any longer. Don't just say "still waiting".

```sh
gh pr checks <N> | awk -F'\t' '$2!="pass" && $2!="skipping"'   # what is not done
gh run list --branch <branch> --limit 5 --json databaseId,name,status,conclusion,headSha,createdAt
gh api repos/{owner}/{repo}/actions/jobs/<job-id> \
  --jq '{status,started_at,runner_name}, (.steps[] | "\(.name) \(.status) \(.conclusion)")'
```

Compare each unfinished job against how long the same job usually takes
on `main` (`gh api repos/{owner}/{repo}/actions/runs/<main-run-id>/jobs`),
then act on what you find:

- **Every step `completed`, but the job is still `in_progress`** (or the
  run says `success` while a check stays pending): the runner's completion
  never reached GitHub. Re-run that job (`gh run rerun <run-id> --job
  <job-id>`). It will never finish by itself.
- **`queued` with no `runner_name`**: no runner picked it up. Look for
  other queued jobs on the same label. If the pool looks stuck, report it,
  because rerunning won't help.
- **Running much longer than on `main`**: read the live log (`gh api
  repos/{owner}/{repo}/actions/jobs/<id>/logs`) for a hang. Cancel and
  rerun once only if it is clearly stuck, and say so in the PR.
- **An `@claude` round with no reply**: check its `claude.yml` run, as in
  §3 (a failed run gets one retry).

Tell the user what you found and what you did, then start a new 30-minute
timer. A second stall of the same kind is a hand-back (§ *Stop and hand back*).

### CI failures

1. Read the log with `gh run view <run-id> --log-failed`, or
   `gh run view --job <job-id> --log` for one job.
2. Sort the failure:
   - **Caused by the change**: fix it. Bug fixes are test-first
     (`CLAUDE.md`, `CODE-REVIEW.md`).
     For a design doc, the fix is the doc. Make the acceptance criteria and
     failure cases explicit, and make sure every failure path in the design
     denies.
   - **Flaky test**: don't simply rerun it. Fix the flake in this PR if it is
     small and clearly scoped. Otherwise rerun once with
     `gh run rerun <run-id> --failed` and note it in the PR for the owner.
   - **Infrastructure** (the runner died, a registry 5xx, a cancelled run
     that wasn't superseded): run `gh run rerun <run-id> --failed`. If it
     fails the same way twice, stop and report.
3. Run the matching local gate before pushing.

### Review comments

These come from `claude[bot]` and from people. Treat every finding as a
claim to verify, not an order:

- **Security finding** (a bypass, a widened approval, a leaked credential,
  a fail-open path): never decline one on your own judgement. Fix it if the
  fix is unambiguous. Otherwise stop and hand back (see the end of this
  skill).
- **Real bug**: write a failing test, fix it, and commit it on its own with
  a Conventional message that names the finding.
- **Not a bug, or out of scope**: say why, concretely, with code
  references. Don't make a change just to quiet a reviewer.
- **Reply in the thread**, then **resolve it**. Nothing enforces this here,
  but §4 won't merge while any thread is open:

  ```sh
  gh api repos/{owner}/{repo}/pulls/<N>/comments/<comment-id>/replies -f body='Fixed in <sha>, test-first. …'
  gh api graphql -f query='mutation{resolveReviewThread(input:{threadId:"<thread-id>"}){thread{isResolved}}}'
  ```

  Resolve threads opened by people only when the fix plainly matches what
  they asked for. If there is any doubt, reply and leave the thread open
  for them.

- For findings in an issue comment, such as an `@claude` round's report,
  reply in one PR comment that covers each point with its commit SHA.

Push the batch, then go back to waiting. The automatic review usually won't look
at the fixes. §3 gets them reviewed.

## 3. `@claude` review rounds

A round is requested in three cases. All share one cap of 3 rounds per PR:

- **Large PR (more than 2000 lines):** always request rounds, even when the
  automatic review was clean.
- **Any PR with commits pushed after the automatic review**, such as fixes
  for its findings: request rounds until those commits are reviewed. A small
  PR whose automatic review was clean and that got no later commits needs
  no rounds.
- **No automatic review at all** (see *No Claude review comment* below).

**Track which commit each review covered.** Call it the *marker*:

- **Automatic review**, with findings or with a clean summary: the `headSha`
  of the `claude-review` run whose `createdAt`…`updatedAt` window contains
  the `created_at` of what it posted (`gh run list --workflow
  claude-code-review.yml --branch <branch> --json
  headSha,createdAt,updatedAt`). If windows overlap, take the older SHA.
  Both workflows post as `claude[bot]`, and only a `## Code review` summary
  is certainly from `claude-review`. If an inline comment also falls inside
  a `claude.yml` run's window, treat it as that round's and use the round's
  named SHA. Don't use an inline comment's `original_commit_id`. It records
  the head when the comment was posted, not the code the job checked out.
- **No Claude review comment on the PR at all:** nothing is reviewed. The
  check can go green, or be skipped, without posting anything. Wait until
  `claude-review` has finished. If it posted nothing, round 1 is a full
  review of the PR.
- **A round:** only the SHA named in the request, even if its inline
  comments carry a later `original_commit_id`. If the `@claude` job itself
  pushes a commit, that commit comes after the marker and is unreviewed.
- **After a rebase:** §4 moves the marker. Record the move in a PR comment
  ("reviewed marker → `<sha>` after rebase, per range-diff") so it
  survives a context reset.

The unreviewed commits are `git log --oneline <marker>..HEAD`. Don't compare
commit dates with comment times, because a commit can be made before a
review and pushed after it.

Request a round once the previous review's findings are handled, CI is
green on the current head, and `claude-review` has finished. Post a PR
comment:

```
@claude please review again (round K of 3), up to `<head sha>`.
Since your last review (`<marker>`):

- `<sha>`: <what changed and why; say "your finding, test-first" where it applies>
- …

Focus on <the parts most likely to be wrong>.
```

On a large PR with a clean automatic review, ask for a full review of the
PR in round 1, instead of "since your last review".

- **At most 3 rounds.** Count the `claude[bot]` replies whose header is
  "**Claude finished @<the account you post as>'s task …**" and that answer
  a comment starting `@claude please review again (round`. Don't count your
  own comments, because a retry would count twice, and don't count any other
  `@claude` question, yours or a person's. A reply counts only if it
  actually reviewed the requested range. One that says it couldn't (a failed
  checkout, out of turns) is a failed run. It is neither a round nor clean.
  Counting on the PR survives a context reset.
- Wait for the "**Claude finished …**" reply. If its job failed or it never
  posts within ~20 minutes of the run finishing, check the job with
  `gh run view`. A failed run doesn't use up a round, so retry it once by
  posting the same round's comment again, with the current head SHA. If
  the retry fails too, stop and hand back.
- Handle the round's findings as in §2, then request the next round.
  Don't post any other `@claude` comment while a round is open. One job at
  a time keeps every reply attributable.
- **Stop early** when a round leaves nothing to push. That means it reports
  nothing actionable, or you declined each finding with a reply saying why.
  Commits that land later (a rebase, a person's push, an `@claude` job's
  commit) reopen the rounds under the second case above.
- If round 3 still has findings, fix them as usual. Don't request a fourth
  round. Say in the final report that the round limit was reached.

## 4. Merge

Merge only when **all** of these hold for the **current head SHA**:

- Every check has finished, each as `success`, `skipped` or `neutral`, with
  none pending. Today that means `claude-review` alone. A PR with **no**
  checks at all is not green: it means the review workflow didn't run, so
  find out why.
- Every commit has been reviewed: `git log <marker>..HEAD` (§3) is empty,
  and every finding of every review is handled. A finding is handled when
  it was declined with a reply, or fixed in a commit that a later review
  covered. A review whose findings were all declined, with nothing pushed,
  satisfies this. Nothing re-runs, and nothing needs to. **Exception:**
  once the 3-round cap is reached, commits after round 3's marker that fix
  one of its findings, and are named in the reply to it, merge unreviewed.
  The final report names them. Any other commit after the marker is a
  hand-back. Fixed findings raised in
  or after round 3 count as handled once each has a reply naming its
  commit.
- On a large PR, the `@claude` rounds are finished: a round that left
  nothing to push (§3), or 3 rounds with round 3's findings handled as in
  §2.
- No review thread is unresolved, and no person's comment is unanswered.
  Every `@claude` report has a reply that covers each of its points.
- The PR title is still a correct Conventional Commit for the final diff.
  Edit it with `gh pr edit --title` if the scope changed.
- The PR is mergeable. If it conflicts, rebase on `origin/main`, force-push
  with `--force-with-lease`, and go back to §2. The marker is no longer an
  ancestor of `HEAD`, so compare the two versions:

  ```sh
  git fetch origin <marker>        # only if it is missing locally
  base=$(git merge-base <marker> origin/main)   # the old fork point, even after origin/main moved
  git range-diff "$base"..<marker> origin/main..HEAD
  ```

  Any range-diff line other than `=` counts as changed, including a dropped
  (`<`) or new (`>`) commit. A `!` whose only difference is moved context
  lines, with the commit's own `+`/`-` lines identical, doesn't. Commits
  stay reviewed only up to the **first changed commit**, because a later
  commit that replays identically still sits on top of the change. Move the
  marker to the rebased copy of the last commit before the first changed
  one, or to the new merge-base if the first commit changed. If nothing
  changed, it moves to the rebased copy of the marker. If there was no
  marker yet, everything stays unreviewed. Everything after the marker is
  unreviewed. If the round cap is already used up and the rebase changed
  reviewed code, stop and hand back.

Then run:

```sh
gh pr merge <N> --squash --match-head-commit <the head SHA you checked> --delete-branch --subject "<the PR title> (#<N>)"
```

`--match-head-commit` makes GitHub refuse the merge if a commit landed after
your checks, for example from a person or an `@claude` job. If it refuses,
go back to §2 for the new head.

`--delete-branch` is needed because the repo keeps merged branches. Stop
any PR watch, then report the result: the merged SHA, the number of fix
commits, the number of review rounds, whether the round cap was reached
and which commits merged unreviewed, and anything left for the owner (a
flake rerun, a declined finding).

## Stop and hand back instead of merging when

- A fix would widen the PR's scope: a new concern, a design decision, a
  change to a key constraint, a "Rejected" or an "Explicitly set aside" item in
  `CLAUDE.md`, or a locked `docs/NN` decision.
- A security finding has no unambiguous fix, or you'd decline it.
- The round cap is reached and a commit after round 3 fixes a security
  finding, or changes a design doc's decisions or failure paths, or the
  key constraints in `CLAUDE.md`. Those never merge unreviewed, so the cap
  exception in §4 doesn't apply to them.
- A person asks for changes or has an open question you can't settle with
  code.
- The same check fails 3 times after fixes, or an infrastructure failure
  repeats.
- A reviewer's finding and `CLAUDE.md` or a design doc disagree, and you
  can't tell which one is right.

The steps above also stop and hand back in these cases:

- An `@claude` round's retry fails too (§3).
- The review-thread query reports `hasNextPage` (§2).
- The round cap is used up and a rebase changed reviewed code (§4).
- The round cap is used up and a commit after round 3's marker isn't a fix
  named in a reply to one of its findings (§4).

Say exactly what is blocking and leave the PR open.
