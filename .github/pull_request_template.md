<!--
The PR TITLE must be a Conventional Commit: `type(scope): subject`.
PRs land by squash merge, so this title becomes the commit subject on main.
Type and scope table: CONTRIBUTING.md.
-->

## What and why

<!-- The diff says how. Say what changes, and what made it worth changing.
Link the design doc and the chunk (e.g. docs/02 GW3). -->

## Verification

<!--
What you ran, and what it said. "Tests pass" is not verification; the name
of the gate and its result is. If something couldn't be run here, say which
and why.
-->

## Security

<!-- Does this touch the decision path, a trust boundary, elevations,
credentials, Telegram handling, or what gets logged? If so, which failure
cases did you test, and do they deny? If not, say "no decision-path change". -->

## Checklist

- [ ] Title is a Conventional Commit, with the right type and scope
- [ ] Implements a design doc whose decisions are locked (or is a bug fix, docs or chore)
- [ ] Tests for anything behavioural; for a bug fix, the test was written first and seen to fail
- [ ] Failure paths on the decision path are tested and deny
- [ ] Docs updated where the change makes them wrong: the design doc for a decision, `ROADMAP.md` status, `docs/gotchas.md`, and `BUGS.md` entries deleted when fixed
