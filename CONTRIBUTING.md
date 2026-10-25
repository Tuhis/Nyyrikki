# Contributing to Nyyrikki

Nyyrikki is maintained by one person. Small, focused changes are easy to
review. Large ones should be discussed first, as a proposal issue or a
design doc, before any code is written.

If you are reporting a **security vulnerability**, do not open an issue.
Follow [SECURITY.md](SECURITY.md) instead.

## Design first

Nothing gets implemented without a design doc. A roadmap item is picked up
by writing `docs/NN-short-slug.md` from [`docs/TEMPLATE.md`](docs/TEMPLATE.md),
and the owner approves its decisions before code starts. The full process
is in [`docs/README.md`](docs/README.md). A bug fix doesn't need a design
doc, unless it changes a decision.

## Using AI

Much of Nyyrikki will be written with AI assistance, including code, tests
and design docs. That is fine and expected. There are two requirements,
and they apply whether or not a model was involved.

**You understand every line you are submitting.** Not "it passes the
tests", and not "the model explained it to me". You can say why the code
is shaped the way it is, what happens when it fails, and which
alternatives were rejected. In a security component, a branch nobody knew
was there is a vulnerability waiting to be found.

**Scope it and build it as you would by hand.** AI makes volume cheap,
and volume is exactly what a solo-maintained project can't absorb. Don't
add speculative abstractions, drive-by rewrites or knobs nobody asked for.
One concern per PR, tests for the behaviour that changed, and a diff
someone can hold in their head.

If the honest summary of a PR is "I asked for X and this is what came
back", it isn't finished yet. Read it, cut what doesn't belong, and submit
the part you would defend.

## Commit messages are load-bearing

Commits and PR titles follow
**[Conventional Commits](https://www.conventionalcommits.org/)**. PRs land
by squash merge, so the **PR title** becomes the commit subject on `main`.
This makes the history readable now and lets release automation
(release-please, as in `gawk`) cut versions and changelogs later without
rewriting anything.

```
feat(proxy): deny requests whose session predates the IdP logout
fix(escalation): reject a Telegram callback after the grant expired
docs(roadmap): propose R8, per-route approval quorum
docs(r4): lock OD3, the model never allows admin routes alone
chore(deps): bump the OIDC client library
```

`feat` is a minor bump, `fix` a patch, and `!` or `BREAKING CHANGE:` a
major. `docs`, `chore`, `test`, `refactor` and `ci` release nothing.

Scopes: a component name once components exist (`proxy`, `policy`, `ai`,
`escalation`, `audit`, `deploy`), a roadmap item for its design doc
(`r4`), or `roadmap`, `docs` or `deps`.

## Where things live

`CLAUDE.md` has the map. It is a rule, not a courtesy: each fact has
exactly one authoritative home.

| You want | Read |
|---|---|
| What's built and what's next | [`ROADMAP.md`](ROADMAP.md) |
| Why an item is designed the way it is | its `docs/NN-*.md` |
| How design docs work | [`docs/README.md`](docs/README.md) |
| Known bugs | [`BUGS.md`](BUGS.md) |
| Coding and review rules, the gates | [`CODE-REVIEW.md`](CODE-REVIEW.md) |
| Threat model | [`SECURITY.md`](SECURITY.md) |

## Running the gates before you push

None are defined yet. R1's design doc picks the toolchain, and the PR that
implements it adds the exact commands here. See `CODE-REVIEW.md` §Gates.

## Adding a dependency

Each dependency is part of the security boundary. Say in the PR why it is
needed and why the standard library isn't enough. The licence policy (and
its CI check) is set in R1.

## What a good PR looks like

- One concern per PR. "Fix the thing" plus "and reformat this file" is two.
- Tests for anything behavioural, written before the fix if it is a bug.
  For anything on the decision path, that includes the failure case and
  proof that it denies.
- The design doc updated when a decision changes, not just the code.
- `ROADMAP.md` status and `docs/gotchas.md` kept in sync when your change
  makes them wrong. `BUGS.md` entries deleted when your change fixes them.
- A description that says what changes and why. The diff already says how.
