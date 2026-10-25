# RN — Title (docs/NN)

<!--
Copy to docs/NN-short-slug.md, add it to the index in docs/README.md and
link it from its ROADMAP.md row. Delete these comments as you fill the
sections in. A section that doesn't apply says so in one line: it is not
deleted.
-->

**Status**: proposed YYYY-MM-DD. Status lives in
[`ROADMAP.md`](../ROADMAP.md). This line only says what stage the
document itself is at (drafted, owner decisions taken, implemented,
reviewed) and what is still open.

Chunks **XX0–XXn** (`XX` = <what the prefix stands for>; unused).

**Relationship to earlier work**: what this builds on, and which earlier
decisions it revises (`docs/NN Dn`).

---

## 1. Purpose

The problem, in the situation where it hurts. What a user or operator
can't do today, and what changes when this ships. Not the solution yet.

### Non-goals

What this deliberately does not do, so that review doesn't ask for it.

## 2. Measured and verified before writing

Every claim the design leans on, tested here or sourced from a primary
source, with the date and the version.

| # | Claim | How | Result |
|---|---|---|---|
| M1 | | | |

## 3. Owner decisions

Questions only the owner can answer, each with a recommendation. Record
the answer and the date. Nothing is implemented against an open OD.

| # | Question | Decision |
|---|---|---|
| OD1 | | *Open.* Recommendation: … |

## 4. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | | |

### Rejected alternatives

| Alternative | Why not |
|---|---|
| | |

## 5. Design

How it works: components, data flow, interfaces, configuration. For each
new config knob, list the flag, env var, deployment value and the
production call site that consumes it (`CODE-REVIEW.md`).

## 6. Security considerations

Required, even when the answer is short.

- New trust boundaries and inputs, who controls each, and where it is
  validated.
- How each new dependency failure ends in deny.
- What reaches the model, the audit log and Telegram, and what is
  redacted.
- New ways to reach an upstream, and how they pass the decision point.

## 7. Acceptance criteria

| Goal | Verified by |
|---|---|
| G1 | the test (or the manual step, and who runs it) |

## 8. Chunks

| Chunk | Scope | Done when |
|---|---|---|
| **XX1** | | G1 |

Ordering notes: which chunk must land first, and why.

## 9. Risks and open questions

## 10. How it was implemented (YYYY-MM-DD)

<!-- Added during implementation. Where the build differs from §4 and §5,
and why. Revise the decision rows in place with a dated note. -->

## 11. Post-implementation review (YYYY-MM-DD)

<!-- Added at close-out. Findings, their fixes, and any new rules for
CODE-REVIEW.md. -->
