# Design docs

One numbered doc per roadmap item. Each records the decisions, the
alternatives that were rejected and *why*, and explicit acceptance
criteria. A doc should still make sense years later as a record of what
was decided, rather than a snapshot of what was true that week. Status
lives in [`ROADMAP.md`](../ROADMAP.md), never here.

Not a design doc, but in this directory:

| File | What |
|---|---|
| [`TEMPLATE.md`](TEMPLATE.md) | The skeleton every new design doc starts from |
| [`gotchas.md`](gotchas.md) | A consolidated list of gotchas, each of which cost real debugging time |

## Index

| Doc | Item |
|---|---|
| — | No design docs yet. R1 will be `01`. |

## The process

1. **Propose.** An item enters `ROADMAP.md` as 💡 with a short *why* and
   *scope*. That PR is `docs(roadmap): propose RN — …`. Larger ideas from
   outside start as a Proposal issue.
2. **Design.** Copy [`TEMPLATE.md`](TEMPLATE.md) to `docs/NN-short-slug.md`
   (the next free number) and add it to the index above. Mark the roadmap
   row 📝 and link the doc. Write the purpose and the questions first.
3. **Measure before deciding.** Wherever a decision leans on a claim about
   a library, protocol, API or model behaviour, test it or cite a primary
   source, and record it in the doc's "Measured and verified" table with
   the date and the version. A design built on an unverified claim gets
   rebuilt.
4. **Owner decisions.** Questions only the owner can answer are listed as
   `OD1`, `OD2`, … with a recommendation each. The owner's answers are
   recorded in the doc with the date. Nothing is implemented against an
   open OD.
5. **Lock and chunk.** Decisions become `D1`, `D2`, … rows. Work is split
   into chunks with a two-letter prefix unique to the doc. Every goal gets
   a "verified by" row; every chunk a "done when" naming goals. The roadmap
   row goes to 🔧.
6. **Implement** chunk by chunk, one concern per PR, following
   [`CODE-REVIEW.md`](../CODE-REVIEW.md). Each PR's review works from the
   doc's decisions and acceptance criteria, not just the diff.
7. **Record how it was built.** When implementation diverges from the doc,
   add a dated "How it was implemented" section saying where and why. The
   decision table is revised in place, with a dated note.
8. **Close out.** A post-implementation review against the doc. Its
   findings go into the doc (and into `CODE-REVIEW.md`, if one becomes a
   rule). The roadmap row goes to ✅ only when every acceptance criterion
   has been verified, including the manual ones. Otherwise the row says
   which criteria are still open.

## Conventions

- File names are `NN-short-slug.md`. Numbers are never reused, including
  for rejected docs.
- Every doc defines **explicit acceptance criteria**: a goal → verified-by
  table and a per-chunk "done when" column. A doc that lists proposed
  changes without them is how a critical review finding gets missed.
- Chunk prefixes are two letters, unique across all docs (e.g. `GW` for the
  gateway core, `TG` for Telegram). Claim the prefix in the doc's header.
- Decisions are revised in place with a dated note, never silently
  rewritten. Keep the old decision visible when the reasoning matters.
- Every doc has a **Security considerations** section, even when its
  answer is "no new trust boundary": say why.
- Link to other docs by number (`docs/03`) and decision (`docs/03 D4`).
- A gotcha discovered while writing or building a doc goes into
  [`gotchas.md`](gotchas.md) with a link back. It is not restated
  elsewhere.
