# Code & Review Guidelines

Adapted from `gawk`'s guidelines, which came from a post-implementation
review that found six issues in code whose tests were all green. The general
rules below carried over because each cost `gawk` a real bug. The
security rules are Nyyrikki's own starting set. When a review here finds
a defect a rule would have caught, add the rule and cite the finding, so
every rule stays concrete. Applies to human and AI contributors alike.

## Fixing bugs: test-first, always

Write a test that reproduces the bug, **run it and watch it fail**, then
fix, then watch it pass. Never land a fix whose test didn't first fail. A
test written after the fix proves nothing about the bug.

- If the bug is genuinely unreachable from the existing harnesses, say so
  explicitly in the PR and agree on the fallback *before* fixing. Adding a
  small test seam is usually better than skipping the test.
- Pure-quality refactors don't need new tests, but must stay green under
  the full gates (below).

## Security rules

These apply to every change. Nyyrikki's job is to say no correctly.

**Fail closed, and prove it.** Every path that can error, time out or get
an unexpected answer (IdP, token validation, policy evaluation, the model,
Telegram, the audit sink) ends in deny. For each such dependency there is
a test that makes it fail and asserts deny. A default branch in a decision
`switch` is deny.

**One decision point.** Authorization for a request is decided in exactly
one place. A second "quick check" elsewhere drifts from the first. Review
asks: can any route, method or upgrade (WebSocket, HTTP/2, redirects)
reach the upstream without passing it?

**The model's output is parsed, never trusted.** A model response is
validated against a strict schema; anything else is a deny or an
escalation. Free text never becomes a decision. A test feeds malformed,
empty, truncated and adversarial responses.

**Request content is untrusted input to the model.** Anything the
requester controls (path, query, headers, body, display name) is clearly
delimited in the prompt and can't change the instructions. A change that
puts new request data into a prompt comes with an injection test.

**An approval is bound to exactly one thing.** A Telegram approval names
the request (or the grant scope) it approves, the approver it came from
and when it expires. Check all three, and accept it once. A replayed,
expired, forwarded or foreign-chat callback is rejected, with a test for
each.

**Secrets never leave their lane.** Tokens, cookies, session IDs and
`Authorization` headers never appear in logs, prompts, audit free-text or
Telegram messages. Redaction happens at the boundary, with a test that
asserts the redacted form.

**Every decision is audited, including the failures.** Allow, deny,
escalate, approve, reject, expire, plus deny-because-a-dependency-failed.
An audit write that fails doesn't turn into an allow.

## Coding guidelines

**Error paths must release what they acquired.** Any setup that fails
midway tears down everything it built before returning the error. Route
success and failure through one shared teardown. A leaked pending
escalation is a request held open forever, or worse, an approval with no
waiter.

**Type your failure phases.** When callers behave differently depending
on *where* an operation failed (deny vs. escalate vs. retry), encode that
in the error type. Don't let them guess from messages.

**One event, one authoritative signal.** When several async signals report
the same underlying event (an escalation timing out vs. an approval
arriving), their settle order is unspecified. Pick the signal that carries
the semantics and make the others defer to it. Never let
whichever-fires-first decide behaviour. For escalations: exactly one of
approve, deny and expire wins, atomically, and the loser is a no-op.

**Shared constants have exactly one definition.** Decision values, scope
names and error codes are defined once and imported everywhere. A literal
copy is a future mismatch.

**New config knobs land fully plumbed in the same change:** flag, env var,
deployment values, docs, **and the production call site**. `gawk` once
shipped six knobs that were parsed, charted and documented, but wired only
into a test helper, so all six did nothing in production and every test
stayed green. Walk each knob from the flag to the object that consumes it.

**Counters and stats survive their owner's deletion.** Fold per-child
counters into the aggregate *before* deleting the parent. Anything counted
after deletion is silently lost.

## Review checklist

Work from the design doc, not just the diff. Design docs (`docs/NN-*.md`)
are contracts with **locked decisions** and per-chunk **acceptance
criteria**.

1. **Locked decisions**: re-read them and check that the code does what
   they say. Green tests don't catch contract violations nobody tested.
2. **Acceptance criteria → tests**: walk every criterion and point at the
   test that covers it. A missing one is a finding, even when the code
   looks right.
3. **Walk the failure paths by hand**: for each step in a setup sequence,
   ask "what is live if *this* fails, who cleans it up, and **is the
   result deny**?"
4. **Hunt settle-order races**: wherever two goroutines, promises or
   callbacks react to one event, ask which order the test exercised and
   what happens in the other order.
5. **Bypass hunt**: list every way a request can reach the upstream and
   check that each one passes the single decision point. Look at
   alternative methods, encodings, path normalisation, upgrades,
   redirects and health endpoints.
6. **Trust boundaries**: for every new input (request field, model output,
   Telegram update, config), ask who controls it and where it is
   validated.
7. **Error mapping at boundaries**: every distinct failure crossing a
   boundary needs a deliberate status and audit reason, not a catch-all.
8. **Ops surface**: flags, deployment values, metrics, audit and log
   fields ship together, or the gap is called out explicitly.

## Gates (all must pass before merge)

None yet: no language or toolchain has been chosen. The design doc that
picks them (R1, `docs/01`) defines the gates. That PR adds them here
**and** in `CONTRIBUTING.md`'s "Running the gates", and makes CI enforce
them. At a minimum, expect a formatter check, a linter, the full test
suite with the race detector (or the language's equivalent), a dependency
licence check and a secret scan.

`gawk` lesson worth keeping: make sure each gate actually checks
something. A typecheck that type-checks nothing passes vacuously, and that
is worse than no gate at all.
