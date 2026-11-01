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
an unexpected answer (agent authentication, the target registry,
Telegram, the audit sink, the credential store, credential issuance, the
target system) ends in deny. For each such dependency there is a test
that makes it fail and asserts deny. A default branch in a decision
`switch` is deny.

**One decision point.** Whether a request may run is decided in exactly
one place. A second "quick check" elsewhere drifts from the first. Review
asks: can any MCP tool or method (resources, prompts, sampling), CLI
command, transport, batch or follow-up request reach a target without
passing it?

**No approval, no request.** The decision point allows a request only
when a one-off approval of exactly that request, or a live elevation
matching agent, human and target, covers it. Listing targets is the only
thing that runs without one. Every other branch is deny, with a test.

**What is forwarded is what was approved.** An incoming request is
parsed once into a canonical form *before* the decision. The approval
binds to that form, the approver is shown that form, and the forwarder
sends exactly that form. Nothing passes through a shell. Nothing is
re-parsed after the decision. A test shows that every way of smuggling
a second request or extra parameters past the parser is rejected.

**Elevations expire for real.** An elevation is checked against the
server clock on every request, not when it was granted. The 30-minute
cap is enforced where elevations are created, whatever the agent asked
for. Streaming and long-lived requests (watch, exec, port-forward) are
cut when the elevation expires or is ended. Each of those has a test.

**The target system sees the real user.** Where a target supports
impersonation or delegation, Nyyrikki acts *as* the human the agent is
bound to, not as itself. The impersonated identity comes from the
authenticated binding, never from the request or anything else the
agent controls. Impersonation headers or fields in the agent's own
request are stripped or rejected, with a test. A target that can't
impersonate is called out in its design doc, together with how the
request is still attributed.

**Issued credentials are leases.** A temporary credential that Nyyrikki
creates on a target system has the narrowest scope and shortest lifetime
that work. It never leaves Nyyrikki, and it is revoked on every path:
success, failure, timeout, cancellation, elevation end and shutdown.
Leftovers from a crash are found and revoked at startup. Each of those
paths has a test asserting the revocation.

**The agent is untrusted.** Its requests and its stated reason are
attacker-controlled. The reason is shown to approvers as the agent's
claim, escaped, and never in a way that can pass for Nyyrikki's own
text. A change that shows new agent-controlled data to an approver comes
with a test using hostile input (markup, look-alike characters, very
long text).

**An approval is bound to exactly one thing.** A one-off approval names
the exact request; an elevation names its targets, its agent and human,
and its expiry, and covers only requests that carry its handle. Each
also names the approver it came from. Check all of them, and accept a
callback once. A replayed, expired, forwarded or
foreign-chat callback is rejected, with a test for each.

**Secrets never leave their lane.** Nyyrikki's own credentials, the
temporary credentials it issues, agent tokens, and secret contents from
target systems never appear in logs, audit free-text or Telegram
messages. Nyyrikki never puts its own credentials or leases in a
response or an error returned to the agent either. (A target's response
to a request, approved one-off or under an elevation, that reads them
because the human can is an accepted risk: docs/04 OD3, SECURITY.md.) Redaction happens at
the boundary, with a test that asserts the redacted form. The target's
response to an approved request is the exception: it is returned
unredacted (`ROADMAP.md` R9).

**MCP and CLI stay in step.** Both are thin clients of one API. A
change that adds or changes an operation in one does it in both, with a
test for each, and neither gains a way to approve, deny or end
anything.

**Every decision is audited, including the failures.** Allow, deny,
escalate, approve, reject, expire, every forwarded request (as which
user, covered by what, with which result), elevations granted, ended and
expired, credentials issued and revoked, plus
deny-because-a-dependency-failed. An audit write that fails doesn't
turn into an allow.

## Coding guidelines

**Error paths must release what they acquired.** Any setup that fails
midway tears down everything it built before returning the error. Route
success and failure through one shared teardown. A leaked pending
escalation is a tool call held open forever. A leaked elevation is
access that should have ended. A leaked issued credential
is standing access nobody is watching. And an approval with no waiter
is worse than either.

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
5. **Bypass hunt**: list every way a request can reach a target and
   check that each one passes the single decision point. Look at every
   MCP tool and method, every CLI command, transports, batching, request encodings and
   parser differences, redirects, streaming upgrades, the impersonated
   identity, elevation expiry, and the gap between check and forwarding.
6. **Trust boundaries**: for every new input (agent request, agent
   reason, target response, Telegram update, config), ask who controls
   it and where it is validated.
7. **Error mapping at boundaries**: every distinct failure crossing a
   boundary needs a deliberate status and audit reason, not a catch-all.
8. **Ops surface**: flags, deployment values, metrics, audit and log
   fields ship together, or the gap is called out explicitly.

## Gates (all must pass before merge)

Defined by [docs/01](docs/01-foundations.md) D17 and §5.6, run by
`scripts/gates.sh` locally and by the `gates` job in CI. Tool versions are
pinned in `.github/workflows/ci.yml` (measured 2026-10-26, docs/01 M12):
staticcheck v0.8.2, govulncheck v1.9.0, go-licenses v2.0.1, gitleaks
v8.30.1, kubeconform v0.8.0.

| Gate | Command |
|---|---|
| format | `test -z "$(gofmt -l .)"` |
| vet | `go vet ./...` |
| staticcheck | `staticcheck ./...` |
| tidy | `go mod tidy -diff` |
| tests | `go test -race -count=1 ./...` |
| coverage | `go test -count=1 -coverpkg=./... -coverprofile=… ./...`; the total from `go tool cover -func` must not be below `coverage-floor.txt` (docs/09 D5). It fails closed: a missing or malformed floor, an empty profile or an unreadable total fails |
| vulnerabilities | `govulncheck ./...` |
| licences | `go-licenses check ./... --allowed_licenses=MIT,BSD-2-Clause,BSD-3-Clause,Apache-2.0,ISC`, ignoring hand-reviewed modules, whose LICENSE hashes are pinned in `scripts/pinned-licenses` |
| secrets | `gitleaks dir . --redact --config .gitleaks.toml` (it also matches elevation handles and stream tickets) |
| chart | `helm lint`, `helm template … \| kubeconform -strict -kubernetes-version 1.35.0`, and the chart's template tests |
| pinning | every action pinned to a SHA, every workflow defaulting to `contents: read` |

`coverage-floor.txt` holds one whole percent: the measured total, rounded
down, less one point. The point is margin for statements whose coverage
depends on timing (three in `internal/telegram` on 2026-11-01, so the
total moved between 83.02% and 83.07% over five runs); without it the
gate would fail at random on a slow runner. Raise it in a commit of its own (or alongside the tests that earn
it) when the total has grown a whole point past it. Never lower it
without saying why in the PR description; the reviewer checks that the
reason holds.

Every gate has a canary in `test/canaries/`, and `scripts/gates-selftest.sh`
(the `gates-selftest` step in CI) fails if any gate passes its canary.
`gawk` lesson worth keeping: a gate that checks nothing passes
vacuously, which is worse than no gate at all.
