# R3 — Audit log (docs/03)

**Status**: drafted 2026-10-26. No owner decisions needed. Awaiting the
owner's approval of the doc as a whole; merging the PR that adds it is
that approval. Status lives in [`ROADMAP.md`](../ROADMAP.md).

Chunks **AU1–AU2** (`AU` = audit; unused).

**Relationship to earlier work**: builds on [docs/01](01-foundations.md)
D11 (SQLite plus JSON lines on stdout) and D16 (everything logged is
agent-readable).

---

## 1. Purpose

Because the target's own logs show the human, not the agent, Nyyrikki's
audit log is the only record that ties a request back to the agent that
made it and to what covered it. After the fact, "who asked for this, who
approved it, what ran and what happened?" must be answerable for every
request, including the ones that were refused.

### Non-goals

- Shipping the log anywhere: the stdout copy is picked up by the
  cluster's own log pipeline.
- Retention and pruning: v1 keeps every record. The operator surface
  (R7) decides how records are reviewed and aged out.
- Tamper evidence against someone who owns Nyyrikki's pod: they are in
  the trust base (SECURITY.md).

## 2. Measured and verified before writing

| # | Claim | How | Result |
|---|---|---|---|
| M1 | SQLite triggers can abort `UPDATE` and `DELETE` on a table with `RAISE(ABORT, …)` | SQLite documentation, "CREATE TRIGGER"; ran it with `modernc.org/sqlite` v1.61.0, 2026-10-26 | Confirmed. D2 |
| M2 | `encoding/json` sorts map keys; `SetEscapeHTML(false)` turns off `<>&` escaping | `docs/measured.md` (audit M1) | Re-read; confirmed |

## 3. Owner decisions

None. The questions R3 raises (what to record, where) are answered by
`CLAUDE.md` and docs/01.

## 4. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | **One record per event**, with: `id` (`aud_` ULID), `time`, `kind` (§5.1), `human`, `agent` (the agent key as a keyed hash, D3), `client_id`, `target` (or targets), `run_id`, `elevation_id`, `approval_id`, `request` (the canonical argv after docs/04 D14's redaction, plus stdin length and SHA-256), `run_as` (Kubernetes user and groups), `covered_by` (`one-off`, `elevation`, or empty), `decision` (`allow`, `deny`, or empty), `code` (docs/02 D14), `exit_code`, `detail` (Nyyrikki's own short text, never agent text). The agent's reason is stored too, as `reason`, since it is part of what the approver saw. | `CLAUDE.md`: every request recorded with agent, human, target, exact request, what covered it and what it did. *Extended 2026-10-30 by [docs/07](07-ssh-target.md) D2, D5*: `request.command` holds an SSH request's command string, and `cert_serial` the serial of the certificate an SSH run was issued, in `run_started` (written before anything reaches the host) and the run's last record. |
| D2 | **Append-only in SQLite**: table `audit` with triggers that abort any `UPDATE` or `DELETE` (M1). The audit code has only an `Append` function. | No path in the code can rewrite history. |
| D3 | **The agent key appears only as `HMAC-SHA256(audit_key, agent key)`, first 16 hex characters**, where `audit_key` is 32 random bytes generated on first start and kept in the database. | docs/01 D16: agent keys appear only as a keyed hash. A plain hash of a guessable `sid` could be reversed. |
| D4 | **A failed write is a deny.** The decision point and the runner write the record of a step before acting on it: the allow record before forwarding, the approval-requested record before sending to Telegram. If that write fails, the step doesn't happen and the call fails `unavailable`. The record of a run's result is written after the run; if that fails, it is logged on stderr and the call still returns the result, since the request already ran. | INV-10: a failed audit write doesn't turn into an allow. |
| D5 | **Every record is also written to stdout** as one JSON line with the same fields, after the SQLite write succeeds. | docs/01 D11. |
| D6 | **Never in a record**: tokens, DPoP proofs, elevation handles, stream tickets, Telegram callback data, stdin contents, the target's response. The response's size and exit status are recorded. | docs/01 D16, INV-09. |

### Rejected alternatives

| Alternative | Why not |
|---|---|
| Recording the target's response | It may hold secrets (R9 is deferred), and the log is agent-readable (D16). |
| Hash-chaining records | Protects against an attacker who can write the database, who already owns everything (trust base). Reconsidered if records leave the pod. |

## 5. Design

### 5.1 Kinds

`auth_failed`, `invalid_request`, `run_requested`, `elevation_requested`,
`approval_sent`, `approval_settled` (with `decision` and `code`:
approved, denied, expired, withdrawn), `decision` (allow or deny, with
`covered_by`), `run_started`, `run_finished` (`exit_code`, output sizes),
`run_cut`, `elevation_live`, `elevation_ended`, `elevation_expired`,
`stream_attached`, `dependency_failed`.

*Extended 2026-10-30 by [docs/07](07-ssh-target.md) D16*: `host_setup_served`
(the target and the client address), once per fetch of an SSH host's
setup script.

*Extended 2026-10-31 by [docs/08](08-ssh-onboarding.md) D14*:
`ssh_ca_warning` (the fingerprints, in `detail`), once each time the set
of extra `user_ca_public_keys` equal to a key derived from the CA Secret
changes.

### 5.2 Schema

```sql
CREATE TABLE audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  time_ms INTEGER NOT NULL,
  kind TEXT NOT NULL,
  record TEXT NOT NULL            -- the JSON object of D1
);
CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
```

## 6. Security considerations

- **Inputs.** The canonical request and the reason are agent-controlled;
  they are stored as JSON strings, never interpreted. The redaction of
  docs/04 D14 is applied before they are stored.
- **Dependency failures.** SQLite unwritable: D4.
- **What reaches the log.** D6; the log is agent-readable (docs/01 D16).
- **New ways to reach a target.** None.

## 7. Acceptance criteria

| Goal | Verified by |
|---|---|
| G1 Every kind of §5.1 is written by the path that causes it, with agent, human and target | integration tests assert the records of each M1–M3 scenario |
| G2 `UPDATE` and `DELETE` on `audit` fail | `TestAuditAppendOnly` |
| G3 A failed audit write before forwarding denies | `TestAuditFailureDenies` |
| G4 No record contains a token, handle, ticket, stdin contents or a secret-bearing value | `TestAuditNeverContainsSecrets`: runs every scenario with marker secrets and scans the database and stdout |
| G5 The agent key appears only as the keyed hash | same test |

## 8. Chunks

| Chunk | Scope | Done when |
|---|---|---|
| **AU1** | schema, `Append`, stdout copy, keyed hash | G2, G5 |
| **AU2** | every call site of §5.1 | G1, G3, G4 |

## 9. Risks and open questions

- **The database grows without bound.** At a few hundred records a day
  that is years before it matters; R7 adds pruning.

## 10. How it was implemented (YYYY-MM-DD)

<!-- Added during implementation. -->

## 11. Post-implementation review (YYYY-MM-DD)

<!-- Added at close-out. -->
