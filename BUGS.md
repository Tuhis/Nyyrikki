# Known bugs

Confirmed defects that aren't fixed yet. Each entry says how it was found,
what the impact is, and where a fix would start. Remove an entry when it is
fixed, and move anything durable it taught us into the relevant
`docs/NN-*.md` or `docs/gotchas.md`.

A defect that could grant access it shouldn't is a vulnerability, not a
bug. It doesn't go here; see [SECURITY.md](SECURITY.md).

## The check after enrollment can race sshd's reload

**Found**: 2026-11-01, by the e2e (`test/e2e`, step "SE6: the host is
set up and enrolled by the served script"), once in several runs on a
loaded host (load about 8); the same code passed on the re-run.

**What happens**: `deploy/ssh-host/nyyrikki-host-setup.sh` reloads sshd
(`ny_reload_sshd`, `systemctl reload` or `kill -HUP`) and posts
`/hosts/<target>/enroll/check` straight away (around line 2390). On a
reload sshd re-executes itself and briefly closes its listening socket,
so nyyrikkid's dial for the check can land in that gap and report
`host_unreachable`.

**Impact**: no access is granted that shouldn't be, and the host is
enrolled: runs on it work once sshd is listening again (they do their
own live host check). The cost is a false failure: the setup exits 1
and warns that the check after enrollment failed and that runs fail,
which can lead an operator to spend a new token re-enrolling a host
that was already fine.

**Where a fix would start**: after `ny_reload_sshd` in the enrollment
path, wait (bounded, a few seconds) until sshd accepts a TCP connection
on its port before posting the check; or let nyyrikkid retry the check's
dial briefly on connection refused. A test needs a reload that holds
the socket closed long enough to be hit every time.

## `TestHostCheckElevationParallel` asserts on wall-clock time

**Found**: 2026-11-01, during docs/09 PB2 (`scripts/gates.sh`, `test`
gate), once while a Docker build loaded the machine: "checks took
927ms: not parallel". It passed three times on its own and on a full
rerun.

**Impact**: a flaky `test` gate under load; no product defect is known.

**Where a fix would start**: assert parallelism by overlap (a fake host
check that blocks until all are in flight) instead of by elapsed time.
