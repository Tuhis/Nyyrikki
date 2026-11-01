# R13 — Public release readiness (docs/09)

**Status**: drafted 2026-11-01, with the owner's decision (OD1) taken
the same day. Status lives in [`ROADMAP.md`](../ROADMAP.md).

Chunks **PB1–PB7** (`PB` = public; unused).

**Relationship to earlier work**: revises docs/06 D1 (what the image
holds) and D6 (what a release publishes), and settles docs/06 M3
(attestations) by signing releases with a key-less signature instead.
Adds a coverage gate to docs/01 D17. Changes nothing on the decision
path.

---

## 1. Purpose

The repository is private, and the owner wants it public under its
Apache-2.0 licence (docs/01 OD10). An outsider who finds it today
meets a 30-line README with no status, no picture of what an approval
looks like and no way to try it short of a Kubernetes cluster, a
hand-configured Keycloak realm and a Telegram bot. Someone who finds a
vulnerability is told to "contact the maintainer privately" without
being told how. The binaries and the image don't carry their
dependencies' licence texts. Releases ship a checksum file but nothing
that says the files came from this repository's workflow. Coverage can
fall without anyone noticing. And `main` is unprotected, because a
private repository on the free plan has no rulesets.

The sibling project `gawk` went through this and is public. This doc
takes what it got right for outsiders (the README, a reporting channel,
licence notices, coverage, a way to try it, the repository settings) and
leaves out its sheer size, which `CLAUDE.md` warns against.

### Non-goals

- Changing anything on the decision path, the threat model or an
  invariant. A review of the security model before going public is a
  different item. This one makes no claim about it, and the README says
  so.
- A website, a demo deployment or a hosted instance.
- macOS for the quickstart. Docker Desktop doesn't route the host to
  container addresses, which the quickstart's issuer URL relies on
  (see §5.5). Linux only, said plainly.
- Rewriting git history. It was scanned and is clean (M1).

## 2. Measured and verified before writing

| # | Claim | How | Result |
|---|---|---|---|
| M1 | The git history holds no secret | gitleaks v8.30.1 with `.gitleaks.toml` over every pushed commit (439), 2026-11-01 | Two findings, both the test constant `nyst_test-ticket-…` in `internal/stream/stream_test.go`. The private keys in history are `…` placeholders in setup docs. The only infrastructure names are the ioio telemetry endpoints and the runner label, which `gawk`'s public history already holds |
| M2 | The workflows don't run outside code on the owner's runners | Read `ci.yml`, `e2e.yml`, `ssh-host.yml`, `claude.yml`, `claude-code-review.yml`, 2026-11-01 | Confirmed: a PR whose head isn't this repository runs on `ubuntu-latest` (a positive check); the Claude workflows need write access or `tuhokuutio[bot]` (docs/01 D18) |
| M3 | A private repository on the free plan has no rulesets or branch protection | `GET /repos/Tuhis/Nyyrikki/rulesets`, 2026-11-01 | 403 "Upgrade to GitHub Pro or make this repository public". `gawk`'s rulesets are readable and active |
| M4 | Cross-package statement coverage | `go test -coverpkg=./... ./...`, go 1.26.8, 2026-11-01 | 83.0% in total. Lowest: `cmd/nyyrikkid` 0%, `internal/runner` 44%, `cmd/nyyrikki` 47%, `internal/store` 65% |
| M5 | GitHub artifact attestations in a private repository need GitHub Enterprise Cloud | GitHub docs, "Using artifact attestations", 2026-11-01 | Confirmed. Sigstore's key-less signing (cosign with the workflow's OIDC token) needs no plan and works in a private repository, at the cost of the repository and workflow names being written to the public transparency log |
| M6 | `docker`, `kind`, `helm` and `kubectl` on a Linux host are enough for the e2e stack | `test/e2e/env_test.go` | Confirmed: the e2e test builds kind, Keycloak and the chart from these alone; it notes the host must reach the docker network's addresses |

## 3. Owner decisions

| # | Question | Decision |
|---|---|---|
| OD1 | Go public, and with what first? | **Prepare it as recommended, and do everything that can be done from the repository** (owner decision 2026-11-01). The owner flips the visibility and changes the settings in §5.7, which need the owner's rights. |

## 4. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | **The README is the front page**, at `gawk`'s level: a status line (pre-1.0, not independently audited, one maintainer), what it does and what it doesn't, a diagram of the flow, the shape of a Telegram approval, the features, quick links. No counts that drift and no status tracking (`CLAUDE.md`). | An outsider decides in a minute whether to read on; the status line keeps that decision honest. |
| D2 | **Vulnerabilities are reported through GitHub private vulnerability reporting**, linked from SECURITY.md and from an issue-template `config.yml`. Until the repository is public, SECURITY.md says to wait for it rather than disclose. | A channel that exists, is private, and needs no e-mail address in the repository. |
| D3 | **Licence notices are generated at build time, not committed.** The image holds the licence texts of every module compiled into `nyyrikkid` under `/usr/share/doc/nyyrikki/licenses`, made by `go-licenses save` in the build stage. A release adds `nyyrikki-licenses.tar.gz`, the same for the CLI. *Revises docs/06 D1 and D6.* | MIT, BSD and Apache-2.0 require the notices with binaries. A committed file drifts on every Renovate bump (`gawk` needed a post-upgrade task and a CI check to keep up); a generated one can't. |
| D4 | **Releases are signed key-less with cosign**: the image by digest, the OCI chart by digest, and `SHA256SUMS` as a blob (`SHA256SUMS.sigstore.json`). The image also carries BuildKit's SBOM and provenance attestations. The release job verifies each signature against this repository's release workflow identity before it uploads anything, and fails otherwise. The setup docs show how to verify. *Settles docs/06 M3.* | Ties an artifact to the workflow that made it, with no key to keep (M5). Verifying in the job catches a signature that was never made, the "configured but doesn't reach production" failure. |
| D5 | **A coverage gate** in `scripts/gates.sh`: cross-package total coverage (`-coverpkg=./...`) must not fall below the floor in `coverage-floor.txt`, set to the measured value rounded down to a whole percent. Raising it is a commit. It has a canary, like every gate. | Coverage that falls unseen is how untested branches build up; a single total floor is simple enough to keep honest. Per-package floors were rejected (below). |
| D6 | **A local quickstart on Linux**: `dev/quickstart.sh up` builds a kind cluster, Keycloak and Nyyrikki from the checkout, and uses a **real Telegram bot** the user made with BotFather, then prints how to sign in and run a first request. `dev/quickstart.sh down` removes it all. The setup shares its code with the e2e test, so the e2e keeps it working. | The only way to see Nyyrikki today is a real deployment. A fake approver would show the wrong thing and put an approval surface on the user's machine, which `CLAUDE.md` forbids. |
| D7 | **Renovate runs `go mod tidy` after updates.** | Keeps the `tidy` gate green on dependency PRs. |
| D8 | **Repository settings when the repository goes public** (§5.7) are recorded here and applied by the owner. | They need admin rights the coding agent doesn't hold, and they're part of being ready. |

### Rejected alternatives

| Alternative | Why not |
|---|---|
| A committed `THIRD-PARTY-NOTICES.md` | Drifts on every bump; needs a freshness check and Renovate post-upgrade commands (`gawk` did this). |
| GitHub artifact attestations | Need GitHub Enterprise Cloud while the repository is private (M5). Worth adding next to D4 once public. |
| A signing key held in a GitHub secret | One more credential to guard, rotate and lose; key-less signing needs none. |
| Per-package coverage floors | Many numbers to maintain, and a refactor that moves code between packages fails them for no reason. The total floor catches the real failure. |
| A quickstart with the e2e's fake Bot API | Shows an approval flow that isn't the product, and puts an approve button on the machine the agent runs on. |
| Waiting for M4 before going public | The design doesn't rely on the code being secret. A status line says what is unfinished. |

## 5. Design

### 5.1 README (PB1)

Sections, in order: one-paragraph pitch; the status line; a Mermaid
diagram (agent → `nyyrikkid` → Telegram approver; on approval,
`nyyrikkid` → target, as the human); what an approval message shows,
as text in the message's own wording; features; "try it" (the
quickstart, Linux); install (`docs/setup/`); how it works (links to
docs/01, docs/02); quick links. Badges: CI, E2E, licence, latest
release.

### 5.2 Reporting (PB1)

SECURITY.md §Reporting: the Security tab's "Report a vulnerability"
button, a link to `/security/advisories/new`, and what to include.
`.github/ISSUE_TEMPLATE/config.yml` links the same, plus the setup docs.

### 5.3 Licence notices (PB2)

- Dockerfile: the build stage installs `go-licenses` at the version
  pinned in `ci.yml`, runs `go-licenses save ./cmd/nyyrikkid
  --save_path=/out/licenses` with the same ignores as the `licenses`
  gate, and copies the go-sdk's and Nyyrikki's own licence files in by
  hand. The final stage copies `/out/licenses` to
  `/usr/share/doc/nyyrikki/licenses`.
- `release.yml`: the same for `./cmd/nyyrikki`, packed as
  `dist/nyyrikki-licenses.tar.gz` and covered by `SHA256SUMS`.
- CI `image` job: checks that the image holds the directory and that it
  isn't empty, through `docker create` and `docker cp`, since the
  image has no shell.

### 5.4 Signed releases (PB3)

- `release.yml` `publish` job: `id-token: write`; cosign installed by
  its pinned installer action; `sbom: true` and `provenance: mode=max`
  on the image build; `cosign sign --yes` on the image digest and on
  the chart's OCI digest from `helm push`; `cosign sign-blob --bundle
  SHA256SUMS.sigstore.json` on `SHA256SUMS`.
- Each is verified in the job with `--certificate-identity
  https://github.com/Tuhis/Nyyrikki/.github/workflows/release.yml@refs/heads/main`
  and `--certificate-oidc-issuer
  https://token.actions.githubusercontent.com` before `gh release
  upload`. A failure stops the job: nothing pointing at an unsigned
  image is published (the job already publishes the image first, so
  the image may exist unsigned; the release notes and assets that point
  at it don't).
- `docs/setup/install.md` gets "Verifying a release" with the same
  commands.

### 5.5 Coverage gate (PB4)

`gate coverage`: runs `go test -count=1 -coverpkg=./... -coverprofile`
over the module, reads the total from `go tool cover -func`, and fails
if it is below `coverage-floor.txt`. The `test` gate keeps `-race`;
this gate runs without it, as `gawk` does, because the two together
take twice as long. The canary is a tiny module under
`test/canaries/coverage/` with an untested function and a floor of 90.

### 5.6 Quickstart (PB5)

- The e2e setup in `test/e2e/env_test.go` is split so that the part
  that makes the network, the cluster, Keycloak and the realm, the CA,
  and the chart install lives in a package the quickstart can call
  (it takes the Telegram API URL and token as inputs). The e2e passes
  its fake bot; the quickstart passes `https://api.telegram.org` and the
  user's token.
- `dev/quickstart.sh up` checks for `docker`, `kind`, `helm`, `kubectl`
  and Go, asks for the bot token (read without echo) and the user's
  Telegram ID (docs/setup/telegram.md), and runs the Go program. The
  bot token goes into the cluster's Secret and a `0600` file under
  `dev/.quickstart/`, which is git-ignored, and is never printed.
- It prints the `nyyrikki login` command with `--ca` for the stack's
  CA, the Keycloak user's name and password, and a first
  `nyyrikki run` against the kind cluster.
- The issuer is Keycloak at its docker-network address (as the e2e),
  which the host reaches on Linux. macOS is out (§1).
- Names differ from the e2e's (`nyyrikki-quickstart`) so that the two
  can't remove each other.

### 5.7 Repository settings (PB7, the owner)

Applied after the visibility flip:

- Private vulnerability reporting on.
- A `main` ruleset as `gawk`'s: no deletion, no force push, linear
  history, PRs with squash only, threads resolved, required checks
  `build (1.26.x)`, `build (1.27.x)`, `gates`, `image`.
- Squash merge only; delete branches on merge.
- Description: "Lets AI agents run privileged requests, each approved
  by a human on Telegram". Topics: `mcp`, `ai-agents`, `kubernetes`,
  `security`, `privileged-access`, `telegram`, `go`.
- Actions: require approval for workflows from all outside
  contributors.
- The self-hosted runner pool registered to this repository only.
- The GHCR packages `nyyrikki` and `charts/nyyrikki` public, since
  docs/setup/install.md installs from them.
- `.claude/skills/ship-pr` updated: rulesets now enforce what it used to
  enforce by discipline.

## 6. Security considerations

- **No new trust boundary in the product.** PB1–PB5 don't change
  `nyyrikkid`'s code paths. PB5 adds test and development code that
  isn't in the image.
- **The quickstart holds a real bot token** on the user's machine,
  which is also where a test agent would run. That is acceptable only
  because the quickstart is for trying Nyyrikki, and its output says
  so: a bot token on the agent's machine lets that agent read the bot's
  updates and answer as the bot, though not tap for the approver. It
  must not be the bot of a real deployment. The docs and the script say
  this before asking for the token.
- **Signing adds `id-token: write`** to the release job, which already
  pushes the image. The OIDC token is used only by cosign in that job.
  Sigstore's public log records the repository and workflow names (M5),
  which go public anyway.
- **The build stage installs `go-licenses`** from the module proxy,
  checked against the checksum database. It runs only in the build
  stage; nothing of it reaches the final image except the licence
  texts.
- **Going public exposes the workflows to outside PRs.** M2 shows that
  they run hosted; §5.7 adds the approval requirement on top.

## 7. Acceptance criteria

| Goal | Verified by |
|---|---|
| G1 The README states what Nyyrikki is, its status and that it isn't audited, and links to setup, design and security | Review of PB1 |
| G2 A vulnerability has a private channel, named in SECURITY.md and in the issue chooser | PB1 review; the owner opens the issue chooser after §5.7 and sees the link working |
| G3 The image and the CLI release carry their dependencies' licence texts | CI `image` job checks the directory; the release job fails if the archive is empty |
| G4 Every release artifact is signed by this repository's release workflow, and the release fails if a signature can't be verified | The release job's verify steps; the owner runs install.md's verify commands on the next release (manual) |
| G5 Coverage can't fall below its floor unseen | The `coverage` gate in CI; `gates-selftest` shows it fails on its canary |
| G6 Someone with a Linux machine and a Telegram bot can try Nyyrikki with one command, and remove it with another | The e2e runs the shared setup on every PR; the quickstart is run up to `nyyrikki targets` without a bot by the implementer, and end to end with a real bot by the owner (manual) |
| G7 Renovate's Go PRs are tidy | The next Renovate Go PR passes the `tidy` gate |
| G8 The settings of §5.7 are in place | The owner, after the flip (manual) |

## 8. Chunks

| Chunk | Scope | Done when |
|---|---|---|
| **PB1** | README, SECURITY.md reporting, issue-template `config.yml`, `.gitignore`, this doc | G1, G2 (repository part) |
| **PB2** | Licence notices in the image and the release | G3 |
| **PB3** | Signed releases, SBOM and provenance, install.md verification | G4 |
| **PB4** | Coverage gate and canary | G5 |
| **PB5** | Quickstart, the e2e setup shared with it | G6 |
| **PB6** | Renovate `gomodTidy` (lands with PB1: one line) | G7 |
| **PB7** | Repository settings, by the owner | G2, G8 |

Ordering: PB1 first, since it carries this doc. PB2–PB6 are
independent. PB7 after PB1–PB3, so that the first thing outsiders see
already reports, licenses and signs.

## 9. Risks and open questions

- **PB3 can't be fully verified until the next release.** The verify
  steps make a broken signature fail the job instead of shipping
  silently.
- **The quickstart's Keycloak runs `start-dev` with `admin/admin`** on a
  docker network. It isn't reachable from outside the host, but it is a
  development setup and the script says so.
- **A public repository invites drive-by PRs** that the design-first
  process will turn away. CONTRIBUTING.md already says so.

## 10. How it was implemented (YYYY-MM-DD)

<!-- Added during implementation. -->

## 11. Post-implementation review (YYYY-MM-DD)

<!-- Added at close-out. -->
