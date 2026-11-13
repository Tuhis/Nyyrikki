# R14 — SOPS target: files encrypted with Google Cloud KMS (docs/10)

**Status**: implemented 2026-11-13 (§10), SO1–SO5; open: the manual
check G9 and M12, against the real Cloud KMS. Drafted 2026-11-12. Owner decisions OD1 and OD2 taken the
same day; OD3, OD5, OD6 and OD7 taken 2026-11-12 on the draft, OD4 on
2026-11-13. Approved 2026-11-13, when the PR that added it (#74)
merged. Status lives in
[`ROADMAP.md`](../ROADMAP.md).

Chunks **SO1–SO5** (`SO` = SOPS; unused).

**Relationship to earlier work**: a third target type next to Kubernetes
and SSH. It reuses the operations, the decision point and elevations of
[docs/02](02-gateway-core.md), the audit log of
[docs/03](03-audit-log.md), the canonical-argv rules of
[docs/04](04-kubectl-passthrough.md) D1–D3 and the messages of
[docs/05](05-telegram-escalation.md). It has no interactive runs, so
`/stream` is not involved. It is the first target where the request's
work happens **inside Nyyrikki** (a file is decrypted in the pod), and
the first that **can't run as the human** (OD3). When this doc is
approved, these rows get dated notes: docs/01 D14 (OD6 here), docs/02 D5
and D13, docs/03 D1, docs/05 D5 and D7, docs/06 D2, and `SECURITY.md` INV-05
and its accepted risks (OD3 here).

---

## 1. Purpose

Secrets kept in git are encrypted with [SOPS](https://github.com/getsops/sops),
with the key in Google Cloud KMS. An agent working in such a repository
can't read a secret that isn't deployed, change one value in an
encrypted file, or add a new encrypted file, unless it holds a Google
credential that can use the KMS key. That credential works forever, on
every file the key protects, with nothing approved and nothing recorded.

With this, an agent sends an encrypted file to Nyyrikki and asks for one
SOPS operation on it. The approver sees what is asked: the operation,
the path it names, which file, and the KMS key it uses. Nyyrikki
unwraps the file's data key with its own Google credential, does the
operation in the pod, and returns the result. The data key and the
Google credential never leave Nyyrikki.

### Non-goals

- **Running unmodified `sops` on the agent's machine against Nyyrikki**
  (SOPS's key service protocol). The agent would receive the file's data
  key, which opens every past and future version of that file (OD1).
- **Google Cloud in general**, or any other use of Cloud KMS (signing,
  raw encrypt and decrypt of arbitrary data).
- **Other SOPS key types**: age, PGP, AWS KMS, Azure Key Vault, Vault
  transit, HuaweiCloud. A file that lists any of them is refused (D4).
- **`edit`, `exec-env`, `exec-file`, `publish`, `rotate`, `updatekeys`,
  `groups`, `keyservice`, `filestatus`** (OD4).
- **Reading `.sops.yaml`.** The file lives in the agent's repository;
  the agent passes what it needs as flags (D2).
- **Redacting the plaintext that comes back.** A decrypted secret is the
  response, and it reaches the agent as it is (`CLAUDE.md`, R9).

## 2. Measured and verified before writing

Measured on 2026-11-12 with a Go probe on Go 1.26.8 against
`github.com/getsops/sops/v3` v3.13.3 and `google.golang.org/api`
v0.289.0, with a fake key service and a fake KMS HTTP server. Nothing
here was run against the real Cloud KMS; M10–M12 say what is still to
measure. SO4 turns M1–M8 and M15 into tests.

| # | Claim | How | Result |
|---|---|---|---|
| M1 | SOPS's command-line program is `package main` (`cmd/sops`), so its command tree can't be imported the way kubectl's can (docs/04 D2). The operations are importable: `cmd/sops/common` (`DecryptTree`, `EncryptTree`), the stores, and `sops.TreeBranch.Set`, `Unset`, `Truncate` | read the source; the probe decrypted, set a value and re-encrypted through them | Confirmed. D1, D2 |
| M2 | The library asks a caller-supplied key service for the data key: `common.DecryptTree` takes `KeyServices []keyservice.KeyServiceClient`, an interface with `Encrypt` and `Decrypt`. A key service that refuses a key makes the decrypt fail | probe: a fake key service saw one `Decrypt` call per decrypt; a file naming another KMS key failed with "no master key was able to decrypt the file" | Confirmed. D5 |
| M3 | Each value is AES-256-GCM encrypted with its key path as additional data, so a ciphertext only decrypts at the path it was encrypted for | probe: swapped the ciphertexts of two keys; renamed the key of one | Both fail: "cipher: message authentication failed". D8, §6 |
| M4 | The file's MAC covers every value in order, cleartext ones included, and is encrypted with the data key. Removing a value, or changing `mac_only_encrypted`, `unencrypted_suffix` or `encrypted_regex` in the metadata, fails the MAC check. Key names of cleartext values are not covered | probe: each variant; read `Tree.Decrypt` | Confirmed: "MAC mismatch" for each. §6 |
| M5 | SOPS's MAC error prints both MACs, which are SHA-512 hashes of the file's plaintext values | probe output: "MAC mismatch. File has 583B…, computed EC3A…" | Confirmed. D9: SOPS's error text never reaches the agent |
| M6 | Changing a value in an existing file needs the data key (one KMS decrypt) and no KMS encrypt; the wrapped data key in the file stays the same | probe: `Set` then `EncryptTree`; the fake key service counted +1 decrypt, +0 encrypt, and the `enc` line was unchanged | Confirmed. D2, §6 |
| M7 | `gcpkms.MasterKey` takes a token source and client options from the caller (`NewTokenSource`, `ClientOptions`, `UseRESTClient`). With a token source set it doesn't read `GOOGLE_CREDENTIALS` or `GOOGLE_OAUTH_ACCESS_TOKEN` | probe with `GOOGLE_OAUTH_ACCESS_TOKEN` set in the environment: the fake KMS saw the token source's token | Confirmed. D5, D6 |
| M8 | `option.WithRequestReason` reaches the wire through SOPS's key source as the `X-Goog-Request-Reason` header (REST), or `x-goog-request-reason` metadata (gRPC) | probe: the fake KMS received `POST /v1/…/cryptoKeys/k:decrypt` with the header; read `transport/grpc/dial.go` | Confirmed. D7 |
| M9 | Linking the SOPS library adds 106 modules to `nyyrikkid`, which has 97 today: the AWS, Azure, Vault and HuaweiCloud SDKs, age and PGP among them. Eleven are MPL-2.0 (`getsops/sops`, `hashicorp/vault/api` and nine `hashicorp/*` helpers), which docs/01 D14's allowlist doesn't hold. The probe binary is 64 MB | `go list -deps` on the probe and on `./cmd/nyyrikkid`; the first line of each module's licence file | Confirmed. OD5, OD6. `go-licenses` itself not yet run on them: SO1 |
| M10 | Cloud Audit Logs record the request reason in `protoPayload.requestMetadata.requestAttributes.reason` | the field's definition in `google.golang.org/genproto` (`AttributeContext.Request.reason`: "used by security systems to associate auditing information with a request") | Field exists. **Not yet measured** that a KMS decrypt's log entry carries it: G9, manual |
| M11 | Cloud KMS `Decrypt` and `Encrypt` are Data Access audit logs of type `DATA_READ`, which have to be enabled | [Cloud KMS audit logging](https://docs.cloud.google.com/kms/docs/audit-logging), read 2026-11-12 | Confirmed from the docs. That they are off by default is Google's general rule for Data Access logs, not re-read here: the setup doc says to enable them either way |
| M12 | When a federated workload identity impersonates a service account, the audit log's `principalEmail` is the service account and `serviceAccountDelegationInfo` holds the federated subject | [IAM audit log examples](https://docs.cloud.google.com/iam/docs/audit-logging/examples-workload-identity), read 2026-11-12 | Confirmed from the docs. **Not yet measured**: Workload Identity Federation from a pod's projected ServiceAccount token, end to end. SO5 |
| M13 | SOPS's built-in key service (`keyservice.Server`, behind `NewLocalClient`) builds its Google key as `gcpkms.MasterKey{ResourceID: …}` with no token source and no client options, and calls `Decrypt()` without the caller's context. So it uses whatever credential the process environment gives (`GOOGLE_CREDENTIALS`, `GOOGLE_OAUTH_ACCESS_TOKEN`, then Application Default Credentials), can't add a request reason, can't use one credential per target, and can't be cut. It also serves every key type, and a Vault key's address comes from the file | read `keyservice/server.go` and `gcpkms/keysource.go` | Confirmed. D5: it can't be used as it is |
| M14 | `sops decrypt` and `sops encrypt` have `--filename-override`, for a file read from stdin; `sops set` and `sops unset` don't, and take the file as their first argument | read `cmd/sops/main.go` | Confirmed. D2 |
| M15 | SOPS tries every key of a key group in turn and treats a key service's error as "try the next key": `decryptKeyGroup` collects the errors, returns the first success, and reports the errors only together, as text, when every key failed | read `sops.go` (`decryptKeyGroup`, `decryptKey`), 2026-11-13 (review round 1 of #74) | Confirmed. D5, D9: an error from the wrapper doesn't by itself fail the run, and the reason a call failed can't be taken from SOPS's error |
| M16 | SOPS's Google key source reads `SOPS_GCP_KMS_ENDPOINT`, `SOPS_GCP_KMS_UNIVERSE_DOMAIN` and `SOPS_GCP_KMS_CLIENT_TYPE` from the environment on every call, whatever token source it was given: the first two decide where the request, and the access token with it, is sent | read `gcpkms/keysource.go` (`newKMSClient`), 2026-11-13, while building SO3; the tests' own `sops` program is pointed at the fake KMS this way | Confirmed. D6: M7 holds for the credential only. `nyyrikkid` refuses to start with either of the first two set (§10). *Revised 2026-11-13 (review of #75)*: SOPS adds those two after the options it is handed (`newKMSClient`, read again), so pinning the endpoint with an option doesn't override them, and the refusal stays. The Google client reads variables of its own (`GOOGLE_CLOUD_UNIVERSE_DOMAIN`, `GOOGLE_API_USE_MTLS_ENDPOINT`, `GOOGLE_API_USE_MTLS`, `GOOGLE_API_USE_CLIENT_CERTIFICATE`; found by searching `google.golang.org/api` for the variables it reads); `nyyrikkid` refuses to start with those set too. Whether the client's own universe-domain check would have refused a mismatch with a bare token source was not tested. *Revised 2026-11-13 (review round 2 of #75)*: three more things were looked at. **The credential file** names where its token exchange is sent (`token_url`, `token_info_url`, `service_account_impersonation_url`, `universe_domain`; a key's `token_uri`), and the pod's ServiceAccount token goes with a federation's: only Google's own endpoints are accepted (D6). **`SOPS_GCP_KMS_CLIENT_TYPE`** can't change the client: `newKMSClient` takes the REST client when the variable says `rest` *or* the option is set, and Nyyrikki always sets the option (read again, v3.13.3), so it is not refused. **`HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`, `SSL_CERT_FILE` and `SSL_CERT_DIR`** are read by Go itself and are *not* refused: a proxy is ordinary in a cluster with restricted egress and sees only TLS to Google, and a root certificate added next to one is the operator's own choice, as the image's roots are. They are trusted as the operator's, like the config and the Secret (`docs/setup/sops.md`) |
| M17 | SOPS's `audit` package reads `/etc/sops/audit.yaml` when the process starts, panics if it doesn't parse, and connects to the PostgreSQL servers it names; without the file it does nothing | read `audit/audit.go` (`init`), 2026-11-13 | Confirmed. The image has no such file; `docs/gotchas.md` |
| M18 | `go-licenses save` copies the whole source of an MPL-2.0 module next to its licence text, not the licence alone | ran `scripts/save-licenses.sh ./cmd/nyyrikkid`, 2026-11-13: the eleven modules' source, about 5 MB | Confirmed. OD6: the image ships the source MPL-2.0 asks to be made available |
| M19 | A Workload Identity Federation configuration with a file-sourced token loads through `golang.org/x/oauth2/google` v0.36.0 (`CredentialsFromJSONWithType`) and exchanges at the `token_url` it names; the library's own notes call loading a configuration of unchecked type a security risk | the federation test against the fake token service, 2026-11-13 | Confirmed against the fake. D6. Google's real token service: M12, still open |

## 3. Owner decisions

| # | Question | Decision |
|---|---|---|
| OD1 | Who does the cryptography? Nyyrikki unwraps the data key and hands it to the agent's own `sops`; Nyyrikki runs the SOPS operation itself; or a general `gcloud` target. | **Nyyrikki runs the operation; the data key never leaves it** (owner, 2026-11-12). Handing out the data key gives the agent every past and future version of the file until the key is rotated, and the approver would see only a key name and an opaque blob. |
| OD2 | In scope now, though it is a third target type and outside the first version? | **Yes** (owner, 2026-11-12). |
| OD3 | Cloud KMS can't act as a human, so INV-05 ("requests run on the target as the human") can't hold as it does for Kubernetes. One Google service account for Nyyrikki, or one per human that Nyyrikki impersonates? | **One service account per target, and every KMS call carries a request reason naming the run, the human and what covered it** (owner, 2026-11-12; D7). Google's log then shows Nyyrikki as the principal and the human only as Nyyrikki's claim; Nyyrikki's own audit log is the record of who. Per-human service accounts would put the human in the authenticated principal and cap each human's reach with IAM. With one human they separate nobody; they can be added later as a field of the human registry without changing this design. |
| OD4 | Which operations? | **`decrypt` (with `--extract`), `set`, `unset` and `encrypt`** (owner, 2026-11-13). They cover reading a secret, changing one value and adding a file. Not `rotate` and `updatekeys`: they change which keys protect a file, which the approver can't judge from a message, and a human can run them. Not `edit`, `exec-env`, `exec-file` and `publish`: they need an editor, run a program or write to a bucket from Nyyrikki's pod. |
| OD5 | Use the SOPS library, or write the file format in Nyyrikki? The library is SOPS's own code, so what Nyyrikki decrypts and writes is what `sops` and Flux read. It also links 106 more modules into the process that holds every credential, including four cloud SDKs Nyyrikki never calls (M9). Writing the format (AES-GCM values, the MAC, the YAML and JSON stores, comments) is, by estimate, about a thousand lines with no new dependency beyond a KMS call, and it is a second implementation of a cryptographic file format that can drift from SOPS's. | **The SOPS library, and its existing key service where possible** (owner, 2026-11-12). docs/04 rejected a second implementation of kubectl for the same reason. The cost is supply chain: pinned versions, the checksum database, govulncheck and Renovate bound it (docs/01 D14). The built-in key service can't be used as it is (M13); shown that, the owner confirmed **Nyyrikki's own key service** the same day. D5 keeps it as small as it can be: SOPS's own Google key source makes the call. |
| OD6 | How do the eleven MPL-2.0 modules pass the licence gate? | **Admitted, by name** (owner, 2026-11-12), as docs/01 D14 does for the go-sdk: each reviewed by hand, ignored by name with the reason, its licence file pinned by hash. Not MPL-2.0 on the allowlist for everything. MPL-2.0 is file-level copyleft: Nyyrikki uses the modules unmodified, and the image and the release already ship every dependency's licence text (docs/09 D3). |
| OD7 | What does the Telegram message show of the file? The first draft listed every path that comes back and every cleartext value. | **What the agent asks to do, exactly which file, and the agent's reason; not a list of the file's keys** (owner, 2026-11-12, in two answers the same day: the first dropped the list, the second required the file to be identified). The message has one line saying the operation and the path it names, the file's name, what the file itself says in cleartext, the command, the KMS key and the agent's reason (D8). The file's name can only be the agent's statement, since Nyyrikki never sees the repository; the cleartext values are the part Nyyrikki can vouch for (§6). |

## 4. Decisions

| # | Decision | Why |
|---|---|---|
| D1 | **A `sops` target** has a `sops` block (§5.4) instead of `kubernetes` or `ssh`: one Google credential and the list of KMS keys it may use. `list_targets` returns `type: "sops"`. `run` and `elevate` are the same operations as for the other types; `interactive: true` is `invalid_request`. | One operation set (docs/02 D1). The target is the pair the approver can reason about: a credential and the keys it opens. |
| D2 | **The request** is `args` and `stdin`, as for kubectl (docs/04 D1). `args` is a SOPS command line without the leading `sops`, in SOPS's own syntax, limited to: `decrypt [--extract PATH] [--output-type T]`, `set PATH VALUE`, `unset PATH`, and `encrypt --gcp-kms KEY [--encrypted-regex R \| --unencrypted-regex R \| --encrypted-suffix S \| --unencrypted-suffix S]`; each also takes `--input-type T` and `--filename-override NAME`, both required. `T` is `yaml`, `json` or `dotenv`. `NAME` is the file's path in the agent's repository. The flag is SOPS's own for naming a file read from stdin on `decrypt` and `encrypt`; `set` and `unset` take it here too, where `sops` takes the file as an argument (M14). Nyyrikki only shows and records the name (D8), and it is 1–200 printable characters. `PATH` is SOPS's tree path (`["stringData"]["password"]`), `VALUE` is JSON. **`stdin` is the file**: encrypted for `decrypt`, `set` and `unset`, plaintext for `encrypt`. There is no file name: nothing is read from or written to Nyyrikki's disk. Any other command or flag is `invalid_request` naming it. | OD4. Agents already know SOPS's commands. The type is stated, not guessed from the name, so the name decides nothing. The name is required because the approver must be told which file (OD7). *Revised 2026-11-13 (SO2, §10)*: the path reader is stricter than SOPS's, which splits on `[` and can't express a key holding one: a key may hold neither bracket nor its own quote, so a path reads one way only. A positional that starts with `-` goes after `--`, and the canonical argv keeps the `--`. A file with more than one YAML document is refused: SOPS's `set` and `--extract` act on the first only, which the message couldn't say plainly. |
| D3 | **Parsed once, by Nyyrikki's own parser; what the approver sees, what the approval binds to and what runs are one value.** SOPS's parser can't be imported (M1) and nothing is ever handed to a `sops` program, so there is exactly one parser and no second one to disagree with. The canonical argv is the command, the set flags as `--name=value` sorted by name, then the positional arguments (docs/04 D3). The digest is docs/04 §5.3's with the prefix `nyyrikki-sops-request-v1`, over the target, the canonical argv and stdin. The runner works from the canonical request, never the agent's original. | INV-02. |
| D4 | **The file is parsed before the approval, without any key**, with SOPS's store for the stated type, and refused (`invalid_request`) unless: it parses; for `decrypt`, `set` and `unset` it has SOPS metadata with exactly one key group, **only Google KMS keys** in it, at least one, each of them in the target's `keys` and **no resource ID twice**; for `decrypt --extract` and `unset`, the path exists; for `encrypt` it has no SOPS metadata yet, and the request's `--gcp-kms` names exactly one key, a full CryptoKey resource name that is in the target's `keys` (SOPS's comma-separated list is refused). No KMS call is made before a `Grant` exists. | A request nobody could run shouldn't reach the approver (docs/02 D13). A file that names a Vault, AWS or Azure key would otherwise make Nyyrikki call an address the agent chose (M13). Shamir groups can't be satisfied by one key type. *Revised 2026-11-12 (OD5, OD7), before approval*: files that also list other key types were first accepted with those keys ignored, and files with `mac_only_encrypted` refused, because their cleartext was shown; it no longer is. *Revised 2026-11-13 (review of #74)*: a repeated resource ID is refused; SOPS tries every key entry in turn, so a file repeating an allowed key with junk wrapped keys would have turned one approval into as many KMS calls as fit in 1 MiB. The same day (second review of #74): `encrypt`'s key, which comes from the request and not from the file, is checked here too; before, only the wrapper checked it, after the approver had been shown it. *Revised 2026-11-13 (SO2, §10)*: the file's own encryption rules are checked too: each at most 200 bytes, and each regular expression must compile (`file_rules`). SOPS compiles a rule again for every value it walks, so a long one in a large file would hold an approved run for minutes. A tree nested more than 64 levels deep is refused. |
| D5 | **Running**, in-process: the runner checks the `Grant`'s digest against the request, loads the file again from the same bytes, and calls SOPS's library (`common.DecryptTree`, `EncryptTree`, `TreeBranch.Set`, `Unset`, `Truncate`) with **one key service: a thin one of Nyyrikki's that wraps SOPS's own Google key source**. SOPS's built-in key service can't carry the target's credential, the reason or the run's context (M13), so the wrapper does only that: it refuses any key that isn't a Google KMS key in the target's `keys`, builds SOPS's `gcpkms.MasterKey` for it with the target's token source (D6) and the reason (D7) as client options, and calls its `DecryptContext` or `EncryptContext` with the run's context. It is made per run, **answers at most one call per resource ID**, and **keeps a record of the run**: each call's key and outcome as one of D9's codes, and a latch that is set when it refuses anything (a key that isn't allowed, a second call for a key). SOPS goes on to the next key after an error (M15), so the runner reads the record when the library returns: with the latch set the run fails, whatever SOPS returned, and nothing is returned to the agent; every failure's code comes from the record, never from SOPS's error (D9, D11). The KMS request itself is SOPS's code. The MAC is always checked: there is no `--ignore-mac`. `decrypt` returns the plaintext file, or the value at `--extract`; `set` and `unset` change the tree and re-encrypt with the same data key (M6); `encrypt` generates a data key in the pod, wraps it with the named key, and returns the encrypted file. The data key and the plaintext of anything not returned exist only in memory for the length of the run. | OD1, OD5. The wrapper is the one place that decides which keys are used, and how often. *Revised 2026-11-13 (review of #74)*: the one-call limit was promised by D11 and enforced nowhere. The same day (review round 1): the record and the latch, since a refusal alone doesn't stop SOPS (M15). *Revised 2026-11-13 (SO3, §10)*: the runner also repeats D4's check against its own list of the target's keys before it reads the credential; the Cloud KMS client is the REST one; a data key is zeroed when the run is done with it. |
| D6 | **The Google credential** is a file per target, a mounted Secret (`sops.gcp_kms.credentials_file`), read on each use (docs/06 D4), never logged. Two kinds are accepted, checked when the config is loaded and on each read: a **Workload Identity Federation** configuration (`type: external_account`) whose subject token comes from a file, which is the pod's projected ServiceAccount token, so the file holds no secret; or a **service account key** (`type: service_account`). Any other type, and an `external_account` whose token source is a URL, a program or an AWS or Azure environment, is refused. The access token is asked for with the scope `https://www.googleapis.com/auth/cloudkms`, kept in memory until it expires, and passed to SOPS's key source as a token source (M7), so no environment variable is read. | docs/01 D15: credentials are mounted files. Federation means no long-lived Google secret anywhere; the key file is for clusters whose issuer Google can't reach. A credential configuration can name a program to run, so only the two shapes Nyyrikki needs are accepted. *Revised 2026-11-13 (SO3, M16)*: "no environment variable is read" holds for the credential only. SOPS takes the Cloud KMS endpoint and universe domain from the environment whatever it is given, so `nyyrikkid` refuses to start while `SOPS_GCP_KMS_ENDPOINT` or `SOPS_GCP_KMS_UNIVERSE_DOMAIN` is set. A federation configuration may hold only the fields Nyyrikki knows; an unknown one is refused. The token source is kept while the file's bytes stay the same, and a token exchange has its own 15 s limit, not the run's. *Revised 2026-11-13 (review round 2 of #75, M16)*: the file also says where the token exchange is sent, and for a federation the pod's ServiceAccount token goes with it. Only Google's own endpoints are accepted, as `gcloud` writes them: `token_url` must be `https://sts.googleapis.com/v1/token`; `token_info_url`, if set, `https://sts.googleapis.com/v1/introspect`; `service_account_impersonation_url`, if set, a `:generateAccessToken` call on `https://iamcredentials.googleapis.com/v1/…`; a key's `token_uri`, if set, `https://oauth2.googleapis.com/token`; `universe_domain`, if set, `googleapis.com`. Anything else is refused when the file is read, with an error that holds nothing from the file. Regional and mTLS endpoints and other universes are refused with them, until someone needs one. |
| D7 | **Every KMS call carries a request reason** (M8): `nyyrikki run=<run id> human=<human id> covered_by=<approval:<id>\|elevation:<id>>`, at most 256 characters, built by Nyyrikki from the `Grant` only. It never holds the agent's stated reason, the elevation's handle, a token or anything from the file. The run ID is the one in Nyyrikki's audit log, where the agent, the approver and the exact request are. | OD3. The log line at Google leads to Nyyrikki's record. The agent's reason is the agent's text; the handle is a secret (docs/01 D24). |
| D8 | **What the approver sees** (extending docs/05 D5, and D7 for the elevation message) is what the agent asks to do, on which file, and why (OD7). Above the command, **one line of fixed wording** built by Nyyrikki from the canonical request and the parse of D4: "Decrypt and return the whole file (N encrypted values)"; "Decrypt and return one value: `stringData.password`", with "(N encrypted values)" when the path is a branch; "Change one value: `<path>` (new value not shown)", or "Add a value:" when the path doesn't exist yet; "Remove one value: `<path>`"; "Encrypt a new file: N values encrypted, M left in cleartext". Then **which file**, in two lines: "File (agent's claim):" with the name from `--filename-override`, escaped as docs/04 §5.2; and, for `decrypt`, `set` and `unset`, "The file says:" with the file's own cleartext values, one per line, each as its path in SOPS's form and its value, both JSON-quoted (`["metadata"]["name"] = "db-creds"`), with control, bidi and zero-width characters escaped as docs/04 §5.2, when it has between one and twelve of them that fit in 400 characters; otherwise "N cleartext values, not shown", and for a file with `mac_only_encrypted`, whose cleartext the MAC doesn't cover, "cleartext not verifiable, not shown". **`encrypt` has no "The file says" line**: its stdin is plaintext, every value in it may be a secret, including one the agent's regex wrongly leaves in cleartext, and no MAC covers it yet; its message has the counts and the name only, and no last-modified time, which a plaintext file doesn't have. Then: "Runs as" `Nyyrikki's Google credential, for <human>`, as fixed text; the KMS key; the canonical command, with `set`'s `VALUE` shown as `‹redacted: N bytes, sha256:<first 12 hex>›` (docs/04 D14); the file's size, hash and last-modified time; and the agent's reason, marked as its claim, as in every message (docs/05 D5). Encrypted paths are not listed, and stdin is never shown as text. An elevation message says, for a `sops` target, "decrypts and changes any file encrypted with:" and the target's keys. | OD7. `CLAUDE.md`: the approver sees the request itself, and the command is still there in full; the lines above it are derived from the same canonical value and the same bytes, as "root via sudo" is (docs/07 D12). The name is the agent's word and is marked so. The cleartext values are the file's own: a run that returns anything has passed the MAC check that covers them (M4). The cap keeps a file with much cleartext from burying the line that says what is asked. *Revised 2026-11-13 (review of #74)*: the line first applied to `encrypt` too, which would have sent the plaintext of a small Secret to Telegram. The same day (review round 1): the values were first joined as `path=value, …` unquoted; the MAC doesn't cover a cleartext value's key name (M4), so a key renamed to `name=staging-db, metadata.old` would have made the line name another file. Quoted, a key can't end its own string. *Revised 2026-11-13 (SO2, §10)*: the path in the line that says what is asked is in SOPS's form too, quoted like the cleartext lines (`["stringData"]["password"]`), not dotted: a dotted path can't tell the key `a.b` from `b` under `a`. A path that names a branch gets wording of its own: "Decrypt and return everything under:", "Replace everything under:" and "Remove everything under:", each with its number of values. A `set` whose path runs through an existing value says so: "Replace the value at `<prefix>` with a branch, to add: `<path>`", since SOPS then replaces that value. A file with no cleartext value says "nothing in cleartext". An empty string counts as cleartext: SOPS doesn't encrypt one. |
| D9 | **What reaches the agent**: for a successful run, exit code 0 and the result on stdout, as SOPS's store wrote it. For any failure, a fixed code and detail from Nyyrikki's own list (`mac_mismatch`, `value_not_decryptable`, `key_not_allowed`, `kms_call_limit`, `kms_denied`, `kms_unavailable`, `path_not_found`, `invalid_request`), **never SOPS's or Google's error text** and never a partial result. SOPS's own logging is discarded. | The KMS codes come from the wrapper's record of the run (D5), since SOPS reports key failures only as text (M15). M5: SOPS's errors contain hashes of the plaintext, and a KMS error can echo request details. INV-08. A fixed list also means a wrapped key that isn't a SOPS data key (some other secret encrypted with the same KMS key) decrypts to nothing the agent sees. *Revised 2026-11-13 (SO3, §10)*: three details were added, each a fixed word: `credentials_unavailable` (D12), `result_not_writable` (the result can't be written as that file type) and `output_too_large` (the result is over `run.max_output`: a run returns all of its result or none, so nothing is truncated). The agent gets a code and a message, so the detail is the message's first word. Faults of the file are `invalid_request`; Cloud KMS and the credential are `unavailable`. Cloud KMS's 400 is `value_not_decryptable` (it couldn't decrypt the wrapped key), its 401, 403 and 404 are `kms_denied`, anything else is `kms_unavailable`. A failure after the data key was there, a panic of the library's included, is `result_not_writable`, never a KMS detail. |
| D10 | **The audit record** (extending docs/03 D1) holds the canonical argv with `set`'s value redacted, stdin's size and hash, `run_as` as the fixed text of D8, and a new field `kms_keys`: the resource IDs the run called. Each KMS call that fails or is refused is audited with its code, from the wrapper's record (D5). Nothing of the plaintext, the data key or the token. | INV-09, INV-10. *Revised 2026-11-13 (SO3)*: a call Cloud KMS failed is a `dependency_failed` record with `kms_keys` naming its key; a call the key service refused is a `decision` record with `deny`, and names no key the target doesn't have. |
| D11 | **Limits**: the request limits of docs/02 D13 (stdin at most 1 MiB) and the run timeout of docs/04 D7 apply. A run makes at most one KMS call per Google KMS key that the file or, for `encrypt`, the request names, in the file's order, and stops at the first that succeeds: D4 refuses a file that names a key twice, and the wrapper refuses a second call for a key whatever the file says (D5), so the calls of one run are bounded by the target's `keys`. The KMS client's context is the run's, so a cut (docs/04 D8) ends the call; a result is returned only if the run wasn't cut. | A crafted file can't turn one approval into many KMS calls. |
| D12 | **Dependency failures end in deny** (INV-07): an unreadable or malformed credential file, a failed token exchange, KMS unreachable, denied or slow, are `unavailable` with a detail from D9's list, audited, and nothing is returned. A startup check loads and validates each target's credential file (docs/06) but makes no call to Google. | Fail closed. *Revised 2026-11-13 (SO3)*: the startup check logs what is wrong, by target, and the server starts: the other targets keep working, as with the SSH CA keys (docs/08 D1). The detail of a credential that can't be loaded is `credentials_unavailable`. |

### Rejected alternatives

| Alternative | Why not |
|---|---|
| Unwrapping the data key for the agent's own `sops` (SOPS's key service protocol behind a local shim) | OD1: one tap hands over a key that opens every version of the file, and the approver sees nothing that identifies the file. |
| A general `gcloud` or Google API target | A much larger surface than was asked for, and `gcloud kms decrypt` is the previous row. |
| Shipping the `sops` program and running it as a child, as kubectl is run | It would need the file on disk, and it reads `.sops.yaml`, environment variables and an editor setting, and can run programs (`exec-env`). The library does the four operations in-process on bytes (M1). |
| An encrypt-only Google credential on the agent's machine, for new files | A target credential on the machine the agent controls (`CLAUDE.md`), and it doesn't cover changing a file (M6). |
| Passing the agent's or the human's own token to Google (Workforce Identity Federation with the authorization server as provider) | INV-06: no token is passed on to a target. Nyyrikki holds only the agent's access token, whose audience is Nyyrikki. |
| SOPS's built-in key service, with the credential from the process environment | It takes one credential for the whole process from an environment variable or Application Default Credentials, sends no request reason, ignores the run's context, and serves key types Nyyrikki doesn't offer (M13). D5 wraps SOPS's Google key source instead, which is the same code one level down. |
| Showing the whole file, or every path and cleartext value, to the approver | OD7: the message should say what is asked. The ciphertext tells the approver nothing, and a long list hides the one line that matters. |
| `--ignore-mac` | Values could be dropped or the cleartext changed without the run failing (M4). |
| Reading `.sops.yaml` creation rules in Nyyrikki | A file from the agent's repository deciding which key Nyyrikki uses. The key is in the request, where the approver sees it (D2). |

## 5. Design

### 5.1 Flow

```
args, stdin ──Parse──► canonical request ──► Digest ──► approval / elevation ──► Grant
                 │
                 └─ load file, no key (D4) ──► Display: what is asked, the KMS key ──► approver

Grant ──► load file ──► SOPS library ──► key service wrapper (D5) ──► SOPS's Google key source,
                              │            with the token (D6) and the reason (D7) ──► Cloud KMS
                              │
                              └─ MAC checked ──► result, or a fixed error code (D9)
```

### 5.2 Package

`internal/sopstarget`: the request parser and canonical form (D2, D3),
the pre-approval file check and display (D4, D8), the key service
wrapper (D5),
the credential loader (D6), the reason (D7) and the runner. The runner
takes a `Grant` (docs/02 D6). Nothing outside this package imports the
SOPS library.

### 5.3 What a run looks like

```sh
nyyrikki run --reason "rotate the shop database password" sops-prod -i -- \
  set --input-type yaml --filename-override clusters/prod/shop/db-creds.enc.yaml \
  '["stringData"]["password"]' '"n3w-pass"' \
  < db-creds.enc.yaml > db-creds.enc.yaml.new
```

The approver sees:

```
Run request: sops-prod
Change one value: stringData.password (new value not shown)
File (agent's claim): clusters/prod/shop/db-creds.enc.yaml
The file says:
  ["apiVersion"] = "v1"
  ["kind"] = "Secret"
  ["metadata"]["name"] = "db-creds"
  ["metadata"]["namespace"] = "shop"
Runs as: Nyyrikki's Google credential, for owner
KMS key: projects/acme/locations/europe-north1/keyRings/flux/cryptoKeys/prod
Agent: … (claimed name), key 3f9a…, signed in 12:01
┌──────────────────────────────────────────────────────────────┐
│ set --filename-override=clusters/prod/shop/db-creds.enc.yaml  │
│   --input-type=yaml '["stringData"]["password"]'              │
│   ‹redacted: 10 bytes, sha256:9c1e5b0a77d2›                   │
└──────────────────────────────────────────────────────────────┘
‹sops yaml, 1423 bytes, sha256:ab12cd34ef56, last modified 2026-11-02T09:14:07Z›
Agent's claim (unverified): rotate the shop database password
Expires 12:06:04          [Approve] [Deny]
```

Google's Data Access log for the key shows one `Decrypt` by Nyyrikki's
service account with the reason
`nyyrikki run=01K… human=owner covered_by=approval:01K…`.

### 5.4 Configuration

```yaml
targets:
  - name: sops-prod
    description: Flux secrets of the prod cluster
    humans: [owner]
    sops:
      gcp_kms:
        credentials_file: /etc/nyyrikki/gcp/sops-prod.json   # mounted Secret (D6)
        keys:                                                # the only keys this target uses (D4, D5)
          - projects/acme/locations/europe-north1/keyRings/flux/cryptoKeys/prod
```

*Revised 2026-11-13 (SO5, §10)*: in the chart, a target's credential is
`targets[].sops.gcpKMS.secretName`, a Secret with the key
`credentials.json`, as a remote Kubernetes target names its own; the
federation audience is `gcp.workloadIdentityAudience`. There is no
`secrets.gcp`.

`keys` is required and non-empty; each entry is a full CryptoKey
resource name, checked by format when the config is loaded. Each knob's
consumer: `credentials_file` → the credential loader (D6) and the
startup check (D12); `keys` → the pre-approval check (D4), the key
service wrapper (D5) and the elevation message (D8). The chart mounts the
Secrets named in `secrets.gcp` at fixed paths, as docs/06 §10 does for
the others, and projects a ServiceAccount token with the federation
audience when `gcp.workloadIdentityAudience` is set; its config test
checks that every field reaches the binary. No flag or environment
variable is added.

### 5.5 Setting Google up

`docs/setup/sops.md` (SO5) has the steps, by hand, for both credential
kinds: a service account with `roles/cloudkms.cryptoKeyEncrypterDecrypter`
on the named keys and nothing else; for federation, a workload identity
pool and provider for the cluster's issuer, restricted to Nyyrikki's
ServiceAccount, allowed to impersonate that service account; and Data
Access audit logs (`DATA_READ`) enabled for Cloud KMS (M11). Nyyrikki
never configures Google itself.

## 6. Security considerations

- **New inputs.** The file is agent-controlled and is parsed before any
  approval (D4), by SOPS's stores, within docs/02 D13's size limit. A
  parser bug there is reachable by any authenticated agent without a
  tap. The parse makes no network call and uses no key.
- **What an approval of a decrypt gives the agent**: the plaintext of
  that version of that file, or of the extracted value. Not the data
  key, so not other versions. The agent can submit any version it
  holds, an old one from git history included.
- **Which file** (OD7). The message names the file twice, and the two
  lines are worth different things. The name is the agent's statement:
  Nyyrikki never sees the repository, so a steered agent can send the
  production file under a harmless name. The line "The file says" is
  the file's own cleartext values, which the agent can't change, drop
  or reorder without the run failing (M4). Their key names are another
  matter: the MAC doesn't cover them, so the agent can rename the key a
  cleartext value sits under. Each value is therefore the file's, in
  the file's order, and each path next to it is only as true as the
  agent left it; the quoting of D8 keeps a renamed key from passing as
  a second value. So for a file that keeps identifying fields in
  cleartext (a Secret manifest encrypted with `encrypted_regex`) it is
  the line to trust. A file encrypted in full has no such line, and
  then only the name, the KMS key and the path stand between the
  approver and any other file under that key. What narrows that: a
  target per KMS key, with keys split by how sensitive their files are,
  and `--extract`, whose path is shown and can't be forged.
- **What the agent can't forge.** Without the data key it can't produce
  a value that decrypts at another path (M3), so a value returned for
  the path in the message was encrypted for that path. It can't drop or
  reorder values or change a cleartext value without the run failing
  (M4). It can rename the key of a cleartext value, as above.
- **Which keys.** The file names the KMS key, or for `encrypt` the
  request does, so the agent chooses among the target's `keys`, and the
  approver sees which. A key outside
  the list, or of another type, is refused before the approval (D4) and
  again in the key service wrapper (D5).
- **KMS as an oracle.** The agent can put any ciphertext of an allowed
  key where the wrapped data key goes. Nyyrikki decrypts it, the result
  fails as a data key, and nothing of it is returned (D9). One
  approval, or one run under an elevation, allows at most one such
  call per key in the target's `keys`, since a file can name each of
  them once (D4, D5, D11).
- **`set` and `unset` change what a file says without the approver
  seeing the new value.** The redaction keeps the secret out of
  Telegram and the audit log (docs/04 D14); the hash binds the approval
  to it. The result goes back to the agent, not into git: a human or a
  review still merges it.
- **`encrypt`** reveals nothing; its risk is a file whose secret stays
  in cleartext because the agent's regex didn't match. The message
  says how many values are encrypted and how many are left in cleartext
  (D8), not which.
- **Under an elevation**, every file the agent holds under the target's
  keys can be decrypted and changed for up to 30 minutes without a
  message each. The elevation message says so (D8); each run is audited
  (INV-10).
- **Identity** (OD3). Google sees Nyyrikki's service account for every
  human. INV-05 holds only in the weaker form "Nyyrikki records the
  human and tells the target"; `SECURITY.md` gets that as an accepted
  risk when this doc is approved. The service account's reach is the
  blast radius: its role on the listed keys, and nothing else in the
  project.
- **Credentials.** With federation there is no Google secret at rest:
  the pod's ServiceAccount token is exchanged per use, and whoever
  controls the pod can do the same until the federation binding is
  removed. With a key file, the key is a long-lived secret in a Secret;
  rotate it by replacing the Secret (read on each use). Access tokens
  live for at most an hour in memory and can't be revoked; removing the
  service account's role on the key ends their use at once. Nothing of
  them reaches a result, an error, a log or a message (INV-08).
- **The plaintext passes through the pod's memory**, including values
  that aren't returned when `--extract` is used. A compromise of the
  pod during a run sees them; it could also use the credential directly.
- **Dependencies** (OD5). The SOPS library and what it pulls in run in
  the process that holds every credential. Only the Google KMS path is
  reachable from a request: files naming other key types are refused
  (D4), and the wrapper is the only key service given to the library
  (D5).
- **Dependency failures** end in deny (D12).

## 7. Acceptance criteria

| Goal | Verified by |
|---|---|
| G1 A request reaches the library only as the canonical form the approver saw; any other command, flag, type or `interactive` is refused before an approval | unit tests of the parser, with a round-trip check as docs/04 D3 (SO2) |
| G2 A file is refused before the approval when it doesn't parse, names a key outside the target's `keys` or of another type (in the file, or in `encrypt`'s `--gcp-kms`, which must name exactly one), has no Google KMS key, has several key groups, names a key twice, or lacks the path asked for; no KMS call, and no call to any other address, is made without a `Grant` | unit tests; an integration test with a fake KMS that fails the test on any call before approval; a test that hands the runner a file repeating a key, past D4, and asserts the fake KMS saw one call for it and the run failed with `kms_call_limit` and no output, though a later key in the file would have decrypted it (SO2, SO3, SO4) |
| G3 `decrypt`, `decrypt --extract`, `set`, `unset` and `encrypt` each return what `sops` v3.13.3 returns for the same input, and their output is read back by that `sops` | integration tests against a fake KMS, comparing with the `sops` program pinned in the test (SO3, SO4) |
| G4 A swapped, renamed or dropped value, changed metadata and a wrapped key that isn't a data key each end in a fixed error code, with no output and no SOPS or Google error text in the result, the log or the audit record | tests for each, asserting on the result, the captured log and the audit record (SO3, SO4) |
| G5 The message says what is asked in D8's fixed wording, the file's name marked as the agent's claim, the file's cleartext values under D8's cap, the KMS key, the command and the agent's reason; for `encrypt` it shows no value at all; it lists no encrypted path the request doesn't name; `set`'s value appears nowhere in the message or the audit record; a request without `--filename-override` is refused | golden tests of the rendered message for each operation, for a file with no cleartext, one over the cap and one with `mac_only_encrypted`; a test searching the message and the audit record for the value; a golden test for `encrypt` asserting that none of the input's values, encrypted or left in cleartext, is in the message; a golden test with a cleartext key name containing `=`, `, `, a quote, a newline and a bidi control; a golden test of the elevation message for a `sops` target (SO2) |
| G6 Every KMS call is made by SOPS's Google key source with the target's credential and the reason of D7, and nothing else from the request; the audit record names the keys called; a cut run's call is cancelled | integration test reading the fake KMS's received headers; a test that cuts a run while the fake KMS holds the call (SO3) |
| G7 Only the two credential kinds of D6 load; no environment variable changes which credential is used; a broken file, a failed exchange and an unreachable or denying KMS each end in `unavailable`, audited | unit tests of the loader; integration tests with the fake token endpoint and KMS failing in each way (SO3) |
| G8 The licence gate passes with the admitted modules pinned, and fails on its canary | the gate and its canary in CI (SO1) |
| G9 Against the real Cloud KMS, with federation from a cluster: a decrypt approved on a real phone returns the plaintext, a denied one makes no KMS call, and Google's Data Access log shows the service account and the reason | manual, by the owner (SO5) |

## 8. Chunks

| Chunk | Scope | Done when |
|---|---|---|
| **SO1** | The SOPS library as a dependency: the licence review, the pinned licence hashes, the gate's ignore list; govulncheck clean | G8 |
| **SO2** | `internal/sopstarget`: the request parser, the canonical form and digest, the pre-approval file check, the display; the `sops` block in config; `type: "sops"` in `list_targets`; message rendering | G1, G2 (unit), G5 |
| **SO3** | The key service wrapper, the credential loader, the reason, the runner, the fixed error codes; audit fields; wiring into the decision point and the MCP and CLI `run` | G3, G4, G6, G7 |
| **SO4** | The fake KMS and token endpoint in `test/`; integration and e2e tests against the pinned `sops` program; M1–M8 and M15 as tests | G2 (integration), G3, G4 |
| **SO5** | The chart (Secret mounts, the projected token), `docs/setup/sops.md`, the dated notes in docs/01, 02, 03, 05, 06 and `SECURITY.md`; M12 measured; the manual check | G9 |

Ordering notes: SO1 first: the library has to pass the licence gate
(OD6) before anything is built on it. SO2 before SO3: nothing may call KMS until the
request and the display exist. SO4's fakes are needed by SO3's tests and
can land with it.

## 9. Risks and open questions

- **A file's name can't be verified** (OD7, §6). For files encrypted in
  full it is all the approver has. Binding a name to a file would need
  Nyyrikki to read the repository, or the name to be inside the file
  where the MAC covers it; neither is designed here.
- **The dependency weight** (M9) is the main cost of OD5. What would
  reopen it: a vulnerability in a linked SDK that is reachable without
  a request, or SOPS splitting its key sources into separate modules.
- **The wrapper depends on SOPS's `gcpkms` options** (`NewTokenSource`,
  `ClientOptions`), which are outside the one package SOPS calls
  stable (`decrypt`). A SOPS release can change them; the tests of G3
  and G6 catch it at the Renovate PR.
- **Workload Identity Federation from the owner's cluster** is not
  measured (M12): Google has to be able to read the cluster issuer's
  keys, or be given them. If it can't, the key file is the fallback.
- **The request reason in a real log entry** is not measured (M10).
- **Files that also list age, PGP or another cloud's keys are refused**
  (D4), though their Google key alone could decrypt them. Accepting them
  means making sure no other key source is ever tried.
- **`dotenv` files have no nesting**, and INI and binary files are not
  offered; adding a type is a store and a display test, no new decision.

## 10. How it was implemented (2026-11-13)

SO1–SO5 in one PR, as docs/07's chunks were. Where the build differs
from §4 and §5, the decision rows carry a dated note; this section says
what was built and where each goal is tested.

**What was built.**

- `internal/sopstarget`: `request.go` (the parser, the canonical argv,
  the digest, the check of the file before approval, the display),
  `keyservice.go` (the key service around SOPS's Google key source, its
  record and latch), `creds.go` (the credential loader), `runner.go`.
  It is the only package that imports the SOPS library; its test fakes
  are in `internal/sopstarget/sopstest`, not under `test/`, next to the
  other packages' fakes.
- `config`: the `sops` block and `Target.Type`; `codes.TypeSOPS`;
  `audit.Record.KMSKeys`; `approval.SOPSRequest` and
  `approval.SOPSTarget`, which the decision point fills from the request
  and the registry; the message in `telegram/render.go`; the dispatch in
  `runner` and `mcpserver`; the runner's start in `server`.
- The display quoting of docs/04 §5.2 moved to `textsafe.Quote`, so the
  kubectl and SOPS displays share one definition.
- The chart: a Secret per SOPS target mounted at
  `/etc/nyyrikki/gcp/<target>/credentials.json`, and a projected
  ServiceAccount token at `/var/run/secrets/nyyrikki/gcp/token` when
  `gcp.workloadIdentityAudience` is set; `docs/setup/sops.md`.
- The `sops` program is pinned as a tool in `go.mod`, at the library's
  version. The test gate builds it after the suite and runs the
  `TestSOPSProgram…` tests against it (`scripts/gates.sh sops-program`,
  a part of the test gate with two canaries of its own, with
  `NYYRIKKI_SOPS_PROGRAM`): files it encrypts are decrypted, and what
  Nyyrikki returns is read back by it (G3). Every other test makes its
  files with the library, so a plain `go test` builds no program and
  skips those two. *Revised 2026-11-13 (CI of #75)*: the tests first
  built the program themselves, inside the suite, which ran CI's
  runners out of disk next to the suite's own links.
- `google.golang.org/grpc` and `go.opentelemetry.io/otel` were raised
  past what SOPS asks for, because `govulncheck` reported the versions
  it brought in.

**Where each goal is tested.**

| Goal | Tests |
|---|---|
| G1 | `sopstarget`: `TestParseRefusesWhatIsNotOffered`, `TestCanonicalForm`; `server`: `TestSOPSRefusedBeforeApproval` |
| G2 | `sopstarget`: `TestParseRefusesFiles` (no KMS call), `TestOneCallPerKey`, `TestKeyServiceRefusesOtherKeys`; `server`: `TestSOPSRunMCP` (no call before the tap, none after a denial) |
| G3 | `sopstarget`: `TestSOPSProgramFilesAreRead`, `TestSOPSProgramReadsWhatIsReturned` (against the `sops` program, in the test gate); `TestDecrypt`, `TestDecryptExtractAndTypes`, `TestSetAndUnset`, `TestEncrypt` (against the library's own files) |
| G4 | `sopstarget`: `TestTamperedFiles`; `server`: `TestSOPSRefusedBeforeApproval` |
| G5 | `sopstarget`: `TestAsks`, `TestFileSays`, `TestSetValueIsRedacted`; `telegram`: `TestRenderSOPSRun` (the golden message), `TestRenderSOPSOperations`, `TestRenderSOPSHostile`, `TestRenderSOPSElevation`; `decision`: `TestSOPSOneOff`, `TestElevationSOPS` |
| G6 | `sopstarget`: `TestDecrypt` (reason, token, `kms_keys`), `TestCut`; `server`: `TestSOPSElevationAndCLI` |
| G7 | `sopstarget`: `TestValidateCredentials`, `TestFederationAndReload`, `TestDependencyFailures`, `TestNewRunner`; `server`: `TestSOPSCredentialUnavailable`; `chart`: `TestChartSOPSTarget` |
| G8 | the licence gate and its canary; `scripts/pinned-licenses` |
| G9 | **open**: manual, by the owner |

**What was not built or not measured.**

- No end-to-end test on kind: Cloud KMS has no emulator to put in the
  cluster, and the fake is in-process. The integration tests run the
  whole path from the MCP call to the fake KMS in one process.
- Nothing was run against Google: G9 and M12 are open, and
  `docs/setup/sops.md` says so at its top. The federation exchange is
  tested against a fake token service only (M19).
- Per-human service accounts (OD3) and binding a file's name to the
  file (§9) are not built.

## 11. Post-implementation review (YYYY-MM-DD)

Not yet reviewed.
