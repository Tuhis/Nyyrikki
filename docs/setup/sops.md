# SOPS targets

A SOPS target lets an agent ask for one SOPS operation on a file
encrypted with a Google Cloud KMS key: decrypting it or one value of it,
changing or removing one value, or encrypting a new file
([docs/10](../10-sops-target.md)). The agent sends the file; Nyyrikki
does the work with its own Google credential and returns the result. The
file's data key and the credential never reach the agent.

> **Checked against Google once, by hand.** On 2026-11-14 and
> 2026-11-15 the federation steps below (1, 2, 3a with
> `--jwk-json-path`, 4 and 5) were followed on one cluster, and an
> encrypt and a decrypt ran against the real Cloud KMS (docs/10 G9,
> M12). The service account key of 3b and a provider that reads the
> cluster's issuer itself were not tried. The automated tests use a fake
> Cloud KMS and a fake token service. Tell the maintainer where a step
> is wrong.

## What you decide first

- **Which keys.** A target lists the CryptoKeys it may use, and uses no
  other. A window on a target (an elevation) covers every file its keys
  protect, and the message for one request can't say for certain which
  file it is ([docs/10](../10-sops-target.md) §6). Use one target per
  key, and split keys by how sensitive their files are.
- **Federation or a key file.** With Workload Identity Federation,
  Nyyrikki exchanges its pod's ServiceAccount token for a short-lived
  Google token, and no long-lived Google secret exists anywhere. It
  needs Google to be able to check your cluster's tokens. A service
  account key works on any cluster, and is a long-lived secret in a
  Kubernetes Secret.

Cloud KMS can't act as a person. Google's log shows Nyyrikki's service
account for every human, with a reason that names the run
(`nyyrikki run=… human=… covered_by=…`). Nyyrikki's own audit log is
the record of who asked and who approved.

## 1. The service account and its rights

One service account per target, with one role on the target's keys and
nothing else in the project:

```sh
gcloud iam service-accounts create nyyrikki-sops --project PROJECT

gcloud kms keys add-iam-policy-binding KEY \
  --keyring KEYRING --location LOCATION --project PROJECT \
  --member serviceAccount:nyyrikki-sops@PROJECT.iam.gserviceaccount.com \
  --role roles/cloudkms.cryptoKeyEncrypterDecrypter
```

A target that only ever decrypts and changes existing files needs only
`roles/cloudkms.cryptoKeyDecrypter`; `encrypt` then fails with
`kms_denied`.

## 2. Turn on the audit log

Cloud KMS's decrypt and encrypt calls are Data Access logs, which are
written only once you enable them: in the console, **IAM & Admin → Audit
Logs → Cloud Key Management Service (KMS) API → Data Read**. Without
this, Google keeps no record of the calls, and the reason Nyyrikki sends
goes nowhere. Calls made before it is on are never logged.

From a shell, the same setting is one entry in the project's IAM
policy (this replaces an entry the project already has for Cloud KMS):

```sh
gcloud projects get-iam-policy PROJECT --format=json > policy.json
jq '.auditConfigs = ((.auditConfigs // []) | map(select(.service != "cloudkms.googleapis.com")))
    + [{"service":"cloudkms.googleapis.com","auditLogConfigs":[{"logType":"DATA_READ"}]}]' \
  policy.json > policy.new.json
gcloud projects set-iam-policy PROJECT policy.new.json
```

The reason is in each entry's
`protoPayload.requestMetadata.requestAttributes.reason`. Google stores
it base64-encoded, inside a short binary envelope that holds the text
twice, so decode it to read it:

```sh
gcloud logging read '
  protoPayload.serviceName="cloudkms.googleapis.com"
  AND protoPayload.authenticationInfo.principalEmail="nyyrikki-sops@PROJECT.iam.gserviceaccount.com"' \
  --project PROJECT --limit 1 \
  --format='value(protoPayload.requestMetadata.requestAttributes.reason)' \
  | base64 -d 2>/dev/null | strings
```

With federation, the entry's `principalEmail` is the service account,
and `serviceAccountDelegationInfo` names Nyyrikki's ServiceAccount.

## 3a. Workload Identity Federation

Create a pool and a provider for your cluster's issuer, restricted to
Nyyrikki's ServiceAccount (`RELEASE-nyyrikki` in the release's
namespace), and let that identity act as the service account:

```sh
gcloud iam workload-identity-pools create nyyrikki \
  --location global --project PROJECT

gcloud iam workload-identity-pools providers create-oidc cluster \
  --location global --workload-identity-pool nyyrikki --project PROJECT \
  --issuer-uri ISSUER \
  --attribute-mapping google.subject=assertion.sub \
  --attribute-condition "assertion.sub == 'system:serviceaccount:NAMESPACE:RELEASE-nyyrikki'"

gcloud iam service-accounts add-iam-policy-binding \
  nyyrikki-sops@PROJECT.iam.gserviceaccount.com --project PROJECT \
  --role roles/iam.workloadIdentityUser \
  --member "principal://iam.googleapis.com/projects/NUMBER/locations/global/workloadIdentityPools/nyyrikki/subject/system:serviceaccount:NAMESPACE:RELEASE-nyyrikki"
```

`ISSUER` is your cluster's ServiceAccount issuer
(`kubectl get --raw /.well-known/openid-configuration`). If Google can't
reach it, as with the default `https://kubernetes.default.svc.cluster.local`,
give the provider the cluster's keys instead: add
`--jwk-json-path jwks.json` to the provider command, with
`kubectl get --raw /openid/v1/jwks > jwks.json`. Google then trusts
those keys only. When the apiserver's signing key is replaced, give the
provider the new ones (`providers update-oidc … --jwk-json-path`), or
every run fails with `credentials_unavailable`.

A pool stands for where the identities come from, so name it after the
cluster if other workloads may use it later; its name can't be changed.

Then make the credential configuration. It names the file the chart
puts the pod's token in, and holds no secret:

```sh
gcloud iam workload-identity-pools create-cred-config \
  projects/NUMBER/locations/global/workloadIdentityPools/nyyrikki/providers/cluster \
  --service-account nyyrikki-sops@PROJECT.iam.gserviceaccount.com \
  --credential-source-file /var/run/secrets/nyyrikki/gcp/token \
  --output-file credentials.json
```

Nyyrikki accepts a configuration only if its token comes from a file.
One that names a URL, a program, a certificate or another cloud is
refused, as is any field Nyyrikki doesn't know
([docs/10](../10-sops-target.md) D6).

## 3b. Or a service account key

```sh
gcloud iam service-accounts keys create credentials.json \
  --iam-account nyyrikki-sops@PROJECT.iam.gserviceaccount.com
```

Make it on a machine no agent runs on, and remove the file once the
Secret exists.

## 4. The Secret and the values

The chart creates no Secret. The credential goes into one with the key
`credentials.json`, in Nyyrikki's namespace:

```sh
kubectl -n NAMESPACE create secret generic nyyrikki-gcp-sops-prod \
  --from-file=credentials.json=credentials.json
```

```yaml
targets:
  - name: sops-prod
    description: Flux secrets of the prod cluster
    sops:
      gcpKMS:
        secretName: nyyrikki-gcp-sops-prod
        keys:
          - projects/PROJECT/locations/LOCATION/keyRings/KEYRING/cryptoKeys/KEY

# Only with Workload Identity Federation: the audience the provider
# accepts, which makes the chart put a ServiceAccount token for it at
# /var/run/secrets/nyyrikki/gcp/token.
gcp:
  workloadIdentityAudience: https://iam.googleapis.com/projects/NUMBER/locations/global/workloadIdentityPools/nyyrikki/providers/cluster
```

If the chart's NetworkPolicy restricts egress, Nyyrikki also has to
reach `cloudkms.googleapis.com`, `sts.googleapis.com` and
`iamcredentials.googleapis.com` (the last two only with federation), and
`oauth2.googleapis.com` with a key file.

Don't set `SOPS_GCP_KMS_ENDPOINT`, `SOPS_GCP_KMS_UNIVERSE_DOMAIN`,
`GOOGLE_CLOUD_UNIVERSE_DOMAIN`, `GOOGLE_API_USE_MTLS_ENDPOINT`,
`GOOGLE_API_USE_MTLS` or `GOOGLE_API_USE_CLIENT_CERTIFICATE` on the pod:
they decide where the calls, and the access token with them, are sent,
so Nyyrikki refuses to start with any of them set.

The credential file says where its token exchange is sent, too. Nyyrikki
accepts only Google's own endpoints, as `gcloud` writes them:
`https://sts.googleapis.com/v1/token`,
`https://sts.googleapis.com/v1/introspect`,
`https://iamcredentials.googleapis.com/v1/…:generateAccessToken`,
`https://oauth2.googleapis.com/token` and the universe domain
`googleapis.com`. A file that names a regional or mTLS endpoint, another
universe or anything else is refused.

`HTTPS_PROXY`, `NO_PROXY`, `SSL_CERT_FILE` and `SSL_CERT_DIR` work as
they do for any Go program, and Nyyrikki doesn't refuse them. A proxy
sees only TLS to Google. A root certificate you add is one Nyyrikki
trusts for those calls: with a proxy that uses it, the proxy reads the
access token and the data keys.

## 5. Check it

At start, Nyyrikki reads each target's credential file and logs an error
if it can't be used; it makes no call to Google then. A run on a target
whose credential is broken fails with `credentials_unavailable`.

```sh
nyyrikki targets            # sops-prod is listed with type sops
nyyrikki run --reason "check the setup" -i sops-prod -- \
  decrypt --input-type yaml --filename-override clusters/prod/secret.enc.yaml \
  --extract '["stringData"]["user"]' < clusters/prod/secret.enc.yaml
```

The approver sees what is asked, the file's name as the agent's claim,
the file's own cleartext values and the key. After the tap the value is
printed, and Google's Data Access log has one `Decrypt` by the service
account with the run's reason.

## What an agent can ask for

`stdin` is always the file, and the result comes back on stdout; nothing
is read from or written to a disk. Every request needs `--input-type`
(`yaml`, `json` or `dotenv`) and `--filename-override` with the file's
path in the repository, which the approver is shown as the agent's
claim.

| Request | Returns |
|---|---|
| `decrypt` | the decrypted file |
| `decrypt --extract '["a"]["b"]'` | that value, or that branch |
| `decrypt --output-type json` | the decrypted file, as JSON |
| `set '["a"]["b"]' '"new"'` | the file with that value changed or added, re-encrypted |
| `unset '["a"]["b"]'` | the file with that value removed, re-encrypted |
| `encrypt --gcp-kms KEY [--encrypted-regex R]` | the file, encrypted with that key |

`set`'s value is JSON, and is never shown: the approver and the audit
log get its size and a hash. Not offered: `rotate`, `updatekeys`,
`edit`, `exec-env`, `exec-file`, `publish`, any other key type, files
with more than one YAML document, and `--ignore-mac`.

A failed run returns nothing and one of: `mac_mismatch`,
`value_not_decryptable`, `key_not_allowed`, `kms_call_limit`,
`path_not_found`, `result_not_writable`, `output_too_large`
(`invalid_request`), or `kms_denied`, `kms_unavailable`,
`credentials_unavailable` (`unavailable`).

## Replacing the credential

Replace the Secret; Nyyrikki reads the file on each use, so the next run
uses it with no restart. With a key file, delete the old key in Google
afterwards. To take a target's access away at once, remove the service
account's role on the key: tokens Nyyrikki already holds stop working
with it.
