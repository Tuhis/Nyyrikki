# Install

## Secrets

Create these in Nyyrikki's namespace. The chart creates none
([docs/06](../06-packaging-and-deployment.md) D2):

```sh
kubectl -n nyyrikki create secret tls nyyrikki-tls --cert=tls.crt --key=tls.key
kubectl -n nyyrikki create secret generic nyyrikki-telegram --from-file=bot-token=./bot-token
kubectl -n nyyrikki create secret generic nyyrikki-keycloak --from-file=client-secret=./client-secret
```

The certificate must be valid for the canonical URL's host. Nyyrikki
terminates TLS itself (docs/01 D10). An Ingress in front must use TLS
passthrough, or re-encrypt and log neither `Authorization` nor `DPoP`.
It must also pass the `DPoP-Nonce` and `WWW-Authenticate` response
headers through unchanged: the CLI needs them to learn Nyyrikki's DPoP
nonce, and without them every CLI call fails with 401.

## Values

```yaml
canonicalURL: https://nyyrikki.example.com
auth:
  issuer: https://keycloak.example.com/realms/nyyrikki
human:
  subject: <the owner's user ID in Keycloak>
  kubernetes:
    user: owner@example.com      # who requests run as
    groups: [admins]
  telegramUserID: 123456789      # from docs/setup/telegram.md, before installing
targets:
  - name: this-cluster
    description: The cluster Nyyrikki runs in
    inCluster: true
networkPolicy:
  ingressNamespaces: [agents]
```

```sh
helm install nyyrikki oci://ghcr.io/tuhis/charts/nyyrikki --version <version> -n nyyrikki -f values.yaml
```

The chart is also attached to each release as `nyyrikki-<version>.tgz`, and is in
`deploy/chart/nyyrikki` in the repository at the release tag.

Pin the image by digest: each release lists it in its notes and in the
`IMAGE` asset. Set `image.digest` to the `sha256:…` part only (the
second line of `IMAGE`), not the whole reference. If the image is in a private
registry, or the GHCR package hasn't been made public yet (a new GHCR
package is private), create a pull Secret and list it in
`image.pullSecrets`.

If an Ingress or Gateway fronts Nyyrikki, add its controller's namespace
(for example `ingress-nginx`) to `networkPolicy.ingressNamespaces`, or the
NetworkPolicy drops its traffic. With `networkPolicy.egress.restrict`, the
in-cluster API server usually has to be allowed by its endpoint IPs
(`kubectl get endpoints kubernetes`), not the `kubernetes` Service IP.

The chart grants Nyyrikki's ServiceAccount only `impersonate` on the
human's user and groups (docs/06 D3). Requests then run with the human's
own rights.

## Verifying a release

Releases after 0.4.0 are signed key-less with
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/)
by this repository's release workflow (docs/09 D4): the image and the
OCI chart by digest, and `SHA256SUMS`, which covers the other release
assets, with its signature in `SHA256SUMS.sigstore.json`. Verify before
installing. Each command fails unless the signature was made by the
release workflow on `main`:

```sh
SIGNER=https://github.com/Tuhis/Nyyrikki/.github/workflows/release.yml@refs/heads/main
ISSUER=https://token.actions.githubusercontent.com

# The image: the digest is the second line of the IMAGE asset, and in the notes.
cosign verify --certificate-identity "$SIGNER" --certificate-oidc-issuer "$ISSUER" \
  ghcr.io/tuhis/nyyrikki@sha256:<image digest>

# The OCI chart: the digest is on the release notes' Chart line.
cosign verify --certificate-identity "$SIGNER" --certificate-oidc-issuer "$ISSUER" \
  ghcr.io/tuhis/charts/nyyrikki@sha256:<chart digest>

# The release assets: download them, SHA256SUMS and SHA256SUMS.sigstore.json
# into one directory, then:
cosign verify-blob --certificate-identity "$SIGNER" --certificate-oidc-issuer "$ISSUER" \
  --bundle SHA256SUMS.sigstore.json SHA256SUMS
sha256sum -c SHA256SUMS   # add --ignore-missing if you downloaded only some
```

On macOS, use `shasum -a 256 -c SHA256SUMS`. Then install exactly what
you verified: the chart by its digest, which Helm checks
(`helm install nyyrikki oci://ghcr.io/tuhis/charts/nyyrikki:<version>@sha256:<chart digest> …`),
and `image.digest` set to the image digest.

The image also carries BuildKit's SBOM and SLSA provenance for each
platform. They are inside the signed image index, so the image's
signature covers them. To read them:

```sh
docker buildx imagetools inspect ghcr.io/tuhis/nyyrikki@sha256:<image digest> --format '{{json .SBOM}}'
docker buildx imagetools inspect ghcr.io/tuhis/nyyrikki@sha256:<image digest> --format '{{json .Provenance}}'
```

## Remote clusters

Apply `deploy/remote-target/nyyrikki-target.yaml` on the remote cluster,
after replacing the user and group. Copy its token and CA into a Secret
here, as the file's comments show, and add the target:

```yaml
targets:
  - name: lab
    server: https://lab.example.com:6443
    secretName: nyyrikki-target-lab
```

Kubernetes 1.35 or newer is required. Older targets are refused (docs/01 D13).

## Your own rights, and Nyyrikki's credentials

Requests run as you. If you can read Nyyrikki's Secrets, mint tokens for
its ServiceAccount, write anything in its namespace, debug its node or
create privileged or `hostPath` pods, then one request you approve, or
any request under an elevation you granted, can hand the agent
Nyyrikki's credentials. That is an accepted risk, and your tap is the
defence. Withholding those rights (the full list is in
[SECURITY.md](../../SECURITY.md), Accepted risks) narrows it; running
Nyyrikki on a cluster you don't administer closes it.

## Rotating credentials

Replace a Secret's value. Nyyrikki reads every credential file on use, so
no restart is needed (docs/06 D4). The in-cluster token is rotated by the
kubelet.

## Checks after install

- `kubectl auth can-i --list --as=system:serviceaccount:nyyrikki:nyyrikki-nyyrikki`
  shows only `impersonate` on the human's names, plus the discovery rules
  everyone has.
- From an agent's identity, `kubectl auth can-i get secrets -n nyyrikki`,
  `create pods/exec -n nyyrikki`, `get pods/proxy -n nyyrikki` and
  `get services/proxy -n nyyrikki` are all `no` (SECURITY.md).
