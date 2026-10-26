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
  telegramUserID: 0              # fill in after /start
targets:
  - name: this-cluster
    description: The cluster Nyyrikki runs in
    inCluster: true
networkPolicy:
  ingressNamespaces: [agents]
```

```sh
helm install nyyrikki deploy/chart/nyyrikki -n nyyrikki -f values.yaml
```

The chart grants Nyyrikki's ServiceAccount only `impersonate` on the
human's user and groups (docs/06 D3). Requests then run with the human's
own rights.

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
its ServiceAccount, exec into its pod, debug its node or create
privileged or `hostPath` pods, then one request you approve can hand the
agent Nyyrikki's credentials. That is an accepted risk, and your tap is
the defence. To close it, withhold those rights from the human Nyyrikki
acts as, on this cluster and on `nyyrikki-system` in remote ones, or run
Nyyrikki on a cluster you don't administer
([SECURITY.md](../../SECURITY.md), Accepted risks).

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
