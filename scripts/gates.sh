#!/usr/bin/env bash
# Runs Nyyrikki's gates (docs/01 D17, CODE-REVIEW.md §Gates).
#   scripts/gates.sh            run every gate on the repository
#   scripts/gates.sh GATE [DIR] run one gate, in DIR (used by gates-selftest)
set -euo pipefail

LICENSES=MIT,BSD-2-Clause,BSD-3-Clause,Apache-2.0,ISC
# The go-sdk's licence files are mid-transition (docs/01 M3) and are reviewed
# by hand (docs/01 D14); its LICENSE hash is pinned in scripts/pinned-licenses.
LICENSE_IGNORE=(--ignore github.com/modelcontextprotocol/go-sdk --ignore github.com/Tuhis/Nyyrikki)
# The SOPS library and the Vault client it links are MPL-2.0, which is not
# on the allowlist. They are admitted by name, each reviewed by hand and its
# LICENSE hash pinned in scripts/pinned-licenses (docs/10 OD6): used
# unmodified, and the image ships their licence texts and source
# (scripts/save-licenses.sh). MPL-2.0 itself stays off the allowlist, so any
# other MPL-2.0 module still fails this gate.
LICENSE_IGNORE+=(
  --ignore github.com/getsops/sops/v3
  --ignore github.com/hashicorp/errwrap
  --ignore github.com/hashicorp/go-cleanhttp
  --ignore github.com/hashicorp/go-multierror
  --ignore github.com/hashicorp/go-retryablehttp
  --ignore github.com/hashicorp/go-rootcerts
  --ignore github.com/hashicorp/go-secure-stdlib/parseutil
  --ignore github.com/hashicorp/go-secure-stdlib/strutil
  --ignore github.com/hashicorp/go-sockaddr
  --ignore github.com/hashicorp/hcl
  --ignore github.com/hashicorp/vault/api
)

gate() {
  local name=$1 dir=${2:-.}
  ( cd "$dir"
    case $name in
      fmt)         out=$(find . -name '*.go' -not -path './test/canaries/*' -print0 | xargs -0 gofmt -l
                     [ "$dir" = . ] || gofmt -l .); if [ -n "$out" ]; then echo "$out"; exit 1; fi ;;
      vet)         go vet ./... ;;
      staticcheck) staticcheck ./... ;;
      tidy)        go mod tidy -diff ;;
      test)        # -p 2: at most two packages are built and linked at a time. The
                   # race test binaries are 100 to 230 MB each since the SOPS
                   # library (docs/10), and one link per CPU ran CI's runners out
                   # of disk (#75). The same in the coverage gate, whose binaries
                   # each hold every package.
                   go test -race -count=1 -p 2 ./...
                   # The SOPS target against the sops program go.mod pins as a
                   # tool, at the library's version (docs/10 G3). After the suite,
                   # not inside it: building the program next to the suite's own
                   # links ran CI's runners out of disk (#75). -v, the count and
                   # the SKIP check: a run that matched no test, or skipped any,
                   # fails.
                   [ "$dir" = . ] || exit 0
                   bin=$(mktemp -d); trap 'rm -rf "$bin"' EXIT
                   go build -o "$bin/sops" github.com/getsops/sops/v3/cmd/sops
                   out=$(NYYRIKKI_SOPS_PROGRAM="$bin/sops" go test -race -count=1 -v -run '^TestSOPSProgram' ./internal/sopstarget/) \
                     || { echo "$out"; exit 1; }
                   n=$(grep -c '^--- PASS: TestSOPSProgram' <<<"$out" || true)
                   [ "$n" -ge 2 ] || { echo "$out"; echo "test: only $n of the sops program tests passed"; exit 1; }
                   ! grep -q '^ *--- SKIP' <<<"$out" || { echo "$out"; echo "test: a sops program test was skipped"; exit 1; }
                   echo "ok  	the sops program tests ($n)" ;;
      coverage)    # Cross-package total against coverage-floor.txt (docs/09 D5).
                   # No -race: the test gate has it. Fails closed: a floor that
                   # isn't a whole number from 1 to 100, an empty profile or an
                   # unparseable total all fail.
                   floor=$(cat coverage-floor.txt 2>/dev/null) || { echo "coverage: no coverage-floor.txt"; exit 1; }
                   [[ $floor =~ ^[0-9]+$ ]] && [ "$floor" -ge 1 ] && [ "$floor" -le 100 ] \
                     || { echo "coverage: coverage-floor.txt must be a whole percent from 1 to 100, not '$floor'"; exit 1; }
                   prof=$(mktemp); trap 'rm -f "$prof"' EXIT
                   # Build go tool covdata into the cache first: go test builds it on
                   # first use while parallel test binaries exec it, and Linux can
                   # refuse the exec of a file another process still holds open for
                   # writing ("text file busy", golang/go#22315; CI, #54).
                   go tool -n covdata >/dev/null
                   go test -count=1 -p 2 -coverpkg=./... -coverprofile="$prof" ./...
                   [ "$(grep -vc '^mode:' "$prof")" -gt 0 ] || { echo "coverage: the profile has no blocks"; exit 1; }
                   total=$(go tool cover -func="$prof" | awk '$1 == "total:" { print $NF }')
                   [[ $total =~ ^[0-9]+(\.[0-9]+)?%$ ]] || { echo "coverage: could not read the total from '$total'"; exit 1; }
                   echo "coverage: total ${total}, floor ${floor}%"
                   awk -v t="${total%\%}" -v f="$floor" 'BEGIN { exit !(t + 0 >= f + 0) }' \
                     || { echo "coverage: total ${total} is below the floor ${floor}%"; exit 1; } ;;
      vuln)        govulncheck ./... ;;
      licenses)    go-licenses check ./... --allowed_licenses="$LICENSES" "${LICENSE_IGNORE[@]}"
                   [ "$dir" != . ] || scripts/check-pinned-licenses.sh ;;
      secrets)     gitleaks dir . --redact --no-banner --verbose --config .gitleaks.toml ;;
      chart)       # Runs once the chart exists (docs/01 D17). --kube-version: Helm's
                   # offline default is the Kubernetes it was built against.
                   [ -d deploy/chart/nyyrikki ] || { echo "no chart yet"; exit 0; }
                   helm lint deploy/chart/nyyrikki -f deploy/chart/nyyrikki/ci/test-values.yaml --kube-version 1.35.0
                   helm template t deploy/chart/nyyrikki -f deploy/chart/nyyrikki/ci/test-values.yaml --kube-version 1.35.0 \
                     | kubeconform -strict -summary -kubernetes-version 1.35.0
                   # With an SSH target: the CA hook and CronJobs (docs/08 D16).
                   helm lint deploy/chart/nyyrikki -f deploy/chart/nyyrikki/ci/test-values.yaml -f deploy/chart/nyyrikki/ci/ssh-values.yaml --kube-version 1.35.0
                   helm template t deploy/chart/nyyrikki -f deploy/chart/nyyrikki/ci/test-values.yaml -f deploy/chart/nyyrikki/ci/ssh-values.yaml --kube-version 1.35.0 \
                     | kubeconform -strict -summary -kubernetes-version 1.35.0
                   # With a SOPS target: the credential and token mounts (docs/10 §5.4).
                   helm lint deploy/chart/nyyrikki -f deploy/chart/nyyrikki/ci/test-values.yaml -f deploy/chart/nyyrikki/ci/sops-values.yaml --kube-version 1.35.0
                   helm template t deploy/chart/nyyrikki -f deploy/chart/nyyrikki/ci/test-values.yaml -f deploy/chart/nyyrikki/ci/sops-values.yaml --kube-version 1.35.0 \
                     | kubeconform -strict -summary -kubernetes-version 1.35.0
                   NYYRIKKI_CHART_TESTS=1 go test -count=1 ./deploy/... ;;
      pinning)     scripts/check-pinning.sh ;;
      *) echo "unknown gate $name" >&2; exit 2 ;;
    esac )
}

if [ $# -gt 0 ]; then gate "$@"; exit; fi
for g in fmt vet staticcheck tidy test coverage vuln licenses secrets chart pinning; do
  echo "== $g"; gate "$g"
done
