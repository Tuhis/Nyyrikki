#!/usr/bin/env bash
# Runs Nyyrikki's gates (docs/01 D17, CODE-REVIEW.md §Gates).
#   scripts/gates.sh            run every gate on the repository
#   scripts/gates.sh GATE [DIR] run one gate, in DIR (used by gates-selftest)
set -euo pipefail

LICENSES=MIT,BSD-2-Clause,BSD-3-Clause,Apache-2.0,ISC
# The go-sdk's licence files are mid-transition (docs/01 M3) and are reviewed
# by hand (docs/01 D14); its LICENSE hash is pinned in scripts/pinned-licenses.
LICENSE_IGNORE=(--ignore github.com/modelcontextprotocol/go-sdk --ignore github.com/Tuhis/Nyyrikki)

gate() {
  local name=$1 dir=${2:-.}
  ( cd "$dir"
    case $name in
      fmt)         out=$(find . -name '*.go' -not -path './test/canaries/*' -print0 | xargs -0 gofmt -l
                     [ "$dir" = . ] || gofmt -l .); if [ -n "$out" ]; then echo "$out"; exit 1; fi ;;
      vet)         go vet ./... ;;
      staticcheck) staticcheck ./... ;;
      tidy)        go mod tidy -diff ;;
      test)        go test -race -count=1 ./... ;;
      vuln)        govulncheck ./... ;;
      licenses)    go-licenses check ./... --allowed_licenses="$LICENSES" "${LICENSE_IGNORE[@]}"
                   [ "$dir" != . ] || scripts/check-pinned-licenses.sh ;;
      secrets)     gitleaks dir . --redact --no-banner --verbose --config .gitleaks.toml ;;
      chart)       # Runs once the chart exists (docs/01 D17).
                   [ -d deploy/chart/nyyrikki ] || { echo "no chart yet"; exit 0; }
                   helm lint deploy/chart/nyyrikki -f deploy/chart/nyyrikki/ci/test-values.yaml
                   helm template t deploy/chart/nyyrikki -f deploy/chart/nyyrikki/ci/test-values.yaml \
                     | kubeconform -strict -summary -kubernetes-version 1.35.0
                   NYYRIKKI_CHART_TESTS=1 go test -count=1 ./deploy/... ;;
      pinning)     scripts/check-pinning.sh ;;
      *) echo "unknown gate $name" >&2; exit 2 ;;
    esac )
}

if [ $# -gt 0 ]; then gate "$@"; exit; fi
for g in fmt vet staticcheck tidy test vuln licenses secrets chart pinning; do
  echo "== $g"; gate "$g"
done
