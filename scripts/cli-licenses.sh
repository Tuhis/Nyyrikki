#!/usr/bin/env bash
# Packs the CLI's licence notices for a release (docs/09 D3, §5.3): the
# sets of every platform the CLI ships for, saved by save-licenses.sh and
# merged, as one tar.gz. Run by release.yml before anything is published,
# and by CI's gates job as the runner's non-root user, so a merge that
# only works as root fails on a PR, not in a release (review of #52).
#   scripts/cli-licenses.sh OUT.tar.gz
set -euo pipefail
[ $# -eq 1 ] || { echo "usage: $0 OUT.tar.gz" >&2; exit 2; }
out=$(realpath -m "$1")
cd "$(dirname "$0")/.."
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
for os in linux darwin; do for arch in amd64 arm64; do
  GOOS=$os GOARCH=$arch scripts/save-licenses.sh ./cmd/nyyrikki "$work/$os-$arch" >/dev/null
  # Their package sets can differ; later sets overwrite equal files.
  mkdir -p "$work/licenses" && cp -R "$work/$os-$arch/." "$work/licenses/"
done; done
tar -czf "$out" -C "$work" licenses
n=$(tar -tzf "$out" | grep -vc '/$' || true)
[ "$n" -gt 3 ] || { echo "$out holds only $n files" >&2; exit 1; }
echo "packed $n licence files into $out"
