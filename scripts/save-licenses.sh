#!/usr/bin/env bash
# Saves the licence texts of every module compiled into PKG to OUTDIR
# (docs/09 D3, §5.3). Shared by the Dockerfile (nyyrikkid, in the image)
# and release.yml (nyyrikki, as nyyrikki-licenses.tar.gz), so the two
# stay in step.
#   scripts/save-licenses.sh PKG OUTDIR   (both relative to the repository root, or absolute)
# Needs go-licenses on PATH, at GO_LICENSES_VERSION in ci.yml. GOOS and
# GOARCH, if set, pick the target's package set, as for go build.
# Fails if anything is missing, or if OUTDIR would end up empty.
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: $0 PKG OUTDIR" >&2; exit 2; }
pkg=$1 out=$2
cd "$(dirname "$0")/.."

# The same ignores as the licenses gate in scripts/gates.sh: the go-sdk's
# licence files are mid-transition and are reviewed by hand (docs/01 D14,
# scripts/pinned-licenses), and Nyyrikki is not a dependency of itself.
# Both are copied in by hand below.
go-licenses save "$pkg" --save_path="$out" \
  --ignore github.com/modelcontextprotocol/go-sdk --ignore github.com/Tuhis/Nyyrikki

# Nyyrikki's own licence.
mkdir -p "$out/github.com/Tuhis/Nyyrikki"
cp LICENSE "$out/github.com/Tuhis/Nyyrikki/LICENSE"

# The go-sdk, if PKG uses it: its LICENSE is the file pinned in
# scripts/pinned-licenses, which names every licence it is under.
if go list -deps "$pkg" | grep -q '^github.com/modelcontextprotocol/go-sdk/'; then
  dir=$(go list -m -f '{{.Dir}}' github.com/modelcontextprotocol/go-sdk)
  [ -s "$dir/LICENSE" ] || { echo "go-sdk LICENSE missing in $dir" >&2; exit 1; }
  mkdir -p "$out/github.com/modelcontextprotocol/go-sdk"
  cp "$dir/LICENSE" "$out/github.com/modelcontextprotocol/go-sdk/LICENSE"
fi

# The Go standard library and runtime, compiled into every binary;
# go-licenses leaves them out.
goroot=$(go env GOROOT)
[ -s "$goroot/LICENSE" ] || { echo "Go LICENSE missing in $goroot" >&2; exit 1; }
mkdir -p "$out/go"
cp "$goroot/LICENSE" "$out/go/LICENSE"

# Copies from the module cache keep its read-only mode, both go-licenses'
# and ours; make the set writable so release.yml can merge the platforms'
# sets over each other as a non-root user (review of #52).
chmod -R u+w "$out"

# Fail closed: a module's licence beside Nyyrikki's own and Go's, at least.
n=$(find "$out" -type f | wc -l)
[ "$n" -gt 2 ] || { echo "only $n licence files in $out" >&2; exit 1; }
echo "saved $n licence files for $pkg to $out"
