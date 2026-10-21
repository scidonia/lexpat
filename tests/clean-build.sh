#!/usr/bin/env bash
# Build the candidate sources in a fresh directory with nothing from the
# working tree's build outputs, editor state or VCS metadata.
#
# The copy models a clean checkout: it contains the flake, the toolchain pin,
# the Lake files and the Lean sources, and no `.lake`, `.direnv`, `.git` or
# `Vendor` directory. The temporary directory is removed on exit.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

tmp="$(mktemp -d /tmp/lexpat-m1.XXXXXX)"
if [ -z "$tmp" ] || [ ! -d "$tmp" ]; then
  echo "clean-build: mktemp did not produce a directory" >&2
  exit 1
fi
trap 'rm -rf -- "$tmp"' EXIT

cp -a \
  "$repo/flake.nix" \
  "$repo/flake.lock" \
  "$repo/lean-toolchain" \
  "$repo/lakefile.lean" \
  "$repo/lake-manifest.json" \
  "$repo/LexPat.lean" \
  "$tmp/"
cp -a "$repo/LexPat" "$tmp/LexPat"
cp -a "$repo/tests" "$tmp/tests"

for excluded in .lake .direnv .git Vendor; do
  if [ -e "$tmp/$excluded" ]; then
    echo "clean-build: $excluded leaked into the clean copy" >&2
    exit 1
  fi
done

echo "clean-build: building in $tmp"
cd "$tmp"
nix develop -c lake build
echo "clean-build: OK (source-only copy)"
