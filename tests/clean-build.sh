#!/usr/bin/env bash
# Build the candidate sources in a fresh directory with nothing from the
# working tree's build outputs, editor state or VCS metadata.
#
# The copy models a clean checkout: it contains the flake, the toolchain pin,
# the Lake files, the Lean sources and the C ABI sources, and no `.lake`,
# `.direnv`, `.git` or `Vendor` directory. It then checks that the default
# build produced a loadable versioned shared object and that a client compiled
# against the in-copy header runs. The temporary directory is removed on exit.
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
cp -a "$repo/include" "$tmp/include"
cp -a "$repo/cabi" "$tmp/cabi"
cp -a "$repo/scripts" "$tmp/scripts"

for excluded in .lake .direnv .git Vendor; do
  if [ -e "$tmp/$excluded" ]; then
    echo "clean-build: $excluded leaked into the clean copy" >&2
    exit 1
  fi
done

echo "clean-build: building in $tmp"
cd "$tmp"
nix develop -c lake build

lib="$tmp/.lake/build/lib/liblexpat.so.1"
if [ ! -f "$lib" ]; then
  echo "clean-build: liblexpat.so.1 was not produced" >&2
  exit 1
fi
if [ ! -L "$tmp/.lake/build/lib/liblexpat.so" ]; then
  echo "clean-build: the linker-name symlink was not produced" >&2
  exit 1
fi
if [ ! -f "$tmp/include/expat.h" ]; then
  echo "clean-build: include/expat.h is missing" >&2
  exit 1
fi

if ! readelf -d "$lib" | grep -q 'Library soname: \[liblexpat.so.1\]'; then
  echo "clean-build: wrong or missing SONAME" >&2
  exit 1
fi
if ! readelf -d "$lib" | grep -q 'Shared library: \[libleanshared.so\]'; then
  echo "clean-build: libleanshared.so is not a runtime dependency" >&2
  exit 1
fi
if nm -D --defined-only "$lib" | grep -Eq 'lexpat_cabi|initialize_|lean_'; then
  echo "clean-build: internal Lean symbols are exported" >&2
  exit 1
fi

nix develop -c bash -c '
  set -e
  cc -std=c11 -Wall -Wextra -Werror -I"$1/include" \
    "$1/tests/c-abi-smoke.c" -L"$1/.lake/build/lib" -llexpat \
    -Wl,-rpath,"$1/.lake/build/lib" -o "$1/c-abi-smoke"
  "$1/c-abi-smoke"
' bash "$tmp"

echo "clean-build: OK (source-only copy)"