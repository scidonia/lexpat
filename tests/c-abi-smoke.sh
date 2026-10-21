#!/usr/bin/env bash
# Build the C ABI artifact and run the direct C smoke client
# against the checked-in header. Capability evidence, not a supported-route
# contract.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lib="$repo/.lake/build/lib"

tmp="$(mktemp -d /tmp/lexpat-cabi-smoke.XXXXXX)"
if [ -z "$tmp" ] || [ ! -d "$tmp" ]; then
  echo "c-abi-smoke: mktemp did not produce a directory" >&2
  exit 1
fi
trap 'rm -rf -- "$tmp"' EXIT

cd "$repo"
nix develop -c lake build

for artifact in "$lib/liblexpat.so.1" "$lib/liblexpat.so" "$repo/include/expat.h"; do
  if [ ! -e "$artifact" ]; then
    echo "c-abi-smoke: missing $artifact" >&2
    exit 1
  fi
done

field() {
  readelf -d "$lib/liblexpat.so.1" | grep -F "$1" || true
}

if ! field "SONAME" | grep -q 'liblexpat.so.1'; then
  echo "c-abi-smoke: SONAME is not liblexpat.so.1" >&2
  exit 1
fi
if ! field "NEEDED" | grep -q 'libleanshared.so'; then
  echo "c-abi-smoke: libleanshared.so is not a runtime dependency" >&2
  exit 1
fi

if nm -D --defined-only "$lib/liblexpat.so.1" | grep -Eq 'lexpat_cabi|initialize_|lean_'; then
  echo "c-abi-smoke: internal Lean symbols are exported" >&2
  exit 1
fi
if ! nm -D --defined-only "$lib/liblexpat.so.1" | grep -q ' T XML_Parse$'; then
  echo "c-abi-smoke: XML_Parse is not exported" >&2
  exit 1
fi

nix develop -c cc -std=c11 -Wall -Wextra -Werror -I"$repo/include" \
  "$repo/tests/c-abi-smoke.c" -L"$lib" -llexpat \
  -Wl,-rpath,"$lib" -o "$tmp/c-abi-smoke"
"$tmp/c-abi-smoke"
