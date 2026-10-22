#!/usr/bin/env bash
# Replay every declared differential exception through the same comparator.
#
#   tests/security-differential-fixed.sh --out <absolute-directory>
#
# Builds the unsanitized `differential-replay` binary from
# `tests/security/differential.c`, which `dlopen`s the shipped candidate and
# the pinned libexpat with `RTLD_NOW | RTLD_LOCAL` and calls each through its
# own `dlsym` table. Before any comparison it requires
# `pkg-config --modversion expat`, `XML_ExpatVersion()` and
# `XML_ExpatVersionInfo()` to match exactly. It then drives every exception in
# `tests/security/differential-exceptions.json` through one `both` invocation
# of that comparator and asserts both exact outcomes.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --out)
      if [ "$#" -lt 2 ]; then
        echo "security-differential-fixed: --out needs a directory" >&2
        exit 2
      fi
      out="$2"
      shift 2
      ;;
    *)
      echo "security-differential-fixed: unknown option $1" >&2
      exit 2
      ;;
  esac
done

if [ -z "$out" ]; then
  echo "security-differential-fixed: --out is required" >&2
  exit 2
fi
case "$out" in
  /*) ;;
  *)
    echo "security-differential-fixed: --out must be an absolute path" >&2
    exit 2
    ;;
esac
mkdir -p "$out"

if [ ! -f "$repo/.lake/build/lib/liblexpat.so.1" ]; then
  echo "security-differential-fixed: build the C ABI artifact first" >&2
  exit 1
fi

pkg_version="$(pkg-config --modversion expat)"
if [ "$pkg_version" != "2.8.5" ]; then
  echo "security-differential-fixed: pkg-config --modversion expat is" \
    "\"$pkg_version\", not exactly \"2.8.5\"" >&2
  exit 1
fi
oracle="$(pkg-config --variable=libdir expat)/libexpat.so.1"
if [ ! -e "$oracle" ]; then
  echo "security-differential-fixed: pinned oracle not found at $oracle" >&2
  exit 1
fi

cc="${CC:-cc}"
"$cc" -std=c11 -O2 -g -Wall -Wextra -Werror \
  -DLEX_DEFAULT_ORACLE="\"$oracle\"" \
  -I"$repo/include" \
  "$repo/tests/security/differential.c" -ldl -o "$out/differential-replay"

# The binary re-reads pkg-config, checks XML_ExpatVersion and
# XML_ExpatVersionInfo exactly, and exits nonzero on any mismatch.
"$out/differential-replay" --version >"$out/version.log"
cat "$out/version.log"
grep -qx 'oracle=expat_2.8.5' "$out/version.log"
grep -qx 'oracle_info=2.8.5' "$out/version.log"
grep -qx "oracle_path=$oracle" "$out/version.log"
grep -qx 'pkg_config=2.8.5' "$out/version.log"

python3 "$repo/tests/security/differential-fixed.py" \
  --replay "$out/differential-replay" --out "$out"
echo "security-differential-fixed: PASS (logs in $out)"
