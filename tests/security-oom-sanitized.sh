#!/usr/bin/env bash
# Deterministic C-shim allocation failures under ASan/UBSan.
#
#   tests/security-oom-sanitized.sh --out <absolute-directory>
#
# Builds a test-only executable that links `cabi/expat.c` and the Lean module
# objects directly, so `-Wl,--wrap=malloc/calloc/free` reaches the shim's own
# allocations only. The capability control runs first and must observe a known
# shim allocation with no fault; the matrix then consumes one shim-owned fault
# at each selected callsite and asserts the public result, the same parser's
# error code, the callback counts and that every recorded allocation was freed.
#
# The shipped `.so` is not modified and no Lean-runtime allocation is faulted.
# ASan's leak detector stays off because the pinned Lean/libuv startup makes a
# one-time allocation that is not a shim leak; the wrapper's free ledger is the
# cleanup detector for every scenario.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --out)
      if [ "$#" -lt 2 ]; then
        echo "security-oom-sanitized: --out needs a directory" >&2
        exit 2
      fi
      out="$2"
      shift 2
      ;;
    *)
      echo "security-oom-sanitized: unknown option $1" >&2
      exit 2
      ;;
  esac
done

if [ -z "$out" ]; then
  echo "security-oom-sanitized: --out is required" >&2
  exit 2
fi
case "$out" in
  /*) ;;
  *)
    echo "security-oom-sanitized: --out must be an absolute path" >&2
    exit 2
    ;;
esac
mkdir -p "$out"

if command -v lake >/dev/null 2>&1; then
  (cd "$repo" && lake build lexpatCAbi)
else
  (cd "$repo" && nix develop -c lake build lexpatCAbi)
fi

lean_libdir="$(lean --print-libdir)"
lean_include="$(dirname "$(dirname "$lean_libdir")")/include"
if [ ! -f "$lean_include/lean/lean.h" ]; then
  echo "security-oom-sanitized: lean.h not found under $lean_include" >&2
  exit 1
fi

mapfile -t objects < <(
  find "$repo/.lake/build/ir/LexPat" -name '*.c.o.export' -not -path '*/Exe/*' | sort
)
if [ "${#objects[@]}" -eq 0 ]; then
  echo "security-oom-sanitized: no Lean module objects; run lake build lexpatCAbi" >&2
  exit 1
fi

cc="${CC:-cc}"
"$cc" -std=c11 -Wall -Wextra -Werror -g -O1 -fno-omit-frame-pointer \
  -fsanitize=address,undefined \
  -I"$repo/include" -I"$lean_include" \
  "$repo/tests/security/oom-sanitized.c" "$repo/cabi/expat.c" "${objects[@]}" \
  -L"$lean_libdir" -lleanshared -pthread \
  -Wl,--wrap=malloc -Wl,--wrap=calloc -Wl,--wrap=free \
  -Wl,-rpath,"$lean_libdir" -o "$out/oom-sanitized"

export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"

"$out/oom-sanitized" --control 2>&1 | tee "$out/control.log"
"$out/oom-sanitized" --matrix 2>&1 | tee "$out/matrix.log"
echo "security-oom-sanitized: PASS (logs in $out)"
