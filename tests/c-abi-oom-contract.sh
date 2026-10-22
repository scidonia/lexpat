#!/usr/bin/env bash
# Allocation-failure contract for the C ABI parse path.
#
#   tests/c-abi-oom-contract.sh A3        candidate parse with a faulted shim malloc
#   tests/c-abi-oom-contract.sh control   no-fault capability check under ASan/UBSan
#   tests/c-abi-oom-contract.sh           control, then A3
#
# The executable is a test-only build: the C shim and the prebuilt Lean module
# objects are linked into it directly, with -Wl,--wrap=malloc and
# -Wl,--wrap=calloc around the shim's allocations. Wrapping the shipped
# liblexpat.so.1 at run time would not intercept them. The control build is
# instrumented with ASan and UBSan and leak detection is off, as in
# tests/c-abi-memory.sh, because the artifact has no runtime-finalize step.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "${1:-}" in
  control | A3) modes=("$1") ;;
  "") modes=(control A3) ;;
  *)
    echo "usage: $(basename "$0") [control|A3]" >&2
    exit 2
    ;;
esac
if [ "$#" -gt 1 ]; then
  echo "usage: $(basename "$0") [control|A3]" >&2
  exit 2
fi

if command -v lake >/dev/null 2>&1; then
  (cd "$repo" && lake build lexpatCAbi)
else
  (cd "$repo" && nix develop -c lake build lexpatCAbi)
fi

lean_libdir="$(lean --print-libdir)"
lean_include="$(dirname "$(dirname "$lean_libdir")")/include"
if [ ! -f "$lean_include/lean/lean.h" ]; then
  echo "c-abi-oom-contract: lean.h not found under $lean_include" >&2
  exit 1
fi
objs=()
while IFS= read -r obj; do
  objs+=("$obj")
done < <(find "$repo/.lake/build/ir/LexPat" -name '*.c.o.export' -not -path '*/Exe/*' | sort)
if [ "${#objs[@]}" -eq 0 ]; then
  echo "c-abi-oom-contract: no Lean module objects were found" >&2
  exit 1
fi

tmp="$(mktemp -d /tmp/lexpat-cabi-oom-contract.XXXXXX)"
if [ -z "$tmp" ] || [ ! -d "$tmp" ]; then
  echo "c-abi-oom-contract: mktemp did not produce a directory" >&2
  exit 1
fi
trap 'rm -rf -- "$tmp"' EXIT

compile() {
  cc -std=c11 -Wall -Wextra -Werror -g -I"$repo/include" -I"$lean_include" \
    "$repo/tests/c-abi-oom-contract.c" "$repo/cabi/expat.c" "${objs[@]}" \
    -L"$lean_libdir" -lleanshared -pthread \
    -Wl,--wrap=malloc -Wl,--wrap=calloc \
    -Wl,-rpath,"$lean_libdir" "$@"
}

status=0
for mode in "${modes[@]}"; do
  case "$mode" in
    control)
      echo "c-abi-oom-contract: building the ASan/UBSan control"
      compile -fsanitize=address,undefined -fno-omit-frame-pointer \
        -o "$tmp/c-abi-oom-control"
      echo "c-abi-oom-contract: running the control under ASan/UBSan" \
        "(leak detection off; no runtime finalize)"
      ASAN_OPTIONS="detect_leaks=0:abort_on_error=1" \
      UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
        "$tmp/c-abi-oom-control" control || status=1
      ;;
    A3)
      echo "c-abi-oom-contract: building the A3 candidate parse"
      compile -o "$tmp/c-abi-oom-a3"
      "$tmp/c-abi-oom-a3" A3 || status=1
      ;;
  esac
done
exit "$status"
