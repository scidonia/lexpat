#!/usr/bin/env bash
# Build the C ABI shared object.
#
# Two modes:
#   scripts/build-c-abi.sh
#       Build through Lake, which collects the Lean module objects and invokes
#       this script with their paths.
#   scripts/build-c-abi.sh --out <path> <object>...
#       Compile the C shim and link the shared object. Used by the Lake target
#       and directly by tests that already have the objects.
#
# The toolchain include and runtime directories are derived from
# `lean --print-libdir`; no developer path is hard-coded.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ "$#" -eq 0 ]; then
  cd "$repo"
  exec lake build lexpatCAbi
fi

out=""
objs=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --out)
      if [ "$#" -lt 2 ]; then
        echo "build-c-abi: --out needs a path" >&2
        exit 1
      fi
      out="$2"
      shift 2
      ;;
    --*)
      echo "build-c-abi: unknown option $1" >&2
      exit 1
      ;;
    *)
      objs+=("$1")
      shift
      ;;
  esac
done

if [ -z "$out" ]; then
  echo "build-c-abi: --out is required" >&2
  exit 1
fi
if [ "${#objs[@]}" -eq 0 ]; then
  echo "build-c-abi: at least one Lean object is required" >&2
  exit 1
fi
for obj in "${objs[@]}"; do
  if [ ! -f "$obj" ]; then
    echo "build-c-abi: missing Lean object $obj" >&2
    exit 1
  fi
done

lean_libdir="$(lean --print-libdir)"
lean_prefix="$(dirname "$(dirname "$lean_libdir")")"
lean_include="$lean_prefix/include"
if [ ! -f "$lean_include/lean/lean.h" ]; then
  echo "build-c-abi: lean.h not found under $lean_include" >&2
  exit 1
fi

cc="${CC:-cc}"
work="$repo/.lake/build/cabi"
mkdir -p "$work" "$(dirname "$out")"

"$cc" -std=c11 -Wall -Wextra -Werror -fPIC -fvisibility=hidden \
  -I"$repo/include" -I"$lean_include" \
  -c "$repo/cabi/expat.c" -o "$work/expat.o"

# The ambient NIX_LDFLAGS can carry a developer rpath; link with only the
# paths this script supplies.
link_env=()
if [ -n "${NIX_LDFLAGS:-}" ]; then
  link_env=(env -u NIX_LDFLAGS)
fi

# The shared object is not unloadable. Initializing the Lean runtime starts
# background threads whose entry points are inside `libleanshared.so`, and the
# Lean runtime has no shutdown entry point that would stop and join them. A
# `dlclose` of this object therefore releases the runtime under threads that are
# still running in it: at best the unload races a thread that has not reached its
# first instruction yet, at worst it unmaps code a parked thread will return
# into. `-z nodelete` keeps this object and the runtime it depends on mapped for
# the life of the process, which is the lifetime those threads assume.
"${link_env[@]}" "$cc" -shared -o "$out" "$work/expat.o" "${objs[@]}" \
  -L"$lean_libdir" -lleanshared -pthread \
  -Wl,-z,nodelete \
  -Wl,--no-undefined \
  -Wl,-soname,liblexpat.so.1 \
  -Wl,-rpath,"$lean_libdir" \
  -Wl,--version-script,"$repo/cabi/exports.map"

ln -sfn "liblexpat.so.1" "$(dirname "$out")/liblexpat.so"
