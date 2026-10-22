#!/usr/bin/env bash
# Bounded libFuzzer smoke: the approved CI budget.
#
#   tests/security-fuzz-smoke.sh --out <absolute-directory> [--build-dir DIR]
#
# Targets, counts, caps and seed are fixed here:
#
#   parser      -runs=10000 -max_len=8192  45s
#   cabi        -runs=10000 -max_len=8192  45s
#   artifact    -runs=2000  -max_len=4096  30s
#   differential-runs=5000  -max_len=4096  45s
#
# Every target must reach its requested completed-unit count within its cap.
# A missing count or a nonzero target status fails the smoke. Seeds are copied
# into a fresh directory under --out; the checked-in seeds are never rewritten.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out=""
build_dir=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --out)
      if [ "$#" -lt 2 ]; then
        echo "security-fuzz-smoke: --out needs a directory" >&2
        exit 2
      fi
      out="$2"
      shift 2
      ;;
    --build-dir)
      if [ "$#" -lt 2 ]; then
        echo "security-fuzz-smoke: --build-dir needs a directory" >&2
        exit 2
      fi
      build_dir="$2"
      shift 2
      ;;
    *)
      echo "security-fuzz-smoke: unknown option $1" >&2
      exit 2
      ;;
  esac
done

if [ -z "$out" ]; then
  echo "security-fuzz-smoke: --out is required" >&2
  exit 2
fi
case "$out" in
  /*) ;;
  *)
    echo "security-fuzz-smoke: --out must be an absolute path" >&2
    exit 2
    ;;
esac
mkdir -p "$out"

if [ -z "$build_dir" ]; then
  build_dir="$out/build"
  bash "$repo/scripts/security-fuzz-build.sh" --out "$build_dir"
fi
# The prepared build is accepted only when its content manifests, toolchain and
# oracle identities and every named target hash match this checkout. A failed
# validation cannot become a green fuzz count.
python3 "$repo/scripts/security-fuzz-verify.py" --build-dir "$build_dir" || {
  echo "security-fuzz-smoke: prepared build refused" >&2
  exit 1
}

export ASAN_OPTIONS="detect_leaks=0:quarantine_size_mb=16:abort_on_error=1"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"

run_target() {
  local target="$1" runs="$2" max_len="$3" cap="$4" seeds="$5" binary="$6"
  local dir="$out/$target"
  local corpus="$dir/corpus"
  mkdir -p "$corpus" "$dir/artifacts"
  if [ ! -d "$seeds" ]; then
    echo "security-fuzz-smoke: missing seed group $seeds" >&2
    exit 1
  fi
  local seed_count
  seed_count="$(find "$seeds" -type f | wc -l)"
  if [ "$seed_count" -eq 0 ]; then
    echo "security-fuzz-smoke: seed group $seeds is empty" >&2
    exit 1
  fi
  cp -R "$seeds/." "$corpus/"

  local status=0
  timeout --signal=TERM --kill-after=5s "$cap" \
    "$build_dir/$binary" \
    -runs="$runs" -max_len="$max_len" -timeout=2 -rss_limit_mb=2048 \
    -seed=46980 -print_final_stats=1 \
    -artifact_prefix="$dir/artifacts/" "$corpus" \
    >"$dir/run.log" 2>&1 || status=$?

  local completed
  completed="$(grep -o 'stat::number_of_executed_units: [0-9]*' "$dir/run.log" \
    | tail -n 1 | awk '{print $2}')"
  if [ -z "$completed" ]; then
    completed=0
  fi
  if [ "$status" -ne 0 ]; then
    echo "security-fuzz-smoke: $target exited $status" >&2
    tail -n 20 "$dir/run.log" >&2
    return 1
  fi
  if [ "$completed" -lt "$runs" ]; then
    echo "security-fuzz-smoke: $target completed $completed of $runs units" >&2
    return 1
  fi
  if find "$dir/artifacts" -type f | grep -q .; then
    echo "security-fuzz-smoke: $target wrote an artifact; triage it" >&2
    find "$dir/artifacts" -type f >&2
    return 1
  fi
  printf 'PASS %s: %s executed units (requested %s, cap %s, seeds %s)\n' \
    "$target" "$completed" "$runs" "$cap" "$seed_count"
}

run_target parser 10000 8192 45s \
  "$repo/tests/security/seeds/parser" parser-fuzz
run_target cabi 10000 8192 45s \
  "$repo/tests/security/seeds/cabi" cabi-fuzz
run_target artifact 2000 4096 30s \
  "$repo/tests/security/seeds/cabi" artifact-fuzz
echo "NOTE artifact: library coverage is absent; only the harness is instrumented"
run_target diff 5000 4096 45s \
  "$repo/tests/security/seeds/diff" differential-fuzz

echo "security-fuzz-smoke: PASS (logs in $out)"
