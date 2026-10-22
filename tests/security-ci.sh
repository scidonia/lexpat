#!/usr/bin/env bash
# The bounded security step: CVE checks, fixed differential replay, injected
# shim OOM and the four-target libFuzzer smoke.
#
#   tests/security-ci.sh --out <absolute-directory> [--build-dir <absolute-directory>]
#
# The scaling sentinel is deliberately not a stage here: it is a timing
# measurement, and its drift control classifies an unusable session rather than
# a security failure. `.github/workflows/ci.yml` runs it as its own required
# step through `tests/security-scaling-ci.sh`, which owns the one classified
# retry. Everything this script runs is either a pass or a failure.
#
# With `--build-dir`, the prepared build is verified against its own content
# manifests before any runtime check: a missing, stale or mismatched build is
# refused rather than used. The same check runs again after the C ABI artifact
# build, because `lake build` can relink the shipped artifact or regenerate Lean
# C after the entry check. Without `--build-dir`, the script builds the fuzz
# targets under `--out`, verifies that fresh build, and then runs the checks.
#
# Every stage announces its start, prints its elapsed time and keeps its own log
# under <out>/stages. On failure the script names the failed stage and its log,
# so a wall-clock cap cannot erase which stage was running. The caller applies
# the hard wall cap around this whole command (including `nix develop`).
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out=""
build_dir=""
last_stage=""
stage_log=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --out)
      if [ "$#" -lt 2 ]; then
        echo "security-ci: --out needs a directory" >&2
        exit 2
      fi
      out="$2"
      shift 2
      ;;
    --build-dir)
      if [ "$#" -lt 2 ]; then
        echo "security-ci: --build-dir needs a directory" >&2
        exit 2
      fi
      build_dir="$2"
      shift 2
      ;;
    *)
      echo "security-ci: unknown option $1" >&2
      exit 2
      ;;
  esac
done

if [ -z "$out" ]; then
  echo "security-ci: --out is required" >&2
  exit 2
fi
for path_name in out build_dir; do
  value="${!path_name}"
  if [ -n "$value" ]; then
    case "$value" in
      /*) ;;
      *)
        echo "security-ci: --$path_name must be an absolute path" >&2
        exit 2
        ;;
    esac
  fi
done
mkdir -p "$out/stages"

stage_log_for() {
  printf '%s/stages/%s.log' "$out" "$1"
}

stage() {
  local name="$1"
  shift
  last_stage="$name"
  stage_log="$(stage_log_for "$name")"
  local started=$SECONDS
  echo "security-ci: stage $name: start"
  local rc=0
  "$@" 2>&1 | tee "$stage_log" || rc=$?
  local elapsed=$((SECONDS - started))
  if [ "$rc" -ne 0 ]; then
    echo "security-ci: stage $name: FAILED exit=$rc elapsed=${elapsed}s log=$stage_log" >&2
    return "$rc"
  fi
  echo "security-ci: stage $name: end elapsed=${elapsed}s log=$stage_log"
}

on_exit() {
  local code=$?
  if [ "$code" -ne 0 ] && [ -n "$last_stage" ]; then
    echo "security-ci: FAILED at stage $last_stage (exit $code); log ${stage_log:-unknown}" >&2
  fi
}
trap on_exit EXIT

if [ -n "$build_dir" ]; then
  [ -d "$build_dir" ] || {
    echo "security-ci: no prepared build at $build_dir" >&2
    exit 1
  }
  stage verify-prepared-build python3 "$repo/scripts/security-fuzz-verify.py" \
    --build-dir "$build_dir"
fi

corpus_identity() {
  echo "security-ci: corpus identity against 46980d2"
  git -C "$repo" diff --exit-code 46980d2 -- tests/corpus
  if [ -n "$(git -C "$repo" status --short -- tests/corpus)" ]; then
    echo "security-ci: tests/corpus has untracked or staged changes" >&2
    git -C "$repo" status --short -- tests/corpus >&2
    return 1
  fi
}

cabi_artifact() {
  (cd "$repo" && lake build lexpatCAbi)
}

stage corpus-identity corpus_identity
stage cabi-artifact cabi_artifact

# `lake build` above can relink the shipped artifact or regenerate Lean C that
# the prepared manifest covers. Re-check before any target or parser runs; a
# build that no longer matches its manifest stops here, before CVE or fuzz.
if [ -n "$build_dir" ]; then
  stage verify-prepared-build-after-artifact \
    python3 "$repo/scripts/security-fuzz-verify.py" --build-dir "$build_dir"
fi

if [ -z "$build_dir" ]; then
  stage fuzz-build bash "$repo/scripts/security-fuzz-build.sh" --out "$out/fuzz-build"
  build_dir="$out/fuzz-build"
  stage verify-fresh-build python3 "$repo/scripts/security-fuzz-verify.py" \
    --build-dir "$build_dir"
fi

stage cve python3 "$repo/tests/security-cve.py" --no-build
stage fixed-differential bash "$repo/tests/security-differential-fixed.sh" \
  --out "$out/diff-fixed"
stage oom-sanitized bash "$repo/tests/security-oom-sanitized.sh" \
  --out "$out/oom-sanitized"
stage fuzz-smoke bash "$repo/tests/security-fuzz-smoke.sh" \
  --out "$out/fuzz-smoke" --build-dir "$build_dir"

echo "security-ci: PASS (stage logs in $out/stages)"
