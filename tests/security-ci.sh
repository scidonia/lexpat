#!/usr/bin/env bash
# The bounded security step: CVE checks, fixed differential replay, injected
# shim OOM, benchmark smoke and the four-target libFuzzer smoke.
#
#   tests/security-ci.sh --out <absolute-directory>
#
# The caller applies the hard wall cap around this whole command (including
# `nix develop` startup). Every stage writes its log under --out; the script
# stops at the first failure.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out=""

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
case "$out" in
  /*) ;;
  *)
    echo "security-ci: --out must be an absolute path" >&2
    exit 2
    ;;
esac
mkdir -p "$out"

echo "security-ci: corpus identity against 46980d2"
git -C "$repo" diff --exit-code 46980d2 -- tests/corpus
if [ -n "$(git -C "$repo" status --short -- tests/corpus)" ]; then
  echo "security-ci: tests/corpus has untracked or staged changes" >&2
  git -C "$repo" status --short -- tests/corpus >&2
  exit 1
fi

echo "security-ci: C ABI artifact"
(cd "$repo" && lake build lexpatCAbi)

echo "security-ci: fuzz build"
bash "$repo/scripts/security-fuzz-build.sh" --out "$out/fuzz-build" \
  2>&1 | tee "$out/fuzz-build.log"

echo "security-ci: CVE-class corpus"
python3 "$repo/tests/security-cve.py" --no-build 2>&1 | tee "$out/cve.log"

echo "security-ci: fixed differential exceptions"
bash "$repo/tests/security-differential-fixed.sh" --out "$out/diff-fixed" \
  2>&1 | tee "$out/diff-fixed.log"

echo "security-ci: injected shim allocation failures"
bash "$repo/tests/security-oom-sanitized.sh" --out "$out/oom-sanitized" \
  2>&1 | tee "$out/oom-sanitized.log"

echo "security-ci: scaling benchmark smoke"
bash "$repo/tests/security-benchmark.sh" --suite ci --out "$out/benchmark-ci" \
  2>&1 | tee "$out/benchmark-ci.log"

echo "security-ci: bounded fuzz smoke"
bash "$repo/tests/security-fuzz-smoke.sh" --out "$out/fuzz-smoke" \
  --build-dir "$out/fuzz-build" 2>&1 | tee "$out/fuzz-smoke.log"

echo "security-ci: PASS (logs in $out)"
