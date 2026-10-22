#!/usr/bin/env bash
# One recorded long libFuzzer campaign.
#
#   tests/security-fuzz-campaign.sh --target parser|cabi|diff|artifact \
#       --runs N --seed S --out <absolute-directory> [--build-dir DIR]
#
# Records the exact command, seed, requested and completed units, elapsed wall
# time, peak resident set size, the source revision and dirty-tree digest, the
# build manifest digest and the initial corpus digest under --out/run.json.
# A run that reaches its outer cap before the requested count, exits nonzero,
# or writes a crash/timeout artifact is reported as failed, never as a pass.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target=""
runs=""
seed=""
out=""
build_dir=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --target)
      target="${2:-}"
      shift 2 || { echo "campaign: --target needs a value" >&2; exit 2; }
      ;;
    --runs)
      runs="${2:-}"
      shift 2 || { echo "campaign: --runs needs a value" >&2; exit 2; }
      ;;
    --seed)
      seed="${2:-}"
      shift 2 || { echo "campaign: --seed needs a value" >&2; exit 2; }
      ;;
    --out)
      out="${2:-}"
      shift 2 || { echo "campaign: --out needs a value" >&2; exit 2; }
      ;;
    --build-dir)
      build_dir="${2:-}"
      shift 2 || { echo "campaign: --build-dir needs a value" >&2; exit 2; }
      ;;
    *)
      echo "campaign: unknown option $1" >&2
      exit 2
      ;;
  esac
done

case "$target" in
  parser) binary=parser-fuzz; max_len=8192; seeds="$repo/tests/security/seeds/parser" ;;
  cabi) binary=cabi-fuzz; max_len=8192; seeds="$repo/tests/security/seeds/cabi" ;;
  diff) binary=differential-fuzz; max_len=4096; seeds="$repo/tests/security/seeds/diff" ;;
  artifact) binary=artifact-fuzz; max_len=4096; seeds="$repo/tests/security/seeds/cabi" ;;
  *)
    echo "campaign: --target must be parser, cabi, diff or artifact" >&2
    exit 2
    ;;
esac
case "$runs" in
  '' | *[!0-9]* | 0)
    echo "campaign: --runs must be a positive integer" >&2
    exit 2
    ;;
esac
case "$seed" in
  '' | *[!0-9]*)
    echo "campaign: --seed must be a non-negative integer" >&2
    exit 2
    ;;
esac
case "$out" in
  /*) ;;
  *)
    echo "campaign: --out must be an absolute path" >&2
    exit 2
    ;;
esac
mkdir -p "$out"

if [ -z "$build_dir" ]; then
  build_dir="$out/build"
  bash "$repo/scripts/security-fuzz-build.sh" --out "$build_dir"
fi
# Validate the prepared build before any target runs: a stale or mismatched
# build is refused here, not after a campaign has burned its budget.
python3 "$repo/scripts/security-fuzz-verify.py" --build-dir "$build_dir" || {
  echo "campaign: prepared build refused" >&2
  exit 1
}

corpus="$out/corpus"
artifacts="$out/artifacts"
mkdir -p "$corpus" "$artifacts"
cp -R "$seeds/." "$corpus/"
corpus_digest="$(cd "$corpus" && find . -type f -print0 | sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)"
initial_files="$(find "$corpus" -type f | wc -l)"

export ASAN_OPTIONS="detect_leaks=0:quarantine_size_mb=16:abort_on_error=1"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1"

start_ns="$(date +%s%N)"
status=0
/usr/bin/time -v "$build_dir/$binary" \
  -runs="$runs" -max_len="$max_len" -timeout=2 -rss_limit_mb=2048 \
  -seed="$seed" -print_final_stats=1 \
  -artifact_prefix="$artifacts/" "$corpus" \
  >"$out/stdout.log" 2>"$out/stderr.log" || status=$?
end_ns="$(date +%s%N)"
elapsed_ms=$(((end_ns - start_ns) / 1000000))

completed="$(grep -o 'stat::number_of_executed_units: [0-9]*' "$out/stderr.log" \
  | tail -n 1 | awk '{print $2}')"
if [ -z "$completed" ]; then
  completed=0
fi
rss_kb="$(grep 'Maximum resident set size (kbytes):' "$out/stderr.log" \
  | tail -n 1 | grep -o '[0-9]*$')"
if [ -z "$rss_kb" ]; then
  rss_kb=0
fi
coverage="$(grep -o 'stat::number_of_executed_units: [0-9]*\|cov: [0-9]*\|ft: [0-9]*' "$out/stderr.log" | tail -n 3 | tr '\n' ' ')"
artifact_count="$(find "$artifacts" -type f | wc -l)"
build_manifest="$(sha256sum "$build_dir/source-manifest.sha256" | cut -d' ' -f1)"
build_json="$(sha256sum "$build_dir/build.json" | cut -d' ' -f1)"
targets_manifest="$(sha256sum "$build_dir/targets.sha256" | cut -d' ' -f1)"

python3 - "$out/run.json" "$target" "$binary" "$runs" "$completed" "$seed" \
  "$max_len" \
  "$build_dir/$binary -runs=$runs -max_len=$max_len -timeout=2 -rss_limit_mb=2048 -seed=$seed -print_final_stats=1 -artifact_prefix=$artifacts/ $corpus" \
  "$elapsed_ms" "$rss_kb" "$status" "$artifact_count" "$coverage" \
  "$(git -C "$repo" rev-parse HEAD)" \
  "$(git -C "$repo" status --porcelain | sha256sum | cut -d' ' -f1)" \
  "$build_manifest" "$build_json" "$targets_manifest" "$corpus_digest" \
  "$initial_files" <<'PY'
import json
import sys

(out, target, binary, runs, completed, seed, max_len, command, elapsed, rss,
 status, artifacts, coverage, revision, dirty, build_manifest, build_json,
 targets_manifest, corpus_digest, files) = sys.argv[1:]
row = {
    "format": 1,
    "target": target,
    "binary": binary,
    "runs_requested": int(runs),
    "runs_completed": int(completed),
    "seed": int(seed),
    "max_len": int(max_len),
    "command": command,
    "elapsed_ms": int(elapsed),
    "peak_rss_kb": int(rss),
    "exit_status": int(status),
    "artifacts": int(artifacts),
    "coverage_tail": coverage.strip(),
    "revision": revision,
    "dirty_digest": dirty,
    "build_manifest_sha256": build_manifest,
    "build_json_sha256": build_json,
    "targets_manifest_sha256": targets_manifest,
    "initial_corpus_digest": corpus_digest,
    "initial_corpus_files": int(files),
}
with open(out, "w", encoding="utf-8") as handle:
    json.dump(row, handle, indent=2)
print(json.dumps(row, indent=2))
PY

if [ "$status" -ne 0 ]; then
  echo "campaign: $target exited $status; see $out/stderr.log" >&2
  exit 1
fi
if [ "$artifact_count" -ne 0 ]; then
  echo "campaign: $target wrote $artifact_count crash/timeout artifacts" >&2
  find "$artifacts" -type f >&2
  exit 1
fi
if [ "$completed" -lt "$runs" ]; then
  echo "campaign: INCOMPLETE $target: $completed of $runs units" >&2
  exit 1
fi
echo "campaign: PASS $target completed $completed units in ${elapsed_ms}ms (RSS ${rss_kb} KiB)"
