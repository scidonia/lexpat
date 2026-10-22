#!/usr/bin/env bash
# Paired whole-input and chunked benchmark for the lexpat C ABI against libexpat.
#
#   tests/performance-benchmark.sh --candidate-source ABS --out ABS \
#       --phase text|full|smoke --samples N --warmups N --chunk 4096 \
#       [--base-source ABS] [--enforce]
#
# `--base-source` and `--enforce` are required together for the text and full
# threshold phases. `smoke` accepts only a candidate source, performs the same
# corpus, handler and oracle preflight, and reports a 3-sample diagnostic
# without enforcing host-sensitive speed thresholds.
#
# Each source is built with `lake build lexpatCAbi` in the pinned dev shell this
# script runs in. Every measured process loads exactly one lexpat artifact plus
# the pinned libexpat oracle through separate `dlopen(RTLD_NOW | RTLD_LOCAL)`
# handles; base and candidate artifacts are never loaded into one process.
# Trials interleave base, oracle, candidate and oracle again, rotating the side
# and mode order, so a reading is never a single uninterrupted block.
#
# The driver records raw per-sample nanoseconds per document. `compare.py`
# turns those samples into ratio rows, checks the drift sentinels and appends
# the enforced assertions. Timed parse region, corpus hashes, artifact hashes,
# compiler identity and CPU facts are written beside the samples under --out.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
manifest="$repo/tests/performance/manifest.json"
driver_src="$repo/tests/performance-benchmark.c"
compare="$repo/tests/performance/compare.py"

die() {
  echo "performance-benchmark: $*" >&2
  exit 2
}

candidate_source=""
base_source=""
out=""
phase=""
samples=""
warmups=""
chunk="4096"
enforce=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --candidate-source)
      candidate_source="${2:-}"
      [ -n "$candidate_source" ] || die "--candidate-source needs a path"
      shift 2
      ;;
    --base-source)
      base_source="${2:-}"
      [ -n "$base_source" ] || die "--base-source needs a path"
      shift 2
      ;;
    --out)
      out="${2:-}"
      [ -n "$out" ] || die "--out needs a path"
      shift 2
      ;;
    --phase)
      phase="${2:-}"
      shift 2
      ;;
    --samples)
      samples="${2:-}"
      shift 2
      ;;
    --warmups)
      warmups="${2:-}"
      shift 2
      ;;
    --chunk)
      chunk="${2:-}"
      shift 2
      ;;
    --enforce)
      enforce=1
      shift
      ;;
    *)
      die "unknown argument $1"
      ;;
  esac
done

case "$phase" in
  text | full)
    [ -n "$base_source" ] || die "--phase $phase requires --base-source"
    [ "$enforce" -eq 1 ] || die "--phase $phase requires --enforce"
    ;;
  smoke)
    [ -z "$base_source" ] || die "--phase smoke takes no --base-source"
    [ "$enforce" -eq 0 ] || die "--phase smoke does not enforce thresholds"
    ;;
  *)
    die "--phase must be text, full or smoke"
    ;;
esac

[ -n "$candidate_source" ] || die "--candidate-source is required"
[ -n "$out" ] || die "--out is required"

case "$candidate_source" in
  /*) ;;
  *) die "--candidate-source must be an absolute path" ;;
esac
case "$out" in
  /*) ;;
  *) die "--out must be an absolute path" ;;
esac
if [ -n "$base_source" ]; then
  case "$base_source" in
    /*) ;;
    *) die "--base-source must be an absolute path" ;;
  esac
fi

[ -d "$candidate_source" ] || die "no such source directory: $candidate_source"
[ -f "$candidate_source/lakefile.lean" ] || die "$candidate_source is not a lexpat source tree"
if [ -n "$base_source" ]; then
  [ -d "$base_source" ] || die "no such base source directory: $base_source"
  [ -f "$base_source/lakefile.lean" ] || die "$base_source is not a lexpat source tree"
fi
[ -f "$manifest" ] || die "missing performance manifest: $manifest"
[ -f "$driver_src" ] || die "missing performance driver: $driver_src"

if [ -z "$samples" ]; then
  if [ "$phase" = "smoke" ]; then samples=3; else samples=9; fi
fi
if [ -z "$warmups" ]; then
  if [ "$phase" = "smoke" ]; then warmups=1; else warmups=3; fi
fi
case "$samples$warmups$chunk" in
  *[!0-9]*) die "--samples, --warmups and --chunk take non-negative integers" ;;
esac

mkdir -p "$out"
if [ -n "$(ls -A "$out")" ]; then
  die "--out must be empty: $out"
fi

raw="$out/raw.csv"
observations="$out/observations"
schedule="$out/schedule.txt"
provenance="$out/provenance.txt"
logs="$out/logs"
mkdir -p "$observations" "$logs"
: >"$schedule"
: >"$provenance"

record() { printf '%s\t%s\n' "$1" "$2" >>"$provenance"; }

# ---------------------------------------------------------------- affinity --
affinity_ok=0
cpu=""
if command -v taskset >/dev/null 2>&1; then
  for candidate in $(seq 0 $(( $(nproc) - 1 ))); do
    if taskset -c "$candidate" true >/dev/null 2>&1; then
      cpu="$candidate"
      affinity_ok=1
      break
    fi
  done
fi
if [ "$affinity_ok" -eq 1 ]; then
  record affinity "cpu=$cpu mask=$(taskset -pc $$ 2>/dev/null | sed 's/^[^:]*: //' || true)"
  pin=(taskset -c "$cpu")
else
  record affinity "unavailable (taskset missing or no usable CPU); thresholds not accepted"
  pin=()
fi

# -------------------------------------------------------------- provenance --
record candidate_source "$candidate_source"
record base_source "${base_source:-none}"
record phase "$phase"
record samples "$samples"
record warmups "$warmups"
record chunk "$chunk"
record enforce "$enforce"
record uname "$(uname -srm)"
record host "$(uname -n)"
record cpu_model "$(grep -m1 'model name' /proc/cpuinfo | sed 's/^[^:]*: //')"
record nproc "$(nproc)"
record loadavg_start "$(cut -d' ' -f1-3 /proc/loadavg)"
if [ -n "$cpu" ] && [ -r "/sys/devices/system/cpu/cpu$cpu/cpufreq/scaling_governor" ]; then
  record governor "cpu$cpu=$(cat "/sys/devices/system/cpu/cpu$cpu/cpufreq/scaling_governor")"
else
  record governor "unavailable"
fi
record cc_path "$(command -v "${CC:-cc}")"
record cc_version "$("${CC:-cc}" --version | head -1)"
record cc_target "$("${CC:-cc}" -dumpmachine)"
record lean_version "$(lean --version | head -1)"
record lake_version "$(lake --version 2>&1 | head -1)"
record clang_version "$(clang --version | head -1)"
record pkg_config_expat "$(pkg-config --modversion expat)"
record python_version "$(python3 --version 2>&1)"
record nix_version "$(nix --version 2>/dev/null | head -1 || echo unavailable)"
record flake_lock_sha256 "$(sha256sum "$repo/flake.lock" | cut -d' ' -f1)"
record driver_source "$driver_src"
record driver_sha256 "$(sha256sum "$driver_src" | cut -d' ' -f1)"
record manifest_sha256 "$(sha256sum "$manifest" | cut -d' ' -f1)"

expat_libdir="$(pkg-config --variable=libdir expat)"
expat_lib="$expat_libdir/libexpat.so"
[ -f "$expat_lib" ] || die "no pinned libexpat at $expat_lib"
record expat_path "$expat_lib"
record expat_sha256 "$(sha256sum "$expat_lib" | cut -d' ' -f1)"

# ------------------------------------------------------- corpus and driver --
(
  cd "$repo/tests/performance/corpus"
  sha256sum ./*.xml | sed 's#\./##' | sort
) >"$out/corpus.sha256"
record corpus_sha256 "$(sha256sum "$out/corpus.sha256" | cut -d' ' -f1)"

driver="$out/performance-benchmark"
# shellcheck disable=SC2086
"${CC:-cc}" -O2 -std=c11 -Wall -Wextra -Werror -o "$driver" "$driver_src" -ldl \
  >"$logs/driver-build.log" 2>&1 || die "driver build failed (see $logs/driver-build.log)"
record driver_binary "$driver"
record driver_binary_sha256 "$(sha256sum "$driver" | cut -d' ' -f1)"
record driver_cflags "-O2 -std=c11 -Wall -Wextra -Werror -ldl"

oracle_version="$("$driver" version --lib "$expat_lib" --side expat \
  --file "$repo/tests/performance/corpus/small.xml" 2>/dev/null)"
record oracle_version "$(echo "$oracle_version" | tr '\n' ' ')"

# ------------------------------------------------------------ source builds --
build_source() {
  local src="$1"
  local label="$2"
  local log="$logs/build-$label.log"
  ( cd "$src" && lake build lexpatCAbi ) >"$log" 2>&1 ||
    die "lake build lexpatCAbi failed for $label (see $log)"
  local so="$src/.lake/build/lib/liblexpat.so.1"
  [ -f "$so" ] || die "no artifact at $so after building $label"
  printf '%s\n' "$so"
}

source_manifest() {
  local src="$1"
  local target="$2"
  (
    cd "$src"
    {
      find LexPat -name '*.lean' -type f
      printf '%s\n' LexPat.lean lakefile.lean lake-manifest.json lean-toolchain \
        flake.nix flake.lock cabi/expat.c cabi/exports.map include/expat.h \
        scripts/build-c-abi.sh
    } | sort | while IFS= read -r path; do
      if [ -f "$path" ]; then
        sha256sum "$path"
      else
        printf 'missing\t%s\n' "$path"
      fi
    done
  ) >"$target"
  printf '%s\n' "$(sha256sum "$target" | cut -d' ' -f1)"
}

candidate_so="$(build_source "$candidate_source" candidate)"
record candidate_artifact "$candidate_so"
record candidate_artifact_sha256 "$(sha256sum "$candidate_so" | cut -d' ' -f1)"
record candidate_source_manifest "$(mkdir -p "$out/source"; source_manifest "$candidate_source" "$out/source/candidate.sha256")"
(cd "$candidate_source" && git rev-parse HEAD 2>/dev/null || true) >"$out/source/candidate-head.txt"
record candidate_head "$(cat "$out/source/candidate-head.txt")"
record candidate_head_status "$(cd "$candidate_source" && git status --porcelain 2>/dev/null | wc -l) changed paths"

base_so=""
if [ -n "$base_source" ]; then
  base_so="$(build_source "$base_source" base)"
  record base_artifact "$base_so"
  record base_artifact_sha256 "$(sha256sum "$base_so" | cut -d' ' -f1)"
  record base_source_manifest "$(source_manifest "$base_source" "$out/source/base.sha256")"
  (cd "$base_source" && git rev-parse HEAD 2>/dev/null || true) >"$out/source/base-head.txt"
  record base_head "$(cat "$out/source/base-head.txt")"
fi

# ---------------------------------------------------------------- preflight --
all_cases() {
  printf '%s\n' small text-512k elements-10k attrs-1000 depth-256 mixed utf16le latin1
}

cases_for_phase() {
  case "$phase" in
    text) printf '%s\n' text-512k ;;
    *) printf '%s\n' small text-512k elements-10k attrs-1000 depth-256 mixed utf16le latin1 ;;
  esac
}

sides_for_run() {
  if [ -n "$base_source" ]; then
    printf '%s\n' base candidate expat
  else
    printf '%s\n' candidate expat
  fi
}

corpus="$repo/tests/performance/corpus"
observe() {
  local side="$1" lib="$2" case="$3" mode="$4" suffix="$5"
  "${pin[@]}" "$driver" observe --side "$side" --lib "$lib" --case "$case" \
    --file "$corpus/$case.xml" --mode "$mode" --chunk "$chunk" \
    >"$observations/$case.$side$suffix.jsonl" 2>"$logs/observe-$case-$side$suffix.log" ||
    die "preflight parse failed for $case/$side/$mode (see $logs/observe-$case-$side$suffix.log)"
}

echo "performance-benchmark: preflight ($phase)" >&2
for case in $(all_cases); do
  for side in $(sides_for_run); do
    case "$side" in
      base) lib="$base_so" ;;
      candidate) lib="$candidate_so" ;;
      expat) lib="$expat_lib" ;;
    esac
    observe "$side" "$lib" "$case" whole ""
    observe "$side" "$lib" "$case" chunked ".chunked"
  done
done
python3 "$compare" --manifest "$manifest" --verify --observations "$observations" \
  --sides "$(sides_for_run | paste -sd, -)" ||
  die "preflight observation does not match the declared expectations"

# -------------------------------------------------------------- calibration --
calibrate_reps() {
  local case="$1"
  local mode="$2"
  local line reps
  "${pin[@]}" "$driver" calibrate --side expat --lib "$expat_lib" --case "$case" \
    --file "$corpus/$case.xml" --mode "$mode" --chunk "$chunk" \
    --target-ms 8 --cap 128 >"$logs/calibrate-$case-$mode.txt" 2>&1 ||
    die "calibration failed for $case/$mode"
  reps="$(sed -n 's/.*reps=\([0-9]*\).*/\1/p' "$logs/calibrate-$case-$mode.txt")"
  [ -n "$reps" ] || die "calibration produced no repetition count for $case/$mode"
  line="$(cat "$logs/calibrate-$case-$mode.txt")"
  printf '%s\n' "$line" >>"$schedule"
  printf '%s\n' "$reps"
}

expectations() {
  python3 "$compare" --manifest "$manifest" --emit-expectations --case "$1"
}

measure_once() {
  local side="$1"
  local lib="$2"
  local case="$3"
  local mode="$4"
  local trial="$5"
  local reps="$6"
  local header="$7"
  local -a flags
  flags=($(expectations "$case"))
  local -a header_flag=()
  if [ "$header" = "1" ]; then header_flag=(--header); fi
  "${pin[@]}" "$driver" measure --side "$side" --lib "$lib" --case "$case" \
    --file "$corpus/$case.xml" --mode "$mode" --chunk "$chunk" \
    --warmups "$warmups" --samples 1 --sample-start "$trial" --reps "$reps" \
    "${header_flag[@]}" "${flags[@]}" >>"$raw" 2>>"$logs/measure.log" ||
    die "measured trial failed for $case/$mode/$side (see $logs/measure.log)"
}

lib_for() {
  case "$1" in
    base) printf '%s\n' "$base_so" ;;
    candidate) printf '%s\n' "$candidate_so" ;;
    expat) printf '%s\n' "$expat_lib" ;;
    *) die "unknown side $1" ;;
  esac
}

echo "performance-benchmark: calibration" >&2
declare -A reps_table=()
# The drift control is the small document under every phase, so its repetition
# count is always calibrated even when the phase measures another case only.
for case in $(printf '%s\n' $(cases_for_phase) small | sort -u); do
  for mode in whole chunked; do
    reps_table["$case/$mode"]="$(calibrate_reps "$case" "$mode")"
  done
done

# ---------------------------------------------------------------- controls --
echo "performance-benchmark: control before" >&2
: >"$raw"
# The first row of raw.csv needs one header; measure_once emits it once.
header_written=0
control_measure() {
  local side="$1" case_id="$2" trial="$3"
  local reps="${reps_table[small/whole]}"
  local -a flags
  flags=($(expectations small))
  local -a header_flag=()
  if [ "$header_written" -eq 0 ]; then
    header_flag=(--header)
    header_written=1
  fi
  "${pin[@]}" "$driver" measure --side "$side" --lib "$(lib_for "$side")" \
    --case "$case_id" --file "$corpus/small.xml" --mode whole --chunk "$chunk" \
    --warmups "$warmups" --samples 5 --reps "$reps" \
    "${header_flag[@]}" "${flags[@]}" >>"$raw" 2>>"$logs/measure.log" ||
    die "control run failed for $side (see $logs/measure.log)"
}

for side in $(sides_for_run); do
  control_measure "$side" control-before 1
done

echo "performance-benchmark: measuring ($samples trials)" >&2
for trial in $(seq 1 "$samples"); do
  for case in $(cases_for_phase); do
    if [ $((trial % 2)) -eq 1 ]; then
      side_order=(base candidate)
      mode_order=(whole chunked)
    else
      side_order=(candidate base)
      mode_order=(chunked whole)
    fi
    for side in "${side_order[@]}"; do
      if [ "$side" = "base" ] && [ -z "$base_source" ]; then continue; fi
      for mode in "${mode_order[@]}"; do
        measure_once "$side" "$(lib_for "$side")" "$case" "$mode" "$trial" \
          "${reps_table["$case/$mode"]}" 0
        measure_once expat "$expat_lib" "$case" "$mode" "$trial" \
          "${reps_table["$case/$mode"]}" 0
      done
    done
  done
done

echo "performance-benchmark: control after" >&2
for side in $(sides_for_run); do
  control_measure "$side" control-after 1
done
record loadavg_end "$(cut -d' ' -f1-3 /proc/loadavg)"
record raw_sha256 "$(sha256sum "$raw" | cut -d' ' -f1)"
record schedule_sha256 "$(sha256sum "$schedule" | cut -d' ' -f1)"
{
  echo "chunk=$chunk"
  for key in "${!reps_table[@]}"; do
    echo "reps $key ${reps_table[$key]}"
  done
} | sort >>"$schedule"

# ------------------------------------------------------------------ results --
echo "performance-benchmark: comparing" >&2
set +e
python3 "$compare" --manifest "$manifest" --results --raw "$raw" \
  --out "$out" --phase "$phase" --affinity-ok "$affinity_ok" \
  --require-samples "$samples" \
  $( [ "$enforce" -eq 1 ] && printf '%s' --enforce ) >"$out/report.stdout" 2>"$out/report.stderr"
status=$?
set -e
cat "$out/report.stdout"
cat "$out/report.stderr" >&2
echo "performance-benchmark: report $out/report.md; ratios $out/ratios.csv" >&2
exit "$status"
