#!/usr/bin/env bash
# Scaling and denial-of-service evidence for the bounded C ABI.
#
#   tests/security-benchmark.sh --suite ci --out <absolute-directory>
#   tests/security-benchmark.sh --pair \
#       --base-source DIR --candidate-source DIR --base SHA \
#       --candidate-tree TREE --path-blob-manifest FILE \
#       --manifest-sha256 SHA --samples 7 --out <absolute-directory>
#
# The driver schedules one case, drift control or limit-adjacent input per
# entry and measures each entry in its own forked child, so `rss_kb` is that
# entry's resident peak. Within a case, one-shot and chunked trials alternate.
#
# `ci` builds the driver against the current artifact, runs three trials per
# case and applies the broader 3.5 doubling sentinel. `pair` builds the same
# driver against the extracted base and candidate sources and walks the plan
# once: for every entry it runs the base and candidate binaries back to back,
# alternating which side goes first, so base/candidate readings are
# interleaved rather than run as two complete suites. `pair` runs seven trials
# in the same session and applies the 2.75 doubling bound plus the 1.25
# candidate/base matched-size flag. Both modes fail on a drift-control shift
# above 15%. Machine, CPU, governor and load facts are recorded beside the
# pinned-CPU note. The CSV, report and identity arguments are written under
# --out.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mode=""
out=""
base_source=""
candidate_source=""
base_commit="46980d2"
candidate_tree=""
path_blob_manifest=""
manifest_sha256=""
samples=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --suite)
      mode="${2:-}"
      shift 2 || { echo "security-benchmark: --suite needs a value" >&2; exit 2; }
      ;;
    --pair)
      mode="pair"
      shift
      ;;
    --base-source)
      base_source="${2:-}"
      shift 2 || { echo "security-benchmark: --base-source needs a value" >&2; exit 2; }
      ;;
    --candidate-source)
      candidate_source="${2:-}"
      shift 2 || { echo "security-benchmark: --candidate-source needs a value" >&2; exit 2; }
      ;;
    --base)
      base_commit="${2:-}"
      shift 2 || { echo "security-benchmark: --base needs a value" >&2; exit 2; }
      ;;
    --candidate-tree)
      candidate_tree="${2:-}"
      shift 2 || { echo "security-benchmark: --candidate-tree needs a value" >&2; exit 2; }
      ;;
    --path-blob-manifest)
      path_blob_manifest="${2:-}"
      shift 2 || { echo "security-benchmark: --path-blob-manifest needs a value" >&2; exit 2; }
      ;;
    --manifest-sha256)
      manifest_sha256="${2:-}"
      shift 2 || { echo "security-benchmark: --manifest-sha256 needs a value" >&2; exit 2; }
      ;;
    --samples)
      samples="${2:-}"
      shift 2 || { echo "security-benchmark: --samples needs a value" >&2; exit 2; }
      ;;
    --out)
      out="${2:-}"
      shift 2 || { echo "security-benchmark: --out needs a value" >&2; exit 2; }
      ;;
    *)
      echo "security-benchmark: unknown option $1" >&2
      exit 2
      ;;
  esac
done

if [ -z "$mode" ] || [ -z "$out" ]; then
  echo "security-benchmark: --suite ci|--pair and --out are required" >&2
  exit 2
fi
case "$out" in
  /*) ;;
  *)
    echo "security-benchmark: --out must be an absolute path" >&2
    exit 2
    ;;
esac
mkdir -p "$out"

cc="${CC:-cc}"
lean_version="$(lean --version | head -n 1)"
toolchain="$("$cc" --version | head -n 1); $lean_version; expat $(pkg-config --modversion expat)"
toolchain="${toolchain//,/;}"
uname_note="$(uname -srm)"
cpu_model="$(awk -F': ' '/^model name/{print $2; exit}' /proc/cpuinfo 2>/dev/null \
  || true)"
cores="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo unknown)"
governor="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor \
  2>/dev/null || echo unknown)"
loadavg="$(awk '{print $1"/"$2"/"$3}' /proc/loadavg 2>/dev/null || echo unknown)"
pinner=()
pin_note="pinned=none"
if command -v taskset >/dev/null 2>&1 && taskset -c 0 true 2>/dev/null; then
  pinner=(taskset -c 0)
  pin_note="pinned=cpu0"
fi
flags="-O2 -std=c11 driver=$(sha256sum "$repo/tests/security-benchmark.c" | cut -d' ' -f1)"
flags="$flags $pin_note"
flags="$flags machine=$uname_note cpu=${cpu_model:-unknown} cores=$cores"
flags="$flags governor=$governor loadavg=$loadavg"
flags="${flags//,/;}"

build_binary() {
  local source="$1" side="$2"
  if [ ! -d "$source" ]; then
    echo "security-benchmark: missing source $source" >&2
    return 1
  fi
  (cd "$source" && lake build lexpatCAbi)
  "$cc" -std=c11 -O2 -Wall -Wextra -Werror \
    -I"$source/include" \
    "$repo/tests/security-benchmark.c" \
    -L"$source/.lake/build/lib" -llexpat \
    -Wl,-rpath,"$source/.lake/build/lib" -o "$out/benchmark-$side"
}

if [ "$mode" = "ci" ]; then
  (cd "$repo" && lake build lexpatCAbi)
  "$cc" -std=c11 -O2 -Wall -Wextra -Werror \
    -I"$repo/include" "$repo/tests/security-benchmark.c" \
    -L"$repo/.lake/build/lib" -llexpat \
    -Wl,-rpath,"$repo/.lake/build/lib" -o "$out/benchmark-candidate"
  "${pinner[@]}" "$out/benchmark-candidate" --suite ci --samples 3 --seed 46985 \
    --side candidate --base-commit "$base_commit" \
    --toolchain "$toolchain" --flags "$flags" \
    --csv "$out/candidate.csv" | tee "$out/run.log"
  python3 "$repo/tests/security/benchmark_compare.py" --ci \
    --candidate-csv "$out/candidate.csv" \
    --report "$out/report.txt"
  echo "security-benchmark: PASS (CI suite; logs in $out)"
  exit 0
fi

if [ -z "$base_source" ] || [ -z "$candidate_source" ] || [ -z "$candidate_tree" ] \
  || [ -z "$manifest_sha256" ]; then
  echo "security-benchmark: --pair needs --base-source, --candidate-source," \
    "--candidate-tree and --manifest-sha256" >&2
  exit 2
fi
if [ -z "$samples" ]; then
  samples=7
fi
if [ -z "$path_blob_manifest" ]; then
  echo "security-benchmark: --pair needs --path-blob-manifest" >&2
  exit 2
fi

build_binary "$base_source" base 2>&1 | tee "$out/base-build.log"
build_binary "$candidate_source" candidate 2>&1 | tee "$out/candidate-build.log"

# The plan is deterministic from the driver, the suite and the seed, so both
# binaries describe the same entries. Walk it once, running the two sides back
# to back and alternating which side goes first.
: >"$out/base.csv"
: >"$out/candidate.csv"
mapfile -t plan < <("$out/benchmark-candidate" --suite full --seed 46985 --plan)
if [ "${#plan[@]}" -eq 0 ]; then
  echo "security-benchmark: the driver produced an empty plan" >&2
  exit 1
fi
printf '%s\n' "${plan[@]}" >"$out/plan.txt"
: >"$out/interleave.log"
index=0
for _ in "${plan[@]}"; do
  if [ $((index % 2)) -eq 0 ]; then
    order=(base candidate)
  else
    order=(candidate base)
  fi
  for side in "${order[@]}"; do
    printf 'entry %s %s\n' "$index" "$side" >>"$out/interleave.log"
    "${pinner[@]}" "$out/benchmark-$side" --suite full --samples "$samples" \
      --seed 46985 --entry "$index" --side "$side" \
      --base-commit "$base_commit" --candidate-tree "$candidate_tree" \
      --manifest-sha256 "$manifest_sha256" \
      --toolchain "$toolchain" --flags "$flags" --csv "$out/$side.csv" \
      >>"$out/$side.log" 2>&1 || {
      echo "security-benchmark: $side entry $index failed" >&2
      exit 1
    }
  done
  index=$((index + 1))
done
printf 'interleaved %d entries (base/candidate order alternates per entry)\n' \
  "$index" | tee -a "$out/interleave.log"

python3 "$repo/tests/security/benchmark_compare.py" --pair \
  --base-csv "$out/base.csv" --candidate-csv "$out/candidate.csv" \
  --base "$base_commit" --candidate-tree "$candidate_tree" \
  --manifest-sha256 "$manifest_sha256" \
  --path-blob-manifest "$path_blob_manifest" \
  --candidate-source "$candidate_source" \
  --report "$out/report.txt"
echo "security-benchmark: PASS (paired full suite; logs in $out)"
