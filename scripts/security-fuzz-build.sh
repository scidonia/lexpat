#!/usr/bin/env bash
# Build the libFuzzer security targets from the current source tree.
#
#   scripts/security-fuzz-build.sh --out <absolute-directory>
#
# Three build shapes answer different questions:
#
#   * parser-fuzz and cabi-fuzz compile the generated Lean C modules and
#     `cabi/expat.c` with Clang's coverage + ASan/UBSan instrumentation and
#     link them in. They observe the candidate's own instructions.
#   * differential-fuzz links only the harness and the libFuzzer runtime. The
#     same instrumented objects are also linked into `liblexpat-diff.so`, and
#     the fuzzer loads that candidate *and* the pinned, uninstrumented
#     `libexpat.so.1` with `dlopen(..., RTLD_NOW | RTLD_LOCAL)`, calling each
#     through its own `dlsym` table. Neither parser is linked into the
#     differential executable, so no `XML_*` symbol is resolved at link time.
#     The candidate library is ASan/UBSan/coverage-instrumented; its sanitizer
#     references are resolved from the static runtime that the ASan fuzzer
#     executable already carries, which is why the library is linked without
#     `--no-undefined`.
#   * artifact-fuzz links the C ABI harness to the shipped
#     `.lake/build/lib/liblexpat.so.1` with only the harness instrumented. Its
#     library coverage is absent by construction; it is a loader/client smoke.
#
# The differential replay binary is unsanitized and loads the shipped candidate
# and the pinned oracle with the same two-table `dlopen` comparator. The build
# requires `pkg-config --modversion expat` to be exactly `2.8.5` and runs the
# replay's `--version` guard, which re-reads that identity and checks
# `XML_ExpatVersion()` and `XML_ExpatVersionInfo()` exactly. Everything is
# written under --out; no build output enters the checkout.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --out)
      if [ "$#" -lt 2 ]; then
        echo "security-fuzz-build: --out needs a directory" >&2
        exit 2
      fi
      out="$2"
      shift 2
      ;;
    *)
      echo "security-fuzz-build: unknown option $1" >&2
      exit 2
      ;;
  esac
done

if [ -z "$out" ]; then
  echo "security-fuzz-build: --out is required" >&2
  exit 2
fi
case "$out" in
  /*) ;;
  *)
    echo "security-fuzz-build: --out must be an absolute path" >&2
    exit 2
    ;;
esac

mkdir -p "$out/obj"
work="$out/obj"

# The oracle is resolved from this pkg-config, so an exact match is a
# prerequisite for every comparison below. A near match such as 2.8.50 is a
# failure, not an acceptable oracle.
pkg_version="$(pkg-config --modversion expat)"
if [ "$pkg_version" != "2.8.5" ]; then
  echo "security-fuzz-build: pkg-config --modversion expat is" \
    "\"$pkg_version\", not exactly \"2.8.5\"" >&2
  exit 1
fi

if command -v lake >/dev/null 2>&1; then
  (cd "$repo" && lake build)
  (cd "$repo" && lake build FuzzParser)
else
  (cd "$repo" && nix develop -c lake build)
  (cd "$repo" && nix develop -c lake build FuzzParser)
fi

clang="${CLANG:-clang}"
lean_libdir="$(lean --print-libdir)"
lean_include="$(dirname "$(dirname "$lean_libdir")")/include"
if [ ! -f "$lean_include/lean/lean.h" ]; then
  echo "security-fuzz-build: lean.h not found under $lean_include" >&2
  exit 1
fi
if ! "$clang" --version | head -n 1 | grep -q 'clang version 21\.1\.8'; then
  echo "security-fuzz-build: expected the pinned Clang 21.1.8" >&2
  "$clang" --version >&2
  exit 1
fi

sources=()
while IFS= read -r source; do
  sources+=("$source")
done < <(
  {
    find "$repo/.lake/build/ir/LexPat" -name '*.c' -not -path '*/Exe/*'
    printf '%s\n' "$repo/.lake/build/ir/LexPat.c"
    printf '%s\n' "$repo/.lake/build/ir/tests/FuzzParser.c"
    printf '%s\n' "$repo/cabi/expat.c"
  } | sort
)
if [ "${#sources[@]}" -lt 9 ]; then
  echo "security-fuzz-build: only ${#sources[@]} generated sources found" >&2
  exit 1
fi

objects=()
index=0
for source in "${sources[@]}"; do
  object="$work/module-$(printf '%03d' "$index").o"
  index=$((index + 1))
  "$clang" -std=gnu11 -O1 -g -fno-omit-frame-pointer \
    -fsanitize=fuzzer-no-link,address,undefined \
    -DLEAN_EXPORTING -fPIC \
    -I"$repo/include" -I"$lean_include" \
    -c "$source" -o "$object"
  objects+=("$object")
done

sanitize=(-fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer)
lean_link=(-L"$lean_libdir" -lleanshared -pthread -Wl,-rpath,"$lean_libdir")
oracle="$(pkg-config --variable=libdir expat)/libexpat.so.1"
if [ ! -e "$oracle" ]; then
  echo "security-fuzz-build: pinned oracle not found at $oracle" >&2
  exit 1
fi
oracle_define="-DLEX_DEFAULT_ORACLE=\"$oracle\""
candidate_diff="$out/liblexpat-diff.so"

# Instrumented candidate shared object for the differential target. It reuses
# the same coverage/ASan/UBSan objects as the directly linked targets; the
# sanitizer runtime is supplied by the fuzzer executable that `dlopen`s it, so
# the link intentionally does not pass `--no-undefined`.
"$clang" -shared -o "$candidate_diff" "${objects[@]}" \
  -L"$lean_libdir" -lleanshared -pthread \
  -Wl,-soname,liblexpat.so.1 \
  -Wl,-rpath,"$lean_libdir" \
  -Wl,--version-script,"$repo/cabi/exports.map"
candidate_define="-DLEX_DEFAULT_CANDIDATE=\"$candidate_diff\""

# Pure Lean parser target.
"$clang" -std=c11 -O1 -g "${sanitize[@]}" \
  -I"$lean_include" \
  "$repo/tests/security/parser-fuzz.c" "${objects[@]}" \
  "${lean_link[@]}" -o "$out/parser-fuzz"

# Instrumented generated-C + shim C ABI target.
"$clang" -std=c11 -O1 -g "${sanitize[@]}" \
  -I"$repo/include" \
  "$repo/tests/security/cabi-fuzz.c" "${objects[@]}" \
  "${lean_link[@]}" -o "$out/cabi-fuzz"

# Differential target: harness and libFuzzer runtime only. The candidate and
# the oracle are both loaded with dlopen at fuzz time.
"$clang" -std=c11 -O1 -g "${sanitize[@]}" -DLEX_FUZZ_TARGET \
  "$oracle_define" "$candidate_define" -I"$repo/include" \
  "$repo/tests/security/differential.c" -ldl -o "$out/differential-fuzz"

# Unsanitized replay comparator; loads the shipped candidate and the oracle
# with the same two-table dlopen comparator.
"$clang" -std=c11 -O2 -g -Wall -Wextra -Werror \
  "$oracle_define" -DLEX_DEFAULT_CANDIDATE=\"$repo/.lake/build/lib/liblexpat.so.1\" \
  -I"$repo/include" \
  "$repo/tests/security/differential.c" -ldl -o "$out/differential-replay"

# The exact oracle guard runs before the fuzz targets are used: pkg-config was
# checked above, and `--version` checks XML_ExpatVersion and
# XML_ExpatVersionInfo exactly.
"$out/differential-replay" --version >"$out/differential-oracle.txt"

# Shipped artifact: loader/client smoke with harness-only instrumentation.
"$clang" -std=c11 -O1 -g "${sanitize[@]}" \
  -I"$repo/include" \
  "$repo/tests/security/cabi-fuzz.c" \
  -L"$repo/.lake/build/lib" -llexpat \
  -Wl,-rpath,"$repo/.lake/build/lib" -o "$out/artifact-fuzz"

# Record the environment and the exact inputs of this build.
source_manifest="$out/source-manifest.sha256"
: >"$source_manifest"
{
  for source in "${sources[@]}"; do
    sha256sum -- "$source"
  done
  sha256sum -- "$repo/tests/security/parser-fuzz.c" \
    "$repo/tests/security/cabi-fuzz.c" \
    "$repo/tests/security/differential.c" \
    "$repo/tests/FuzzParser.lean" \
    "$repo/scripts/security-fuzz-build.sh"
} >>"$source_manifest"

{
  printf '{\n'
  printf '  "format": 1,\n'
  printf '  "revision": "%s",\n' "$(git -C "$repo" rev-parse HEAD)"
  printf '  "dirty": "%s",\n' \
    "$(git -C "$repo" status --porcelain | sha256sum | cut -d' ' -f1)"
  printf '  "clang": "%s",\n' "$("$clang" --version | head -n 1)"
  printf '  "lean": "%s",\n' "$(lean --version | head -n 1)"
  printf '  "expat": "%s",\n' "$(pkg-config --modversion expat)"
  printf '  "source_manifest_sha256": "%s",\n' \
    "$(sha256sum "$source_manifest" | cut -d' ' -f1)"
  printf '  "instrumented_sources": %s,\n' "${#sources[@]}"
  printf '  "differential_topology": "dlopen RTLD_NOW|RTLD_LOCAL candidate and oracle; separate dlsym tables; neither parser linked into the fuzzer",\n'
  printf '  "differential_candidate": "liblexpat-diff.so",\n'
  printf '  "differential_candidate_instrumentation": "coverage+ASan+UBSan; runtime symbols resolved from the fuzzer executable",\n'
  printf '  "differential_oracle": "%s",\n' "$oracle"
  printf '  "artifact_coverage": "absent: only the harness is instrumented"\n'
  printf '}\n'
} >"$out/build.json"

echo "security-fuzz-build: wrote parser-fuzz, cabi-fuzz, artifact-fuzz,"
echo "security-fuzz-build: liblexpat-diff.so, differential-fuzz and"
echo "security-fuzz-build: differential-replay under $out"
