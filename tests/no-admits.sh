#!/usr/bin/env bash
# Reject admitted goals and non-total definitions in the Lean sources.
#
# Scope: every `.lean` file under `LexPat/` plus the top-level `LexPat.lean`
# (the library, the proofs and the demonstration executable) and the test-only
# `tests/FuzzParser.lean` entry point. The check is textual and deliberately
# strict: it also rejects these words in comments, so a source cannot discuss an
# escape hatch it does not use. An affirmative control injects `sorry` into a
# temporary copy and requires the same scanner to catch it, so a scanner that
# matches nothing cannot pass.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

mapfile -t files < <(find "$repo/LexPat" -type f -name '*.lean' | sort)
files+=("$repo/LexPat.lean" "$repo/tests/FuzzParser.lean")

count=0
for file in "${files[@]}"; do
  if [ ! -f "$file" ]; then
    echo "no-admits: expected source file $file" >&2
    exit 1
  fi
  count=$((count + 1))
done
if [ "$count" -lt 6 ]; then
  echo "no-admits: only $count sources found; scope looks wrong" >&2
  exit 1
fi

scan() {
  # Word-boundary match of the three admitted/unsafe keywords.
  grep -nE '\b(sorry|partial|unsafe)\b' "$@" || true
}

findings="$(scan "${files[@]}")"
if [ -n "$findings" ]; then
  echo "no-admits: found forbidden tokens:" >&2
  echo "$findings" >&2
  exit 1
fi

control_dir="$(mktemp -d /tmp/lexpat-no-admits.XXXXXX)"
trap 'rm -rf -- "$control_dir"' EXIT
printf 'theorem injected : True := by\n  sorry\n' > "$control_dir/Injected.lean"
control="$(scan "$control_dir/Injected.lean")"
if [ -z "$control" ]; then
  echo "no-admits: the affirmative control was not caught" >&2
  exit 1
fi

echo "no-admits: $count sources clean; affirmative control caught the injected token"
