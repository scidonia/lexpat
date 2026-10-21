#!/usr/bin/env bash
# Run the C ABI behavior contracts against the checked-in header and the
# locally built shared object.
#
#   tests/c-abi-contract.sh A1   run the ordered-callback contract
#   tests/c-abi-contract.sh A2   run the fail-closed entity-handler contract
#   tests/c-abi-contract.sh      run each scenario as its own process
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lib="$repo/.lake/build/lib"

if [ "$#" -gt 1 ]; then
  echo "usage: $(basename "$0") [A1|A2]" >&2
  exit 2
fi
case "${1:-}" in
  A1 | A2) scenarios=("$1") ;;
  "") scenarios=(A1 A2) ;;
  *)
    echo "usage: $(basename "$0") [A1|A2]" >&2
    exit 2
    ;;
esac

if command -v lake >/dev/null 2>&1; then
  (cd "$repo" && lake build lexpatCAbi)
else
  (cd "$repo" && nix develop -c lake build lexpatCAbi)
fi

for artifact in "$lib/liblexpat.so.1" "$repo/include/expat.h"; do
  if [ ! -e "$artifact" ]; then
    echo "c-abi-contract: missing $artifact" >&2
    exit 1
  fi
done

tmp="$(mktemp -d /tmp/lexpat-cabi-contract.XXXXXX)"
if [ -z "$tmp" ] || [ ! -d "$tmp" ]; then
  echo "c-abi-contract: mktemp did not produce a directory" >&2
  exit 1
fi
trap 'rm -rf -- "$tmp"' EXIT

"${CC:-cc}" -std=c11 -Wall -Wextra -Werror -I"$repo/include" \
  "$repo/tests/c-abi-contract.c" -L"$lib" -llexpat \
  -Wl,-rpath,"$lib" -o "$tmp/c-abi-contract"

status=0
for scenario in "${scenarios[@]}"; do
  if ! "$tmp/c-abi-contract" "$scenario"; then
    status=1
  fi
done
exit "$status"
