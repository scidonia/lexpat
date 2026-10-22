#!/usr/bin/env bash
# The dedicated scaling sentinel, run as its own CI step.
#
#   tests/security-scaling-ci.sh --out <absolute-directory>
#
# The sentinel is `tests/security-benchmark.sh --suite ci`: three trials per
# case, the 3.5 doubling bound and the 1 KiB drift control before and after
# each family block. On a shared runner the drift control can move above 15%
# without any scaling change, and that makes the session inconclusive rather
# than failed. This helper retries exactly once for that classification and for
# nothing else.
#
# Retry policy. Only the comparator can classify a session inconclusive, so the
# helper retries only when the attempt exits 3 *and* the comparator's exclusive
# marker `<attempt>/drift-inconclusive.signal` holds exactly the bytes
# `DRIFT_INCONCLUSIVE_V1\n` *and* the attempt left its CSV and report. A status
# 3 from a build, compiler, driver or Nix error before the comparator ran has no
# marker and stops at the first attempt; so does a status 3 with a missing,
# partial or mismatched marker. A marker on any other status, a threshold or
# fixture failure, a timeout, a log whose capture fails or that cannot be read
# or written, and a pre-existing output root are all errors: no sleep, no
# second attempt.
#
# `--out` must be an absolute path that does not exist yet. It is created
# exclusively, and each attempt gets its own `attempt-N` directory and
# `attempt-N.log`; the run leaves every attempt's CSV, report, signal and log in
# place, including a failed or inconclusive one.
#
# Exit status
#   0  an attempt passed: status 0, no drift signal, a complete report and CSV
#   1  a failure that is not a drift-retry candidate
#   3  both attempts were drift-inconclusive; the session is not measured
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --out)
      if [ "$#" -lt 2 ]; then
        echo "security-scaling-ci: --out needs a directory" >&2
        exit 2
      fi
      out="$2"
      shift 2
      ;;
    *)
      echo "security-scaling-ci: unknown option $1" >&2
      exit 2
      ;;
  esac
done

if [ -z "$out" ]; then
  echo "security-scaling-ci: --out is required" >&2
  exit 2
fi
case "$out" in
  /*) ;;
  *)
    echo "security-scaling-ci: --out must be an absolute path" >&2
    exit 2
    ;;
esac

# The single pause between the two attempts. It is a fixed part of the policy,
# so nothing about eligibility depends on a caller-supplied value.
pause_seconds=30

expected_signal() {
  printf 'DRIFT_INCONCLUSIVE_V1\n'
}

# A previous root is not a source of reusable evidence, so this must fail rather
# than add this run's attempt directories beside an earlier one's.
if ! mkdir -- "$out" 2>/dev/null; then
  echo "security-scaling-ci: --out must not exist yet: $out" >&2
  exit 2
fi

# Run one attempt. Returns 0 for a pass, 3 for a drift-inconclusive attempt that
# is eligible for the one retry, and 1 for everything that must stop the run.
run_attempt() {
  local number="$1"
  local attempt="$out/attempt-$number"
  local log="$out/attempt-$number.log"
  local signal="$attempt/drift-inconclusive.signal"
  local status=0
  local present=no

  if ! mkdir -- "$attempt"; then
    echo "security-scaling-ci: attempt directory already exists: $attempt" >&2
    return 1
  fi
  # Claim the log exclusively before the attempt starts, so an unwritable or
  # already-present log is a failure here rather than a retry later.
  if ! ( set -o noclobber; : >"$log" ) 2>/dev/null; then
    echo "security-scaling-ci: cannot write the attempt log: $log" >&2
    return 1
  fi

  echo "security-scaling-ci: attempt $number starting"
  # The benchmark writes through `tee` so the log sink has its own status: a
  # redirection failure before the child starts and a write failure while the
  # log fills are capture failures, not a benchmark status to classify.
  # `run_attempt` is called from a `||` list, so `errexit` does not act on this
  # pipeline; both statuses are read before any other command can replace them.
  ( cd "$repo" && nix develop -c bash "$repo/tests/security-benchmark.sh" \
      --suite ci --out "$attempt" ) 2>&1 | tee -a -- "$log" >/dev/null
  local statuses=("${PIPESTATUS[@]}")
  status="${statuses[0]}"
  local capture="${statuses[1]}"

  if [ "$capture" -ne 0 ]; then
    echo "security-scaling-ci: attempt $number log capture failed with status" \
      "$capture: $log" >&2
    return 1
  fi
  if [ ! -f "$log" ] || [ ! -r "$log" ]; then
    echo "security-scaling-ci: attempt $number log is unreadable: $log" >&2
    return 1
  fi
  if ! cat -- "$log"; then
    echo "security-scaling-ci: attempt $number log could not be read: $log" >&2
    return 1
  fi
  if ! echo "security-scaling-ci: attempt $number exit status $status"; then
    echo "security-scaling-ci: attempt $number status line could not be" \
      "written" >&2
    return 1
  fi

  if [ -L "$signal" ] || [ -e "$signal" ]; then
    present=yes
  fi

  if [ "$status" -ne 3 ]; then
    if [ "$present" = yes ]; then
      echo "security-scaling-ci: attempt $number left the drift signal with" \
        "exit status $status; only the comparator's status 3 may carry it" >&2
      return 1
    fi
    if [ "$status" -ne 0 ]; then
      echo "security-scaling-ci: attempt $number failed with status $status;" \
        "that is not a drift-inconclusive retry" >&2
      return 1
    fi
    if [ ! -s "$attempt/report.txt" ] || [ ! -s "$attempt/candidate.csv" ]; then
      echo "security-scaling-ci: attempt $number did not leave a report and" \
        "CSV: $attempt" >&2
      return 1
    fi
    return 0
  fi

  # Status 3 is a retry candidate only when the comparator's own marker and the
  # artefacts it accompanies are all present, and the marker is byte-for-byte
  # the content the comparator writes.
  if [ "$present" != yes ] || [ ! -f "$attempt/candidate.csv" ] \
     || [ ! -f "$attempt/report.txt" ]; then
    echo "security-scaling-ci: attempt $number exited 3 without complete drift" \
      "evidence; not retrying" >&2
    return 1
  fi
  if ! cmp -s -- "$signal" <(expected_signal); then
    echo "security-scaling-ci: attempt $number drift signal is not the exact" \
      "expected content; not retrying" >&2
    return 1
  fi
  return 3
}

# The same `|| status=$?` pattern as inside the function: `errexit` stays on
# for everything else in this script, and the attempt's status is its own.
status=0
run_attempt 1 || status=$?

case "$status" in
  0)
    echo "security-scaling-ci: PASS (attempt 1; logs in $out)"
    exit 0
    ;;
  3)
    echo "security-scaling-ci: attempt 1 is drift-inconclusive; retrying once" \
      "after ${pause_seconds}s"
    sleep "$pause_seconds"
    ;;
  *)
    echo "security-scaling-ci: attempt 1 stopped the run; no retry" >&2
    exit 1
    ;;
esac

status=0
run_attempt 2 || status=$?

case "$status" in
  0)
    echo "security-scaling-ci: PASS (attempt 2; logs in $out)"
    exit 0
    ;;
  3)
    echo "security-scaling-ci: both attempts were drift-inconclusive;" \
      "no scaling result for this session (logs in $out)" >&2
    exit 3
    ;;
  *)
    echo "security-scaling-ci: attempt 2 stopped the run" >&2
    exit 1
    ;;
esac
