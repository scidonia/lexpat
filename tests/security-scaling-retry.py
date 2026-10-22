#!/usr/bin/env python3
"""Controls for the drift-inconclusive scaling retry.

    python3 tests/security-scaling-retry.py              # all three groups
    python3 tests/security-scaling-retry.py --comparator
    python3 tests/security-scaling-retry.py --helper
    python3 tests/security-scaling-retry.py --entrypoint

`comparator` runs the real `tests/security/benchmark_compare.py` against
generated CSVs: a passing session, a drift control above 15%, a doubling ratio
above 3.5, malformed and missing drift rows, an existing signal path (including
a dangling symlink), a report or signal that cannot be written, and CLI misuse.
Each control starts in a fresh directory and asserts the exit status, the
report and whether the signal exists.

`helper` runs the shipped `tests/security-scaling-ci.sh` as it is invoked in
CI, with a `nix` and a `sleep` double first on PATH; the doubles record every
attempt and every pause. It asserts the exact attempt count and pause for an
eligible retry, for two inconclusive attempts, for a status 3 without the
comparator's marker, for a mismatched or partial marker, for a marker on
status 0, for a missing report, for an ordinary failure, for a timeout, for a
log that could not be retained, for a log that cannot be read after the
readability check, for a capture sink that cannot be written in an otherwise
retry-eligible status-3 attempt, and for an existing output root. It also
drives one genuine >15% drift through the real comparator and asserts the
retry.

`entrypoint` needs the pinned shell (`nix develop -c python3 ...`). It makes the
real `tests/security-benchmark.sh` fail in its build before the comparator and
asserts status 3 with no signal and no report; the helper must then stop at
attempt 1. These are local process doubles: they do not reach the network, a
hosted runner or a real benchmark, and they are not hosted evidence.
"""

import argparse
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import traceback

REPO = pathlib.Path(__file__).resolve().parent.parent
COMPARATOR = REPO / "tests" / "security" / "benchmark_compare.py"
BENCHMARK = REPO / "tests" / "security-benchmark.sh"
HELPER = REPO / "tests" / "security-scaling-ci.sh"

# The doubles that fail a log operation still need the system `cat`; resolve it
# before any control puts its own `bin` directory first on PATH.
REAL_CAT = shutil.which("cat")

SIGNAL_BYTES = b"DRIFT_INCONCLUSIVE_V1\n"
CSV_HEADER = ("side,family,shape,cve_id,size,unit,mode,trials,median_ns,rss_kb,"
              "base_commit,candidate_tree,manifest_sha256,toolchain,flags")
CONTROL_TIMEOUT = 300


class ControlError(Exception):
    pass


def need(condition, message):
    if not condition:
        raise ControlError(message)


def run_control(name, function, *args):
    try:
        function(*args)
    except ControlError as exc:
        print(f"FAIL {name}: {exc}", file=sys.stderr)
        return False
    except Exception:  # a broken control is a reported failure, not a skip
        print(f"FAIL {name}: the control itself failed", file=sys.stderr)
        traceback.print_exc()
        return False
    print(f"PASS {name}")
    return True


# -- generated benchmark CSVs ------------------------------------------------

def row(family, shape, size, median, *, unit="input-bytes", mode="one-shot",
        cve="", trials=3):
    return (f"candidate,{family},{shape},{cve},{size},{unit},{mode},{trials},"
            f"{median},1024,46980d2,,test,test")


def suite_csv(*, drift_scale=1.0, growth=1.0, drift=True,
              drop_before=False, drop_after=False):
    """A `--suite ci` CSV: five families, a limit row and one drift block.

    `growth` is the exponent of the median against the size, so 1.0 gives a
    doubling ratio of 2.0 and 2.0 gives 4.0.
    """
    lines = [CSV_HEADER]
    for family in ("token", "colon", "elements", "attributes", "depth"):
        for size in (64, 128, 256, 512):
            lines.append(row(family, f"{family}-case", size,
                             int(1000 * (size / 64) ** growth)))
    lines.append(row("limit", "limit-raw", 1048576, 5000, trials=1))
    if drift:
        if not drop_before:
            lines.append(row("drift", "colon-before", 1024, 100000, trials=21))
        if not drop_after:
            lines.append(row("drift", "colon-after", 1024,
                             int(100000 * drift_scale), trials=21))
    return "\n".join(lines) + "\n"


def fresh(root, name):
    work = root / name
    work.mkdir()
    return work


def run_comparator(work, csv_text, *, signal=None, report=None):
    csv_path = work / "candidate.csv"
    csv_path.write_text(csv_text, encoding="utf-8")
    report_path = report if report is not None else work / "report.txt"
    command = [sys.executable, str(COMPARATOR), "--ci",
               "--candidate-csv", str(csv_path), "--report", str(report_path)]
    if signal is not None:
        command += ["--drift-signal", str(signal)]
    proc = subprocess.run(command, capture_output=True, text=True,
                          timeout=CONTROL_TIMEOUT)
    return proc, report_path


def need_no_signal(signal, context):
    need(not os.path.lexists(signal),
         f"{context} left the drift signal at {signal}")


# -- comparator group -------------------------------------------------------

def comparator_pass(root):
    work = fresh(root, "pass")
    signal = work / "drift-inconclusive.signal"
    proc, report = run_comparator(work, suite_csv(), signal=signal)
    need(proc.returncode == 0,
         f"a clean session exited {proc.returncode}: {proc.stderr.strip()}")
    need_no_signal(signal, "a clean session")
    text = report.read_text(encoding="utf-8")
    need("CI sentinel: 15 doubling ratios <= 3.5" in text,
         f"the passing report is incomplete: {text!r}")
    need("FAIL" not in text, f"the passing report records a failure: {text!r}")


def comparator_drift(root):
    work = fresh(root, "drift")
    signal = work / "drift-inconclusive.signal"
    proc, report = run_comparator(work, suite_csv(drift_scale=1.639),
                                 signal=signal)
    need(proc.returncode == 3,
         f"a 63.9% drift shift exited {proc.returncode}: {proc.stderr.strip()}")
    need(signal.is_file() and not signal.is_symlink(),
         f"the drift signal is not a regular file: {signal}")
    data = signal.read_bytes()
    need(data == SIGNAL_BYTES,
         f"the drift signal holds {data!r}, not {SIGNAL_BYTES!r}")
    text = report.read_text(encoding="utf-8")
    need("drift block colon" in text and "inconclusive" in text,
         f"the drift report does not record the inconclusive block: {text!r}")


def comparator_doubling(root):
    work = fresh(root, "doubling")
    signal = work / "drift-inconclusive.signal"
    proc, report = run_comparator(work, suite_csv(growth=2.0), signal=signal)
    need(proc.returncode == 1,
         f"a doubling ratio of 4.0 exited {proc.returncode}, not 1")
    need_no_signal(signal, "a scaling threshold failure")
    text = report.read_text(encoding="utf-8")
    need("4.000 > 3.5" in text,
         f"the report does not name the doubling failure: {text!r}")


def comparator_malformed_drift(root):
    work = fresh(root, "malformed-drift")
    signal = work / "drift-inconclusive.signal"
    proc, report = run_comparator(work, suite_csv(drop_after=True),
                                 signal=signal)
    need(proc.returncode == 1,
         f"an incomplete drift block exited {proc.returncode}, not 1")
    need_no_signal(signal, "an incomplete drift block")
    need("incomplete" in report.read_text(encoding="utf-8"),
         "the report does not name the incomplete drift block")


def comparator_missing_drift(root):
    work = fresh(root, "missing-drift")
    signal = work / "drift-inconclusive.signal"
    proc, report = run_comparator(work, suite_csv(drift=False), signal=signal)
    need(proc.returncode == 1,
         f"a CSV without drift rows exited {proc.returncode}, not 1")
    need_no_signal(signal, "a CSV without drift rows")
    need("drift family is absent" in report.read_text(encoding="utf-8"),
         "the report does not name the absent drift family")


def comparator_existing_signal(root):
    work = fresh(root, "existing-signal")
    signal = work / "drift-inconclusive.signal"
    signal.write_bytes(b"stale attempt\n")
    proc, _ = run_comparator(work, suite_csv(drift_scale=1.639), signal=signal)
    need(proc.returncode == 1,
         f"an existing signal path exited {proc.returncode}, not 1")
    need(signal.read_bytes() == b"stale attempt\n",
         "the existing signal was modified instead of refused")


def comparator_dangling_signal(root):
    work = fresh(root, "dangling-signal")
    target = work / "absent-target"
    signal = work / "drift-inconclusive.signal"
    signal.symlink_to(target)
    proc, _ = run_comparator(work, suite_csv(drift_scale=1.639), signal=signal)
    need(proc.returncode == 1,
         f"a dangling signal symlink exited {proc.returncode}, not 1")
    need(signal.is_symlink() and os.readlink(signal) == str(target),
         "the dangling signal symlink was replaced instead of refused")
    need(not target.exists(), "the refused signal write created its target")


def comparator_report_failure(root):
    work = fresh(root, "report-failure")
    signal = work / "drift-inconclusive.signal"
    report = work / "absent-directory" / "report.txt"
    proc, _ = run_comparator(work, suite_csv(drift_scale=1.639), signal=signal,
                            report=report)
    need(proc.returncode == 1,
         f"an unwritable report exited {proc.returncode}, not 1")
    need_no_signal(signal, "an unwritable report")
    need("cannot write the benchmark report" in proc.stderr,
         f"the failure does not name the report: {proc.stderr.strip()}")


def comparator_signal_failure(root):
    work = fresh(root, "signal-failure")
    signal = work / "absent-directory" / "drift-inconclusive.signal"
    proc, report = run_comparator(work, suite_csv(drift_scale=1.639),
                                 signal=signal)
    need(proc.returncode == 1,
         f"an unwritable drift signal exited {proc.returncode}, not 1")
    need("cannot write the drift signal" in proc.stderr,
         f"the failure does not name the drift signal: {proc.stderr.strip()}")
    need("inconclusive" in report.read_text(encoding="utf-8"),
         "the drift report was not written before the signal failure")


def comparator_cli_misuse(root):
    work = fresh(root, "cli-misuse")
    csv_path = work / "candidate.csv"
    csv_path.write_text(suite_csv(), encoding="utf-8")
    report = work / "report.txt"
    relative = subprocess.run(
        [sys.executable, str(COMPARATOR), "--ci", "--candidate-csv",
         str(csv_path), "--report", str(report), "--drift-signal",
         "relative.signal"],
        capture_output=True, text=True, timeout=CONTROL_TIMEOUT)
    need(relative.returncode == 2,
         f"a relative --drift-signal exited {relative.returncode}, not 2")
    paired = subprocess.run(
        [sys.executable, str(COMPARATOR), "--pair", "--report", str(report),
         "--drift-signal", str(work / "paired.signal")],
        capture_output=True, text=True, timeout=CONTROL_TIMEOUT)
    need(paired.returncode == 2,
         f"a paired --drift-signal exited {paired.returncode}, not 2")


def comparator_group(root):
    checks = [
        ("comparator: passing session", comparator_pass),
        ("comparator: drift above 15%", comparator_drift),
        ("comparator: doubling above 3.5", comparator_doubling),
        ("comparator: incomplete drift block", comparator_malformed_drift),
        ("comparator: absent drift rows", comparator_missing_drift),
        ("comparator: existing signal path", comparator_existing_signal),
        ("comparator: dangling signal symlink", comparator_dangling_signal),
        ("comparator: unwritable report", comparator_report_failure),
        ("comparator: unwritable signal", comparator_signal_failure),
        ("comparator: signal CLI misuse", comparator_cli_misuse),
    ]
    return all([run_control(name, function, root) for name, function in checks])


# -- process doubles --------------------------------------------------------

FAKE_NIX = """#!/usr/bin/env bash
# Test double for `nix develop -c <command>`: records the attempt and then
# behaves as this control describes.
set -u
out=""
previous=""
for argument in "$@"; do
  if [ "$previous" = "--out" ]; then
    out="$argument"
  fi
  previous="$argument"
done
count_file=__COUNT__
attempts=0
if [ -f "$count_file" ]; then
  attempts=$(cat "$count_file")
fi
attempts=$((attempts + 1))
echo "$attempts" > "$count_file"
echo "fake nix: attempt $attempts"
case "$attempts" in
__BODY__*)
  echo "fake nix: unexpected attempt $attempts" >&2
  exit 90
  ;;
esac
"""

FAKE_NIX_EXEC = """#!/usr/bin/env bash
# Test double for `nix develop -c`: records the attempt and runs the requested
# command directly in the caller's environment.
echo run >> __LOG__
while [ "$#" -gt 0 ] && [ "$1" != "bash" ]; do
  shift
done
exec "$@"
"""

FAKE_SLEEP = """#!/usr/bin/env bash
# Test double for `sleep`: records the requested pause instead of taking it.
echo "$@" >> __LOG__
exit 0
"""

FAKE_LAKE = """#!/usr/bin/env bash
# Test double for `lake`: fails the C ABI build before the comparator runs.
echo "fake lake: simulated build failure" >&2
exit 3
"""

FAKE_PYTHON = """#!/usr/bin/env bash
# Test double for `python3`: records that the comparator was invoked.
echo "$@" >> __LOG__
exit 0
"""

FAKE_CAT = """#!/usr/bin/env bash
# Test double for `cat`: fails only when asked to replay an attempt log, so the
# read failure arrives after the helper's readability check has passed. Every
# other invocation, including the here-documents the nix double writes and the
# count file it reads, uses the real cat.
for argument in "$@"; do
  case "$argument" in
    *.log)
      echo "fake cat: simulated read failure for $argument" >&2
      exit 1
      ;;
  esac
done
exec __REAL_CAT__ "$@"
"""

FAKE_TEE = """#!/usr/bin/env bash
# Test double for `tee`: drains the benchmark output and reports a capture
# write failure instead of writing it to the log.
__REAL_CAT__ >/dev/null
echo "fake tee: simulated log capture failure" >&2
exit 1
"""


def write_script(path, text):
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def pass_branch(number):
    return f"""{number})
mkdir -p "$out"
cat > "$out/report.txt" <<'REPORT'
CI sentinel: 15 doubling ratios <= 3.5
OK: benchmark thresholds satisfied
REPORT
cat > "$out/candidate.csv" <<'CSV'
side,family
candidate,token
CSV
exit 0
;;
"""


def drift_branch(number, *, write_signal=True, write_report=True,
                 write_csv=True, remove_log=False, status=3):
    lines = [f"{number})", 'mkdir -p "$out"']
    if write_report:
        lines += ["cat > \"$out/report.txt\" <<'REPORT'",
                  "drift colon: before=100000ns after=163900ns shift=0.639",
                  "FAIL: drift block colon shifted 63.9% (> 15%); inconclusive",
                  "REPORT"]
    if write_csv:
        lines += ["cat > \"$out/candidate.csv\" <<'CSV'", "side,family",
                  "candidate,drift", "CSV"]
    if write_signal:
        lines += ["cat > \"$out/drift-inconclusive.signal\" <<'SIGNAL'",
                  "DRIFT_INCONCLUSIVE_V1", "SIGNAL"]
    if remove_log:
        lines += ['rm -f "$(dirname "$out")/$(basename "$out").log"']
    lines += [f"exit {status}", ";;", ""]
    return "\n".join(lines) + "\n"


def partial_marker_branch(number, text):
    return f"""{number})
mkdir -p "$out"
cat > "$out/report.txt" <<'REPORT'
drift colon: inconclusive
REPORT
cat > "$out/candidate.csv" <<'CSV'
side,family
candidate,drift
CSV
printf '%s' '{text}' > "$out/drift-inconclusive.signal"
exit 3
;;
"""


def marker_with_pass_branch(number):
    return f"""{number})
mkdir -p "$out"
cat > "$out/report.txt" <<'REPORT'
OK: benchmark thresholds satisfied
REPORT
cat > "$out/candidate.csv" <<'CSV'
side,family
candidate,token
CSV
cat > "$out/drift-inconclusive.signal" <<'SIGNAL'
DRIFT_INCONCLUSIVE_V1
SIGNAL
exit 0
;;
"""


def status_branch(number, status):
    return f"""{number})
echo "fake nix: simulated status {status}" >&2
exit {status}
;;
"""


def comparator_branch(number, csv_path):
    return f"""{number})
mkdir -p "$out"
cp {shlex.quote(str(csv_path))} "$out/candidate.csv"
{sys.executable} {shlex.quote(str(COMPARATOR))} --ci \\
  --candidate-csv "$out/candidate.csv" \\
  --drift-signal "$out/drift-inconclusive.signal" \\
  --report "$out/report.txt"
status=$?
exit $status
;;
"""


def prepare_helper(work, body, extra=None):
    bin_dir = work / "bin"
    bin_dir.mkdir()
    count = work / "invocations"
    sleep_log = work / "sleeps"
    write_script(bin_dir / "nix",
                 FAKE_NIX.replace("__COUNT__", shlex.quote(str(count)))
                 .replace("__BODY__", body))
    write_script(bin_dir / "sleep",
                 FAKE_SLEEP.replace("__LOG__", shlex.quote(str(sleep_log))))
    for name in extra or ():
        if name == "cat":
            need(REAL_CAT is not None, "the system cat is not on PATH")
            write_script(bin_dir / "cat",
                         FAKE_CAT.replace("__REAL_CAT__",
                                          shlex.quote(REAL_CAT)))
        elif name == "tee":
            need(REAL_CAT is not None, "the system cat is not on PATH")
            write_script(bin_dir / "tee",
                         FAKE_TEE.replace("__REAL_CAT__",
                                          shlex.quote(REAL_CAT)))
        else:
            raise ControlError(f"unknown process double: {name}")
    return bin_dir, count, sleep_log


def invoke_helper(work, bin_dir, count, sleep_log, *, out=None):
    out = work / "out" if out is None else out
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    proc = subprocess.run(["bash", str(HELPER), "--out", str(out)],
                          capture_output=True, text=True, env=env,
                          timeout=CONTROL_TIMEOUT)
    attempts = int(count.read_text(encoding="utf-8").strip()) if count.exists() else 0
    sleeps = (sleep_log.read_text(encoding="utf-8").split()
              if sleep_log.exists() else [])
    return proc, out, attempts, sleeps


def helper_case(root, name, body, extra=None):
    work = fresh(root, name)
    bin_dir, count, sleep_log = prepare_helper(work, body, extra=extra)
    proc, out, attempts, sleeps = invoke_helper(work, bin_dir, count, sleep_log)
    return proc, out, attempts, sleeps


def helper_eligible_then_pass(root):
    proc, out, attempts, sleeps = helper_case(
        root, "eligible-then-pass", drift_branch(1) + pass_branch(2))
    need(proc.returncode == 0,
         f"an eligible retry that then passed exited {proc.returncode}: "
         f"{proc.stderr.strip()}")
    need(attempts == 2, f"expected 2 attempts, saw {attempts}")
    need(sleeps == ["30"], f"expected one 30-second pause, saw {sleeps}")
    marker = out / "attempt-1" / "drift-inconclusive.signal"
    need(marker.is_file() and marker.read_bytes() == SIGNAL_BYTES,
         "the first attempt's drift signal was not retained")
    need((out / "attempt-1" / "report.txt").is_file(),
         "the first attempt's report was not retained")
    need((out / "attempt-2" / "report.txt").is_file(),
         "the second attempt left no report")
    need((out / "attempt-2.log").is_file(),
         "the second attempt left no log")


def helper_two_inconclusive(root):
    proc, out, attempts, sleeps = helper_case(
        root, "two-inconclusive", drift_branch(1) + drift_branch(2))
    need(proc.returncode == 3,
         f"two inconclusive attempts exited {proc.returncode}, not 3")
    need(attempts == 2, f"expected 2 attempts, saw {attempts}")
    need(sleeps == ["30"], f"expected one 30-second pause, saw {sleeps}")
    for number in (1, 2):
        marker = out / f"attempt-{number}" / "drift-inconclusive.signal"
        need(marker.is_file() and marker.read_bytes() == SIGNAL_BYTES,
             f"attempt {number}'s drift signal was not retained")


def helper_status_one(root):
    proc, out, attempts, sleeps = helper_case(
        root, "status-one", status_branch(1, 1))
    need(proc.returncode == 1,
         f"a failed attempt exited {proc.returncode}, not 1")
    need(attempts == 1, f"a failed attempt ran {attempts} times")
    need(sleeps == [], f"a failed attempt paused: {sleeps}")


def helper_timeout(root):
    proc, out, attempts, sleeps = helper_case(
        root, "timeout", status_branch(1, 124))
    need(proc.returncode == 1,
         f"a timed-out attempt exited {proc.returncode}, not 1")
    need(attempts == 1, f"a timed-out attempt ran {attempts} times")
    need(sleeps == [], f"a timed-out attempt paused: {sleeps}")


def helper_status_three_without_marker(root):
    proc, out, attempts, sleeps = helper_case(
        root, "status-three-without-marker",
        drift_branch(1, write_signal=False))
    need(proc.returncode == 1,
         f"a status 3 without the marker exited {proc.returncode}, not 1")
    need(attempts == 1, f"a status 3 without the marker ran {attempts} times")
    need(sleeps == [], f"a status 3 without the marker paused: {sleeps}")


def helper_partial_marker(root):
    proc, out, attempts, sleeps = helper_case(
        root, "partial-marker", partial_marker_branch(1, "DRIFT_INCONCLUSIVE_V1"))
    need(proc.returncode == 1,
         f"a partial marker exited {proc.returncode}, not 1")
    need(attempts == 1, f"a partial marker ran {attempts} times")
    need(sleeps == [], f"a partial marker paused: {sleeps}")


def helper_mismatched_marker(root):
    proc, out, attempts, sleeps = helper_case(
        root, "mismatched-marker",
        partial_marker_branch(1, "DRIFT_INCONCLUSIVE_V2"))
    need(proc.returncode == 1,
         f"a mismatched marker exited {proc.returncode}, not 1")
    need(attempts == 1, f"a mismatched marker ran {attempts} times")
    need(sleeps == [], f"a mismatched marker paused: {sleeps}")


def helper_marker_with_status_zero(root):
    proc, out, attempts, sleeps = helper_case(
        root, "marker-with-status-zero", marker_with_pass_branch(1))
    need(proc.returncode == 1,
         f"a marker on status 0 exited {proc.returncode}, not 1")
    need(attempts == 1, f"a marker on status 0 ran {attempts} times")
    need(sleeps == [], f"a marker on status 0 paused: {sleeps}")


def helper_missing_report(root):
    proc, out, attempts, sleeps = helper_case(
        root, "missing-report", drift_branch(1, write_report=False))
    need(proc.returncode == 1,
         f"a status 3 without the report exited {proc.returncode}, not 1")
    need(attempts == 1, f"a status 3 without the report ran {attempts} times")
    need(sleeps == [], f"a status 3 without the report paused: {sleeps}")


def helper_lost_log(root):
    proc, out, attempts, sleeps = helper_case(
        root, "lost-log", drift_branch(1, remove_log=True))
    need(proc.returncode == 1,
         f"a lost attempt log exited {proc.returncode}, not 1")
    need(attempts == 1, f"a lost attempt log ran {attempts} times")
    need(sleeps == [], f"a lost attempt log paused: {sleeps}")
    need("unreadable" in proc.stderr,
         f"the failure does not name the lost log: {proc.stderr.strip()}")


def helper_log_read_failure(root):
    proc, out, attempts, sleeps = helper_case(
        root, "log-read-failure", drift_branch(1), extra=["cat"])
    marker = out / "attempt-1" / "drift-inconclusive.signal"
    need(marker.is_file() and marker.read_bytes() == SIGNAL_BYTES,
         "the attempt did not leave the otherwise valid drift signal")
    need(proc.returncode == 1,
         f"an unreadable attempt log exited {proc.returncode}, not 1")
    need(attempts == 1, f"an unreadable attempt log ran {attempts} times")
    need(sleeps == [], f"an unreadable attempt log paused: {sleeps}")
    need("log could not be read" in proc.stderr,
         f"the failure does not name the log read: {proc.stderr.strip()}")


def helper_log_capture_failure(root):
    proc, out, attempts, sleeps = helper_case(
        root, "log-capture-failure", drift_branch(1), extra=["tee"])
    marker = out / "attempt-1" / "drift-inconclusive.signal"
    need(marker.is_file() and marker.read_bytes() == SIGNAL_BYTES,
         "the attempt did not leave the otherwise valid drift signal")
    need(proc.returncode == 1,
         f"a failed log capture exited {proc.returncode}, not 1")
    need(attempts == 1, f"a failed log capture ran {attempts} times")
    need(sleeps == [], f"a failed log capture paused: {sleeps}")
    need("log capture failed" in proc.stderr,
         f"the failure does not name the capture: {proc.stderr.strip()}")


def helper_existing_root(root):
    work = fresh(root, "existing-root")
    bin_dir, count, sleep_log = prepare_helper(work, pass_branch(1))
    out = work / "out"
    out.mkdir()
    proc, out, attempts, sleeps = invoke_helper(work, bin_dir, count, sleep_log,
                                                out=out)
    need(proc.returncode == 2,
         f"an existing output root exited {proc.returncode}, not 2")
    need(attempts == 0, f"an existing output root ran {attempts} attempts")
    need(sleeps == [], f"an existing output root paused: {sleeps}")


def helper_relative_root(root):
    work = fresh(root, "relative-root")
    bin_dir, count, sleep_log = prepare_helper(work, pass_branch(1))
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    proc = subprocess.run(["bash", str(HELPER), "--out", "relative-out"],
                          capture_output=True, text=True, env=env,
                          timeout=CONTROL_TIMEOUT, cwd=str(work))
    need(proc.returncode == 2,
         f"a relative --out exited {proc.returncode}, not 2")
    need(not count.exists(), "a relative --out still ran an attempt")


def helper_genuine_drift(root):
    work = fresh(root, "genuine-drift")
    drift_csv = work / "drift.csv"
    drift_csv.write_text(suite_csv(drift_scale=1.639), encoding="utf-8")
    clean_csv = work / "clean.csv"
    clean_csv.write_text(suite_csv(), encoding="utf-8")
    bin_dir, count, sleep_log = prepare_helper(
        work, comparator_branch(1, drift_csv) + comparator_branch(2, clean_csv))
    proc, out, attempts, sleeps = invoke_helper(work, bin_dir, count, sleep_log)
    need(proc.returncode == 0,
         f"a genuine comparator drift retry exited {proc.returncode}: "
         f"{proc.stderr.strip()}")
    need(attempts == 2, f"expected 2 attempts, saw {attempts}")
    need(sleeps == ["30"], f"expected one 30-second pause, saw {sleeps}")
    marker = out / "attempt-1" / "drift-inconclusive.signal"
    need(marker.is_file() and marker.read_bytes() == SIGNAL_BYTES,
         "the genuine comparator drift signal was not retained")
    need_no_signal(out / "attempt-2" / "drift-inconclusive.signal",
                   "the passing second attempt")


def helper_group(root):
    checks = [
        ("helper: eligible retry then pass", helper_eligible_then_pass),
        ("helper: two inconclusive attempts", helper_two_inconclusive),
        ("helper: ordinary failure", helper_status_one),
        ("helper: timeout", helper_timeout),
        ("helper: status 3 without the marker", helper_status_three_without_marker),
        ("helper: partial marker", helper_partial_marker),
        ("helper: mismatched marker", helper_mismatched_marker),
        ("helper: marker with status 0", helper_marker_with_status_zero),
        ("helper: status 3 without the report", helper_missing_report),
        ("helper: lost attempt log", helper_lost_log),
        ("helper: unreadable attempt log after the check",
         helper_log_read_failure),
        ("helper: failed log capture", helper_log_capture_failure),
        ("helper: existing output root", helper_existing_root),
        ("helper: relative output root", helper_relative_root),
        ("helper: genuine comparator drift", helper_genuine_drift),
    ]
    return all([run_control(name, function, root) for name, function in checks])


# -- real-entrypoint group --------------------------------------------------

def require_pinned_shell():
    missing = [name for name in ("lean", "cc", "pkg-config", "sha256sum")
               if shutil.which(name) is None]
    need(not missing,
         "the entrypoint group needs the pinned shell (missing "
         + ", ".join(missing) + "); run it through `nix develop -c python3`")


def entrypoint_bin_dir(work):
    bin_dir = work / "bin"
    bin_dir.mkdir()
    record = work / "python3-calls"
    sleep_log = work / "sleeps"
    write_script(bin_dir / "lake", FAKE_LAKE)
    write_script(bin_dir / "python3",
                 FAKE_PYTHON.replace("__LOG__", shlex.quote(str(record))))
    write_script(bin_dir / "sleep",
                 FAKE_SLEEP.replace("__LOG__", shlex.quote(str(sleep_log))))
    write_script(bin_dir / "nix",
                 FAKE_NIX_EXEC.replace("__LOG__", shlex.quote(str(work / "nix-calls"))))
    return bin_dir, record, sleep_log


def entrypoint_pre_comparator(root):
    require_pinned_shell()
    work = fresh(root, "entrypoint")
    bin_dir, record, sleep_log = entrypoint_bin_dir(work)
    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"

    out = work / "direct"
    proc = subprocess.run(["bash", str(BENCHMARK), "--suite", "ci",
                           "--out", str(out)],
                          capture_output=True, text=True, env=env,
                          timeout=CONTROL_TIMEOUT)
    need(proc.returncode == 3,
         f"the benchmark entrypoint exited {proc.returncode}, not the build's 3: "
         f"{proc.stderr.strip()[-400:]}")
    need_no_signal(out / "drift-inconclusive.signal",
                   "a pre-comparator status 3")
    need(not (out / "report.txt").exists(),
         "a pre-comparator status 3 wrote a report")
    need(not record.exists(),
         "the comparator ran even though the build failed")

    # The same failure through the shipped helper must stop at attempt 1.
    out = work / "helper-out"
    proc = subprocess.run(["bash", str(HELPER), "--out", str(out)],
                          capture_output=True, text=True, env=env,
                          timeout=CONTROL_TIMEOUT)
    need(proc.returncode == 1,
         f"the helper exited {proc.returncode} for a pre-comparator status 3")
    attempts = work / "nix-calls"
    need(attempts.is_file()
         and len(attempts.read_text(encoding="utf-8").split()) == 1,
         f"the helper did not stop at one attempt: {proc.stderr.strip()}")
    sleeps = (sleep_log.read_text(encoding="utf-8").split()
              if sleep_log.exists() else [])
    need(sleeps == [], f"the helper paused after a pre-comparator status 3: {sleeps}")
    need_no_signal(out / "attempt-1" / "drift-inconclusive.signal",
                   "a pre-comparator status 3")
    need(not (out / "attempt-1" / "report.txt").exists(),
         "a pre-comparator status 3 wrote a report")
    need(not record.exists(),
         "the comparator ran through the helper even though the build failed")


def entrypoint_group(root):
    checks = [
        ("entrypoint: pre-comparator status 3", entrypoint_pre_comparator),
    ]
    return all([run_control(name, function, root) for name, function in checks])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--comparator", action="store_true")
    parser.add_argument("--helper", action="store_true")
    parser.add_argument("--entrypoint", action="store_true")
    args = parser.parse_args()

    selected = []
    if args.comparator or args.helper or args.entrypoint:
        if args.comparator:
            selected.append(("comparator", comparator_group))
        if args.helper:
            selected.append(("helper", helper_group))
        if args.entrypoint:
            selected.append(("entrypoint", entrypoint_group))
    else:
        selected = [("comparator", comparator_group),
                    ("helper", helper_group),
                    ("entrypoint", entrypoint_group)]

    results = []
    with tempfile.TemporaryDirectory(prefix="lexpat-scaling-retry.") as tmp:
        root = pathlib.Path(tmp)
        for name, group in selected:
            group_root = root / name
            group_root.mkdir()
            results.append(group(group_root))
    if all(results):
        print(f"OK: scaling retry controls passed ({len(selected)} group(s))")
        return 0
    print("FAIL: scaling retry controls failed", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
