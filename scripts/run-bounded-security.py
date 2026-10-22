#!/usr/bin/env python3
"""Run one command under a hard monotonic deadline in its own process group.

    python3 scripts/run-bounded-security.py --seconds 300 --grace 5 \\
        --log /tmp/bounded.log -- nix develop -c bash tests/security-ci.sh ...

This wrapper is invoked *outside* `nix develop`, so the deadline it enforces
includes Nix shell evaluation and every child the command starts. The command
runs with `start_new_session=True`, which makes it the leader of a new process
group; on timeout the whole group receives SIGTERM, then SIGKILL after the
grace period, and the direct child is reaped before the wrapper returns.

An on-time exit is only a success when its process group is empty: a child that
exits while a descendant is still running has not finished the work it was
asked to do, so the wrapper cleans that group and reports it separately.

Forwarding and retention are part of the wrapper's own job, so an I/O failure
in either is never swallowed: a failure to read the child's output, to write
the live sink, or to write or re-read the retained log reaches the controlling
thread, the whole process group is terminated and reaped, and the run is
reported as a diagnostics failure carrying the underlying error. A run whose
diagnostics are incomplete is not a success, whatever the child returned.

Exit status
    0    on-time success
    124  timeout: the deadline expired
    125  the command exited but left a descendant in its process group
    126  child output or the retained log failed; the diagnostics are incomplete
    n    the command's own nonzero status

A timeout keeps 124 even when diagnostics also failed, because the expired
deadline is the definite outcome; the diagnostics error is still reported. The
command's combined stdout and stderr are forwarded live to this process's
stdout and appended to the `--log` file, which is kept on every outcome.
"""

import argparse
import os
import shlex
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass

EXIT_TIMEOUT = 124
EXIT_UNCLEAN = 125
EXIT_DIAGNOSTICS = 126
PIPE_DRAIN_SECONDS = 5.0


@dataclass
class Result:
    kind: str  # "ok" | "failed" | "timeout" | "unclean" | "diagnostics"
    code: int
    elapsed: float
    last_stage: str | None
    log_path: str
    error: str | None = None


def _pump(stream, sink, log, failure):
    """Copy combined child output to the live sink and the retained log.

    This runs on a daemon thread, so an I/O error here would otherwise end the
    thread and go unnoticed. It is appended to `failure` for the controlling
    thread, which stops the child group and reports the run as a diagnostics
    failure instead of a success with missing output.
    """
    try:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                return
            sink.write(chunk)
            sink.flush()
            log.write(chunk)
            log.flush()
    except (OSError, ValueError) as exc:
        failure.append(exc)


def _dispatch(killpg, group, sig):
    try:
        killpg(group, sig)
    except ProcessLookupError:
        pass


def _group_alive(killpg, group):
    try:
        killpg(group, 0)
    except ProcessLookupError:
        return False
    return True


def _last_stage(log_path, prefix):
    """Return the last retained stage line. A failed read is the caller's problem."""
    stage = None
    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if line.startswith(prefix):
                stage = line.rstrip("\n")
    return stage


def run(argv, seconds, grace, log_path, *, stage_prefix="security-ci: ",
        clock=time.monotonic, sleep=time.sleep, spawn=subprocess.Popen,
        killpg=os.killpg, out=None, log_open=open, pipe_drain=PIPE_DRAIN_SECONDS):
    """Run `argv` and return a Result. Seams are injectable for the controls."""
    if not argv:
        raise ValueError("no command given")
    if seconds <= 0:
        raise ValueError("--seconds must be positive")
    if grace < 0:
        raise ValueError("--grace must be non-negative")
    sink = out if out is not None else sys.stdout.buffer
    failure = []

    try:
        log = log_open(log_path, "wb")
    except OSError as exc:
        return Result(kind="diagnostics", code=EXIT_DIAGNOSTICS, elapsed=0.0,
                      last_stage=None, log_path=log_path,
                      error=f"cannot open log {log_path}: {exc}")

    closed = False
    try:
        start = clock()
        try:
            log.write(
                ("# run-bounded-security: seconds=%g grace=%g\n# command: %s\n"
                 % (seconds, grace, shlex.join(argv))).encode("utf-8")
            )
            log.flush()
        except (OSError, ValueError) as exc:
            return Result(kind="diagnostics", code=EXIT_DIAGNOSTICS, elapsed=0.0,
                          last_stage=None, log_path=log_path,
                          error=f"cannot write log {log_path}: {exc}")

        proc = spawn(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        group = proc.pid
        reader = threading.Thread(
            target=_pump, args=(proc.stdout, sink, log, failure), daemon=True)
        reader.start()

        def stop_group():
            """TERM, then KILL after the grace: nothing here may outlive us."""
            _dispatch(killpg, group, signal.SIGTERM)
            term_end = clock() + grace
            while clock() < term_end:
                # Reap the direct child first: an unreaped zombie still counts
                # as a member of its group and would keep this wait going.
                proc.poll()
                if not _group_alive(killpg, group):
                    break
                sleep(min(0.05, max(0.0, term_end - clock())))
            _dispatch(killpg, group, signal.SIGKILL)

        deadline = start + seconds
        timed_out = False
        code = None
        while True:
            code = proc.poll()
            if code is not None:
                break
            if failure:
                # A failed sink or log means this run's diagnostics are already
                # incomplete; stop the work instead of letting it run blind.
                break
            now = clock()
            if now >= deadline:
                timed_out = True
                break
            sleep(min(0.05, max(0.0, deadline - now)))

        if timed_out:
            stop_group()
            code = proc.wait()
            kind = "timeout"
            result_code = EXIT_TIMEOUT
        else:
            group_alive = _group_alive(killpg, group)
            if group_alive:
                # Either the child is still running with an incomplete
                # diagnostics path, or it exited and left work behind. Both are
                # cleaned here rather than left for the wrapper's exit.
                stop_group()
            if code is None:
                code = proc.wait()
            if failure:
                kind = "diagnostics"
                result_code = EXIT_DIAGNOSTICS
            elif group_alive:
                kind = "unclean"
                result_code = EXIT_UNCLEAN
            else:
                kind = "ok" if code == 0 else "failed"
                result_code = code

        reader.join(timeout=pipe_drain)
        if reader.is_alive():
            failure.append(TimeoutError(
                "the child's output was still open %g seconds after its process "
                "group was cleaned" % pipe_drain))

        stage = None
        try:
            stage = _last_stage(log_path, stage_prefix)
        except OSError as exc:
            failure.append(exc)
        if failure and kind != "timeout":
            kind = "diagnostics"
            result_code = EXIT_DIAGNOSTICS

        elapsed = clock() - start
        error = None
        if failure:
            error = (f"the run's diagnostics are incomplete: "
                     f"{type(failure[0]).__name__}: {failure[0]}")
        footer = ("# run-bounded-security: status=%s exit=%d elapsed=%.3fs last_stage=%s\n"
                  % (kind, result_code, elapsed, stage or "-"))
        if error:
            footer += f"# run-bounded-security: {error}\n"
        try:
            log.write(footer.encode("utf-8"))
            log.flush()
        except (OSError, ValueError) as exc:
            error = f"{error}; cannot write log {log_path}: {exc}" if error \
                else f"cannot write log {log_path}: {exc}"
            if kind != "timeout":
                kind = "diagnostics"
                result_code = EXIT_DIAGNOSTICS
        try:
            log.close()
        except OSError as exc:
            error = f"{error}; cannot close log {log_path}: {exc}" if error \
                else f"cannot close log {log_path}: {exc}"
            if kind != "timeout":
                kind = "diagnostics"
                result_code = EXIT_DIAGNOSTICS
        else:
            closed = True
        return Result(kind=kind, code=result_code, elapsed=elapsed,
                      last_stage=stage, log_path=log_path, error=error)
    finally:
        if not closed:
            log.close()


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seconds", type=float, required=True,
                    help="hard monotonic deadline, including child startup")
    ap.add_argument("--grace", type=float, default=5.0,
                    help="seconds between SIGTERM and SIGKILL on timeout")
    ap.add_argument("--log", required=True, help="retained output log path")
    ap.add_argument("--stage-prefix", default="security-ci: ",
                    help="prefix identifying a stage line in the log")
    ap.add_argument("command", nargs=argparse.REMAINDER,
                    help="-- command and arguments")
    args = ap.parse_args(argv)
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        ap.error("a command is required after --")

    log_dir = os.path.dirname(os.path.abspath(args.log))
    try:
        os.makedirs(log_dir, exist_ok=True)
        result = run(command, args.seconds, args.grace, args.log,
                     stage_prefix=args.stage_prefix)
    except ValueError as exc:
        print(f"run-bounded-security: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        # No command started and no log exists: the run has no diagnostics.
        print(f"run-bounded-security: log {args.log}: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return EXIT_DIAGNOSTICS

    stream = sys.stderr if result.code != 0 else sys.stdout
    print(f"run-bounded-security: status={result.kind} exit={result.code} "
          f"elapsed={result.elapsed:.1f}s", file=stream)
    print(f"run-bounded-security: last stage: {result.last_stage or '(none)'}",
          file=stream)
    print(f"run-bounded-security: log: {result.log_path}", file=stream)
    if result.error:
        print(f"run-bounded-security: {result.error}", file=stream)
    return result.code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
