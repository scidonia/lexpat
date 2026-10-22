#!/usr/bin/env python3
"""Controls for scripts/run-bounded-security.py.

    python3 tests/security-timeout.py            # fake-clock unit controls
    python3 tests/security-timeout.py --focused  # live descendant smoke

The default mode exercises the wrapper's timing, timeout, reaping, unclean-group
and diagnostics branches with an injected clock, an injected process factory,
an injected `killpg` and an injected log opener: no live clock, no child process
and no network are consulted, and the fake clock is the only time source the
wrapper sees. The diagnostics controls make the live sink and the retained log
fail and require the wrapper to stop the group and report a nonzero
diagnostics status instead of the child's own success.

`--focused` runs the real wrapper around a short-lived command that starts a
background descendant, and checks that the deadline returns 124 and that both
the command and its descendant are gone afterwards.
"""

import argparse
import importlib.util
import io
import os
import pathlib
import signal
import sys
import tempfile
import time

REPO = pathlib.Path(__file__).resolve().parent.parent


def load_wrapper():
    path = REPO / "scripts" / "run-bounded-security.py"
    spec = importlib.util.spec_from_file_location("run_bounded_security", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += max(seconds, 0.0)
        # Give the pump thread a turn, as a real sleep would.
        time.sleep(0)


class FakeProc:
    def __init__(self, output=b"", code=0, never=False):
        self.stdout = io.BytesIO(output)
        self._code = code
        self.never = never
        self.pid = 4242
        self.reaped = False

    def poll(self):
        return None if self.never else self._code

    def wait(self):
        self.reaped = True
        return self._code


class FakeGroup:
    def __init__(self, alive):
        self.alive = alive
        self.signals = []

    def __call__(self, pgid, sig):
        if sig == 0:
            if not self.alive:
                raise ProcessLookupError
            return
        self.signals.append(sig)
        if sig == signal.SIGKILL:
            self.alive = False


class FailingSink:
    """A live sink that cannot accept output, like a closed pipe."""

    def __init__(self, errno=32, message="Broken pipe"):
        self.errno = errno
        self.message = message

    def write(self, data):
        raise OSError(self.errno, self.message)

    def flush(self):
        pass

    def getvalue(self):
        return b"<the sink accepted nothing>"


class FailingLog(io.BytesIO):
    """A retained log whose writes stop working after `allowed` of them."""

    def __init__(self, allowed=1, errno=28, message="No space left on device"):
        super().__init__()
        self.allowed = allowed
        self.errno = errno
        self.message = message
        self.writes = 0

    def write(self, data):
        self.writes += 1
        if self.writes > self.allowed:
            raise OSError(self.errno, self.message)
        return super().write(data)


def failing_open(error):
    def opener(path, mode):
        raise error
    return opener


def check(label, condition, detail=""):
    if condition:
        print(f"PASS {label}")
        return 0
    print(f"FAIL {label}{': ' + detail if detail else ''}")
    return 1


def run_fake(wrapper, output=b"", code=0, never=False, group_alive=False,
             seconds=300.0, grace=5.0, log_open=None, sink_factory=io.BytesIO):
    clock = FakeClock()
    proc = FakeProc(output=output, code=code, never=never)
    group = FakeGroup(alive=group_alive)
    seams = {}
    if log_open is not None:
        seams["log_open"] = log_open
    with tempfile.TemporaryDirectory() as tmp:
        log_path = os.path.join(tmp, "bounded.log")
        sink = sink_factory()
        result = wrapper.run(
            ["fake", "--command"],
            seconds,
            grace,
            log_path,
            clock=clock,
            sleep=clock.sleep,
            spawn=lambda *args, **kwargs: proc,
            killpg=group,
            out=sink,
            **seams,
        )
        log = pathlib.Path(log_path).read_bytes() if os.path.exists(log_path) else b""
    return result, group, proc, log, sink.getvalue(), clock


def fake_controls():
    wrapper = load_wrapper()
    failures = 0

    # 1. On-time success: output is forwarded to the live sink and the log.
    result, group, proc, log, live, _ = run_fake(
        wrapper, output=b"security-ci: CVE-class corpus\nsecurity-ci: PASS\n", code=0)
    failures += check("on-time success kind", result.kind == "ok", result.kind)
    failures += check("on-time success code", result.code == 0, str(result.code))
    failures += check("live forwarding", b"security-ci: PASS" in live)
    failures += check("retained log output", b"security-ci: PASS" in log)
    failures += check(
        "last stage reported",
        result.last_stage == "security-ci: PASS",
        str(result.last_stage),
    )
    failures += check("no signals on success", group.signals == [], str(group.signals))

    # 2. An ordinary stage failure keeps the command's own status.
    result, group, proc, log, _, _ = run_fake(
        wrapper, output=b"security-ci: fixed differential exceptions\n", code=3)
    failures += check("stage failure kind", result.kind == "failed", result.kind)
    failures += check("stage failure code", result.code == 3, str(result.code))
    failures += check("stage failure log retained", b"differential" in log)
    failures += check(
        "stage failure names last stage",
        result.last_stage == "security-ci: fixed differential exceptions",
        str(result.last_stage),
    )

    # 3. Timeout: TERM, then KILL after the grace, then the child is reaped.
    result, group, proc, log, _, clock = run_fake(
        wrapper, output=b"security-ci: bounded fuzz smoke\n", never=True,
        seconds=10.0, grace=5.0)
    failures += check("timeout kind", result.kind == "timeout", result.kind)
    failures += check("timeout code", result.code == 124, str(result.code))
    failures += check("timeout reached the injected deadline",
                      result.elapsed >= 10.0, f"{result.elapsed}")
    failures += check("timeout clock is the injected one", clock.now >= 10.0,
                      f"{clock.now}")
    failures += check(
        "timeout sends TERM before KILL",
        len(group.signals) >= 2
        and group.signals[0] == signal.SIGTERM
        and signal.SIGKILL in group.signals,
        str(group.signals),
    )
    failures += check("timeout reaps the child", proc.reaped)
    failures += check(
        "timeout log records the status",
        b"status=timeout exit=124" in log,
        log.decode("utf-8", "replace")[-120:],
    )

    # 4. The command exits but leaves a descendant: cleaned, never success.
    result, group, proc, log, _, _ = run_fake(
        wrapper, output=b"security-ci: scaling benchmark smoke\n", code=0,
        group_alive=True, grace=2.0)
    failures += check("unclean kind", result.kind == "unclean", result.kind)
    failures += check("unclean code", result.code == 125, str(result.code))
    failures += check(
        "unclean group is terminated and killed",
        signal.SIGTERM in group.signals and signal.SIGKILL in group.signals,
        str(group.signals),
    )
    failures += check("unclean group is empty afterwards", not group.alive)

    # 5. Argument controls.
    for label, kwargs in (
        ("zero deadline refused", {"seconds": 0.0}),
        ("negative grace refused", {"seconds": 1.0, "grace": -1.0}),
    ):
        try:
            run_fake(wrapper, **kwargs)
        except ValueError:
            failures += check(label, True)
        else:
            failures += check(label, False, "no ValueError")

    # 6. A child that exits 0 while the live sink failed is not a success: the
    #    wrapper must not pass on the child's own status.
    result, group, proc, log, _, _ = run_fake(
        wrapper, output=b"security-ci: PASS\n", code=0,
        sink_factory=FailingSink)
    failures += check("successful child with a failed sink kind",
                      result.kind == "diagnostics", result.kind)
    failures += check("successful child with a failed sink code",
                      result.code == 126, str(result.code))
    failures += check("successful child with a failed sink names the failure",
                      "Broken pipe" in (result.error or ""), str(result.error))
    failures += check("successful child with a failed sink logs the status",
                      b"status=diagnostics exit=126" in log,
                      log.decode("utf-8", "replace")[-160:])
    failures += check("an exited child's group is not signalled again",
                      group.signals == [], str(group.signals))

    # 7. An unreadable retained log is a failure, not an absent stage.
    with tempfile.TemporaryDirectory() as tmp:
        try:
            wrapper._last_stage(os.path.join(tmp, "absent.log"), "security-ci: ")
        except OSError:
            failures += check("log read failure is not swallowed", True)
        else:
            failures += check("log read failure is not swallowed", False,
                              "returned None instead of raising")

    # 8. A log that cannot be created stops the run before it reports anything.
    result, group, proc, log, _, _ = run_fake(
        wrapper, log_open=failing_open(OSError(13, "Permission denied")))
    failures += check("unopenable log kind", result.kind == "diagnostics", result.kind)
    failures += check("unopenable log code", result.code == 126, str(result.code))
    failures += check("unopenable log names the failure",
                      "Permission denied" in (result.error or ""), str(result.error))

    # 9. A sink failure while the child is still running stops the whole group.
    result, group, proc, log, _, _ = run_fake(
        wrapper, output=b"security-ci: CVE-class corpus\n", never=True,
        group_alive=True, seconds=100000.0, grace=1.0, sink_factory=FailingSink)
    failures += check("live sink failure kind", result.kind == "diagnostics", result.kind)
    failures += check("live sink failure code", result.code == 126, str(result.code))
    failures += check("live sink failure reaps the child", proc.reaped)
    failures += check("live sink failure cleans the group",
                      signal.SIGKILL in group.signals and not group.alive,
                      str(group.signals))

    # 10. A retained log that stops accepting bytes aborts a live run too.
    result, group, proc, log, _, _ = run_fake(
        wrapper, output=b"security-ci: bounded fuzz smoke\n", never=True,
        group_alive=True, seconds=100000.0, grace=1.0,
        log_open=lambda path, mode: FailingLog(allowed=1))
    failures += check("live log failure kind", result.kind == "diagnostics", result.kind)
    failures += check("live log failure code", result.code == 126, str(result.code))
    failures += check("live log failure names the failure",
                      "No space left on device" in (result.error or ""),
                      str(result.error))
    failures += check("live log failure reaps the child", proc.reaped)
    failures += check("live log failure cleans the group",
                      signal.SIGKILL in group.signals and not group.alive,
                      str(group.signals))

    print(f"security-timeout: {'PASS' if failures == 0 else 'FAIL'} "
          f"({failures} failed checks)")
    return 0 if failures == 0 else 1


def pid_alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def focused():
    """Live smoke: the real wrapper on a command with a background descendant."""
    wrapper = load_wrapper()
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        pidfile = pathlib.Path(tmp) / "pids"
        log_path = os.path.join(tmp, "bounded.log")
        script = (
            f"echo $$ > {pidfile}; sleep 30 & echo $! >> {pidfile}; wait"
        )
        result = wrapper.run(["bash", "-c", script], 1.0, 1.0, log_path)
        failures += check("live timeout kind", result.kind == "timeout", result.kind)
        failures += check("live timeout code", result.code == 124, str(result.code))
        failures += check("live log exists", os.path.exists(log_path))
        # The command writes its own and its descendant's pid immediately.
        pids = []
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and len(pids) < 2:
            if pidfile.exists():
                pids = [int(x) for x in pidfile.read_text().split()]
            if len(pids) < 2:
                time.sleep(0.05)
        failures += check("live descendant recorded its pid", len(pids) == 2, str(pids))
        gone = True
        for pid in pids:
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and pid_alive(pid):
                time.sleep(0.05)
            if pid_alive(pid):
                gone = False
                print(f"FAIL live descendant {pid} survived the timeout")
                failures += 1
        if pids and gone:
            failures += check("live descendants terminated", True)

    print(f"security-timeout: focused {'PASS' if failures == 0 else 'FAIL'} "
          f"({failures} failed checks)")
    return 0 if failures == 0 else 1


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--focused", action="store_true",
                    help="run the live descendant smoke instead of fake controls")
    args = ap.parse_args(argv)
    if args.focused:
        return focused()
    return fake_controls()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
