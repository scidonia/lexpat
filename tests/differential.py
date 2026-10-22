#!/usr/bin/env python3
"""Differential check: lexpat against the system libexpat oracle.

Reads `tests/corpus/cases.json`, materialises each case's input in a private
temporary directory, runs `lexpatTrace` and a freshly compiled
`tests/reference.c`, and compares:

  * accepted documents: the ordered events `lexpatTrace` emits, normalized
    (adjacent text coalesced, attribute sets canonicalized by raw name), must
    equal the fixture's expected events; the oracle's events must match its own
    declared expectation independently;
  * rejected documents: accept/reject and the semantic error code on both
    sides, plus the exact internal reason for Lean.

Every fixture expectation is asserted on both sides independently. Rows that
declare an intentional difference (`exception`) must actually differ, and the
reason is printed; an exception that no longer holds is a failure, never a
silent skip. Three negative controls run through the same Lean-outcome
comparison: an unmutated trace must compare equal, a mutated event field must be
detected, and a flipped accept flag must be detected in both directions.

Only the Python standard library is used. No network, LLM, clock or live
service is contacted: libexpat is a local test oracle, never linked into the
Lean library or its executable.
"""

import argparse
import copy
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASES_PATH = ROOT / "tests" / "corpus" / "cases.json"
TRACE_BIN = ROOT / ".lake" / "build" / "bin" / "lexpatTrace"
REFERENCE_SRC = ROOT / "tests" / "reference.c"


class HarnessError(Exception):
    pass


def run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def build_reference(tmp_dir):
    """Compile the C oracle. Prefer plain -lexpat; fall back to pkg-config."""
    exe = tmp_dir / "reference"
    base = [
        "cc",
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        str(REFERENCE_SRC),
    ]
    result = run(base + ["-lexpat", "-o", str(exe)])
    if result.returncode == 0:
        return exe, None
    pkg = run(["pkg-config", "--cflags", "--libs", "expat"])
    if pkg.returncode != 0:
        raise HarnessError(
            "cannot link libexpat: -lexpat failed and pkg-config found no expat\n"
            + result.stderr
        )
    flags = pkg.stdout.split()
    result = run(base + flags + ["-o", str(exe)])
    if result.returncode != 0:
        raise HarnessError("cannot compile tests/reference.c:\n" + result.stderr)
    return exe, "linked via pkg-config --cflags --libs expat"


def build_trace(no_build):
    if no_build:
        if not TRACE_BIN.exists():
            raise HarnessError(f"{TRACE_BIN} is missing; run without --no-build")
        return
    result = run(["lake", "build", "lexpatTrace"], cwd=ROOT)
    if result.returncode != 0:
        raise HarnessError("lake build lexpatTrace failed:\n" + result.stdout + result.stderr)
    if not TRACE_BIN.exists():
        raise HarnessError(f"{TRACE_BIN} was not produced")


def parse_trace(text, who, case_id):
    events = []
    result = None
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise HarnessError(f"{case_id}: {who} output line {lineno} is not JSON: {exc}")
        if obj.get("format") != 1:
            raise HarnessError(f"{case_id}: {who} line {lineno} lacks \"format\":1")
        if obj.get("type") == "result":
            if result is not None:
                raise HarnessError(f"{case_id}: {who} emitted two result objects")
            result = obj
        else:
            events.append(obj)
    if result is None:
        raise HarnessError(f"{case_id}: {who} emitted no result object")
    return events, result


def coalesce(events):
    """Merge adjacent text events; drop empty text."""
    out = []
    for ev in events:
        if ev.get("type") == "text":
            if ev.get("data", "") == "":
                continue
            if out and out[-1].get("type") == "text":
                out[-1] = dict(out[-1], data=out[-1]["data"] + ev["data"])
                continue
            out.append(dict(ev))
        else:
            out.append(dict(ev))
    return out


def normalize_events(events):
    """Coalesce adjacent text and canonicalize every attribute set.

    The core event keeps attributes in document order and the rendered trace
    sorts them; comparison canonicalizes each attribute set to raw-name order so
    the two sides are compared as sets. Event order stays document order.
    """
    normalized = []
    for ev in coalesce(events):
        attrs = ev.get("attributes")
        if attrs is not None:
            pairs = attrs.items() if isinstance(attrs, dict) else attrs
            ev = dict(ev, attributes=[[k, v] for k, v in sorted(pairs)])
        normalized.append(ev)
    return normalized


def first_event_difference(actual, expected):
    """Describe the first place two normalized event lists differ."""
    for index, (a, e) in enumerate(zip(actual, expected)):
        if a != e:
            return (f"event {index}: {json.dumps(a, sort_keys=True)} != "
                    f"{json.dumps(e, sort_keys=True)}")
    if len(actual) != len(expected):
        return f"{len(actual)} events != {len(expected)} events"
    return "no difference"


def expand_text(events):
    expanded = []
    for ev in events:
        if ev.get("type") == "text" and "dataRepeat" in ev:
            rep = ev["dataRepeat"]
            ev = {k: v for k, v in ev.items() if k != "dataRepeat"}
            ev["data"] = rep["char"] * rep["count"]
        expanded.append(ev)
    return expanded


def expand_expected(spec):
    """Return (events, result dictionary as the trace would carry it)."""
    if "repeatEvents" in spec:
        rep = spec["repeatEvents"]
        template = expand_text(rep["events"])
        events = expand_text(spec.get("openingEvents", []))
        events += [copy.deepcopy(ev) for _ in range(rep["count"]) for ev in template]
        events += expand_text(rep.get("extraEvents", []))
        events += expand_text(spec.get("closingEvents", []))
    elif "nestingEvents" in spec:
        depth = spec["nestingEvents"]["depth"]
        events = [{"format": 1, "type": "start", "name": "e", "attributes": {}}
                  for _ in range(depth)]
        events += [{"format": 1, "type": "end", "name": "e"} for _ in range(depth)]
    else:
        events = expand_text(spec.get("events", []))
    if spec["ok"]:
        result = {"format": 1, "type": "result", "ok": True}
    else:
        result = {
            "format": 1,
            "type": "result",
            "ok": False,
            "code": spec["code"],
            "reason": spec.get("reason", ""),
        }
    return events, result


def expected_from_file(path):
    text = (ROOT / path).read_text(encoding="utf-8")
    events, result = parse_trace(text, "fixture " + path, path)
    if not result["ok"]:
        if "code" not in result or "reason" not in result:
            raise HarnessError(f"{path}: rejected result needs code and reason")
        spec = {"ok": False, "code": result["code"], "reason": result["reason"]}
    else:
        spec = {"ok": True}
    return events, spec


def outcome_of(result, events):
    """A comparable outcome: accepted with normalized events, or rejected with a code."""
    if result["ok"]:
        return {"ok": True, "events": normalize_events(events)}
    return {"ok": False, "code": result.get("code")}


def outcome_matches(actual, expected):
    if bool(actual["ok"]) != bool(expected["ok"]):
        return False
    if actual["ok"]:
        return actual.get("events") == expected.get("events")
    return actual.get("code") == expected.get("code")


def check_lean(case_id, lean_result, lean_events, spec, expected_events):
    """Assert the Lean outcome, including decoded events, against the fixture.

    This is the single comparison path for the Lean side: accepted documents are
    compared event by event, rejections by code and exact reason. The negative
    controls in `negative_controls` call this function too.
    """
    actual = outcome_of(lean_result, lean_events)
    expected = lean_outcome_of(spec, expected_events)
    if actual["ok"] != expected["ok"]:
        if expected["ok"]:
            raise HarnessError(
                f"{case_id}: Lean rejected an accepted fixture: "
                f"{actual.get('code')} / {lean_result.get('reason')}"
            )
        raise HarnessError(f"{case_id}: Lean accepted a rejected fixture")
    if expected["ok"]:
        if actual["events"] != expected["events"]:
            raise HarnessError(
                f"{case_id}: Lean events differ from the fixture: "
                + first_event_difference(actual["events"], expected["events"])
            )
        return
    if actual.get("code") != expected["code"]:
        raise HarnessError(
            f"{case_id}: Lean code {actual.get('code')} != expected {expected['code']}"
        )
    if lean_result.get("reason") != spec["reason"]:
        raise HarnessError(
            f"{case_id}: Lean reason {lean_result.get('reason')} != expected {spec['reason']}"
        )


def materialize(case, tmp_dir):
    if "file" in case:
        return (ROOT / case["file"]).read_bytes()
    if "hex" in case:
        return bytes.fromhex(case["hex"])
    if "pattern" in case:
        p = case["pattern"]
        return (
            bytes.fromhex(p["prefix"])
            + bytes([int(p["repeatByte"], 16)]) * p["repeatCount"]
            + bytes.fromhex(p["suffix"])
        )
    if "nested" in case:
        depth = case["nested"]["depth"]
        return b"<e>" * depth + b"</e>" * depth
    if "refs" in case:
        r = case["refs"]
        count, per_text = r["count"], r["perText"]
        full, rem = divmod(count, per_text)
        out = bytearray(b"<root>")
        for _ in range(full):
            out += b"<e>" + b"&#65;" * per_text + b"</e>"
        if rem:
            out += b"<e>" + b"&#65;" * rem + b"</e>"
        out += b"</root>"
        return bytes(out)
    raise HarnessError(f"{case['id']}: no input form")


def run_lean(case, tmp_dir):
    """Materialize one case, run `lexpatTrace`, and parse its trace."""
    case_id = case["id"]
    input_path = tmp_dir / f"{case_id}.bin"
    input_path.write_bytes(materialize(case, tmp_dir))
    lean_run = run([str(TRACE_BIN), str(input_path)])
    if lean_run.returncode not in (0, 1):
        raise HarnessError(
            f"{case_id}: lexpatTrace exit {lean_run.returncode}: {lean_run.stderr}"
        )
    events, result = parse_trace(lean_run.stdout, "lean", case_id)
    return input_path, lean_run, events, result


def reference_expected(case, expected_events, expected_spec):
    """The oracle's declared outcome, defaulting to the Lean expectation."""
    if "reference" in case:
        spec = case["reference"]
        ref_events, _ = expand_expected(spec)
        return {"ok": spec["ok"],
                "events": normalize_events(ref_events) if spec["ok"] else None,
                "code": spec.get("code")}
    return {"ok": expected_spec["ok"],
            "events": normalize_events(expected_events) if expected_spec["ok"] else None,
            "code": expected_spec.get("code")}


def negative_controls(accepted, rejected):
    """Prove the Lean-outcome comparison is not vacuous.

    Both samples are real Lean outputs from the current run. The affirmative
    control re-runs the unmutated comparison; the other two change what Lean
    reported and require `check_lean` to reject it.
    """
    if accepted is None or rejected is None:
        raise HarnessError("negative controls need one accepted and one rejected case")
    accepted_id, accepted_result, accepted_events, accepted_spec, accepted_expected = accepted
    rejected_id, rejected_result, rejected_events, rejected_spec, rejected_expected = rejected

    # Control 0: the unmutated Lean trace compares equal, so a later failure is
    # the mutation's and not a standing disagreement.
    check_lean(accepted_id, accepted_result, accepted_events,
               accepted_spec, accepted_expected)
    print(f"CONTROL unmutated: Lean events for {accepted_id} compare equal to the fixture")

    # Control 1: change one event field in the Lean events. The same comparison
    # must notice.
    mutated = copy.deepcopy(accepted_events)
    mutated_index = None
    for i, ev in enumerate(mutated):
        if ev.get("type") in ("start", "end"):
            mutated[i] = dict(ev, name=ev["name"] + "-mutated")
            mutated_index = i
            break
    if mutated_index is None:
        raise HarnessError("negative control found no name-bearing event")
    try:
        check_lean(accepted_id, accepted_result, mutated,
                   accepted_spec, accepted_expected)
    except HarnessError:
        pass
    else:
        raise HarnessError("control: field mutation was not detected")
    print(f"CONTROL field-mutation: Lean event {mutated_index} name changed; "
          "comparator detected it")

    # Control 2: flip the accept flag in both directions.
    flipped_rejected = {"format": 1, "type": "result", "ok": False,
                        "code": "INVALID_TOKEN", "reason": "invalidToken"}
    flipped_accepted = {"format": 1, "type": "result", "ok": True}
    detected = 0
    for case in (
        (accepted_id, flipped_rejected, accepted_events, accepted_spec, accepted_expected),
        (rejected_id, flipped_accepted, rejected_events, rejected_spec, rejected_expected),
    ):
        try:
            check_lean(*case)
        except HarnessError:
            detected += 1
    if detected != 2:
        raise HarnessError("control: accept/reject flip was not detected")
    print("CONTROL accept-flip: accepted->rejected and rejected->accepted both detected")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group", help="only run cases in this group")
    parser.add_argument("--no-build", action="store_true",
                        help="use the existing .lake/build/bin/lexpatTrace")
    args = parser.parse_args()

    build_trace(args.no_build)

    if not CASES_PATH.exists():
        raise HarnessError(f"missing {CASES_PATH}")

    document = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    if document.get("format") != 1:
        raise HarnessError("cases.json must carry \"format\":1")
    cases = document["cases"]
    for case in cases:
        if "expectedFile" in case:
            events, spec = expected_from_file(case["expectedFile"])
        else:
            events, spec = expand_expected(case["expected"])
        case["_expected"] = (events, spec)

    groups = sorted({case["group"] for case in cases})
    selected = cases
    if args.group:
        if args.group not in groups:
            raise HarnessError(f"unknown group {args.group!r}; groups: {', '.join(groups)}")
        selected = [case for case in cases if case["group"] == args.group]

    with tempfile.TemporaryDirectory(prefix="lexpat-m1-", dir="/tmp") as tmp_name:
        tmp_dir = Path(tmp_name)
        reference, deviation = build_reference(tmp_dir)
        if deviation:
            print(f"NOTE: reference build deviation: {deviation}")

        version = run([str(reference), "--version"]).stdout.strip()
        pkg_version = run(["pkg-config", "--modversion", "expat"]).stdout.strip()
        if version != "expat_2.8.5" or pkg_version != "2.8.5":
            raise HarnessError(
                "the differential requires the pinned libexpat 2.8.5 reference; "
                f"got {version} (pkg-config {pkg_version})")
        print(f"reference: {version} (pkg-config expat {pkg_version})")
        print(f"cases: {len(selected)} of {len(cases)} (groups: {', '.join(groups)})")

        exceptions = []
        accepted_sample = None
        rejected_sample = None
        for case in selected:
            case_id = case["id"]
            input_path, lean_run, lean_events, lean_result = run_lean(case, tmp_dir)
            ref_run = run([str(reference), str(input_path)])
            if ref_run.returncode not in (0, 1):
                raise HarnessError(
                    f"{case_id}: reference exit {ref_run.returncode}: {ref_run.stderr}"
                )
            ref_events, ref_result = parse_trace(ref_run.stdout, "reference", case_id)

            events, spec = case["_expected"]
            check_lean(case_id, lean_result, lean_events, spec, events)
            if accepted_sample is None and spec["ok"] and lean_events:
                accepted_sample = (case_id, lean_result, lean_events, spec, events)
            if rejected_sample is None and not spec["ok"]:
                rejected_sample = (case_id, lean_result, lean_events, spec, events)

            if "expectedFile" in case and case.get("exactTrace"):
                produced = lean_run.stdout
                shipped = (ROOT / case["expectedFile"]).read_text(encoding="utf-8")
                if produced != shipped:
                    raise HarnessError(
                        f"{case_id}: Lean trace bytes differ from {case['expectedFile']}"
                    )

            ref_expected = reference_expected(case, events, spec)
            actual_ref = outcome_of(ref_result, ref_events)
            if not outcome_matches(actual_ref, ref_expected):
                raise HarnessError(
                    f"{case_id}: reference outcome {actual_ref} != declared {ref_expected}"
                )

            if "exception" in case:
                lean_outcome = lean_outcome_of(spec, events)
                if outcome_matches(actual_ref, lean_outcome):
                    raise HarnessError(
                        f"{case_id}: declared exception no longer differs: {case['exception']}"
                    )
                exceptions.append((case_id, case["exception"]))
                print(f"PASS [{case['group']}] {case_id}: "
                      f"declared exception differs (exception)")
            else:
                if not outcome_matches(actual_ref, lean_outcome_of(spec, events)):
                    raise HarnessError(f"{case_id}: reference outcome differs from fixture")
                print(f"PASS [{case['group']}] {case_id}: "
                      f"{'accepted' if spec['ok'] else 'rejected ' + spec['code']}")

        def control_sample(wanted_ok):
            """A real Lean outcome for the controls, from the corpus if needed."""
            for candidate in cases:
                candidate_events, candidate_spec = candidate["_expected"]
                if candidate_spec["ok"] != wanted_ok:
                    continue
                if wanted_ok and not candidate_events:
                    continue
                _, _, sample_events, sample_result = run_lean(candidate, tmp_dir)
                return (candidate["id"], sample_result, sample_events,
                        candidate_spec, candidate_events)
            raise HarnessError("negative controls need an accepted and a rejected case")

        if accepted_sample is None:
            accepted_sample = control_sample(True)
        if rejected_sample is None:
            rejected_sample = control_sample(False)
        negative_controls(accepted_sample, rejected_sample)
        if exceptions:
            print("intentional differences:")
            for case_id, reason in exceptions:
                print(f"  {case_id}: {reason}")
        print(f"OK: {len(selected)} cases matched")
        return 0


def lean_outcome_of(spec, events):
    if spec["ok"]:
        return {"ok": True, "events": normalize_events(events)}
    return {"ok": False, "code": spec["code"]}


if __name__ == "__main__":
    try:
        sys.exit(main())
    except HarnessError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
