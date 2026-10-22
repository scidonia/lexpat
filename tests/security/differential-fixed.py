#!/usr/bin/env python3
"""Replay every declared differential exception through the same comparator.

`tests/security-differential-fixed.sh` builds the unsanitized
`differential-replay` binary and invokes this driver. Each manifest row names
one fixed corpus case; the driver materializes its exact input and runs one
`--compare both` invocation of the shared two-library `dlopen` comparator, so
the candidate and the oracle are loaded and called together in a single
process. It asserts:

  * the candidate's outcome equals that case's exact `expected` object;
  * the oracle's outcome equals that case's exact `reference` object;
  * the two outcomes still differ.

An exception that stops differing, a row that no longer resolves to a corpus
exception, or any event/code drift is a failure. No heuristic classifies a
difference.
"""

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def load_harness():
    path = ROOT / "tests" / "c-abi-differential.py"
    spec = importlib.util.spec_from_file_location("c_abi_differential", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


D = load_harness()

MANIFEST = ROOT / "tests" / "security" / "differential-exceptions.json"
CORPUS = ROOT / "tests" / "corpus" / "cases.json"
CANDIDATE = ROOT / ".lake" / "build" / "lib" / "liblexpat.so.1"


class ReplayError(Exception):
    pass


def need(condition, message):
    if not condition:
        raise ReplayError(message)


def expected_outcome(spec):
    events, result = D.expand_expected(spec)
    if result["ok"]:
        return ("accept", events)
    code = D.ERROR_CODES.get(result["code"])
    need(code is not None, f"unknown expected error code {result['code']}")
    return ("reject", code)


def parse_side(line, case_name):
    prefix, separator, payload = line.partition(" ")
    need(prefix in ("candidate", "oracle") and separator,
         f"{case_name}: the comparator emitted an unprefixed line: "
         f"{line[:120]}")
    return prefix, payload


def run_both(binary, path):
    """Run the shared comparator once, which records both sides in one process."""
    env = dict(os.environ)
    env["LEXPAT_DIFF_CANDIDATE"] = str(CANDIDATE)
    result = subprocess.run([str(binary), "--compare", "both", str(path)],
                            capture_output=True, text=True, env=env, cwd=ROOT)
    if result.returncode != 0:
        raise ReplayError(f"comparison failed with {result.returncode}:\n"
                          + result.stderr[-2000:])
    lines = {"candidate": [], "oracle": []}
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        side, payload = parse_side(line, path.name)
        lines[side].append(payload)
    outcomes = {}
    for side in ("candidate", "oracle"):
        need(lines[side], f"{path.name}: the comparator emitted no {side} output")
        events, outcome = D.parse_output("\n".join(lines[side]), side, path.name)
        if outcome["ok"]:
            outcomes[side] = ("accept", D.to_fixture(events))
        else:
            outcomes[side] = ("reject", outcome["code"])
    return outcomes["candidate"], outcomes["oracle"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replay", required=True,
                        help="path to the differential-replay binary")
    parser.add_argument("--out", required=True,
                        help="directory for replay logs")
    args = parser.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    replay = Path(args.replay)

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    need(manifest.get("format") == 1, "the exception manifest must carry format 1")
    rows = manifest["cases"]
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    by_id = {case["id"]: case for case in corpus["cases"]}
    exceptions = {case["id"] for case in corpus["cases"] if "exception" in case}
    need(sorted(row["case"] for row in rows) == sorted(exceptions),
         "the manifest does not account for exactly the corpus exceptions")

    lines = []
    with tempfile.TemporaryDirectory(prefix="lexpat-diff-fixed-", dir="/tmp") as tmp:
        tmp_path = Path(tmp)
        for row in rows:
            case_id = row["case"]
            need(case_id in by_id, f"{case_id}: unresolved corpus case")
            case = by_id[case_id]
            need("exception" in case, f"{case_id}: row is not a declared exception")
            need(row.get("reason"), f"{case_id}: missing reason")
            need(row.get("candidate") == "corpus:expected",
                 f"{case_id}: candidate outcome is not bound to the corpus expectation")
            need(row.get("oracle") == "corpus:reference",
                 f"{case_id}: oracle outcome is not bound to the corpus reference")
            need("expected" in case and "reference" in case,
                 f"{case_id}: the corpus row lacks one exact outcome")

            data = D.materialize(case)
            path = tmp_path / f"{case_id}.bin"
            path.write_bytes(data)
            candidate, oracle = run_both(replay, path)
            want_candidate = expected_outcome(case["expected"])
            want_oracle = expected_outcome(case["reference"])
            need(candidate == want_candidate,
                 f"{case_id}: candidate outcome {candidate[0]} does not match its "
                 f"exact expectation {want_candidate[0]}")
            need(oracle == want_oracle,
                 f"{case_id}: oracle outcome {oracle[0]} does not match its "
                 f"exact expectation {want_oracle[0]}")
            need(candidate != oracle,
                 f"{case_id}: the declared difference no longer holds")
            kind = ("reject" if candidate[0] == "reject"
                    else "accept")
            other = ("reject" if oracle[0] == "reject" else "accept")
            line = (f"PASS {case_id}: candidate {kind} {candidate[1]}, "
                    f"oracle {other} {oracle[1]}")
            print(line)
            lines.append(line)

    (out / "replay.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"OK: {len(rows)} declared exceptions differ exactly as recorded")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ReplayError, D.HarnessError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
