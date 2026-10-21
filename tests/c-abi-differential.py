#!/usr/bin/env python3
"""Differential check for the C ABI call surface.

One source, `tests/c-abi-client.c`, is compiled twice: against
`include/expat.h` and `.lake/build/lib/liblexpat.so.1`, and against the dev
shell's system Expat header and library. Both clients run over every input in
`tests/corpus/cases.json` on identical bytes, under the same partitions, and
their supported-subset outcomes are compared.

What is compared:

  * accepted documents: event order, payloads and attribute order, with
    adjacent text coalesced (never across a CDATA boundary) because the two
    implementations split character data at different points;
  * rejected documents: accept/reject and the numeric error code, for the
    codes both headers define; lexpat's named extensions above 44 can only
    appear on rows the manifest declares as intentional differences;
  * every callback is delivered while a parse call is active, on both sides;
  * fixture expectations from `tests/corpus/cases.json` are asserted on the
    candidate and on the reference independently, so neither side is merely
    compared with the other;
  * callback-time byte index, line and column are asserted against explicitly
    authored expectations for representative UTF-8, UTF-16, BOM, CRLF,
    reference, CDATA and empty-tag cases, with the per-case differences
    declared in `LOCATIONS`;
  * a prefix-timing case shows the candidate's per-token callback timing
    against independently stated per-call counts, and records the system
    Expat's deferral as a declared difference;
  * the buffer entry points are exercised over the corpus through
    `XML_GetBuffer`/`XML_ParseBuffer`.

Rows with an `exception` reason in the manifest must actually differ between
the candidate and the reference, and the reason is printed; an exception that
stops differing is a failure. Negative controls mutate an event field, flip an
accept flag and make an exception row stop differing, so the comparisons are
shown to observe what they claim.

Fixtures are materialised in a private `TemporaryDirectory` under `/tmp`. No
network, clock, model or live service is contacted; libexpat is a local test
oracle and is never linked into the C ABI artifact.
"""

import argparse
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASES_PATH = ROOT / "tests" / "corpus" / "cases.json"
CLIENT_SRC = ROOT / "tests" / "c-abi-client.c"
HEADER = ROOT / "include" / "expat.h"
LIB_DIR = ROOT / ".lake" / "build" / "lib"
LIB = LIB_DIR / "liblexpat.so.1"

# Partitions applied to every case. `byte` is single-byte feeding; `fixed:7`
# splits tokens at every position class; the seeded partition uses the same
# rule as `tests/streaming.py` (one LCG step per feed, length 1 + s mod N).
PARTITIONS = ["whole", "byte", "fixed:7", "seeded:13:{seed}"]
BUFFER_PARTITIONS = ["whole", "fixed:4096"]

# `XML_GetBuffer` refuses a reservation larger than the remaining input budget
# before any parse call, so an over-budget document reports the request-boundary
# refusal rather than the parse-budget code. The same document through
# `XML_Parse` reports LIMIT_INPUT. Both are fail-closed refusals; the buffer
# expectation is stated here rather than derived from either client.
BUFFER_FIXTURE_CODES = {"limit-input-over": "INVALID_ARGUMENT"}


class HarnessError(Exception):
    pass


def run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def parse_enum(header_path, name):
    """Read one enum's enumerator names and values from a C header.

    Only plain `NAME` and `NAME = N` forms are used by the headers this check
    reads, so a tiny scanner is enough and a change in shape fails loudly.
    """
    text = header_path.read_text(encoding="utf-8")
    marker = "enum " + name + " {"
    start = text.index(marker) + len(marker)
    depth = 1
    values = {}
    token = ""
    next_value = 0
    index = start
    while index < len(text) and depth > 0:
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                break
        elif char == "," or char == "\n":
            entry = token.strip()
            if entry and not entry.startswith("/*") and not entry.startswith("//"):
                if "=" in entry:
                    label, raw = entry.split("=", 1)
                    label = label.strip()
                    value = int(raw.strip(), 0)
                else:
                    label = entry
                    value = next_value
                values[label] = value
                next_value = value + 1
            token = ""
            index += 1
            continue
        elif char == "/" and text[index:index + 2] == "/*":
            close = text.index("*/", index)
            index = close + 2
            continue
        token += char
        index += 1
    if not values:
        raise HarnessError(f"no enumerators found in enum {name}")
    return values


ERROR_CODES = {name.removeprefix("XML_ERROR_") if name.startswith("XML_ERROR_") else name: value
               for name, value in parse_enum(HEADER, "XML_Error").items()}


def build_artifact(no_build):
    if no_build:
        if not LIB.exists():
            raise HarnessError(f"{LIB} is missing; run without --no-build")
        return
    result = run(["lake", "build", "lexpatCAbi"], cwd=ROOT)
    if result.returncode != 0:
        raise HarnessError("lake build lexpatCAbi failed:\n" + result.stdout + result.stderr)
    if not LIB.exists():
        raise HarnessError(f"{LIB} was not produced")


def build_clients(tmp_dir):
    candidate = tmp_dir / "lexpat-client"
    result = run([
        "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
        f"-I{ROOT / 'include'}", str(CLIENT_SRC),
        f"-L{LIB_DIR}", "-llexpat",
        f"-Wl,-rpath,{LIB_DIR}", "-o", str(candidate),
    ])
    if result.returncode != 0:
        raise HarnessError("cannot compile the candidate client:\n" + result.stderr)

    reference = tmp_dir / "expat-client"
    pkg = run(["pkg-config", "--cflags", "--libs", "expat"])
    if pkg.returncode != 0:
        raise HarnessError("pkg-config found no expat:\n" + pkg.stderr)
    flags = pkg.stdout.split()
    result = run([
        "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
        *flags, str(CLIENT_SRC), "-o", str(reference),
    ])
    if result.returncode != 0:
        raise HarnessError("cannot compile the reference client:\n" + result.stderr)
    return candidate, reference


def materialize(case):
    if "file" in case:
        return (ROOT / case["file"]).read_bytes()
    if "hex" in case:
        return bytes.fromhex(case["hex"])
    if "pattern" in case:
        p = case["pattern"]
        return (bytes.fromhex(p["prefix"]) + bytes([int(p["repeatByte"], 16)]) * p["repeatCount"]
                + bytes.fromhex(p["suffix"]))
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


def expand_text(events):
    expanded = []
    for event in events:
        if event.get("type") == "text" and "dataRepeat" in event:
            rep = event["dataRepeat"]
            event = {k: v for k, v in event.items() if k != "dataRepeat"}
            event["data"] = rep["char"] * rep["count"]
        expanded.append(event)
    return expanded


def expand_expected(spec):
    if "repeatEvents" in spec:
        rep = spec["repeatEvents"]
        template = expand_text(rep["events"])
        events = expand_text(spec.get("openingEvents", []))
        events += [copy.deepcopy(event) for _ in range(rep["count"]) for event in template]
        events += expand_text(rep.get("extraEvents", []))
        events += expand_text(spec.get("closingEvents", []))
    elif "nestingEvents" in spec:
        depth = spec["nestingEvents"]["depth"]
        events = [{"format": 1, "type": "start", "name": "e", "attributes": {}} for _ in range(depth)]
        events += [{"format": 1, "type": "end", "name": "e"} for _ in range(depth)]
    else:
        events = expand_text(spec.get("events", []))
    if spec["ok"]:
        result = {"ok": True}
    else:
        result = {"ok": False, "code": spec["code"]}
    return events, result


def expected_from_file(path):
    text = (ROOT / path).read_text(encoding="utf-8")
    events, result = parse_output(text, "fixture " + path, path)
    if result["ok"]:
        spec = {"ok": True}
    else:
        code = result.get("codeName", result.get("code"))
        if not isinstance(code, str):
            raise HarnessError(f"{path}: rejected fixture result needs a code name")
        spec = {"ok": False, "code": code}
    return events, spec


def parse_output(text, who, case_id):
    events = []
    result = None
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise HarnessError(f"{case_id}: {who} line {lineno} is not JSON: {exc}")
        if obj.get("format") != 1:
            raise HarnessError(f"{case_id}: {who} line {lineno} lacks \"format\":1")
        if obj.get("type") == "result":
            if result is not None:
                raise HarnessError(f"{case_id}: {who} emitted two result objects")
            result = obj
        elif obj.get("type") == "timing":
            raise HarnessError(f"{case_id}: {who} emitted timing output in parse mode")
        else:
            if result is not None:
                raise HarnessError(f"{case_id}: {who} emitted an event after the result")
            events.append(obj)
    if result is None:
        raise HarnessError(f"{case_id}: {who} emitted no result object")
    return events, result


def coalesce(events):
    """Merge adjacent text; keep the first text event's position and payloads.

    Never coalesces across a CDATA boundary: `cdataStart`/`cdataEnd` events
    separate the text runs.
    """
    out = []
    for event in events:
        if event.get("type") == "text":
            if out and out[-1].get("type") == "text":
                merged = dict(out[-1])
                merged["data"] = merged.get("data", "") + event.get("data", "")
                merged["length"] = merged.get("length", 0) + event.get("length", 0)
                out[-1] = merged
                continue
            out.append(dict(event))
        else:
            out.append(dict(event))
    return out


def to_fixture(events):
    """Drop callback positions and the ordered attribute pairs.

    The manifest is authored from the document, not from parser output: event
    order and payloads remain, while attributes compare as a name-keyed map.
    """
    converted = []
    for event in coalesce(events):
        event = {k: v for k, v in event.items()
                 if k not in ("byte", "line", "column", "specified", "length")}
        if "attributes" in event:
            event["attributes"] = {name: value for name, value in event["attributes"]}
        converted.append(event)
    return converted


def first_event_difference(actual, expected):
    for index, (a, e) in enumerate(zip(actual, expected)):
        if a != e:
            return (f"event {index}: {json.dumps(a, sort_keys=True)} != "
                    f"{json.dumps(e, sort_keys=True)}")
    if len(actual) != len(expected):
        return f"{len(actual)} events != {len(expected)} events"
    return "no difference"


def check_side(side, case_id, events, result, spec, expected_events, length,
               code_override=None):
    if result.get("outsideParse", 1) != 0:
        raise HarnessError(
            f"{case_id}: {side} delivered {result['outsideParse']} callbacks outside a parse call")
    expected_status = 1 if spec["ok"] else 0
    if result.get("status") != expected_status:
        raise HarnessError(
            f"{case_id}: {side} status {result.get('status')} != {expected_status}")
    if result.get("length") != length:
        raise HarnessError(
            f"{case_id}: {side} fed {result.get('length')} bytes, expected {length}")
    if bool(result.get("ok")) != bool(spec["ok"]):
        raise HarnessError(f"{case_id}: {side} accept/reject differs from the fixture")
    for index, event in enumerate(events):
        if event.get("type") == "start":
            pairs = len(event.get("attributes", []))
            if event.get("specified") != 2 * pairs:
                raise HarnessError(
                    f"{case_id}: {side} specified attribute count {event.get('specified')}"
                    f" != {2 * pairs} at event {index}")
    if spec["ok"]:
        actual = to_fixture(events)
        expected = [dict(event) for event in expected_events]
        if actual != expected:
            raise HarnessError(
                f"{case_id}: {side} events differ from the fixture: "
                + first_event_difference(actual, expected))
    else:
        name = code_override or spec["code"]
        want = ERROR_CODES.get(name)
        if want is None:
            raise HarnessError(f"{case_id}: unknown expected error code {name}")
        if result.get("code") != want:
            raise HarnessError(
                f"{case_id}: {side} code {result.get('code')} != {want} ({name})")


def outcome_of(events, result):
    if result.get("ok"):
        return {"ok": True, "events": comparable_events(events)}
    return {"ok": False, "code": result.get("code")}


def comparable_events(events):
    comparable = []
    for event in coalesce(events):
        event = {k: v for k, v in event.items() if k not in ("byte", "line", "column")}
        comparable.append(event)
    return comparable


def compare_sides(case_id, candidate, reference, is_exception):
    cand_events, cand_result = candidate
    ref_events, ref_result = reference
    cand = outcome_of(cand_events, cand_result)
    ref = outcome_of(ref_events, ref_result)
    if is_exception:
        differs = (cand["ok"] != ref["ok"]
                   or (not cand["ok"] and cand.get("code") != ref.get("code"))
                   or (cand["ok"] and cand.get("events") != ref.get("events")))
        if not differs:
            raise HarnessError(f"{case_id}: a declared exception no longer differs")
        return
    if cand["ok"] != ref["ok"]:
        raise HarnessError(
            f"{case_id}: candidate {'accepted' if cand['ok'] else 'rejected'} but the "
            f"reference {'accepted' if ref['ok'] else 'rejected'}")
    if cand["ok"]:
        if cand["events"] != ref["events"]:
            raise HarnessError(
                f"{case_id}: candidate and reference events differ: "
                + first_event_difference(cand["events"], ref["events"]))
    elif cand.get("code") != ref.get("code"):
        raise HarnessError(
            f"{case_id}: candidate code {cand.get('code')} != reference code {ref.get('code')}")


def reference_expectation(case, expected_events, expected_spec):
    if "reference" not in case:
        return expected_events, expected_spec
    events, spec = expand_expected(case["reference"])
    return events, spec


# Callback-time positions for representative cases, authored from the input
# bytes. Byte indexes are raw 0-based offsets, lines are 1-based and columns are
# 0-based scalar positions of the event's token opener; the candidate's
# documented differences are the empty-element end anchor (the opener, where
# Expat reports the position after the tag) and BOM columns (not counted by the
# candidate). Text entries are compared after adjacent text is coalesced.
LOCATIONS = {
    "enc-utf8-text": {
        "candidate": [("start", "a", 0, 1, 0), ("text", "\u20ac", 3, 1, 3),
                      ("end", "a", 6, 1, 4)],
        "reference": [("start", "a", 0, 1, 0), ("text", "\u20ac", 3, 1, 3),
                      ("end", "a", 6, 1, 4)],
    },
    "enc-utf8-bom": {
        "candidate": [("start", "a", 3, 1, 0), ("end", "a", 3, 1, 0)],
        "reference": [("start", "a", 3, 1, 1), ("end", "a", 7, 1, 5)],
    },
    "enc-utf16le-bom": {
        "candidate": [("start", "a", 2, 1, 0), ("end", "a", 2, 1, 0)],
        "reference": [("start", "a", 2, 1, 1), ("end", "a", 10, 1, 5)],
    },
    "enc-utf16be-bom": {
        "candidate": [("start", "a", 2, 1, 0), ("end", "a", 2, 1, 0)],
        "reference": [("start", "a", 2, 1, 1), ("end", "a", 10, 1, 5)],
    },
    "enc-utf16le-signature": {
        "candidate": [("start", "a", 0, 1, 0), ("end", "a", 0, 1, 0)],
        "reference": [("start", "a", 0, 1, 0), ("end", "a", 8, 1, 4)],
    },
    "xml-line-endings": {
        "candidate": [("start", "a", 0, 1, 0), ("text", "x\ny\nz\n", 3, 1, 3),
                      ("end", "a", 10, 4, 0)],
        "reference": [("start", "a", 0, 1, 0), ("text", "x\ny\nz\n", 3, 1, 3),
                      ("end", "a", 10, 4, 0)],
    },
    "xml-unicode-text": {
        "candidate": [("start", "a", 0, 1, 0), ("text", "\u00e9\U0001f600", 3, 1, 3),
                      ("end", "a", 9, 1, 5)],
        "reference": [("start", "a", 0, 1, 0), ("text", "\u00e9\U0001f600", 3, 1, 3),
                      ("end", "a", 9, 1, 5)],
    },
    "xml-refs": {
        "candidate": [("start", "a", 0, 1, 0), ("text", "&<>'\"AA", 3, 1, 3),
                      ("end", "a", 39, 1, 39)],
        "reference": [("start", "a", 0, 1, 0), ("text", "&<>'\"AA", 3, 1, 3),
                      ("end", "a", 39, 1, 39)],
    },
    "xml-empty-tags": {
        "candidate": [("start", "a", 0, 1, 0), ("start", "b", 3, 1, 3),
                      ("end", "b", 3, 1, 3), ("start", "c", 7, 1, 7),
                      ("end", "c", 10, 1, 10), ("end", "a", 14, 1, 14)],
        "reference": [("start", "a", 0, 1, 0), ("start", "b", 3, 1, 3),
                      ("end", "b", 7, 1, 7), ("start", "c", 7, 1, 7),
                      ("end", "c", 10, 1, 10), ("end", "a", 14, 1, 14)],
    },
    "xml-attr-spaced": {
        "candidate": [("start", "r", 0, 1, 0), ("end", "r", 0, 1, 0)],
        "reference": [("start", "r", 0, 1, 0), ("end", "r", 16, 1, 16)],
    },
    "enc-utf8-bom-decl": {
        "candidate": [("xmlDecl", None, 3, 1, 0), ("start", "a", 41, 1, 38),
                      ("end", "a", 41, 1, 38)],
        "reference": [("xmlDecl", None, 3, 1, 1), ("start", "a", 41, 1, 39),
                      ("end", "a", 45, 1, 43)],
    },
    "xml-cdata": {
        "candidate": [("start", "a", 0, 1, 0), ("cdataStart", None, 3, 1, 3),
                      ("text", "x", 12, 1, 12), ("cdataEnd", None, 13, 1, 13),
                      ("cdataStart", None, 16, 1, 16), ("cdataEnd", None, 25, 1, 25),
                      ("end", "a", 28, 1, 28)],
        "reference": [("start", "a", 0, 1, 0), ("cdataStart", None, 3, 1, 3),
                      ("text", "x", 12, 1, 12), ("cdataEnd", None, 13, 1, 13),
                      ("cdataStart", None, 16, 1, 16), ("cdataEnd", None, 25, 1, 25),
                      ("end", "a", 28, 1, 28)],
    },
    "xml-comment-pi": {
        "candidate": [("comment", "p", 0, 1, 0), ("pi", "d", 8, 1, 8),
                      ("start", "a", 16, 1, 16), ("comment", "c", 19, 1, 19),
                      ("pi", "", 27, 1, 27), ("end", "a", 32, 1, 32),
                      ("comment", "e", 36, 1, 36), ("pi", "", 44, 1, 44)],
        "reference": [("comment", "p", 0, 1, 0), ("pi", "d", 8, 1, 8),
                      ("start", "a", 16, 1, 16), ("comment", "c", 19, 1, 19),
                      ("pi", "", 27, 1, 27), ("end", "a", 32, 1, 32),
                      ("comment", "e", 36, 1, 36), ("pi", "", 44, 1, 44)],
    },
    "xml-namespace-raw": {
        "candidate": [("start", "p:a", 0, 1, 0), ("end", "p:a", 0, 1, 0)],
        "reference": [("start", "p:a", 0, 1, 0), ("end", "p:a", 26, 1, 26)],
    },
    "xml-standalone-yes": {
        "candidate": [("xmlDecl", None, 0, 1, 0), ("start", "a", 38, 1, 38),
                      ("end", "a", 38, 1, 38)],
        "reference": [("xmlDecl", None, 0, 1, 0), ("start", "a", 38, 1, 38),
                      ("end", "a", 42, 1, 42)],
    },
}


def event_identity(event):
    kind = event.get("type")
    if kind in ("start", "end"):
        return kind, event.get("name")
    if kind in ("text", "comment"):
        return kind, event.get("data")
    if kind == "pi":
        return kind, event.get("data")
    return kind, None


def check_locations(side, case_id, events, table):
    actual = [event_identity(event) for event in coalesce(events)]
    actual_positions = [(event["byte"], event["line"], event["column"])
                        for event in coalesce(events)]
    expected = [(kind, name) for kind, name, _, _, _ in table]
    if actual != expected:
        raise HarnessError(
            f"{case_id}: {side} location case events {actual} != {expected}")
    for index, (kind, name, byte, line, column) in enumerate(table):
        got = actual_positions[index]
        want = (byte, line, column)
        if got != want:
            raise HarnessError(
                f"{case_id}: {side} event {index} ({kind} {name!r}) position {got} != {want}")


def chunk_position_table(events):
    return [(event.get("type"), event.get("name"), event.get("data"),
             tuple(map(tuple, event.get("attributes", []))),
             event.get("byte"), event.get("line"), event.get("column"))
            for event in coalesce(events)]


def seeded_partition(case_id):
    seed = int.from_bytes(hashlib.sha256(case_id.encode()).digest()[:4], "big")
    return [partition.format(seed=seed) if "{seed}" in partition else partition
            for partition in PARTITIONS]


def run_case(binary, path, partition, use_buffer):
    cmd = [str(binary), "--parse", str(path), "--partition", partition]
    if use_buffer:
        cmd.append("--buffer")
    return run(cmd)


# Prefix timing: the document is fed as "<r", ">", "<c/", ">", "</r>". The
# candidate's per-token sink determines the `r` start at the byte that
# completes the tag; the system Expat defers that handler while the tag sits at
# the end of the supplied buffer. Both tables are stated here rather than
# derived from either run.
TIMING_STEPS = [("<r", 2), (">", 1), ("<c/", 3), (">", 1), ("</r>", 4)]
CANDIDATE_TIMING = [(0, 0, 0), (1, 0, 0), (1, 0, 0), (2, 1, 0), (2, 2, 0)]
REFERENCE_TIMING = [(0, 0, 0), (0, 0, 0), (1, 0, 0), (2, 1, 0), (2, 2, 0)]


def parse_timing(text, who):
    steps = []
    result = None
    for line in text.splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if obj.get("type") == "timing":
            steps.append(obj)
        elif obj.get("type") == "result":
            result = obj
        else:
            raise HarnessError(f"timing: {who} emitted {obj.get('type')}")
    if result is None:
        raise HarnessError(f"timing: {who} emitted no result")
    return steps, result


def check_timing(side, steps, result, expected):
    if result.get("outsideParse", 1) != 0:
        raise HarnessError(f"timing: {side} called back outside a parse call")
    if len(steps) != len(expected):
        raise HarnessError(f"timing: {side} produced {len(steps)} steps, expected {len(expected)}")
    for index, (step, want) in enumerate(zip(steps, expected)):
        if step.get("status") != 1:
            raise HarnessError(f"timing: {side} step {index} was not OK")
        if step.get("fed") != TIMING_STEPS[index][1]:
            raise HarnessError(f"timing: {side} step {index} fed {step.get('fed')}")
        got = (step.get("starts"), step.get("ends"), step.get("texts"))
        if got != want:
            raise HarnessError(f"timing: {side} step {index} counts {got} != {want}")
    if not result.get("ok"):
        raise HarnessError(f"timing: {side} final result was not ok")


def negative_controls(samples, filtered):
    accepted = samples["accepted"]
    rejected = samples["rejected"]
    exception = samples["exception"]
    pair = samples["accepted_pair"]
    if accepted is None or rejected is None or exception is None or pair is None:
        if filtered:
            print("NOTE controls: skipped because a required sample is outside the "
                  "selected group; run without --group for the control evidence")
            return
        raise HarnessError("negative controls need accepted, rejected and exception samples")

    case_id, events, result, spec, expected, length = accepted
    check_side("candidate", case_id, events, result, spec, expected, length)
    print(f"CONTROL unmutated: candidate events for {case_id} match the fixture")

    mutated = copy.deepcopy(events)
    mutated[0] = dict(mutated[0], name=mutated[0].get("name", "x") + "-mutated")
    try:
        check_side("candidate", case_id, mutated, result, spec, expected, length)
    except HarnessError:
        pass
    else:
        raise HarnessError("control: a mutated event name was not detected")
    print("CONTROL event-mutation: a changed start name was detected")

    flipped = dict(result, ok=not result.get("ok"), status=1 - result.get("status", 1))
    try:
        check_side("candidate", case_id, events, flipped, spec, expected, length)
    except HarnessError:
        pass
    else:
        raise HarnessError("control: a flipped accept flag was not detected")
    print("CONTROL accept-flip: a flipped accept flag was detected")

    exception_case, cand, ref, is_exception = exception
    compare_sides(exception_case, cand, ref, is_exception)
    try:
        compare_sides(exception_case, cand, cand, is_exception)
    except HarnessError:
        pass
    else:
        raise HarnessError("control: an exception that stopped differing was not detected")
    print(f"CONTROL exception: {exception_case} differs, and equality is rejected")

    case_id, cand, ref = pair
    mutated_events = copy.deepcopy(cand[0])
    mutated_events[0] = dict(mutated_events[0],
                             name=mutated_events[0].get("name", "x") + "-mutated")
    try:
        compare_sides(case_id, (mutated_events, cand[1]), ref, False)
    except HarnessError:
        pass
    else:
        raise HarnessError("control: the side-to-side comparator missed a name change")
    print("CONTROL side-mutation: the side-to-side comparator detected a name change")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group", help="only run cases in this group")
    parser.add_argument("--no-build", action="store_true",
                        help="use the existing .lake/build/lib/liblexpat.so.1")
    args = parser.parse_args()

    build_artifact(args.no_build)
    document = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    if document.get("format") != 1:
        raise HarnessError("cases.json must carry \"format\":1")
    cases = document["cases"]
    groups = sorted({case["group"] for case in cases})
    selected = cases
    if args.group:
        if args.group not in groups:
            raise HarnessError(f"unknown group {args.group!r}; groups: {', '.join(groups)}")
        selected = [case for case in cases if case["group"] == args.group]

    with tempfile.TemporaryDirectory(prefix="lexpat-cabi-", dir="/tmp") as tmp_name:
        tmp_dir = Path(tmp_name)
        candidate_bin, reference_bin = build_clients(tmp_dir)
        candidate_version = run([str(candidate_bin), "--version"]).stdout.strip()
        reference_version = run([str(reference_bin), "--version"]).stdout.strip()
        pkg_version = run(["pkg-config", "--modversion", "expat"]).stdout.strip()
        print(f"candidate: {candidate_version} ({LIB})")
        print(f"reference: {reference_version} (pkg-config expat {pkg_version})")
        print(f"cases: {len(selected)} of {len(cases)} (groups: {', '.join(groups)})")

        exceptions = []
        samples = {"accepted": None, "rejected": None, "exception": None,
                   "accepted_pair": None}

        for case in selected:
            case_id = case["id"]
            data = materialize(case)
            input_path = tmp_dir / f"{case_id}.bin"
            input_path.write_bytes(data)
            if "expectedFile" in case:
                expected_events, expected_spec = expected_from_file(case["expectedFile"])
            else:
                expected_events, expected_spec = expand_expected(case["expected"])
            ref_events_spec, ref_spec = reference_expectation(case, expected_events, expected_spec)
            is_exception = "exception" in case
            seed_partition = seeded_partition(case_id)

            whole_candidate = None
            for partition in seed_partition:
                cand_run = run_case(candidate_bin, input_path, partition, False)
                ref_run = run_case(reference_bin, input_path, partition, False)
                if cand_run.returncode not in (0, 1):
                    raise HarnessError(
                        f"{case_id}: candidate exit {cand_run.returncode}: {cand_run.stderr}")
                if ref_run.returncode not in (0, 1):
                    raise HarnessError(
                        f"{case_id}: reference exit {ref_run.returncode}: {ref_run.stderr}")
                cand_events, cand_result = parse_output(cand_run.stdout, "candidate", case_id)
                ref_events, ref_result = parse_output(ref_run.stdout, "reference", case_id)
                check_side("candidate", case_id, cand_events, cand_result,
                           expected_spec, expected_events, len(data))
                check_side("reference", case_id, ref_events, ref_result,
                           ref_spec, ref_events_spec, len(data))
                compare_sides(case_id, (cand_events, cand_result),
                              (ref_events, ref_result), is_exception)
                if partition == "whole":
                    whole_candidate = cand_events
                    if samples["accepted"] is None and expected_spec["ok"] and cand_events:
                        samples["accepted"] = (case_id, cand_events, cand_result,
                                               expected_spec, expected_events, len(data))
                    if samples["rejected"] is None and not expected_spec["ok"]:
                        samples["rejected"] = (case_id, cand_events, cand_result,
                                               expected_spec, expected_events, len(data))
                    if samples["exception"] is None and is_exception:
                        samples["exception"] = (case_id, (cand_events, cand_result),
                                                (ref_events, ref_result), True)
                    if samples["accepted_pair"] is None and expected_spec["ok"] and cand_events:
                        samples["accepted_pair"] = (case_id, (cand_events, cand_result),
                                                    (ref_events, ref_result))

            for partition in BUFFER_PARTITIONS:
                cand_run = run_case(candidate_bin, input_path, partition, True)
                ref_run = run_case(reference_bin, input_path, partition, True)
                if cand_run.returncode not in (0, 1):
                    raise HarnessError(
                        f"{case_id}: candidate buffer exit {cand_run.returncode}: "
                        + cand_run.stderr)
                if ref_run.returncode not in (0, 1):
                    raise HarnessError(
                        f"{case_id}: reference buffer exit {ref_run.returncode}: "
                        + ref_run.stderr)
                cand_events, cand_result = parse_output(cand_run.stdout, "candidate-buffer", case_id)
                ref_events, ref_result = parse_output(ref_run.stdout, "reference-buffer", case_id)
                override = BUFFER_FIXTURE_CODES.get(case_id)
                check_side("candidate", case_id, cand_events, cand_result,
                           expected_spec, expected_events, len(data), override)
                check_side("reference", case_id, ref_events, ref_result,
                           ref_spec, ref_events_spec, len(data))
                compare_sides(case_id, (cand_events, cand_result),
                              (ref_events, ref_result), is_exception)

            if case_id in LOCATIONS:
                table = LOCATIONS[case_id]
                cand_events, _ = parse_output(
                    run_case(candidate_bin, input_path, "whole", False).stdout,
                    "candidate", case_id)
                ref_events, _ = parse_output(
                    run_case(reference_bin, input_path, "whole", False).stdout,
                    "reference", case_id)
                check_locations("candidate", case_id, cand_events, table["candidate"])
                check_locations("reference", case_id, ref_events, table["reference"])
                if whole_candidate is not None:
                    whole = chunk_position_table(whole_candidate)
                    for partition in seeded_partition(case_id):
                        events, _ = parse_output(
                            run_case(candidate_bin, input_path, partition, False).stdout,
                            "candidate", case_id)
                        if chunk_position_table(events) != whole:
                            raise HarnessError(
                                f"{case_id}: candidate positions change under {partition}")

            if is_exception:
                exceptions.append((case_id, case["exception"]))
                print(f"PASS [{case['group']}] {case_id}: declared exception differs")
            else:
                print(f"PASS [{case['group']}] {case_id}: "
                      f"{'accepted' if expected_spec['ok'] else 'rejected ' + expected_spec['code']}")

        cand_timing = run([str(candidate_bin), "--timing"])
        ref_timing = run([str(reference_bin), "--timing"])
        if cand_timing.returncode != 0:
            raise HarnessError("candidate timing run failed:\n" + cand_timing.stderr)
        if ref_timing.returncode != 0:
            raise HarnessError("reference timing run failed:\n" + ref_timing.stderr)
        steps, result = parse_timing(cand_timing.stdout, "candidate")
        check_timing("candidate", steps, result, CANDIDATE_TIMING)
        ref_steps, ref_result = parse_timing(ref_timing.stdout, "reference")
        check_timing("reference", ref_steps, ref_result, REFERENCE_TIMING)
        print("PASS timing: candidate per-token callback counts and reference deferral match")
        mutated_timing = list(CANDIDATE_TIMING)
        mutated_timing[1] = (0, 0, 0)
        try:
            check_timing("control", steps, result, mutated_timing)
        except HarnessError:
            pass
        else:
            raise HarnessError("control: a changed timing expectation was not detected")
        print("CONTROL timing: a changed expected count was detected")
        print("NOTE timing: the system Expat defers the start callback while the tag is "
              "the last token in the buffer; the candidate reports it at the completing byte")

        negative_controls(samples, bool(args.group))
        if exceptions:
            print("intentional differences:")
            for case_id, reason in exceptions:
                print(f"  {case_id}: {reason}")
        print(f"OK: {len(selected)} cases matched over "
              f"{len(PARTITIONS)} parse partitions and {len(BUFFER_PARTITIONS)} buffer "
              f"partitions each, plus locations and timing")
        return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except HarnessError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
