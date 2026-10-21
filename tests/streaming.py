#!/usr/bin/env python3
"""Streaming behavior check: independently declared events under every chunking.

Runs `tests/StreamingCases.lean` for direct public-API assertions, then every
corpus case through `lexpatTrace`:

  * one-shot (the default trace), whole-input streaming and fixed chunk sizes
    1, 2, 3, 5, 7, 13 and 64;
  * one seeded partition with `--chunk-size 64 --chunk-seed SEED`, where SEED
    is the first four bytes of `sha256(case_id)` (stable and reproducible);
  * accepted documents must produce the exact terminal result of the one-shot
    trace under every partition, and the typed driver must match the
    independently declared expected events below;
  * rejected documents must produce the same `(code, reason)` as one-shot and
    the same emitted prefix as whole-input streaming (a one-shot rejection has
    no event array, so there is nothing else to compare it with);
  * the fixture's declared expectation is asserted for every partition through
    `differential.check_lean`, and the libexpat oracle's own declared outcome
    (including every `exception` row) is asserted once per case.

The expected raw events for `tests/StreamingEvents.lean`, built as
`lexpatEvents`, are expanded from the explicit event recipes in
`tests/corpus/cases.json`, never from parser output or a rendered trace. A row
whose input ships only as a trace (`expectedFile`) uses the explicit recipe of
a case with byte-identical materialized input, and is refused with a diagnostic
naming the missing recipe if there is none. Corpus recipes declare each start's
attribute values but not their order, so `tests/corpus/raw-attribute-order.json`
supplies the document order for every accepted start with two or more
attributes; a missing, extra, duplicate or non-permutation entry fails. The
harness writes the resulting typed events to a temporary JSON file and
`lexpatEvents` compares all nine partitions of every accepted case positionally
against it, with the one-shot `parseDocument` result as a secondary comparison.
That driver also runs an unmodified affirmative control and a reversed-expected
multi-attribute control through the same typed comparator.

The rendered trace sorts attributes into a JSON object, so it cannot observe
`Event.start`'s attribute order; the typed expected arrays above are the only
observation of it. The trace reader requires exactly one result object and
requires it to be the last object, so an event printed after the result is a
failure. Negative command-line cases assert exit status 2. Controls mutate an
accepted event payload, the terminal result, and the event/result order and
require the same comparators to detect each change.

Only the Python standard library and the local libexpat oracle are used; no
network, model, clock or live service is contacted.
"""

import argparse
import copy
import hashlib
import json
import sys
import tempfile
from pathlib import Path

import differential as D

ROOT = D.ROOT
EVENTS_BIN = ROOT / ".lake" / "build" / "bin" / "lexpatEvents"
ORDER_PATH = ROOT / "tests" / "corpus" / "raw-attribute-order.json"
SIZES = [1, 2, 3, 5, 7, 13, 64]
SEED_SIZE = 64
BLOCK = 65536
PARTITIONS = len(SIZES) + 2


class StreamingError(D.HarnessError):
    pass


def strict_trace(text, who, case_id):
    """Parse a trace and require the single result to be the final object."""
    events, result = D.parse_trace(text, who, case_id)
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        raise StreamingError(f"{case_id}: {who} produced no output")
    try:
        last = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        raise StreamingError(f"{case_id}: {who} last line is not JSON: {exc}")
    if last.get("type") != "result":
        raise StreamingError(
            f"{case_id}: {who} printed an object after the terminal result"
        )
    return events, result


def run_trace(args, case_id, who):
    result = D.run([str(D.TRACE_BIN)] + args)
    if result.returncode not in (0, 1):
        raise StreamingError(
            f"{case_id}: {who} exit {result.returncode}: {result.stderr}"
        )
    events, terminal = strict_trace(result.stdout, who, case_id)
    expected_exit = 0 if terminal.get("ok") else 1
    if result.returncode != expected_exit:
        raise StreamingError(
            f"{case_id}: {who} exit {result.returncode} but result says ok={terminal.get('ok')}"
        )
    return events, terminal, result.stdout


def run_driver(no_build):
    if no_build and not D.TRACE_BIN.exists():
        raise StreamingError(f"{D.TRACE_BIN} is missing; run without --no-build")
    result = D.run(["lake", "env", "lean", "--run", "tests/StreamingCases.lean"],
                   cwd=ROOT)
    if result.returncode != 0:
        raise StreamingError(
            "tests/StreamingCases.lean failed:\n" + result.stdout + result.stderr
        )
    print(result.stdout.strip())


def build_events(no_build):
    if no_build:
        if not EVENTS_BIN.exists():
            raise StreamingError(f"{EVENTS_BIN} is missing; run without --no-build")
        return
    result = D.run(["lake", "build", "lexpatEvents"], cwd=ROOT)
    if result.returncode != 0:
        raise StreamingError(
            "lake build lexpatEvents failed:\n" + result.stdout + result.stderr
        )
    if not EVENTS_BIN.exists():
        raise StreamingError(f"{EVENTS_BIN} was not produced")


def load_attribute_order():
    """The checked-in document order for every multi-attribute start."""
    document = json.loads(ORDER_PATH.read_text(encoding="utf-8"))
    if document.get("format") != 1:
        raise StreamingError(f"{ORDER_PATH.name} must carry \"format\":1")
    cases = document.get("cases")
    if not isinstance(cases, dict):
        raise StreamingError(f"{ORDER_PATH.name}: \"cases\" must be an object")
    order = {}
    for case_id, entries in cases.items():
        if not isinstance(entries, list):
            raise StreamingError(f"{ORDER_PATH.name}: {case_id} entries must be an array")
        seen = {}
        for entry in entries:
            if not isinstance(entry, dict):
                raise StreamingError(
                    f"{ORDER_PATH.name}: {case_id} entry {entry!r} is not an object")
            index = entry.get("eventIndex")
            keys = entry.get("keys")
            if not isinstance(index, int) or isinstance(index, bool) or index < 0:
                raise StreamingError(
                    f"{ORDER_PATH.name}: {case_id} needs a non-negative integer "
                    f"eventIndex: {entry!r}")
            if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
                raise StreamingError(
                    f"{ORDER_PATH.name}: {case_id} keys must be an array of strings: "
                    f"{entry!r}")
            if index in seen:
                raise StreamingError(
                    f"{ORDER_PATH.name}: {case_id} has a duplicate entry for event {index}")
            seen[index] = keys
        order[case_id] = seen
    return order


def fixture_recipe(case, cases, tmp_dir):
    """The explicit event recipe for a case that ships only a trace.

    The recipe must describe the same materialized input bytes. A trace file is
    never a source of expected events, and a missing recipe is refused instead
    of falling back to one.
    """
    data = D.materialize(case, tmp_dir)
    matches = [
        other for other in cases
        if other is not case and "expected" in other
        and D.materialize(other, tmp_dir) == data
    ]
    if not matches:
        raise StreamingError(
            f"{case['id']}: no explicit cases.json event recipe for its "
            f"{len(data)} input bytes; add one instead of deriving the expected "
            f"events from {case.get('expectedFile')}")
    if len(matches) > 1:
        ids = ", ".join(sorted(other["id"] for other in matches))
        raise StreamingError(
            f"{case['id']}: ambiguous event recipes for identical input bytes: {ids}")
    recipe = matches[0]
    return recipe, D.expand_expected(recipe["expected"])[0]


def ordered_attributes(case_id, index, attributes, keys):
    """Bind an ordered key list to the same indexed fixture event's values."""
    if not isinstance(attributes, dict):
        raise StreamingError(f"{case_id}: event {index} attributes is not an object")
    if keys is None:
        if len(attributes) > 1:
            raise StreamingError(
                f"{case_id}: event {index} has {len(attributes)} attributes and needs "
                f"{{\"eventIndex\": {index}, \"keys\": [...]}} in {ORDER_PATH.name}")
        keys = list(attributes)
    if (len(keys) != len(attributes) or len(set(keys)) != len(keys)
            or set(keys) != set(attributes)):
        raise StreamingError(
            f"{case_id}: event {index} keys {keys} are not a permutation of "
            f"{sorted(attributes)}")
    return [[key, attributes[key]] for key in keys]


def typed_events(case_id, events, order):
    """Convert one expanded fixture event array into typed expected events.

    Start attributes become an ordered array of key/value pairs, with the order
    taken from the checked-in overlay and the values from the same fixture
    event.
    """
    overlay = order.get(case_id, {})
    required = set()
    typed = []
    for index, event in enumerate(events):
        kind = event.get("type")
        if kind == "xmlDecl":
            version = event.get("version")
            encoding = event.get("encoding")
            standalone = event.get("standalone")
            if not isinstance(version, str):
                raise StreamingError(f"{case_id}: event {index} xmlDecl lacks a version")
            if not (encoding is None or isinstance(encoding, str)):
                raise StreamingError(f"{case_id}: event {index} xmlDecl has a bad encoding")
            if not (standalone is None or isinstance(standalone, bool)):
                raise StreamingError(f"{case_id}: event {index} xmlDecl has a bad standalone")
            typed.append({"type": "xmlDecl", "version": version,
                          "encoding": encoding, "standalone": standalone})
        elif kind == "start":
            attributes = event.get("attributes", {})
            if len(attributes) >= 2:
                required.add(index)
            typed.append({
                "type": "start",
                "name": event["name"],
                "attributes": ordered_attributes(
                    case_id, index, attributes, overlay.get(index)),
            })
        elif kind == "end":
            typed.append({"type": "end", "name": event["name"]})
        elif kind == "text":
            typed.append({"type": "text", "data": event["data"]})
        elif kind == "comment":
            typed.append({"type": "comment", "data": event["data"]})
        elif kind == "pi":
            typed.append({"type": "pi", "target": event["target"],
                          "data": event["data"]})
        elif kind in ("cdataStart", "cdataEnd"):
            typed.append({"type": kind})
        else:
            raise StreamingError(f"{case_id}: event {index} has unknown type {kind!r}")
    missing = sorted(required - set(overlay))
    if missing:
        raise StreamingError(
            f"{case_id}: missing order for multi-attribute event {missing[0]}; add "
            f"{{\"eventIndex\": {missing[0]}, \"keys\": [...]}} to {ORDER_PATH.name}")
    extra = sorted(set(overlay) - required)
    if extra:
        raise StreamingError(
            f"{case_id}: order entry for event {extra[0]} is not a multi-attribute "
            f"start; remove it from {ORDER_PATH.name}")
    return typed


def write_expected_events(tmp_dir, expected):
    path = tmp_dir / "expected-events.json"
    document = {"format": 1, "cases": expected}
    path.write_text(json.dumps(document, ensure_ascii=True, indent=1) + "\n",
                    encoding="utf-8")
    return path


def run_event_driver(expected_path, expected, accepted):
    """Compare every partition with the independently declared expected events.

    `expected` maps each accepted case ID to its typed expected `Array Event`;
    `lexpatEvents` reads the same arrays from `expected_path`, so the comparison
    never uses its own one-shot result as the expectation.
    """
    if len(expected) != len(accepted):
        raise StreamingError(
            f"{len(expected)} expected arrays for {len(accepted)} accepted inputs")
    args = [f"{case_id}={path}={seed}" for case_id, path, seed in accepted]
    result = D.run([str(EVENTS_BIN), "--expected", str(expected_path)] + args,
                   cwd=ROOT)
    if result.returncode != 0:
        raise StreamingError("lexpatEvents failed:\n" + result.stdout + result.stderr)

    summaries = []
    controls = {"expected-events": set(), "expected-attribute-order": set()}
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise StreamingError(f"lexpatEvents: unparsable line {line!r}: {exc}")
        if "control" in record:
            kind = record["control"]
            if kind not in controls:
                raise StreamingError(f"lexpatEvents: unknown control {kind!r}")
            if record.get("equal") is True or record.get("reversedDetected") is True:
                controls[kind].add(record["id"])
        else:
            summaries.append(record)

    multi_attribute = {
        case_id for case_id, events in expected.items()
        if any(event["type"] == "start" and len(event["attributes"]) >= 2
               for event in events)
    }
    for kind, seen in controls.items():
        if seen != multi_attribute:
            raise StreamingError(
                f"lexpatEvents: {kind} control ran for {sorted(seen)}, "
                f"expected the {len(multi_attribute)} multi-attribute cases "
                f"{sorted(multi_attribute)}")

    if len(summaries) != len(accepted):
        raise StreamingError(
            f"lexpatEvents: {len(summaries)} summaries for {len(accepted)} accepted inputs")
    for record, (case_id, _, _) in zip(summaries, accepted):
        if record.get("id") != case_id or record.get("ok") is not True:
            raise StreamingError(f"lexpatEvents: bad summary for {case_id}: {record}")
        if record.get("partitions") != PARTITIONS:
            raise StreamingError(
                f"lexpatEvents: {case_id} compared {record.get('partitions')} "
                f"partitions, expected {PARTITIONS}")

    total_events = sum(len(events) for events in expected.values())
    total_multi = sum(
        sum(1 for event in events
            if event["type"] == "start" and len(event["attributes"]) >= 2)
        for events in expected.values())
    print(
        f"events: {len(expected)}/{len(accepted)} accepted documents have independently "
        f"declared expected arrays; {len(accepted) * PARTITIONS} positional partition "
        f"comparisons plus {len(expected)} secondary one-shot comparisons; "
        f"{total_events} events, {total_multi} multi-attribute starts; controls: "
        f"unmodified equal and reversed expected attribute array detected for "
        f"{len(multi_attribute)} cases"
    )


def case_seed(case_id):
    """Stable seed from the case ID: the first four SHA-256 bytes, big-endian."""
    return int.from_bytes(hashlib.sha256(case_id.encode("utf-8")).digest()[:4], "big")


def seeded_splits(nbytes, size, seed):
    """Record the partition the seeded CLI mode will use, for failure reports."""
    prng = seed
    splits = []
    off = 0
    carry = 0
    while True:
        block = min(BLOCK, nbytes - off)
        off += block
        data = carry + block
        pos = 0
        while True:
            nxt = (1664525 * prng + 1013904223) % 4294967296
            length = 1 + nxt % size
            if data - pos >= length:
                prng = nxt
                splits.append(length)
                pos += length
            else:
                break
        carry = data - pos
        if block == 0:
            if carry > 0:
                prng = (1664525 * prng + 1013904223) % 4294967296
                splits.append(carry)
            return splits


def compare_accepted(case_id, events, result, one_events, one_result):
    if result != one_result:
        raise StreamingError(
            f"{case_id}: stream result {json.dumps(result, sort_keys=True)} != "
            f"one-shot {json.dumps(one_result, sort_keys=True)}"
        )
    if events != one_events:
        raise StreamingError(
            f"{case_id}: stream events differ from one-shot: "
            + D.first_event_difference(events, one_events)
        )


def compare_rejected(case_id, events, result, one_result, whole_events):
    if result.get("ok", False):
        raise StreamingError(f"{case_id}: stream accepted a rejected document")
    if result.get("code") != one_result.get("code"):
        raise StreamingError(
            f"{case_id}: stream code {result.get('code')} != one-shot {one_result.get('code')}"
        )
    if result.get("reason") != one_result.get("reason"):
        raise StreamingError(
            f"{case_id}: stream reason {result.get('reason')!r} != one-shot "
            f"{one_result.get('reason')!r}"
        )
    if events != whole_events:
        raise StreamingError(
            f"{case_id}: emitted prefix differs from whole-input streaming: "
            + D.first_event_difference(events, whole_events)
        )


def reference_check(case, input_path, reference, expected_events, expected_spec):
    ref_run = D.run([str(reference), str(input_path)])
    if ref_run.returncode not in (0, 1):
        raise StreamingError(
            f"{case['id']}: reference exit {ref_run.returncode}: {ref_run.stderr}"
        )
    ref_events, ref_result = D.parse_trace(ref_run.stdout, "reference", case["id"])
    declared = D.reference_expected(case, expected_events, expected_spec)
    actual = D.outcome_of(ref_result, ref_events)
    if not D.outcome_matches(actual, declared):
        raise StreamingError(
            f"{case['id']}: reference outcome {actual} != declared {declared}"
        )
    if "exception" in case:
        if D.outcome_matches(actual, D.lean_outcome_of(expected_spec, expected_events)):
            raise StreamingError(
                f"{case['id']}: declared exception no longer differs: {case['exception']}"
            )


def negative_cli(sample):
    cases = [
        ["--chunk-size", "0", sample],
        ["--chunk-size", "65537", sample],
        ["--chunk-size", "abc", sample],
        ["--chunk-size", "-1", sample],
        ["--chunk-size", "64", "--chunk-seed", "4294967296", sample],
        ["--chunk-size", "64", "--chunk-seed", "notanumber", sample],
        ["--chunk-seed", "1", sample],
        ["--chunk-size", "whole", "--chunk-seed", "1", sample],
        ["--chunk-size", "64", "--chunk-seed", "1"],
    ]
    for args in cases:
        result = D.run([str(D.TRACE_BIN)] + args)
        if result.returncode != 2:
            raise StreamingError(
                f"CLI arguments {args!r}: expected exit 2, got {result.returncode}"
            )
    print(f"CLI: {len(cases)} invalid argument combinations exited 2")


def controls(sample):
    """The comparators must accept the unmodified trace and reject mutations."""
    case_id, one_events, one_result, whole_events, whole_result, raw = sample
    compare_accepted(case_id, whole_events, whole_result, one_events, one_result)
    print(f"CONTROL unmodified: {case_id} whole-input events compare equal to one-shot")

    mutated = copy.deepcopy(whole_events)
    changed = False
    for index, event in enumerate(mutated):
        if event.get("type") == "text" and event.get("data"):
            mutated[index] = dict(event, data=event["data"] + "-mutated")
            changed = True
            break
        if event.get("type") in ("start", "end"):
            mutated[index] = dict(event, name=event["name"] + "-mutated")
            changed = True
            break
    if not changed:
        raise StreamingError("control found no mutable event")
    try:
        compare_accepted(case_id, mutated, whole_result, one_events, one_result)
    except StreamingError:
        pass
    else:
        raise StreamingError("control: event mutation was not detected")
    print("CONTROL event-mutation: a changed payload was detected")

    flipped = {"format": 1, "type": "result", "ok": False,
               "code": "INVALID_TOKEN", "reason": "invalidToken"}
    try:
        compare_accepted(case_id, whole_events, flipped, one_events, one_result)
    except StreamingError:
        pass
    else:
        raise StreamingError("control: terminal-result mutation was not detected")
    print("CONTROL result-mutation: a changed terminal result was detected")

    lines = [line for line in raw.splitlines() if line.strip()]
    moved = [line for line in lines if json.loads(line).get("type") != "result"]
    terminal = [line for line in lines if json.loads(line).get("type") == "result"]
    if not moved or len(terminal) != 1:
        raise StreamingError("control trace needs an event and one result")
    reordered = "\n".join(terminal + moved) + "\n"
    try:
        strict_trace(reordered, "control", case_id)
    except StreamingError:
        pass
    else:
        raise StreamingError("control: an event after the result was not detected")
    print("CONTROL order: an event moved after the result was detected")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-build", action="store_true",
                        help="use the existing .lake/build/bin/lexpatTrace")
    args = parser.parse_args()

    D.build_trace(args.no_build)
    build_events(args.no_build)
    run_driver(args.no_build)

    document = json.loads(D.CASES_PATH.read_text(encoding="utf-8"))
    if document.get("format") != 1:
        raise StreamingError("cases.json must carry \"format\":1")
    cases = document["cases"]
    for case in cases:
        if "expectedFile" in case:
            events, spec = D.expected_from_file(case["expectedFile"])
        else:
            events, spec = D.expand_expected(case["expected"])
        case["_expected"] = (events, spec)

    accepted_count = 0
    rejected_count = 0
    partition_count = 0
    control_sample = None
    accepted_inputs = []
    expected_raw = {}
    recipe_sources = []
    order = load_attribute_order()

    with tempfile.TemporaryDirectory(prefix="lexpat-stream-", dir="/tmp") as tmp_name:
        tmp_dir = Path(tmp_name)
        reference, deviation = D.build_reference(tmp_dir)
        if deviation:
            print(f"NOTE: reference build deviation: {deviation}")
        print(f"reference: {D.run([str(reference), '--version']).stdout.strip()}")
        print(f"cases: {len(cases)}")

        for case in cases:
            case_id = case["id"]
            input_path = tmp_dir / f"{case_id}.bin"
            data = D.materialize(case, tmp_dir)
            input_path.write_bytes(data)
            expected_events, spec = case["_expected"]

            one_events, one_result, _ = run_trace([str(input_path)], case_id, "one-shot")
            whole_events, whole_result, whole_raw = run_trace(
                ["--chunk-size", "whole", str(input_path)], case_id, "whole"
            )
            reference_check(case, input_path, reference, expected_events, spec)

            partitions = [("whole", whole_events, whole_result, whole_raw)]
            for size in SIZES:
                partitions.append(
                    (f"size-{size}",
                     *run_trace(["--chunk-size", str(size), str(input_path)],
                                case_id, f"size-{size}")))
            seed = case_seed(case_id)
            try:
                seeded = run_trace(
                    ["--chunk-size", str(SEED_SIZE), "--chunk-seed", str(seed),
                     str(input_path)],
                    case_id, f"seeded-{seed}")
            except StreamingError as exc:
                splits = seeded_splits(len(data), SEED_SIZE, seed)
                raise StreamingError(
                    f"{exc}\nseed={seed} size={SEED_SIZE} splits={splits}"
                )
            partitions.append((f"seeded-{seed}", *seeded))

            accepted = bool(one_result.get("ok"))
            if accepted:
                accepted_count += 1
                accepted_inputs.append((case_id, input_path, seed))
                if "expected" in case:
                    fixture_events = expected_events
                else:
                    recipe, fixture_events = fixture_recipe(case, cases, tmp_dir)
                    recipe_sources.append(
                        f"{case_id} <- {recipe['id']} recipe for "
                        f"{len(data)} identical input bytes")
                expected_raw[case_id] = typed_events(case_id, fixture_events, order)
            else:
                rejected_count += 1

            for label, events, terminal, raw in partitions:
                partition_count += 1
                if accepted:
                    compare_accepted(case_id, events, terminal, one_events, one_result)
                else:
                    compare_rejected(case_id, events, terminal, one_result, whole_events)
                D.check_lean(case_id, terminal, events, spec, expected_events)
                if case.get("exactTrace") and accepted:
                    shipped = (ROOT / case["expectedFile"]).read_text(encoding="utf-8")
                    if raw != shipped:
                        raise StreamingError(
                            f"{case_id}: {label} trace bytes differ from {case['expectedFile']}"
                        )

            if control_sample is None and accepted and one_events:
                control_sample = (case_id, one_events, one_result,
                                  whole_events, whole_result, whole_raw)

        if control_sample is None:
            raise StreamingError("no accepted case with events for controls")
        multi_attribute = {
            case_id for case_id, events in expected_raw.items()
            if any(event["type"] == "start" and len(event["attributes"]) >= 2
                   for event in events)
        }
        if set(order) != multi_attribute:
            raise StreamingError(
                f"{ORDER_PATH.name} declares order for {sorted(order)} but the accepted "
                f"multi-attribute starts are {sorted(multi_attribute)}")
        for note in recipe_sources:
            print(f"recipe: {note}")
        expected_path = write_expected_events(tmp_dir, expected_raw)
        run_event_driver(expected_path, expected_raw, accepted_inputs)
        controls(control_sample)
        negative_cli(tmp_dir / f"{cases[0]['id']}.bin")
        print(f"accepted: {accepted_count}, rejected: {rejected_count}, "
              f"partitions: {partition_count}")
        print(f"OK: {len(cases)} cases under {len(SIZES)} fixed sizes, whole input "
              f"and one seeded partition")
        return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except StreamingError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
