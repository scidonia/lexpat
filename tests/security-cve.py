#!/usr/bin/env python3
"""Run the CVE-class regression set against the candidate and pinned Expat.

Reads `tests/security/cve-cases.json`, generates each input locally, and
asserts the candidate's exact result independently of the oracle. Rows that
name a pinned-reference outcome also assert the oracle's exact events or code.
The original `tests/corpus/` tree is not modified: the 108-case baseline is
checked separately, and the encoding-attack references here resolve to its
existing exact expectations.

Rows are one of three forms:

  * a generated input with `candidate` and optional `reference` outcomes;
  * an existing verification command whose PASS text and numeric code are
    required (`XML_ResumeParser` / external-entity creation refusals);
  * a reference to the existing `encoding-attack` corpus group, whose exact
    expected results are validated without inventing imported PoCs.

The checker rejects missing provenance, an unknown generator, an unknown case
reference and an outcome without an exact expected result. It uses no network
and never reads an upstream file at run time.
"""

import argparse
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_harness():
    path = ROOT / "tests" / "c-abi-differential.py"
    spec = importlib.util.spec_from_file_location("c_abi_differential", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


D = load_harness()

CASES_PATH = ROOT / "tests" / "security" / "cve-cases.json"
CORPUS_PATH = ROOT / "tests" / "corpus" / "cases.json"

CLASSIFICATIONS = {"feature absent", "existing mitigation/bound",
                   "residual/unproven", "existing verification"}
REQUIRED_SOURCE = ("class_url", "revision", "path", "license", "provenance")
GENERATORS = {"long-name", "long-attribute", "long-text", "long-comment",
              "long-cdata", "colon-name", "many-attributes",
              "doctype-entity-chain", "doctype-empty", "doctype-model"}


class CheckError(Exception):
    pass


def need(condition, message):
    if not condition:
        raise CheckError(message)


def event(kind, **fields):
    value = {"format": 1, "type": kind}
    value.update(fields)
    return value


def start(name, attributes=None):
    return event("start", name=name, attributes=attributes or [])


def materialize(case):
    generator = case["input"]["generator"]
    if generator == "long-name":
        return b"<" + b"a" * case["input"]["size"] + b"/>"
    if generator == "long-attribute":
        return b'<r a="' + b"x" * case["input"]["size"] + b'"/>'
    if generator == "long-text":
        return b"<r>" + b"x" * case["input"]["size"] + b"</r>"
    if generator == "long-comment":
        return b"<!--" + b"c" * case["input"]["size"] + b"--><r/>"
    if generator == "long-cdata":
        return b"<r><![CDATA[" + b"c" * case["input"]["size"] + b"]]></r>"
    if generator == "colon-name":
        return b"<a" + b":" * case["input"]["size"] + b"b/>"
    if generator == "many-attributes":
        count = case["input"]["count"]
        pairs = b"".join(b' a%d="v%d"' % (i, i) for i in range(count))
        return b"<r" + pairs + b"/>"
    if generator == "doctype-entity-chain":
        return b'<!DOCTYPE r [<!ENTITY e "x">]><r>&e;</r>'
    if generator == "doctype-empty":
        return b"<!DOCTYPE r><r/>"
    if generator == "doctype-model":
        return b"<!DOCTYPE r [<!ELEMENT r (a|b)>]><r/>"
    raise CheckError(f"{case['id']}: unknown generator {generator}")


def expected_events(case):
    generator = case["input"]["generator"]
    if generator == "long-name":
        name = "a" * case["input"]["size"]
        return [start(name), event("end", name=name)]
    if generator == "long-attribute":
        value = "x" * case["input"]["size"]
        return [start("r", [["a", value]]), event("end", name="r")]
    if generator == "long-text":
        return [start("r"), event("text", data="x" * case["input"]["size"]),
                event("end", name="r")]
    if generator == "long-comment":
        return [event("comment", data="c" * case["input"]["size"]),
                start("r"), event("end", name="r")]
    if generator == "long-cdata":
        return [start("r"), event("cdataStart"),
                event("text", data="c" * case["input"]["size"]),
                event("cdataEnd"), event("end", name="r")]
    if generator == "colon-name":
        name = "a" + ":" * case["input"]["size"] + "b"
        return [start(name), event("end", name=name)]
    if generator == "many-attributes":
        pairs = [[f"a{i}", f"v{i}"] for i in range(case["input"]["count"])]
        return [start("r", pairs), event("end", name="r")]
    if generator == "doctype-entity-chain":
        return [start("r"), event("text", data="x"), event("end", name="r")]
    if generator in ("doctype-empty", "doctype-model"):
        return [start("r"), event("end", name="r")]
    raise CheckError(f"{case['id']}: no expected events for {generator}")


def simplify(events):
    """Drop callback positions and length fields, keep ordered attribute pairs."""
    simplified = []
    for item in D.coalesce(events):
        simplified.append({k: v for k, v in item.items()
                           if k not in ("byte", "line", "column", "length",
                                        "specified")})
    return simplified


def check_side(side, case_id, events, result, spec, expected, length):
    need(result.get("outsideParse") == 0,
         f"{case_id}: {side} delivered callbacks outside a parse call")
    need(result.get("length") == length,
         f"{case_id}: {side} fed {result.get('length')} bytes, expected {length}")
    if spec["ok"]:
        need(bool(result.get("ok")),
             f"{case_id}: {side} rejected an expected-accepted input "
             f"(code {result.get('code')})")
        actual = simplify(events)
        if actual != expected:
            detail = D.first_event_difference(actual, expected)
            raise CheckError(f"{case_id}: {side} events differ: {detail}")
        return "accepted"
    need(not bool(result.get("ok")),
         f"{case_id}: {side} accepted an expected-rejected input")
    want = D.ERROR_CODES.get(spec["code"])
    need(want is not None, f"{case_id}: unknown expected code {spec['code']}")
    need(result.get("code") == want,
         f"{case_id}: {side} code {result.get('code')} != {want} ({spec['code']})")
    return f"rejected {spec['code']}"


def validate_case(case):
    for field in ("id", "class", "classification", "source", "candidate"):
        need(field in case, f"{case.get('id', '<no id>')}: missing {field}")
    need(case["classification"] in CLASSIFICATIONS,
         f"{case['id']}: unknown classification {case['classification']}")
    for field in REQUIRED_SOURCE:
        need(isinstance(case["source"].get(field), str) and case["source"][field].strip(),
             f"{case['id']}: source.{field} is missing")
    if "input" in case:
        need(case["input"].get("generator") in GENERATORS,
             f"{case['id']}: unknown input form {case['input'].get('generator')}")
        if case["input"]["generator"] in ("long-name", "long-attribute", "long-text",
                                          "long-comment", "long-cdata",
                                          "colon-name"):
            need(isinstance(case["input"].get("size"), int) and case["input"]["size"] > 0,
                 f"{case['id']}: size must be a positive integer")
        if case["input"]["generator"] == "many-attributes":
            need(isinstance(case["input"].get("count"), int) and case["input"]["count"] > 0,
                 f"{case['id']}: count must be a positive integer")
        need("ok" in case["candidate"],
             f"{case['id']}: candidate outcome is not exact")
        if not case["candidate"]["ok"]:
            need("code" in case["candidate"],
                 f"{case['id']}: rejected candidate needs an exact code")
        if case.get("reference") is not None:
            need("ok" in case["reference"],
                 f"{case['id']}: reference outcome is not exact")
            if not case["reference"]["ok"]:
                need("code" in case["reference"],
                     f"{case['id']}: rejected reference needs an exact code")
    elif "verification" in case["candidate"]:
        verification = case["candidate"]["verification"]
        need(isinstance(verification.get("command"), str)
             and verification.get("expects"),
             f"{case['id']}: verification needs a command and expected text")
        need(isinstance(verification.get("code"), int),
             f"{case['id']}: verification needs the numeric code it observes")
        need(case.get("reference") is None,
             f"{case['id']}: a verification row cannot carry a parser reference")
    elif "corpusReferences" in case["candidate"]:
        need(isinstance(case["candidate"]["corpusReferences"], list)
             and case["candidate"]["corpusReferences"],
             f"{case['id']}: corpusReferences must be a non-empty list")
        need(case.get("reference") is None,
             f"{case['id']}: a corpus-reference row cannot carry a parser reference")
    else:
        raise CheckError(f"{case['id']}: no input, verification or corpus references")


def validate_corpus_references(references):
    document = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    need(document.get("format") == 1, "cases.json must carry format 1")
    by_id = {case["id"]: case for case in document["cases"]}
    expected_group = sorted(case["id"] for case in document["cases"]
                            if case["group"] == "encoding-attack")
    need(sorted(references) == expected_group,
         "the encoding-attack reference set does not match the corpus group")
    for case_id in references:
        case = by_id[case_id]
        spec = case.get("expected")
        need(spec is not None, f"{case_id}: the corpus row has no exact expectation")
        need("ok" in spec, f"{case_id}: the corpus expectation has no accept flag")
        if not spec["ok"]:
            need("code" in spec, f"{case_id}: the corpus rejection has no exact code")
    return len(references)


def run_verifications(cases):
    commands = {}
    for case in cases:
        verification = case["candidate"].get("verification")
        if verification is None:
            continue
        commands.setdefault(verification["command"], []).append((case["id"], verification))
    for command, rows in sorted(commands.items()):
        result = D.run([sys.executable, *command.split()[1:]], cwd=ROOT)
        need(result.returncode == 0,
             f"{command} failed with {result.returncode}:\n"
             + result.stdout[-2000:] + result.stderr[-2000:])
        output = result.stdout + result.stderr
        for case_id, verification in rows:
            need(verification["expects"] in output,
                 f"{case_id}: {command} did not report {verification['expects']!r}")
            need(str(verification["code"]) in output,
                 f"{case_id}: {command} did not report code {verification['code']}")
        print(f"PASS verification: {command} "
              f"({', '.join(case_id for case_id, _ in rows)})")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-build", action="store_true",
                        help="use the existing .lake/build/lib/liblexpat.so.1")
    args = parser.parse_args()

    document = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    need(document.get("format") == 1, "cve-cases.json must carry format 1")
    cases = document["cases"]
    ids = [case["id"] for case in cases]
    need(len(ids) == len(set(ids)), "duplicate case id in cve-cases.json")
    for case in cases:
        validate_case(case)

    D.build_artifact(args.no_build)
    with tempfile.TemporaryDirectory(prefix="lexpat-cve-", dir="/tmp") as tmp_name:
        tmp = Path(tmp_name)
        candidate_bin, reference_bin = D.build_clients(tmp)
        candidate_version = D.run([str(candidate_bin), "--version"]).stdout.strip()
        reference_version = D.run([str(reference_bin), "--version"]).stdout.strip()
        pkg_version = D.run(["pkg-config", "--modversion", "expat"]).stdout.strip()
        need(candidate_version.startswith("lexpat_"),
             f"unexpected candidate identity {candidate_version}")
        need(pkg_version == "2.8.5",
             f"pkg-config expat is {pkg_version}, not the pinned 2.8.5")
        need(reference_version == "expat_2.8.5",
             f"the pinned oracle reports {reference_version}")
        print(f"candidate: {candidate_version}")
        print(f"reference: {reference_version} (pkg-config {pkg_version})")

        run_verifications(cases)

        parse_cases = 0
        for case in cases:
            if "input" not in case:
                if "corpusReferences" in case["candidate"]:
                    count = validate_corpus_references(
                        case["candidate"]["corpusReferences"])
                    print(f"PASS [{case['class']}] {case['id']}: "
                          f"{count} existing encoding-attack rows with exact results")
                continue
            parse_cases += 1
            data = materialize(case)
            path = tmp / f"{case['id']}.bin"
            path.write_bytes(data)
            candidate = D.parse_output(
                D.run_case(candidate_bin, path, "whole", False).stdout,
                "candidate", case["id"])
            candidate_note = check_side("candidate", case["id"], candidate[0],
                                        candidate[1], case["candidate"],
                                        expected_events(case), len(data))
            reference_note = "not compared"
            if case.get("reference") is not None:
                reference = D.parse_output(
                    D.run_case(reference_bin, path, "whole", False).stdout,
                    "reference", case["id"])
                reference_note = check_side("reference", case["id"], reference[0],
                                            reference[1], case["reference"],
                                            expected_events(case), len(data))
            print(f"PASS [{case['class']}] {case['id']}: candidate {candidate_note}; "
                  f"reference {reference_note}; {len(data)} bytes")

        need(parse_cases >= 10,
             f"only {parse_cases} generated parse cases ran; the corpus looks wrong")
        print(f"OK: {len(cases)} CVE-class rows "
              f"({parse_cases} generated inputs) asserted")
        return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (CheckError, D.HarnessError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
