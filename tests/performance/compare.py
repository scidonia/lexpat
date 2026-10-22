#!/usr/bin/env python3
"""Corpus, expectation and timing report tooling for the performance benchmark.

Modes
  --check-corpus     compare a fresh generation with the shipped fixtures and
                     the manifest's declared sizes and SHA-256 digests
  --build-manifest   write a manifest from oracle observations (maintainer tool)
  --verify           compare each side's observed callbacks with the manifest
  --emit-expectations
                     print the driver flags a timed run passes for one case
  --results          turn raw timing samples into ratio rows and enforce them

Everything here is stdlib only. The comparator never times anything itself; it
reads the raw per-sample CSV the C driver wrote and the observations the
preflight recorded, so a timing claim and the correctness claim that licenses
it always refer to the same case set.
"""

import argparse
import base64
import hashlib
import json
import pathlib
import statistics
import sys

CASES = [
    "small",
    "text-512k",
    "elements-10k",
    "attrs-1000",
    "depth-256",
    "mixed",
    "utf16le",
    "latin1",
]

FILENAMES = {case: f"{case}.xml" for case in CASES}

# Whole-input targets from the approved plan: (min speedup, max gap).
WHOLE_TARGETS = {
    "small": (2.0, 20.0),
    "text-512k": (15.0, 20.0),
    "elements-10k": (3.0, 15.0),
    "attrs-1000": (2.0, 10.0),
    "depth-256": (3.0, 15.0),
    "mixed": (5.0, 20.0),
    "utf16le": (10.0, 40.0),
    "latin1": (5.0, 25.0),
}
TEXT_MIN_SPEEDUP = 5.0
TEXT_MIN_THROUGHPUT_MIB = 50.0
MAX_CHUNKED_RATIO = 1.5
MAX_DRIFT = 0.15

COALESCING = (
    "consecutive character-data callbacks with no intervening event are "
    "concatenated into one text record"
)


class Failure(Exception):
    pass


def die(message):
    raise Failure(message)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def b64(value):
    return base64.b64encode(value).decode("ascii")


def load_manifest(path):
    with open(path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    if manifest.get("version") != 1:
        die(f"manifest {path}: unsupported version {manifest.get('version')!r}")
    cases = {case["id"]: case for case in manifest.get("cases", [])}
    if sorted(cases) != sorted(CASES):
        die(f"manifest {path}: expected cases {CASES}, found {sorted(cases)}")
    return manifest, cases


def canonicalise(path):
    """Read one driver observation file and apply the coalescing rule."""
    records = []
    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                die(f"{path}:{lineno}: not JSON: {exc}")
            kind = raw.get("kind")
            if kind == "status":
                if not raw.get("ok"):
                    die(f"{path}:{lineno}: parser reported a failed document")
                continue
            if kind == "start":
                attrs = tuple(
                    (base64.b64decode(pair[0]), base64.b64decode(pair[1]))
                    for pair in raw.get("attrs", [])
                )
                records.append(("start", base64.b64decode(raw["name"]), attrs))
            elif kind == "end":
                records.append(("end", base64.b64decode(raw["name"])))
            elif kind == "text":
                data = base64.b64decode(raw["data"])
                if records and records[-1][0] == "text":
                    records[-1] = ("text", records[-1][1] + data)
                else:
                    records.append(("text", data))
            elif kind == "comment":
                records.append(("comment", base64.b64decode(raw["data"])))
            elif kind == "pi":
                records.append(
                    (
                        "pi",
                        base64.b64decode(raw["target"]),
                        base64.b64decode(raw["data"]),
                    )
                )
            elif kind == "cdata_start":
                records.append(("cdata_start",))
            elif kind == "cdata_end":
                records.append(("cdata_end",))
            elif kind == "xml_decl":
                encoding = raw.get("encoding")
                records.append(
                    (
                        "xml_decl",
                        base64.b64decode(raw["version"]),
                        None if encoding is None else base64.b64decode(encoding),
                        raw.get("standalone", -1),
                    )
                )
            else:
                die(f"{path}:{lineno}: unknown record kind {kind!r}")
    if not records:
        die(f"{path}: no events observed")
    return records


def canonical_json(records):
    lines = []
    for record in records:
        encoded = []
        for field in record:
            if isinstance(field, bytes):
                encoded.append({"b64": b64(field)})
            elif isinstance(field, tuple):
                encoded.append(
                    [
                        [{"b64": b64(name)}, {"b64": b64(value)}]
                        for name, value in field
                    ]
                )
            else:
                encoded.append(field)
        lines.append(json.dumps(encoded, sort_keys=True, separators=(",", ":")))
    return "\n".join(lines)


def event_digest(records):
    return sha256_bytes(canonical_json(records).encode("utf-8"))


def text_digest(records):
    digest = hashlib.sha256()
    for record in records:
        if record[0] == "text":
            digest.update(record[1])
    return digest.hexdigest()


def counts(records):
    result = {
        "start": 0,
        "end": 0,
        "text_bytes": 0,
        "attr_pairs": 0,
        "comment": 0,
        "pi": 0,
        "cdata_start": 0,
        "cdata_end": 0,
        "xml_decl": 0,
    }
    for record in records:
        kind = record[0]
        if kind == "start":
            result["start"] += 1
            result["attr_pairs"] += len(record[2])
        elif kind == "text":
            result["text_bytes"] += len(record[1])
        elif kind == "xml_decl":
            result["xml_decl"] += 1
        else:
            result[kind] += 1
    return result


# --------------------------------------------------------------------------
# --check-corpus
# --------------------------------------------------------------------------


def check_corpus(manifest_path, generated, shipped):
    manifest, cases = load_manifest(manifest_path)
    generated = pathlib.Path(generated)
    shipped = pathlib.Path(shipped)
    problems = []
    for case in CASES:
        name = FILENAMES[case]
        declared = cases[case]
        gen_path = generated / name
        ship_path = shipped / name
        if not gen_path.is_file():
            problems.append(f"{case}: generated fixture {gen_path} is missing")
            continue
        if not ship_path.is_file():
            problems.append(f"{case}: shipped fixture {ship_path} is missing")
            continue
        gen = gen_path.read_bytes()
        ship = ship_path.read_bytes()
        if gen != ship:
            problems.append(f"{case}: generated bytes differ from the shipped fixture")
        if len(ship) != declared["bytes"]:
            problems.append(
                f"{case}: shipped fixture is {len(ship)} bytes, manifest declares "
                f"{declared['bytes']}"
            )
        if sha256_bytes(ship) != declared["sha256"]:
            problems.append(f"{case}: shipped fixture SHA-256 differs from the manifest")
    if problems:
        for problem in problems:
            print(f"check-corpus: {problem}", file=sys.stderr)
        return 1
    total = sum(cases[case]["bytes"] for case in CASES)
    print(
        f"check-corpus: ok: {len(CASES)} fixtures, {total} bytes, "
        f"manifest {manifest_path}"
    )
    for case in CASES:
        print(
            f"check-corpus: {case}: {cases[case]['bytes']} bytes "
            f"sha256={cases[case]['sha256']}"
        )
    return 0


# --------------------------------------------------------------------------
# --build-manifest
# --------------------------------------------------------------------------


def build_manifest(corpus, observations, out, oracle_side):
    corpus = pathlib.Path(corpus)
    observations = pathlib.Path(observations)
    entries = []
    for case in CASES:
        path = corpus / FILENAMES[case]
        if not path.is_file():
            die(f"build-manifest: missing fixture {path}")
        data = path.read_bytes()
        observed = observations / f"{case}.{oracle_side}.jsonl"
        if not observed.is_file():
            die(f"build-manifest: missing observation {observed}")
        records = canonicalise(observed)
        entries.append(
            {
                "id": case,
                "file": FILENAMES[case],
                "bytes": len(data),
                "sha256": sha256_bytes(data),
                "success": True,
                "counts": counts(records),
                "event_digest": event_digest(records),
                "text_digest": text_digest(records),
            }
        )
    manifest = {
        "version": 1,
        "coalescing": COALESCING,
        "oracle_side": oracle_side,
        "cases": entries,
    }
    text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    pathlib.Path(out).write_text(text, encoding="utf-8")
    print(f"build-manifest: wrote {out} ({len(entries)} cases)")
    return 0


# --------------------------------------------------------------------------
# --verify
# --------------------------------------------------------------------------


def verify(manifest_path, observations, sides):
    manifest, cases = load_manifest(manifest_path)
    observations = pathlib.Path(observations)
    problems = []
    checked = 0
    for case in CASES:
        declared = cases[case]
        for side in sides:
            for suffix, required in (("", True), (".chunked", False)):
                path = observations / f"{case}.{side}{suffix}.jsonl"
                label = f"{case}/{side}{suffix or ''}"
                if not path.is_file():
                    if required:
                        problems.append(f"{label}: observation {path} is missing")
                    continue
                try:
                    records = canonicalise(path)
                except Failure as exc:
                    problems.append(f"{label}: {exc}")
                    continue
                digest = event_digest(records)
                if digest != declared["event_digest"]:
                    problems.append(
                        f"{label}: event stream digest {digest} does not match "
                        f"declared {declared['event_digest']}"
                    )
                    continue
                seen = counts(records)
                if seen != declared["counts"]:
                    problems.append(
                        f"{label}: callback counts {seen} do not match declared "
                        f"{declared['counts']}"
                    )
                    continue
                if text_digest(records) != declared["text_digest"]:
                    problems.append(f"{label}: text digest does not match declared")
                    continue
                checked += 1
    if problems:
        for problem in problems:
            print(f"verify: {problem}", file=sys.stderr)
        return 1
    print(
        f"verify: ok: {checked} observations match the declared expectations "
        f"({len(CASES)} cases x {len(sides)} sides); coalescing: {COALESCING}"
    )
    return 0


# --------------------------------------------------------------------------
# --emit-expectations
# --------------------------------------------------------------------------


def emit_expectations(manifest_path, case):
    _, cases = load_manifest(manifest_path)
    if case not in cases:
        die(f"emit-expectations: unknown case {case!r}")
    seen = cases[case]["counts"]
    flags = [
        f"--expect-start {seen['start']}",
        f"--expect-end {seen['end']}",
        f"--expect-text-bytes {seen['text_bytes']}",
        f"--expect-attr-pairs {seen['attr_pairs']}",
        f"--expect-comment {seen['comment']}",
        f"--expect-pi {seen['pi']}",
        f"--expect-cdata-start {seen['cdata_start']}",
        f"--expect-cdata-end {seen['cdata_end']}",
        f"--expect-xml-decl {seen['xml_decl']}",
    ]
    print(" ".join(flags))
    return 0


# --------------------------------------------------------------------------
# --results
# --------------------------------------------------------------------------


def read_raw(path):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        header = f.readline().strip().split(",")
        expected = [
            "sample",
            "side",
            "case",
            "mode",
            "chunk",
            "reps",
            "total_ns",
            "per_doc_ns",
            "include_create",
        ]
        if header != expected:
            die(f"results: {path}: unexpected header {header}")
        for lineno, line in enumerate(f, 2):
            line = line.strip()
            if not line:
                continue
            fields = line.split(",")
            if len(fields) != len(expected):
                die(f"results: {path}:{lineno}: {len(fields)} fields")
            rows.append(
                {
                    "sample": int(fields[0]),
                    "side": fields[1],
                    "case": fields[2],
                    "mode": fields[3],
                    "chunk": int(fields[4]),
                    "reps": int(fields[5]),
                    "total_ns": int(fields[6]),
                    "per_doc_ns": float(fields[7]),
                    "include_create": int(fields[8]),
                }
            )
    return rows


def medians(rows):
    table = {}
    for row in rows:
        table.setdefault((row["side"], row["case"], row["mode"]), []).append(
            row["per_doc_ns"]
        )
    return {key: statistics.median(values) for key, values in table.items()}


def results(manifest_path, raw_path, out, phase, enforce, affinity_ok, require_samples):
    manifest, _ = load_manifest(manifest_path)
    rows = read_raw(raw_path)
    if not rows:
        die(f"results: no timing rows in {raw_path}")
    table = medians(rows)
    sample_counts = {}
    for row in rows:
        sample_counts[(row["side"], row["case"], row["mode"])] = (
            sample_counts.get((row["side"], row["case"], row["mode"]), 0) + 1
        )

    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    ratios = out / "ratios.csv"
    report = out / "report.md"

    cases = ["text-512k"] if phase == "text" else CASES
    include_create = any(row["include_create"] for row in rows)
    problems = []
    inconclusive = []

    # Drift sentinels: the same small document, whole input, before and after.
    drift_lines = []
    for side in ("base", "candidate", "expat"):
        before = table.get((side, "control-before", "whole"))
        after = table.get((side, "control-after", "whole"))
        if before is None or after is None:
            inconclusive.append(f"drift: {side} control reading missing")
            continue
        shift = abs(after / before - 1.0)
        drift_lines.append(
            f"drift {side}: before {before:.3f} ns/doc, after {after:.3f} ns/doc, "
            f"shift {shift * 100:.2f}% (bound {MAX_DRIFT * 100:.0f}%)"
        )
        if shift > MAX_DRIFT:
            inconclusive.append(
                f"drift: {side} control shifted {shift * 100:.2f}% "
                f"(bound {MAX_DRIFT * 100:.0f}%): session inconclusive"
            )

    lines = []
    lines.append(f"# Performance report ({phase} phase)")
    lines.append("")
    lines.append(f"Raw samples: `{raw_path}`")
    lines.append(f"Manifest: `{manifest_path}`")
    lines.append(f"Coalescing rule: {manifest['coalescing']}")
    timed_note = (
        "Timed region: `XML_Parse` only (parser creation, handler registration and "
        "free excluded)"
    )
    if include_create:
        timed_note += "; an include-create diagnostic is also present"
    lines.append(timed_note)
    lines.append("")
    lines.extend(drift_lines)
    lines.append("")
    lines.append(
        "| case | metric | value | unit | construction |"
    )
    lines.append("| --- | --- | ---: | --- | --- |")

    csv_rows = [("case", "metric", "value", "unit", "construction", "samples")]

    def record(case, metric, value, unit, construction, samples):
        lines.append(
            f"| {case} | {metric} | {value:.3f} | {unit} | {construction} |"
        )
        csv_rows.append(
            (case, metric, f"{value:.6f}", unit, construction, str(samples))
        )

    for case in cases:
        base_whole = table.get(("base", case, "whole"))
        cand_whole = table.get(("candidate", case, "whole"))
        expat_whole = table.get(("expat", case, "whole"))
        cand_chunked = table.get(("candidate", case, "chunked"))
        if cand_whole is None or expat_whole is None:
            die(f"results: {case}: missing whole-input reading for a side")
        if cand_whole <= 0 or expat_whole <= 0:
            die(f"results: {case}: non-positive median invalidates the run")
        if base_whole is not None and base_whole <= 0:
            die(f"results: {case}: non-positive base median invalidates the run")
        gap = cand_whole / expat_whole
        samples = min(
            sample_counts.get(("candidate", case, "whole"), 0),
            sample_counts.get(("expat", case, "whole"), 0),
        )
        if base_whole is not None:
            samples = min(samples, sample_counts.get(("base", case, "whole"), 0))
        speedup = None if base_whole is None else base_whole / cand_whole
        if speedup is not None:
            record(
                case,
                "speedup",
                speedup,
                "x",
                "median base ns/doc / median candidate ns/doc",
                samples,
            )
        record(
            case,
            "gap",
            gap,
            "x",
            "median candidate ns/doc / median expat ns/doc",
            samples,
        )
        if case == "text-512k":
            body_bytes = manifest["cases"][
                CASES.index(case)
            ]["counts"]["text_bytes"]
            seconds = cand_whole / 1e9
            mib = body_bytes / seconds / (1024 * 1024)
            record(
                case,
                "throughput",
                mib,
                "MiB/s",
                f"{body_bytes} literal text bytes / candidate parse seconds",
                samples,
            )
            if enforce and mib < TEXT_MIN_THROUGHPUT_MIB:
                problems.append(
                    f"{case}: throughput {mib:.2f} MiB/s < "
                    f"{TEXT_MIN_THROUGHPUT_MIB:.2f} MiB/s"
                )
        if cand_chunked is not None:
            ratio = cand_chunked / cand_whole
            record(
                case,
                "chunked",
                ratio,
                "x",
                f"candidate {rows[0]['chunk']}-byte-feed median ns/doc / "
                "candidate whole-input median ns/doc",
                min(
                    sample_counts.get(("candidate", case, "chunked"), 0),
                    sample_counts.get(("candidate", case, "whole"), 0),
                ),
            )
            if enforce and ratio > MAX_CHUNKED_RATIO:
                problems.append(
                    f"{case}: chunked/whole {ratio:.3f}x > "
                    f"{MAX_CHUNKED_RATIO:.2f}x"
                )

        if not enforce:
            continue
        if speedup is None:
            if phase in ("text", "full"):
                die(f"results: {case}: a speedup row needs a base reading")
            continue
        if phase == "text":
            if speedup < TEXT_MIN_SPEEDUP:
                problems.append(
                    f"{case}: speedup {speedup:.3f}x < {TEXT_MIN_SPEEDUP:.2f}x"
                )
            continue
        min_speedup, max_gap = WHOLE_TARGETS[case]
        if speedup < min_speedup:
            problems.append(
                f"{case}: speedup {speedup:.3f}x < {min_speedup:.2f}x"
            )
        if gap > max_gap:
            problems.append(f"{case}: gap {gap:.3f}x > {max_gap:.2f}x")
        if require_samples and samples < require_samples:
            problems.append(
                f"{case}: {samples} samples, {require_samples} required"
            )

    lines.append("")
    if inconclusive:
        lines.append("## Inconclusive")
        lines.extend(f"- {item}" for item in inconclusive)
        lines.append("")
    if problems:
        lines.append("## Failed assertions")
        lines.extend(f"- {item}" for item in problems)
        lines.append("")
    elif enforce:
        lines.append(
            f"All enforced rows pass ({phase} phase); "
            f"affinity pinned: {'yes' if affinity_ok else 'no'}."
        )
        lines.append("")

    with open(ratios, "w", encoding="utf-8") as f:
        for row in csv_rows:
            f.write(",".join(row) + "\n")
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))

    if inconclusive:
        for item in inconclusive:
            print(f"inconclusive: {item}", file=sys.stderr)
        return 2
    if problems:
        for problem in problems:
            print(f"FAIL {problem}", file=sys.stderr)
        if not affinity_ok:
            print(
                "FAIL: no CPU affinity for this run; thresholds are not accepted",
                file=sys.stderr,
            )
        return 1
    return 0


# --------------------------------------------------------------------------


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest", help="tests/performance/manifest.json")
    ap.add_argument("--check-corpus", action="store_true")
    ap.add_argument("--generated")
    ap.add_argument("--shipped")
    ap.add_argument("--build-manifest", action="store_true")
    ap.add_argument("--corpus")
    ap.add_argument("--observations")
    ap.add_argument("--oracle-side", default="expat")
    ap.add_argument("--out")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--sides", default="lexpat,expat")
    ap.add_argument("--emit-expectations", action="store_true")
    ap.add_argument("--case")
    ap.add_argument("--results", action="store_true")
    ap.add_argument("--raw")
    ap.add_argument("--phase", choices=["text", "full", "smoke"], default="full")
    ap.add_argument("--enforce", action="store_true")
    ap.add_argument("--affinity-ok", type=int, default=0)
    ap.add_argument("--require-samples", type=int, default=0)
    args = ap.parse_args(argv)

    try:
        if args.check_corpus:
            return check_corpus(args.manifest, args.generated, args.shipped)
        if args.build_manifest:
            return build_manifest(
                args.corpus, args.observations, args.out, args.oracle_side
            )
        if args.verify:
            sides = [side for side in args.sides.split(",") if side]
            return verify(args.manifest, args.observations, sides)
        if args.emit_expectations:
            return emit_expectations(args.manifest, args.case)
        if args.results:
            return results(
                args.manifest,
                args.raw,
                args.out,
                args.phase,
                args.enforce,
                bool(args.affinity_ok),
                args.require_samples,
            )
    except Failure as exc:
        print(f"performance/compare.py: {exc}", file=sys.stderr)
        return 1
    ap.error("choose one mode")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
