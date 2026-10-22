#!/usr/bin/env python3
"""Apply the scaling thresholds to benchmark CSV rows.

Two modes:

  --ci     one candidate CSV; every distinct-size pair must double within the
           broader 3.5 sentinel, drift must stay within 15%, and the required
           families must be present.
  --pair   base and candidate CSVs from the same session and driver; every
           matched size must keep candidate/base <= 1.25, every candidate
           doubling <= 2.75, drift <= 15%, and every row must carry the
           candidate tree, manifest SHA-256 and base commit. The path/blob
           manifest digests are verified against the candidate source tree.

A ratio row names its unit and construction. A regression finding cites the
CSV path and line of the exact row it measured.
"""

import argparse
import csv
import hashlib
import os
import sys
from pathlib import Path


class CompareError(Exception):
    pass


def need(condition, message):
    if not condition:
        raise CompareError(message)


def read_rows(path):
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        rows = []
        for row in reader:
            row["_line"] = reader.line_num
            row["size"] = int(row["size"])
            row["trials"] = int(row["trials"])
            row["median_ns"] = int(row["median_ns"])
            rows.append(row)
        return rows


def rows_by_key(rows, include_mode=True):
    grouped = {}
    for row in rows:
        if row["family"] in ("drift", "limit"):
            continue
        key = (row["family"], row["shape"], row["cve_id"], row["unit"])
        if include_mode:
            key += (row["mode"],)
        grouped.setdefault(key, []).append(row)
    for items in grouped.values():
        items.sort(key=lambda row: row["size"])
    return grouped


def check_drift(rows, report):
    blocks = {}
    for row in rows:
        if row["family"] != "drift":
            continue
        shape = row["shape"]
        if shape.endswith("-before"):
            blocks.setdefault(shape[: -len("-before")], {})["before"] = row
        elif shape.endswith("-after"):
            blocks.setdefault(shape[: -len("-after")], {})["after"] = row
    need(blocks, "no drift-control rows were recorded")
    for block, pair in sorted(blocks.items()):
        need("before" in pair and "after" in pair,
             f"drift block {block} is incomplete")
        before = pair["before"]["median_ns"]
        after = pair["after"]["median_ns"]
        need(before > 0, f"drift block {block} has a zero median")
        shift = abs(after - before) / before
        report.append(f"drift {block}: before={before}ns after={after}ns "
                      f"shift={shift:.3f} "
                      f"(lines {pair['before']['_line']},{pair['after']['_line']})")
        need(shift <= 0.15,
             f"drift block {block} shifted {shift:.1%} (> 15%); inconclusive")


def doubling(rows, threshold, report, side):
    grouped = rows_by_key(rows)
    checked = 0
    for key, items in sorted(grouped.items()):
        by_size = {row["size"]: row for row in items}
        for first, second in zip(items, items[1:]):
            if second["size"] != first["size"] * 2:
                continue
            need(first["median_ns"] > 0,
                 f"{first['family']}/{first['shape']} size {first['size']} "
                 f"has a zero median")
            ratio = second["median_ns"] / first["median_ns"]
            report.append(
                f"double {side} {key[0]}/{key[1]} {key[3]} mode={key[4]} "
                f"{first['size']}->{second['size']}: ratio={ratio:.3f} "
                f"unit={first['unit']} construction=T(2N)/T(N) "
                f"(lines {first['_line']},{second['_line']})")
            need(ratio <= threshold,
                 f"{side} {key[0]}/{key[1]} mode={key[4]} "
                 f"T(2N)/T(N)={ratio:.3f} > {threshold} "
                 f"(lines {first['_line']},{second['_line']})")
            checked += 1
    need(checked >= 10, f"only {checked} doubling ratios were checked")
    return checked


def identities(rows, base, candidate_tree, manifest):
    for row in rows:
        need(row["base_commit"] == base,
             f"line {row['_line']}: base_commit is {row['base_commit']}, "
             f"expected {base}")
        need(row["candidate_tree"] == candidate_tree,
             f"line {row['_line']}: candidate_tree is {row['candidate_tree']}, "
             f"expected {candidate_tree}")
        need(row["manifest_sha256"] == manifest,
             f"line {row['_line']}: manifest_sha256 is "
             f"{row['manifest_sha256']}, expected {manifest}")


def verify_path_blob_manifest(manifest_path, source_dir, expected_digest):
    data = Path(manifest_path).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    need(digest == expected_digest,
         f"path/blob manifest digest {digest} != {expected_digest}")
    checked = 0
    for entry in data.split(b"\0"):
        if not entry:
            continue
        meta, _, raw_path = entry.partition(b"\t")
        mode, blob, _stage = meta.split(b" ")
        path = Path(source_dir) / os.fsdecode(raw_path)
        need(path.exists() or path.is_symlink(),
             f"manifest path is missing from the candidate source: {path}")
        if mode == b"120000":
            content = os.readlink(path).encode()
        else:
            content = path.read_bytes()
        header = b"blob %d\0" % len(content)
        actual = hashlib.sha1(header + content).hexdigest()
        need(actual == blob.decode(),
             f"candidate source blob for {path} is {actual}, manifest says "
             f"{blob.decode()}")
        checked += 1
    need(checked > 0, "the path/blob manifest is empty")
    return checked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ci", action="store_true")
    parser.add_argument("--pair", action="store_true")
    parser.add_argument("--base-csv")
    parser.add_argument("--candidate-csv")
    parser.add_argument("--report", required=True)
    parser.add_argument("--base", default="46980d2")
    parser.add_argument("--candidate-tree")
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--path-blob-manifest")
    parser.add_argument("--candidate-source")
    args = parser.parse_args()

    report = []
    try:
        if args.ci:
            need(args.candidate_csv, "--ci needs --candidate-csv")
            rows = read_rows(args.candidate_csv)
            need(rows, "the candidate CSV is empty")
            for row in rows:
                if row["family"] == "limit":
                    continue
                need(row["trials"] >= 3,
                     f"line {row['_line']}: need at least 3 trials")
            families = {row["family"] for row in rows}
            for family in ("token", "colon", "elements", "attributes", "depth",
                           "limit", "drift"):
                need(family in families, f"the {family} family is absent")
            check_drift(rows, report)
            checked = doubling(rows, 3.5, report, "candidate")
            lines = [f"CI sentinel: {checked} doubling ratios <= 3.5"]
        elif args.pair:
            need(args.base_csv and args.candidate_csv,
                 "--pair needs --base-csv and --candidate-csv")
            need(args.candidate_tree and args.manifest_sha256,
                 "--pair needs --candidate-tree and --manifest-sha256")
            base_rows = read_rows(args.base_csv)
            candidate_rows = read_rows(args.candidate_csv)
            identities(base_rows, args.base, args.candidate_tree,
                       args.manifest_sha256)
            identities(candidate_rows, args.base, args.candidate_tree,
                       args.manifest_sha256)
            for row in base_rows + candidate_rows:
                if row["family"] == "limit":
                    continue
                need(row["trials"] >= 7,
                     f"line {row['_line']}: need at least 7 trials")
            check_drift(base_rows, report)
            check_drift(candidate_rows, report)

            base_grouped = rows_by_key(base_rows)
            candidate_grouped = rows_by_key(candidate_rows)
            need(set(base_grouped) == set(candidate_grouped),
                 "the base and candidate CSVs cover different row keys")
            matched = 0
            for key in sorted(base_grouped):
                base_by_size = {row["size"]: row for row in base_grouped[key]}
                for row in candidate_grouped[key]:
                    other = base_by_size.get(row["size"])
                    need(other is not None,
                         f"candidate line {row['_line']}: no base row at "
                         f"size {row['size']}")
                    ratio = row["median_ns"] / other["median_ns"]
                    report.append(
                        f"matched {key[0]}/{key[1]} size={row['size']} "
                        f"unit={row['unit']} mode={key[4]}: "
                        f"candidate/base={ratio:.3f} "
                        f"(lines candidate {row['_line']}, base {other['_line']})")
                    need(ratio <= 1.25,
                         f"candidate/base regression {ratio:.3f} > 1.25 for "
                         f"{key[0]}/{key[1]} size {row['size']} mode {key[4]} "
                         f"(candidate line {row['_line']}, base line "
                         f"{other['_line']})")
                    matched += 1
            checked = doubling(candidate_rows, 2.75, report, "candidate")
            lines = [f"paired: {matched} matched sizes within 1.25; "
                     f"{checked} candidate doubling ratios <= 2.75"]
            if args.path_blob_manifest:
                need(args.candidate_source,
                     "--path-blob-manifest needs --candidate-source")
                count = verify_path_blob_manifest(
                    args.path_blob_manifest, args.candidate_source,
                    args.manifest_sha256)
                lines.append(f"identity: {count} candidate path/blob entries "
                             f"match the snapshot manifest")
        else:
            raise CompareError("select --ci or --pair")

        Path(args.report).write_text("\n".join(report + lines) + "\n",
                                     encoding="utf-8")
        for line in lines:
            print(line)
        print(f"OK: benchmark thresholds satisfied; report {args.report}")
        return 0
    except CompareError as exc:
        Path(args.report).write_text("\n".join(report) + f"\nFAIL: {exc}\n",
                                     encoding="utf-8")
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
