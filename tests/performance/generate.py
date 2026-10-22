#!/usr/bin/env python3
"""Generate the deterministic performance corpus.

    python3 tests/performance/generate.py --out <absolute-directory>

The eight documents are byte-for-byte the ones checked in under
`tests/performance/corpus/`. `tests/performance/compare.py --check-corpus`
compares a fresh generation against the shipped files and the declared sizes
and SHA-256 digests in `tests/performance/manifest.json`, so a change to this
script or to the fixtures is visible rather than silently absorbed.

The generator is pure: it reads nothing, uses no clock or randomness, and
writes exactly the named files into `--out`, which it creates if needed.
"""

import argparse
import pathlib
import sys

# (case id, filename, bytes)
# Every fixture is a complete XML document that libexpat 2.8.5 and the lexpat
# C ABI both accept. The sizes are the ones the milestone baseline measured.
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

FILENAMES = {
    "small": "small.xml",
    "text-512k": "text-512k.xml",
    "elements-10k": "elements-10k.xml",
    "attrs-1000": "attrs-1000.xml",
    "depth-256": "depth-256.xml",
    "mixed": "mixed.xml",
    "utf16le": "utf16le.xml",
    "latin1": "latin1.xml",
}


def build(case):
    if case == "small":
        # A typical document: 20 elements carrying two attributes each.
        out = ['<?xml version="1.0"?><doc>']
        for i in range(20):
            out.append(f'<item id="{i}" kind="k{i % 3}">value {i}</item>')
        out.append("</doc>")
        return "".join(out).encode("utf-8")

    if case == "text-512k":
        # One literal text run below the 1 MiB token ceiling.
        return b"<r>" + b"x" * (512 * 1024) + b"</r>"

    if case == "elements-10k":
        # Many short elements: per-event dispatch cost.
        parts = [b"<r>"]
        for _ in range(10000):
            parts.append(b'<e a="1">x</e>')
        parts.append(b"</r>")
        return b"".join(parts)

    if case == "attrs-1000":
        # One start tag with 1000 attributes.
        attrs = b" ".join(b'a%d="v"' % i for i in range(1000))
        return b"<r " + attrs + b"/>"

    if case == "depth-256":
        # The supported element-depth ceiling, opened and closed.
        return b"<e>" * 256 + b"</e>" * 256

    if case == "mixed":
        # Comments, processing instructions, CDATA sections, numeric
        # references and literal text, repeated.
        unit = b"<!--c--><?pi x?><![CDATA[y]]>&#65;z"
        return b"<r>" + unit * 4000 + b"</r>"

    if case == "utf16le":
        # UTF-16LE with a byte-order mark and a matching declaration.
        text = '<?xml version="1.0" encoding="UTF-16"?><r>' + ("x" * 30000) + "</r>"
        return b"\xff\xfe" + text.encode("utf-16le")

    if case == "latin1":
        # ISO-8859-1 declared and used: every byte is the scalar of its value.
        return (
            b'<?xml version="1.0" encoding="ISO-8859-1"?><r>'
            + b"\xe9" * 60000
            + b"</r>"
        )

    raise SystemExit(f"generate: unknown case {case!r}")


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True, help="absolute output directory")
    args = ap.parse_args(argv)

    out = pathlib.Path(args.out)
    if not out.is_absolute():
        raise SystemExit("generate: --out must be an absolute path")
    out.mkdir(parents=True, exist_ok=True)

    for case in CASES:
        data = build(case)
        (out / FILENAMES[case]).write_bytes(data)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
