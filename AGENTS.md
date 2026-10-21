# Repository test decisions

These are the decisions to read before adding or changing a check. They describe
this repository's behavior, not how any particular change was produced.

## Commands

All Lean and C toolchain commands run through the pinned dev shell:

```sh
nix develop -c lake build                      # library and proofs only
nix develop -c lake build lexpatTrace          # the demonstration executable
nix develop -c lake build lexpatEvents         # raw-event attribute-order driver
nix develop -c lake env lean --run tests/OneShotPrecedence.lean
nix develop -c lake env lean --run tests/StreamingCases.lean
nix develop -c lake exe lexpatTrace tests/corpus/basic.xml
nix develop -c lake exe lexpatTrace --chunk-size 1 tests/corpus/basic.xml
nix develop -c bash tests/clean-build.sh
nix develop -c python3 tests/streaming.py
nix develop -c python3 tests/differential.py
nix develop -c python3 tests/differential.py --group limits
nix develop -c bash tests/no-admits.sh
nix develop -c lake env lean LexPat/Encoding/Proofs.lean
```

`lake build` builds the default library and excludes `LexPat/Exe`; the
executable is deliberately not a default target. `.github/workflows/ci.yml` runs
the library build, the one-shot contract, the executable build, the streaming
harness, the full differential, the `limits` group, the admit check and the
proof audit, in that order, after installing Nix with flakes enabled.

A git-backed flake evaluates the **staged** tree. Stage new or changed flake
inputs (`flake.nix`, `flake.lock`, `lean-toolchain`, `lakefile.lean`,
`lake-manifest.json`) before a `nix develop` command that must see them, and
check that a pinned input in the index is populated rather than an empty blob.
Build outputs (`.lake/`), direnv state and `Vendor/` are never staged.

## Differential boundary

`tests/differential.py` is the behavioral check. It:

* materialises each input in a `TemporaryDirectory(prefix="lexpat-m1-", dir="/tmp")`,
  including generated hex and repeat patterns, and runs both binaries on the
  same bytes;
* compares accepted documents field by field: the events `lexpatTrace` emits,
  after coalescing adjacent text (never across a CDATA boundary) and
  canonicalizing attribute sets by raw name, must equal the fixture's expected
  events; the core event keeps document order and only the rendered trace sorts
  attributes, and error prose and offsets are omitted;
* checks the oracle's accepted events against its own declared expectation and
  rejects a difference, so each side is asserted independently;
* compares rejected documents by accept/reject and public error code, because a
  one-shot Lean parser returns no partial event array, and asserts the exact
  internal `reason` for Lean;
* requires a declared `exception` row to actually differ, and rejects an
  exception that has started to agree instead of skipping it;
* prints the libexpat version it used and runs three negative controls through
  the Lean comparison: an unmutated trace compares equal, a mutated event field
  is detected, and a flipped accept flag is detected in both directions.

The oracle is `tests/reference.c`, compiled in the same temporary directory
with `cc -std=c11 -Wall -Wextra -Werror tests/reference.c -lexpat`, falling back
to `pkg-config --cflags --libs expat` and reporting that deviation. It registers
only the XML declaration, start/end, character data, CDATA, comment and PI
handlers, sets `XML_PARAM_ENTITY_PARSING_NEVER`, installs no external resolver
and never reads a system identifier. libexpat is a test oracle only; no C code is
linked into the Lean library or executable.

## Streaming boundary

`tests/streaming.py` is the behavioral check for the resumable core. It first
runs `tests/StreamingCases.lean`, which asserts the public API directly: every
cut of short encoding, declaration, UTF-8/UTF-16 and markup samples, the
multi-fault pins, ambiguous prefixes, early emission, terminal inertness and
each budget's exact and plus-one crossing, including the first character of each
name or target, numeric-reference digit runs, and a certain declaration fault
that precedes a later input-limit fault, including a non-ASCII byte in an
ASCII-constrained declaration name or value. It then runs every corpus case
through `lexpatTrace` under `--chunk-size` 1, 2, 3, 5, 7, 13, 64, `whole` and
one seeded variable partition:

* accepted documents must produce the same terminal result as the one-shot
  trace under every partition, and the typed driver must match the
  independently declared expected events below;
* rejected documents must produce the same `(code, reason)` as one-shot and
  the same emitted prefix as whole-input streaming. A one-shot rejection has no
  event array, so it is never compared to a nonexistent array;
* the fixture expectation is asserted for every partition through the
  differential's `check_lean`, and the libexpat outcome (including every
  `exception` row) once per case;
* the trace reader requires exactly one result object and requires it to be
  the last object, so an event after the result fails.

The rendered trace sorts attributes into a JSON object, so it cannot observe
`Event.start`'s attribute order. The expected events for
`tests/StreamingEvents.lean`, built as `lexpatEvents`, are independent of the
parser and of the trace: `tests/streaming.py` expands the explicit event recipes
in `tests/corpus/cases.json`, takes each start's attribute values from that same
event, and takes document order from `tests/corpus/raw-attribute-order.json`.
That overlay maps case IDs to `{"eventIndex": N, "keys": [...]}` entries, where
the index is zero-based in the expanded fixture event array; every accepted
start with two or more attributes needs exactly one entry, and a missing, extra,
duplicate or non-permutation entry fails. `trace-basic` ships only a trace, so it
uses the `xml-basic` recipe after its materialized input bytes are shown equal;
another trace-only row without an explicit recipe is refused rather than falling
back to the trace. The harness writes the expected `Array Event` to a temporary
file, and the driver compares all nine partitions positionally against it, with
the one-shot result as a secondary comparison only. An unmodified expected array
must compare equal, and a reversed multi-attribute expected array must be
detected by the same typed comparator.

The seeded partition uses `--chunk-size 64 --chunk-seed SEED`, where `SEED` is
the first four bytes of `sha256(case_id)` read big-endian. The CLI updates
`s := (1664525*s + 1013904223) mod 4294967296` once per actual feed and uses
length `1 + s mod N`; `tests/streaming.py` records the resulting divide for
failure reports. Invalid numbers, `--chunk-seed` without a numeric
`--chunk-size`, and `--chunk-size whole` with a seed exit 2 and are asserted to
do so. Controls mutate an accepted event payload, the terminal result, and the
event/result order, and require the same comparators to detect each change.

The first-fault rule is shared by `Stream` and `parseDocument`: a permanent
error is returned only when the consumed bytes prove it for every continuation.
Incomplete signatures, scalars, references and markup delimiters pause; a
non-ASCII byte inside an ASCII-constrained XML declaration pseudo-attribute name
or value is a certain declaration fault reported at that byte, even while the
encoding choice is still undecided, because no continuation or label restores an
ASCII value. At `finish`, a pending decoder fault is resolved before EOF-only
grammar faults.
Already-returned events are a provisional prefix, not a transactional
guarantee. Stored state is inspected structurally in `StreamingCases.lean`:
pending decoder bytes are at most three, unfinished values are bounded by
`maxTokenChars`, and no field retains a consumed chunk. Address space is not
used as a proxy for resident bytes.

## Corpus

`tests/corpus/cases.json` is the manifest. Each row has an `id`, a `group`
(`encoding-valid`, `encoding-attack`, `xml-valid`, `xml-invalid`, `limits`,
`trace`), one input form, an `expected` outcome, and optionally a `reference`
outcome and an `exception` reason.

Input forms:

* `file`: a path under the repository;
* `hex`: the input bytes as hexadecimal;
* `pattern`: `prefix` hex, one `repeatByte`, a `repeatCount`, `suffix` hex — used
  for the large input and token boundaries without committing a multi-megabyte
  fixture;
* `nested`: `depth` open-and-close pairs named `e`, for the nesting boundary;
* `refs`: `count` numeric references with `perText` per short child element,
  wrapped in one `root` element, for the reference-expansion boundary.

Expected outcomes use `dataRepeat` (`char` repeated `count` times) inside a text
event, `repeatEvents` (a template repeated `count` times, plus `extraEvents`),
`openingEvents`/`closingEvents` around it, and `nestingEvents` (`depth` start
events followed by `depth` end events). `expectedFile` names a shipped JSONL
fixture; with `exactTrace`, the Lean stdout must match that file byte for byte.
A trace-only row used for the raw-event comparison must have a byte-identical
explicit recipe elsewhere in the manifest; the streaming harness refuses it
instead of deriving expected events from the trace.

`tests/corpus/raw-attribute-order.json` is the separate order overlay. Each
start with two or more attributes lists its raw names in document order,
indexed by case ID and zero-based expanded event index. The order is authored
from the input bytes, never from parser output or a sorted rendering, and the
overlay is the only source of attribute order for the typed streaming
comparison.

The `trace` group ships `tests/corpus/basic.xml` with `basic.jsonl` and
`tests/corpus/malformed.xml` with `malformed.jsonl`. `basic.xml` has two
attributes in non-lexical order, so its expected trace asserts sorted rendered
attribute keys, not merely the presence of the tokens.

Fixture expectations are written explicitly, not derived from either parser at
run time. A rejected row asserts its exact internal reason, so a change in which
rule fires is visible.

## Reference versions

The differential prints the oracle it actually compiled (`expat_2.8.5` with the
current `flake.lock`, reported via `pkg-config` and `XML_ExpatVersion`). The
semantic reference for the implemented subset is upstream libexpat `R_2_9_0`
(commit `a76b1174c1ea52abb639a4c69d52b630a8a106a2`). That checkout is not
vendored, linked, fetched or read by any check. An oracle difference is allowed
only after inspecting the specific case and recording it as an `exception` row
with a reason; never weaken the comparison globally.

## Proof audit

`LexPat/Encoding/Proofs.lean` proves its two theorems about the actual
`decodeUtf8One`, not about a restated predicate. `#print axioms` must report only
`propext` and `Quot.sound`; there are no custom axioms. `tests/no-admits.sh`
rejects `sorry`, `partial` and `unsafe` across every `.lean` file under `LexPat/`
and `LexPat.lean`, and injects `sorry` into a temporary copy so the scanner is
shown to catch a real occurrence rather than match nothing.

A build is not evidence of runtime behavior, and these theorems are not an
end-to-end parser or I/O proof. Behavioral claims come from the corpus, the
differential and the budget rows.

## Resource budgets

Defaults: 8 MiB raw input, 1 MiB per name/value/text/comment/CDATA/PI
accumulation, 256 open elements, 1 MiB cumulative reference-expansion output.
Token and reference budgets are measured in decoded characters. A name or
target charges its first character like every later one; a numeric character
reference charges its digit run to the token budget and its expanded character
to the reference budget and to the buffer it lands in. Each boundary
has an exact-boundary row that must be accepted and a boundary-plus-one row that
must be rejected with its own `LIMIT_*` code, with the other three budgets under
their ceilings. The expansion case keeps every text run short and checks the
reference budget before the append that would cross it, so the named failing
budget cannot be the token budget.

## No live external systems

No check contacts a network service, model, clock or live system. The
differential uses the local libexpat build; the corpus inputs are checked in or
generated deterministically in a temporary directory; `tests/clean-build.sh`
copies only candidate sources into `/tmp/lexpat-m1.XXXXXX` and removes it on
exit. `Vendor/expat/` is ignored so an upstream checkout cannot be committed by
accident.

## Documentation claims

`lexpatTrace` is a bounded demonstration and differential fixture. No surface in
this milestone is a production integration route: not the executable, not
`LexPat.parseDocument`, not `LexPat.Stream`, and not any C entry point or other
library call. The library API is documented so its behavior can be inspected
and so a later design has something concrete to build on, not as a supported
route. The event-trace claims above hold only because the differential compares
the Lean events with the fixtures on every accepted row, and the streaming
claims hold only because `tests/streaming.py` compares every partition with
independently declared expected events and with the one-shot result. Changes to
the demonstrated subset, the trace fields, the chunked modes or the limits must
update `README.md`, `docs/compatibility.md` and the shipped JSONL fixtures
together. The one-shot wrapper and the stream share
one earliest-certain-fault rule; a page must not describe the old
decode-everything-first priority as current.
