# Repository test decisions

These are the decisions to read before adding or changing a check. They describe
this repository's behavior, not how any particular change was produced.

## Commands

All Lean and C toolchain commands run through the pinned dev shell:

```sh
nix develop -c lake build                      # library and proofs only
nix develop -c lake build lexpatTrace          # the demonstration executable
nix develop -c lake exe lexpatTrace tests/corpus/basic.xml
nix develop -c bash tests/clean-build.sh
nix develop -c python3 tests/differential.py
nix develop -c python3 tests/differential.py --group limits
nix develop -c bash tests/no-admits.sh
nix develop -c lake env lean LexPat/Encoding/Proofs.lean
```

`lake build` builds the default library and excludes `LexPat/Exe`; the
executable is deliberately not a default target. `.github/workflows/ci.yml` runs
the library build, the executable build, the full differential, the `limits`
group, the admit check and the proof audit, in that order, after installing Nix
with flakes enabled.

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
Token and reference budgets are measured in decoded characters. Each boundary
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
`LexPat.parseDocument`, and not any C entry point or other library call. The
library API is documented so its behavior can be inspected and so a later design
has something concrete to build on, not as a supported route. The event-trace
claims above hold only because the differential compares the Lean events with
the fixtures on every accepted row. Changes to the demonstrated subset, the
trace fields or the limits must update `README.md`, `docs/compatibility.md` and
the shipped JSONL fixtures together.
