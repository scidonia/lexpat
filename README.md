# lexpat

A Lean 4 port of libexpat's XML 1.0 parsing semantics, aimed at untrusted
input. Compatibility is at the specification level, not byte-for-byte or
C-internal: the parser reproduces XML 1.0 (Fifth Edition) document semantics
and Expat's event and error categories, while normalizing details such as error
text, byte offsets and callback chunk boundaries.

This is the second milestone: a pure, total, resumable parser core with a
one-shot wrapper, a demonstration executable with a versioned trace and
chunked feeding modes, a checked-in corpus compared against a local libexpat
build, direct streaming assertions, and machine-checked properties of the
UTF-8 decoder.

## Build and check

The toolchain is pinned (`lean-toolchain`, `flake.lock`); every command runs in
the Nix dev shell.

```sh
nix develop -c lake build
nix develop -c lake build lexpatTrace
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

`lake build` builds only the library and its proofs; the executable is built on
demand, so a bare build needs nothing outside the Lean toolchain. The
differential needs a C compiler and libexpat from the dev shell.

## Library

```lean
LexPat.Stream.new    : LexPat.Limits → LexPat.Stream
LexPat.Stream.feed   : LexPat.Stream → ByteArray → LexPat.Stream × Array LexPat.Event
LexPat.Stream.finish : LexPat.Stream → LexPat.Stream × Array LexPat.Event
LexPat.Stream.result : LexPat.Stream → Option (Except LexPat.ParseError Unit)

LexPat.parseDocument : ByteArray → LexPat.Limits → Except LexPat.ParseError (Array LexPat.Event)
```

`Stream` is the resumable core. `feed` accepts any byte chunk, emits the events
that chunk determines, and returns the continuation state; `finish` resolves
the document. State holds the fixed budgets, cumulative byte and reference
counts, the encoding decision or its bounded undecided prefix, at most three
pending decoder bytes, the grammar continuation, the unfinished lexical value
and the element stack. Returned events are the caller's; the state keeps no
output history and no earlier chunk.

Encoding is selected once from byte evidence and, for an ASCII-compatible
document, from the bounded declaration prefix. Incomplete BOM, UTF-16
signature, multibyte scalar and markup prefixes pause rather than guess. A
permanent error is returned only when the bytes already consumed prove it for
every continuation. A fault completed earlier in the input wins over a later
decoding or input-budget fault; at `finish`, a pending decoder fault is resolved
before EOF-only grammar faults. Events returned before a later rejection are a
provisional prefix, not a transactional guarantee.

`parseDocument` is the one-shot wrapper: it feeds the whole byte array to a
fresh stream, finishes it, and returns the ordered events only on success. A
rejected document returns a `ParseError` carrying the public category, the
concrete rule and a diagnostic byte offset, with no event array. Because the
wrapper shares the stream's rule, it reports the earliest certain fault in
input order. For an input with more than one independent fault this can differ
from a decode-everything-first order; every corpus outcome is unchanged.

This milestone supports no production integration surface, `Stream` and
`parseDocument` included. The library API is documented so its behavior can be
inspected and so a later design has something concrete to build on; it is not a
supported integration route, and no compatibility or stability commitment
attaches to it.

Encoding validation and XML character legality are deliberately separate:
UTF-8, UTF-16, ISO-8859-1 and US-ASCII decide which *scalars* exist, while
`Char`, `NameStartChar` and `NameChar` decide which scalars an XML document may
use.

## Demonstration executable

`lexpatTrace` is a bounded demonstration and differential fixture. It is **not**
a production integration route, and it does not provide, promise or emulate a C
API. Its documented surface is its input syntax and its stable trace shape.

```sh
nix develop -c lake exe lexpatTrace tests/corpus/basic.xml
nix develop -c lake exe lexpatTrace --chunk-size 1 tests/corpus/basic.xml
nix develop -c lake exe lexpatTrace --chunk-size whole tests/corpus/basic.xml
nix develop -c lake exe lexpatTrace --chunk-size 64 --chunk-seed 1 tests/corpus/basic.xml
nix develop -c lake exe lexpatTrace --help
```

It reads one binary XML file and writes JSON Lines to standard output. The
default and `whole` modes read at most `maxInputBytes + 1` bytes; the numeric
and seeded modes assemble 64 KiB IO blocks and stop feeding once the stream is
terminal, so a block may extend past the byte that failed. Every object carries
`"format":1`; the last object is a result.

The default invocation is the one-shot trace. `--chunk-size N` feeds the file
in `N`-byte chunks, where `N` is a decimal integer in `[1,65536]`;
`--chunk-size whole` feeds it in one chunk; and
`--chunk-size N --chunk-seed SEED` selects variable per-feed lengths in `[1,N]`
for a decimal `SEED` in `[0,4294967295]`. The seeded rule is
`s := (1664525*s + 1013904223) mod 4294967296` once per feed, then length
`1 + s mod N`; a final shorter chunk may carry the tail. Invalid numbers,
`--chunk-seed` without a numeric `--chunk-size`, and `--chunk-size whole` with
a seed are usage errors; no flag is silently ignored. The streaming modes print
each event as it is returned and then one result. A rejected stream may already
have printed prefix events; the one-shot mode cannot.

```json
{"format":1,"type":"xmlDecl","version":"1.0","encoding":"UTF-8","standalone":null}
{"format":1,"type":"comment","data":" shipped example "}
{"format":1,"type":"start","name":"doc","attributes":{"a":"first","z":"last"}}
{"format":1,"type":"end","name":"doc"}
{"format":1,"type":"result","ok":true}
```

Event objects carry `type` and the applicable `name`, `attributes`, `data`,
`target`, `version`, `encoding` and `standalone` fields. Attributes are rendered
sorted by raw name; event order is document order, and a start event carries its
attributes in document order. Accepted documents end with
`{"format":1,"type":"result","ok":true}`. Rejected documents end with
`{"format":1,"type":"result","ok":false,"code":"TAG_MISMATCH","reason":"tagMismatch"}`.

Exit status is 0 for an accepted document, 1 for a rejected one (after its result
object), and 2 for a usage or I/O error, which is reported on standard error and
never presented as an XML result. Standard output carries no log chatter.

`tests/corpus/basic.xml` and its expected trace `tests/corpus/basic.jsonl` are
the shipped example; `tests/corpus/malformed.xml` and `malformed.jsonl` show the
rejection shape.

Stable means the field names, values and ordering above do not change without a
format-version bump. It does not make the executable an API.

## Limits

Defaults, per document:

| budget | value | measured in |
| --- | --- | --- |
| raw input | 8 MiB (8388608 bytes) | bytes read |
| one name, attribute value, text, comment, CDATA, PI accumulation or numeric-reference digit run | 1 MiB (1048576) | decoded characters |
| open elements | 256 | element stack depth |
| cumulative reference expansion | 1 MiB (1048576) | decoded characters contributed by predefined and numeric references |

Each check happens before the corresponding append, and each failure is a local
code (`LIMIT_INPUT`, `LIMIT_TOKEN`, `LIMIT_DEPTH`, `LIMIT_ENTITY_EXPANSION`) so a
rejection says which budget was crossed. `tests/corpus/cases.json` contains an
exact-boundary and a boundary-plus-one row for each budget, constructed so the
other three remain under their ceilings. The counters persist across `feed`
calls: a chunk boundary never resets a budget, and the input budget fails at the
first excess byte. An undecided declaration prefix is bounded in storage by
`min(maxInputBytes, maxTokenChars)` plus the fixed `<?xml` discriminator; that
storage ceiling is not itself a public error, and the prefix is handed to the
grammar so its token budget is reported exactly as before. The prefix is also
checked as it arrives: a declaration token the grammar already rejects is
reported as soon as its last byte is consumed, so a later input-budget failure
cannot mask it. A non-ASCII byte inside an ASCII-constrained declaration
pseudo-attribute name or value is likewise a certain declaration fault at that
byte, decided before the encoding choice because no continuation or label can
restore an ASCII value; the same byte outside such a field still waits for its
scalar. An incomplete value is never guessed.

Only attacker-controlled work within these budgets is bounded. A Lean runtime
allocation failure is not claimed to be impossible; total parsing, the explicit
stack and the absence of an entity resolver are what remove the usual
unbounded-recursion and entity-amplification failure modes.

## Supported XML subset

* XML declaration at the start of the document: `version="1.0"`, optional
  `encoding` and optional `standalone="yes"|"no"`, in that order.
* UTF-8 with or without a BOM; UTF-16LE/BE with a BOM or a zero-byte initial
  signature; ISO-8859-1 and US-ASCII selected by the declaration.
* Elements including empty-element tags, attributes with XML CDATA attribute
  value normalization, character data, CDATA sections, comments, processing
  instructions, and the predefined entities `amp`, `lt`, `gt`, `apos`, `quot`
  plus decimal and hexadecimal character references.
* XML 1.0 `Char`, `NameStartChar` and `NameChar`, including supplementary-plane
  names through `U+EFFFF`.
* Document line-ending normalization and the CDATA attribute-value rules:
  literal `CRLF`/`CR`/`LF`/`TAB` become spaces in attribute values, references to
  those code points stay themselves, and literal document line endings become
  `LF`.
* Resumable parsing through `LexPat.Stream` and the `lexpatTrace` chunked
  modes: the same grammar, events, budgets and errors under any chunking. For an
  accepted document the ordered events equal the one-shot result; for a rejected
  one the final `(code, reason)` is the same and any returned events are a
  prefix of the input that was accepted. `finish` alone diagnoses an unfinished
  document.

## Not supported

These are rejected, not simulated or silently skipped:

* the C ABI (any exported `XML_*` function), byte-identical output, exact error
  text or offsets, and callback chunk boundaries;
* every `DOCTYPE`, internal or external DTD subsets, parameter entities,
  non-predefined general entities, external entity resolution, catalogs, and
  system identifiers (no resolver exists and no identifier is read);
* namespace URI processing and namespace-aware name splitting (raw qualified
  names are reported instead);
* XML 1.1, unknown encodings, and encodings other than the four above;
* any production integration or stability promise: `Stream`, `parseDocument`
  and `lexpatTrace` are inspection and demonstration surfaces, and the chunked
  modes do not emulate `XML_Parse`/`XML_ParseBuffer` semantics.

## Proved decoder properties

`LexPat/Encoding/Proofs.lean` proves, about the real `decodeUtf8One`:

* `decodeUtf8One_rejects_overlong_two_byte`: the leads `0xC0` and `0xC1` are
  rejected with reason `overlong` for *every* possible tail.
* `decodeUtf8One_ascii_roundtrip`: an ASCII scalar encoded by `encodeAscii`
  decodes back to that scalar.

`#print axioms` for both reports only `propext` and `Quot.sound`; `tests/no-admits.sh`
rejects `sorry`, `partial` and `unsafe` in every Lean source. A build proves
neither runtime behavior nor parser correctness: the corpus, the differential
and the budget checks are the behavioral evidence, and they are not a proof of
end-to-end correspondence.

## Differential

`tests/differential.py` compiles `tests/reference.c` against the dev shell's
libexpat and runs it and `lexpatTrace` over `tests/corpus/cases.json` on
identical bytes. Accepted documents are compared field by field: the events
`lexpatTrace` emits, normalized by coalescing adjacent text and canonicalizing
attribute sets by raw name, must equal the fixture's expected events, and the
libexpat oracle's events are checked against its own declared expectation
independently. Rejected documents are compared by accept/reject and semantic
error code, with the exact internal reason asserted for Lean. Fixture
expectations are asserted on both sides. Every deliberate difference is declared
in the manifest with its reason, and an exception that stops differing is a
failure. Three negative controls run through the Lean comparison: an unmutated
trace must match, a mutated event field must be detected, and a flipped accept
decision must be detected in both directions. See `docs/compatibility.md` for
the mapping and the enumerated differences, and `AGENTS.md` for the test policy.

`tests/streaming.py` is the separate streaming check. It runs
`tests/StreamingCases.lean` for direct API assertions, then every corpus case
under fixed chunk sizes 1, 2, 3, 5, 7, 13 and 64, whole-input streaming and one
seeded partition. Rejected documents must produce the same `(code, reason)` and
the same emitted prefix as whole-input streaming. The trace reader requires
exactly one result object, last. Negative command-line combinations must exit 2,
and controls show that a changed event, a changed result or an event moved after
the result is detected.

For accepted documents the harness builds an expected `Array Event` from the
manifest's explicit event recipes and the checked-in document order in
`tests/corpus/raw-attribute-order.json`; a row that ships only a trace uses a
recipe with byte-identical input. `tests/StreamingEvents.lean`, built as
`lexpatEvents`, compares all nine partitions and the one-shot result
positionally against that array, so the expectation is independent of the parser
and of the sorted trace rendering. An unmodified expected array and a reversed
multi-attribute array exercise the same typed comparator.

The executable printed at the top of a run is the libexpat build in the dev
shell (recorded as `expat_2.8.5` for the current lock). Upstream libexpat
`R_2_9_0` is the semantic reference for the subset and is not vendored or
fetched by any check.
