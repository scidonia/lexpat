# lexpat

A Lean 4 port of libexpat's XML 1.0 parsing semantics, aimed at untrusted
input. Compatibility is at the specification level, not byte-for-byte or
C-internal: the parser reproduces XML 1.0 (Fifth Edition) document semantics
and Expat's event and error categories, while normalizing details such as error
text, byte offsets and callback chunk boundaries.

This is the first milestone: a bounded, one-shot, pure parser, a demonstration
executable with a versioned trace, a checked-in corpus compared against a local
libexpat build, and machine-checked properties of the UTF-8 decoder.

## Build and check

The toolchain is pinned (`lean-toolchain`, `flake.lock`); every command runs in
the Nix dev shell.

```sh
nix develop -c lake build
nix develop -c lake build lexpatTrace
nix develop -c lake exe lexpatTrace tests/corpus/basic.xml
nix develop -c bash tests/clean-build.sh
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
LexPat.parseDocument : ByteArray → LexPat.Limits → Except LexPat.ParseError (Array LexPat.Event)
```

`parseDocument` takes the whole document as raw bytes and explicit budgets,
and is total and free of global state. It decodes the bytes under a detected
encoding, validates every resulting scalar against XML 1.0 `Char`, parses the
document with an explicit element stack (no recursion on nesting), and returns
the ordered events or a `ParseError` carrying the public category, the concrete
rule that failed and a diagnostic byte offset. There is no partial event array
on failure.

This milestone supports no production integration surface, `parseDocument`
included. The library API is documented so its behavior can be inspected and so
a later design has something concrete to build on; it is not a supported
integration route, and no compatibility or stability commitment attaches to it.

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
nix develop -c lake exe lexpatTrace --help
```

It reads one binary XML file, reading at most `maxInputBytes + 1` bytes, and
writes JSON Lines to standard output. Every object carries `"format":1`; the
last object is a result.

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
| one name, attribute value, text, comment, CDATA or PI accumulation | 1 MiB (1048576) | decoded characters |
| open elements | 256 | element stack depth |
| cumulative reference expansion | 1 MiB (1048576) | decoded characters contributed by predefined and numeric references |

Each check happens before the corresponding append, and each failure is a local
code (`LIMIT_INPUT`, `LIMIT_TOKEN`, `LIMIT_DEPTH`, `LIMIT_ENTITY_EXPANSION`) so a
rejection says which budget was crossed. `tests/corpus/cases.json` contains an
exact-boundary and a boundary-plus-one row for each budget, constructed so the
other three remain under their ceilings.

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
* incremental or resumable parsing; `parseDocument` is one-shot.

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

The executable printed at the top of a run is the libexpat build in the dev
shell (recorded as `expat_2.8.5` for the current lock). Upstream libexpat
`R_2_9_0` is the semantic reference for the subset and is not vendored or
fetched by any check.
