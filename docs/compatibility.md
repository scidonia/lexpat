# Compatibility

lexpat targets **specification-level** compatibility with libexpat: XML 1.0
(Fifth Edition) document semantics, the same order of events, and the same
public error categories where the specification decides the outcome. It does not
target byte-for-byte output, C-internal behavior, exact error strings or offsets,
or callback chunk boundaries, and it is not a C ABI.

The semantic reference is libexpat `R_2_9_0` (commit
`a76b1174c1ea52abb639a4c69d52b630a8a106a2`). No check vendors, fetches or reads
that checkout: the differential runs against the libexpat in the Nix dev shell
(`expat_2.8.5` with the current `flake.lock`) and prints the version it used.

## Event model

| event | fields | notes |
| --- | --- | --- |
| `xmlDecl` | `version`, `encoding` (string or null), `standalone` (bool or null) | only when the document has an XML declaration |
| `start` | `name`, `attributes` | attributes are an object keyed by raw qualified name; the event keeps document order and the rendered trace sorts by that name |
| `end` | `name` | an empty-element tag emits `start` then `end` |
| `text` | `data` | character data, including expanded references |
| `cdataStart` / `cdataEnd` | none | bracket CDATA character data, including empty sections |
| `comment` | `data` | comment body, line endings normalized |
| `pi` | `target`, `data` | data excludes the whitespace separating it from the target |

Normalization rules used when comparing traces:

* adjacent `text` events are coalesced, but never across a CDATA boundary;
* empty text events are not emitted;
* attribute sets are compared as a map canonicalized by raw name, while event
  order and parsed attribute order stay document order;
* error prose and byte offsets are never compared.

Line endings inside character data, CDATA, comments and PI data are normalized
to `LF`. In attribute values, literal `CRLF`, `CR`, `LF` and `TAB` each become
one space, while character references to `#x9`, `#xA` and `#xD` keep those
characters. Attribute values without a DTD use CDATA normalization, and raw `<`
is not allowed in an attribute value.

## Encoding decisions

Byte evidence is checked before any declaration is read:

1. `EF BB BF` selects UTF-8 (the BOM is not part of the document);
2. `FF FE` selects UTF-16LE and `FE FF` selects UTF-16BE;
3. otherwise an initial zero byte followed by `<` (`00 3C`) selects UTF-16BE,
   and `<` followed by a zero byte (`3C 00`) selects UTF-16LE;
4. otherwise a document that begins with `<?xml` followed by whitespace may name
   `UTF-8`, `US-ASCII` or `ISO-8859-1`; without a declaration the document is
   decoded as UTF-8.

The label is located by a bounded byte-level scan of the declaration prefix (at
most `maxTokenChars` bytes). The declaration is then re-parsed under the XML
declaration grammar and its `encoding` value is checked against the encoding
actually used. An unsupported
label is `UNKNOWN_ENCODING`; a label that contradicts the byte evidence (for
example a UTF-8 BOM with `encoding="ISO-8859-1"`, or `encoding="UTF-16"` in a
document with neither BOM nor UTF-16 signature) is `INCORRECT_ENCODING`. Only
`version="1.0"` is accepted.

UTF-8 rejects invalid lead bytes, invalid continuations, overlong forms,
surrogate values, values above `U+10FFFF`, and truncation. UTF-16 rejects an odd
byte count and unpaired surrogates. US-ASCII rejects bytes at or above `0x80`.
Every decoded scalar is then checked against the XML `Char` production, so
`U+FFFE`, `U+FFFF`, NUL and the other C0 controls are rejected even though they
are valid Unicode scalar values.

## Error mapping

The public code names are the `XML_Error` variants of `expat/lib/expat.h` with
the `XML_ERROR_` prefix removed.

| lexpat code | Expat equivalent | raised for |
| --- | --- | --- |
| `SYNTAX` | `XML_ERROR_SYNTAX` | unknown `<!` declaration in the prolog |
| `NO_ELEMENTS` | `XML_ERROR_NO_ELEMENTS` | no document element, or a root that never completes |
| `INVALID_TOKEN` | `XML_ERROR_INVALID_TOKEN` | illegal scalar, bad name, malformed reference, raw `<` in an attribute, stray end tag, `]]>` in text, misplaced reserved PI target, invalid decode |
| `UNCLOSED_TOKEN` | `XML_ERROR_UNCLOSED_TOKEN` | unterminated comment, PI or XML declaration |
| `PARTIAL_CHAR` | `XML_ERROR_PARTIAL_CHAR` | truncated multibyte sequence, odd UTF-16 byte count |
| `TAG_MISMATCH` | `XML_ERROR_TAG_MISMATCH` | end tag does not match the open element |
| `DUPLICATE_ATTRIBUTE` | `XML_ERROR_DUPLICATE_ATTRIBUTE` | duplicate raw qualified attribute name |
| `JUNK_AFTER_DOC_ELEMENT` | `XML_ERROR_JUNK_AFTER_DOC_ELEMENT` | text or a second element in the epilog |
| `UNDEFINED_ENTITY` | `XML_ERROR_UNDEFINED_ENTITY` | unknown named entity (there is no resolver) |
| `BAD_CHAR_REF` | `XML_ERROR_BAD_CHAR_REF` | numeric reference to a non-XML character or a value above `U+10FFFF` |
| `MISPLACED_XML_PI` | `XML_ERROR_MISPLACED_XML_PI` | XML declaration not at the start of the document |
| `UNKNOWN_ENCODING` | `XML_ERROR_UNKNOWN_ENCODING` | unsupported encoding label |
| `INCORRECT_ENCODING` | `XML_ERROR_INCORRECT_ENCODING` | declaration contradicts the byte evidence, or a BOM contradicts the declaration |
| `UNCLOSED_CDATA_SECTION` | `XML_ERROR_UNCLOSED_CDATA_SECTION` | CDATA section without `]]>` |
| `XML_DECL` | `XML_ERROR_XML_DECL` | malformed XML declaration: order, quoting, values, missing version |
| `UNSUPPORTED_DTD` | none (local) | any `DOCTYPE`, refused before its contents are read |
| `LIMIT_INPUT` | none (local) | raw input above the input budget |
| `LIMIT_TOKEN` | none (local) | one name/value/text/comment/CDATA/PI accumulation above the token budget |
| `LIMIT_DEPTH` | none (local) | more open elements than the depth budget |
| `LIMIT_ENTITY_EXPANSION` | none (local) | cumulative predefined/numeric reference output above the reference budget |

The trace also carries a `reason` string naming the concrete rule
(`overlong`, `unpairedSurrogate`, `duplicateAttribute`, ...). Reasons are
diagnostic; only the public code is compared with the oracle for rejected
documents.

## Intentional differences

These are asserted by `tests/corpus/cases.json` as `exception` rows: the Lean
outcome and the oracle outcome are both checked against their declared values,
and the row fails if they stop differing.

* **Every DOCTYPE is refused.** The parser rejects `<!DOCTYPE ...` as
  `UNSUPPORTED_DTD` before reading any declaration, internal subset, system
  identifier or parameter entity. Expat accepts plain, internal-subset and
  `SYSTEM` declarations (and expands internal general entities). This is the
  fail-closed behavior the milestone requires: no DTD, no external entity, no
  resolver, no identifier read.
* **Resource budgets.** Expat has no configurable input, token, nesting or
  reference-expansion budget, so inputs that lexpat rejects with a `LIMIT_*`
  code are accepted by the oracle. The exact-boundary rows are accepted by both.
* **A BOM contradicted by the declaration is rejected.** A UTF-8 BOM followed by
  `encoding="ISO-8859-1"` is `INCORRECT_ENCODING`; Expat accepts the declaration
  and decodes as UTF-8.
* **Supplementary-plane names.** XML 1.0 Fifth Edition `NameStartChar` includes
  `[#x10000-#xEFFFF]`, so a name such as `U+1D11E` is accepted. This libexpat
  build rejects stateful four-byte name characters with `INVALID_TOKEN`.
* **Odd UTF-16 byte count.** lexpat reports `PARTIAL_CHAR` with reason
  `oddUtf16Length`; Expat reports `UNCLOSED_TOKEN`.
* **Truncated UTF-16 surrogate.** An unpaired high or low surrogate is rejected
  during decoding with `INVALID_TOKEN`. Depending on where it appears, Expat may
  reject the document later as `NO_ELEMENTS`; the corpus uses a placement where
  both reject with `INVALID_TOKEN`.
* **Encoding labels.** The recognized labels are `UTF-8`, `UTF8`, `US-ASCII`,
  `ASCII`, `ISO-8859-1`, `ISO8859-1`, `LATIN1`, `LATIN-1`, `UTF-16`, `UTF-16LE`
  and `UTF-16BE`, matched case-insensitively. A UTF-16 document may name
  `UTF-16` or its own byte order; the other byte order is a mismatch.

Ordinary Expat quirks that are not modeled as differences: attributes are
reported with raw qualified names (so `xml:lang` and `xmlns:p` are ordinary
names, not namespace declarations); processing-instruction data excludes the
separator whitespace; an empty CDATA section still emits `cdataStart` and
`cdataEnd`; an XML declaration after a comment or another prolog construct is
`MISPLACED_XML_PI`.

## Fail-closed entity and DTD behavior

There is no entity resolver, no external entity handler, no catalog and no
network or filesystem access from the pure parser. No function accepts a system
identifier, and a `DOCTYPE` is rejected before its identifier would be read.
Named references other than the five predefined entities are
`UNDEFINED_ENTITY`; numeric references are expanded under the reference budget.
Recursive general entities therefore cannot expand, because no general entity
can be declared.

## Future C call support

The future direction is an event/consumer interface over the pure event values
and explicit parser state, so a later adapter could implement
`XML_ParserCreate`, handler registration, status/error codes and chunk feeding
without importing the CLI, JSON or reference C code into the library. Nothing of
that exists in this milestone:

* there is no exported `XML_*` symbol, no header, no shared library and no C
  entry point;
* `parseDocument` is one-shot, so it does not have `XML_Parse`/
  `XML_ParseBuffer` chunk semantics and must not be described as if it did;
* a future streaming implementation must handle boundary-split BOMs, multibyte
  characters, tokens and references explicitly;
* namespace processing (`XML_ParserCreateNS`) and DTD handling remain separate
  future work.

The demonstration executable and the library API exist for inspection and
differential testing of these semantics. This milestone supports no production
integration route, `parseDocument` included.

## Trace stability

`lexpatTrace` emits `"format":1` on every object. Field names, the sorted
attribute rendering, event order and the terminal result shape are stable for
that version. Changing them requires a format-version bump and corresponding
fixture updates. That guarantee is about the trace used by the checks; it is not
an API commitment for production use.
