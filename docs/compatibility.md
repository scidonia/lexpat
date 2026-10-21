# Compatibility

lexpat targets **specification-level** compatibility with libexpat: XML 1.0
(Fifth Edition) document semantics, the same order of events, and the same
public error categories where the specification decides the outcome. It does not
target byte-for-byte output, C-internal behavior, exact error strings or offsets,
or callback chunk boundaries. The repository also ships `include/expat.h` and
`liblexpat.so.1` for a bounded `XML_*` subset. On x86_64-linux with the pinned
Lean runtime that subset is the verified C integration route; it is not a
drop-in replacement for libexpat, and every call outside the subset fails
closed.

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
* error prose and byte offsets are never compared;
* chunk boundaries do not change event boundaries: a text run is emitted at the
  next `<` or at a successful EOF, never because a chunk ended, and a CDATA
  section emits `cdataStart` at its opener and its text plus `cdataEnd` at
  `]]>`.

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

The resumable core makes the same decision once, from the undecided opening
prefix. Incomplete BOMs (`EF`, `EF BB`, `FF`, `FE`), an incomplete zero-byte
UTF-16 signature (`00`, `3C`) and an incomplete `<?xml` discriminator pause
instead of guessing. A recognized `<?xml ` declaration is retained until `?>`
or the scan ceiling (`min(maxInputBytes, maxTokenChars)`), then the label is
located with the same scanner and the prefix is replayed exactly once through
the chosen decoder. Reaching the storage ceiling is not a public error; the
grammar reports the declaration's token budget as before. No event is emitted
before the encoding choice that could change it.

The declaration's pseudo-attribute names and values are ASCII-constrained. While
the encoding is still undecided, a non-ASCII byte inside one of those fields is
a certain declaration fault (`XML_DECL` with the field's own reason, reported at
that byte), because no continuation and no encoding label can restore an ASCII
value; it therefore wins over a later input-budget crossing. The same byte
outside such a field is not decided early: an incomplete multibyte scalar still
waits for its continuation or for `finish`.

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
| `LIMIT_TOKEN` | none (local) | one name/value/text/comment/CDATA/PI accumulation or numeric-reference digit run above the token budget |
| `LIMIT_DEPTH` | none (local) | more open elements than the depth budget |
| `LIMIT_ENTITY_EXPANSION` | none (local) | cumulative predefined/numeric reference output above the reference budget |

The one-shot wrapper and the resumable core share one **earliest certain,
decidable fault** rule. A permanent error is returned only when the bytes
already consumed prove the violation for every continuation; incomplete
signatures, multibyte scalars, references and markup delimiters pause instead
of guessing, and a non-ASCII byte in an ASCII-constrained declaration field is
decided at that byte before the encoding is selected. A parser fault completed
earlier in the input wins over a later
decoding or input-budget fault, and `finish` resolves a pending decoder fault
before EOF-only grammar faults. The one-shot wrapper therefore reports the same
`(code, reason)` as any chunking of the same bytes. For an input with more than
one independent fault this can differ from a decode-everything-first order; no
corpus outcome changes.

A rejected one-shot parse returns no event array. A rejected stream may already
have returned events, because events are irrevocable prefixes once determined;
those prefixes are chunk-invariant and are compared with whole-input streaming,
never with a nonexistent one-shot rejected array, and they are not a
transactional guarantee.

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

## C ABI call surface

The repository builds `include/expat.h` and `liblexpat.so.1` from the streaming
core. Events cross into C through an internal versioned record at the point the
grammar determines them, so handlers run before the feeding `XML_Parse` or
`XML_ParseBuffer` call returns; the pure `Stream.feed`/`Stream.finish` arrays and
`parseDocument` are unchanged.

For x86_64-linux with the pinned Lean runtime, this header and shared object
provide the subset below as the verified C integration route. It is not a
drop-in replacement for libexpat: only the calls named here are exported, the
private `XML_ParserStruct` layout is not Expat's, and the version and feature
list identify lexpat (`lexpat_0.1.0-cabi1`, `{0, 1, 0}`), not Expat.

### Supported calls

Lifecycle and data: `XML_ParserCreate` (only with a NULL encoding),
`XML_ParserFree`, `XML_SetUserData`, and the pinned `XML_GetUserData` macro,
which reads a pointer at offset zero.

Handlers: `XML_SetElementHandler`, `XML_SetStartElementHandler`,
`XML_SetEndElementHandler`, `XML_SetCharacterDataHandler`,
`XML_SetProcessingInstructionHandler`, `XML_SetCommentHandler`,
`XML_SetCdataSectionHandler`, `XML_SetStartCdataSectionHandler`,
`XML_SetEndCdataSectionHandler`, `XML_SetXmlDeclHandler`.

Parse and buffer: `XML_Parse`, `XML_GetBuffer`, `XML_ParseBuffer`.

Error, location, status and identity: `XML_GetErrorCode`, `XML_ErrorString`,
`XML_GetCurrentByteIndex`, `XML_GetCurrentLineNumber`,
`XML_GetCurrentColumnNumber`, `XML_ExpatVersion`, `XML_ExpatVersionInfo`,
`XML_GetFeatureList`, `XML_SetParamEntityParsing` (only
`XML_PARAM_ENTITY_PARSING_NEVER`, and only before the first parse call),
`XML_GetParsingStatus`, `XML_GetSpecifiedAttributeCount`,
`XML_GetIdAttributeIndex`.

Start events deliver attribute name/value pairs in document order, terminated by
a NULL entry. Text callbacks use the explicit byte length. Declarations report
an absent encoding as NULL and standalone as `-1`, `0` or `1`. A handler may
already have run for a prefix of the input when a later byte rejects the
document; the rejection is not retroactive.

### Preconditions and handle lifetime

The caller supplies a live parser handle returned by this library and accessible
memory for every non-NULL pointer and declared length. No C API can verify a
fabricated non-NULL pointer or that a nominal length fits its backing allocation.
`XML_GetUserData` is the pinned Expat macro `(*(void **)(parser))`: it
dereferences the handle directly, has no registry check, and is undefined after
`XML_ParserFree`. `XML_ParserFree` ignores an immediate repeat call, but a
freed address reused for a different parser cannot be distinguished from that
new parser; post-free pointer reuse is caller undefined behavior, and the
registry check only covers released handles before their address is reused.
Freeing a parser inside its own callback stops delivery, releases the parser
after the callback unwinds, and makes further use of the handle invalid.
Re-entrant parse attempts from a callback return `XML_ERROR_REENTRANT_CALL` on
the called parser. `XML_ParserCreate` is supported inside a callback and
returns an independent parser; that parser can be fed once the outer call has
returned, because a parse call made while a callback is running is refused.
Distinct parsers are independent; one parser must not be parsed from two
threads at once.

### Buffers and finality

`XML_GetBuffer` returns an owned, writable reservation of the requested length
for `0 <= length` within the remaining input budget. A new reservation
invalidates the previous one; its bytes are not carried over. A negative length
or a request beyond the remaining budget returns NULL and sets
`XML_ERROR_INVALID_ARGUMENT`. `XML_ParseBuffer` requires a live reservation and
`0 <= length <= capacity`, consumes exactly that prefix, and relinquishes the
reservation when it returns; without a reservation it reports
`XML_ERROR_NO_BUFFER`, and beyond capacity it reports
`XML_ERROR_INVALID_ARGUMENT`. Because a reservation is checked against the
remaining budget before any parse call, an over-budget document fed through a
single reservation reports `XML_ERROR_INVALID_ARGUMENT`, while the same bytes
through `XML_Parse` report `XML_ERROR_LIMIT_INPUT`; both refuse without parsing.
`XML_Parse` copies at most once into a Lean byte array and retains no caller
pointer. Both entry points reject a negative length, a NULL buffer with a
positive length, and new input after a final call (`XML_ERROR_FINISHED`).

### Callback positions

`XML_GetCurrentByteIndex`, `XML_GetCurrentLineNumber` and
`XML_GetCurrentColumnNumber` describe the event currently being delivered: the
0-based raw byte offset of its token opener, a 1-based normalized line, and a
0-based scalar column. Start, end, comment, processing-instruction, declaration
and CDATA events use their own opener; an empty-element end event uses the empty
tag's opener; a text event uses its first body scalar or its first reference
marker. A byte-order mark counts in the raw byte index but not in the line or
column. CRLF counts as one line ending, and CR and LF each start a line. After a
failure the positions refer to the failed token. A duplicate attribute is a
fault of the whole start tag, so its byte index, line and column all name the
opening `<`.

These offsets are lexpat's positions, not Expat's: the system Expat reports an
empty-element end event after the tag and counts a BOM as a column. The C
differential states those differences case by case; no byte-identical position
compatibility is claimed.

### Error mapping

Codes 0 through 44 are the pinned `XML_Error` numbering. The parser never
reports `XML_ERROR_AMPLIFICATION_LIMIT_BREACH` (43) or `XML_ERROR_NOT_STARTED`
(44). These named extensions are reported above 44, so a client comparing
against Expat's enum cannot read them as one of Expat's own codes:

| code | number | raised for |
| --- | --- | --- |
| `XML_ERROR_UNSUPPORTED_DTD` | 45 | any `DOCTYPE`, refused before its contents are read |
| `XML_ERROR_LIMIT_INPUT` | 46 | raw input above the input budget |
| `XML_ERROR_LIMIT_TOKEN` | 47 | one token accumulation above the token budget, or an event frame above its bound |
| `XML_ERROR_LIMIT_DEPTH` | 48 | more open elements than the depth budget |
| `XML_ERROR_LIMIT_ENTITY_EXPANSION` | 49 | cumulative reference output above the reference budget |
| `XML_ERROR_UNSUPPORTED_FEATURE` | 50 | a declared unsupported call or handler |
| `XML_ERROR_MALFORMED_WIRE` | 51 | a malformed internal event record |
| `XML_ERROR_REENTRANT_CALL` | 52 | a parse call made from inside a callback |

`XML_ErrorString` returns a stable static string for every code from 0 through
52 and NULL for an unknown value. The first error is retained: a later call does
not replace it. A NULL or already-released handle makes `XML_GetErrorCode`
report `XML_ERROR_INVALID_ARGUMENT` without dereferencing it, the location
getters return -1, 0 and 0, and `XML_GetSpecifiedAttributeCount` and
`XML_GetIdAttributeIndex` return -1.

### Unsupported calls

Every declared call outside the supported list refuses deterministically; none
is a silent no-op.

| calls | refusal |
| --- | --- |
| `XML_ParserCreateNS`, `XML_ParserCreate_MM`, `XML_ExternalEntityParserCreate` | return NULL |
| `XML_ParserReset` | returns `XML_FALSE` |
| `XML_SetEncoding`, `XML_SetBase` | return `XML_STATUS_ERROR` and poison the parser |
| `XML_GetBase` | returns NULL and poisons the parser |
| `XML_StopParser`, `XML_ResumeParser` | return `XML_STATUS_ERROR` (never `XML_STATUS_SUSPENDED`) and poison the parser |
| `XML_DefaultCurrent` | poisons the parser |
| `XML_GetInputContext` | returns NULL, zeroes the offset and size, and poisons the parser |
| `XML_GetCurrentByteCount` | returns -1 and poisons the parser |
| `XML_UseForeignDTD` | returns `XML_ERROR_UNSUPPORTED_FEATURE` and poisons the parser |
| `XML_SetHashSalt`, `XML_SetHashSalt16Bytes`, `XML_SetReparseDeferralEnabled`, `XML_SetBillionLaughsAttackProtectionMaximumAmplification`, `XML_SetBillionLaughsAttackProtectionActivationThreshold`, `XML_SetAllocTrackerMaximumAmplification`, `XML_SetAllocTrackerActivationThreshold` | return 0 or `XML_FALSE` and poison the parser |
| `XML_MemMalloc`, `XML_MemRealloc` | return NULL and poison the parser |
| `XML_MemFree`, `XML_FreeContentModel` | poison the parser |
| `XML_SetDefaultHandler`, `XML_SetDefaultHandlerExpand`, `XML_SetDoctypeDeclHandler`, `XML_SetStartDoctypeDeclHandler`, `XML_SetEndDoctypeDeclHandler`, `XML_SetElementDeclHandler`, `XML_SetAttlistDeclHandler`, `XML_SetEntityDeclHandler`, `XML_SetUnparsedEntityDeclHandler`, `XML_SetNotationDeclHandler` | a non-NULL registration poisons the parser |
| `XML_SetNamespaceDeclHandler`, `XML_SetStartNamespaceDeclHandler`, `XML_SetEndNamespaceDeclHandler`, `XML_SetReturnNSTriplet` with a non-zero argument, `XML_UseParserAsHandlerArg` | a non-NULL or enabling registration poisons the parser |
| `XML_SetNotStandaloneHandler`, `XML_SetExternalEntityRefHandler`, `XML_SetExternalEntityRefHandlerArg` with a non-NULL argument, `XML_SetSkippedEntityHandler`, `XML_SetUnknownEncodingHandler` with a non-NULL handler | a non-NULL registration poisons the parser |

Poisoning is terminal: the error is `XML_ERROR_UNSUPPORTED_FEATURE` and every
later parse call fails. Clearing a handler with NULL stays harmless, and there
is no resolver, file or network path to reach. `XML_Content` and
`XML_Memory_Handling_Suite` are laid out as public types for source and layout
compatibility; no call produces or consumes them. `XML_SetParamEntityParsing`
returns 1 for `XML_PARAM_ENTITY_PARSING_NEVER` before the first parse call,
returns 0 with no effect after parsing has started, and returns 0 while
poisoning for the other modes before it starts. `XML_GetParsingStatus` fills the
caller's status with `XML_INITIALIZED`, `XML_PARSING` or `XML_FINISHED` and the
final-buffer flag; the flag is set for the call whose `isFinal` argument was
set and is visible that way in its callbacks, and a non-final call clears it.
It never reports `XML_SUSPENDED`, and a NULL out-pointer poisons the parser
with `XML_ERROR_INVALID_ARGUMENT`.

A `DOCTYPE` is refused before its identifier is read, and no DTD, parameter
entity, external entity, catalog or custom allocator is ever consulted.
Namespace-aware parsing is not implemented: `XML_ParserCreateNS` is refused and
qualified names are reported as raw names. `XML_ParserCreate` with a non-NULL
encoding hint returns NULL; an unknown declaration label is rejected with
`XML_ERROR_UNKNOWN_ENCODING`.

`XML_SetParamEntityParsing`, `XML_GetParsingStatus`, the specified-attribute
count and the ID index are supported only in the narrow forms stated above; the
ID index is always -1 because no DTD exists, and the specified-attribute count
is twice the explicit pair count inside a start callback and 0 elsewhere. The
demonstration executable and the Lean library API remain inspection and
differential surfaces, not production integration routes.

## Trace stability

`lexpatTrace` emits `"format":1` on every object. Field names, the sorted
attribute rendering, event order and the terminal result shape are stable for
that version. The `--chunk-size` modes print the same event objects and exactly
one final result; they only change when an event is returned relative to the
input. Changing the shape requires a format-version bump and corresponding
fixture updates. That guarantee is about the trace used by the checks; it is not
an API commitment for production use.
