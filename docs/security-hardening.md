# Security hardening record

This page records the security work on lexpat from the first parser core
through the bounded C ABI: the properties that are structural, the defects
that were found and fixed, the evidence that was added, and the libexpat
features that are still absent. It is a work record, not a claim that the
parser is free of bugs. The current threat model and CVE-class disposition are
in [`docs/security.md`](security.md).

Last updated: 2026-10-22, at commit `4999987` (Milestone 4).

## Supported surface

The supported integration route is the bounded C ABI in `include/expat.h` over
`liblexpat.so.1`, on x86_64-linux with the pinned Lean 4.35.0 runtime. It is
not a drop-in replacement for libexpat. The Lean one-shot API,
`LexPat.Stream`, and `lexpatTrace` are inspection and differential surfaces,
not production routes.

Default limits are 8 MiB raw input, 1 MiB per token accumulation, 256 open
elements, 1 MiB cumulative reference output and a 16 MiB per-callback payload
ceiling. The C ABI fixes these budgets; libexpat's configurable amplification
and alloc-tracker controls are not implemented.

## Structural properties

- The parser core is total Lean. It has no `partial`, `unsafe` or `sorry`; no
  pointer arithmetic; and only bounds-checked access to input data. The C ABI
  shim is separate C code and is not covered by that structural argument.
- UTF-8 rejects invalid leads, invalid continuations, overlong forms,
  surrogates, values above U+10FFFF and truncation. UTF-16 rejects odd byte
  counts and unpaired surrogates. Decoded scalars are checked against the XML
  1.0 `Char` production.
- The parser has no entity resolver, no DTD parser, no network or filesystem
  access, and no external-entity path. A `DOCTYPE` is refused before its
  contents are read; external entity creation and unknown encodings fail closed.
- Element nesting uses an explicit stack, never recursion on input depth.
  Input, token, depth and reference budgets are enforced before the
  corresponding append or allocation.
- The C ABI's private receivers validate a span against its owning chunk and
  the bytes fed so far, the source position, the ordered attribute table, the
  payload ceiling and the payload's UTF-8 legality before allocating, so a
  malformed internal call is refused before any handler runs. Callback payloads
  have a bounded lifetime, and parser handles are tracked so an immediate
  repeated free does not dereference freed memory. A stale pointer whose
  address has been reused is caller undefined behavior and is documented as
  such.
  The serialized internal event record described by HS-7 and HS-9 below is
  superseded: the artifact now calls callback-specific receivers directly, and
  the bounds those findings added are enforced by the receivers before their
  allocations. The findings remain as the record of what was fixed on that
  path.

## Findings and fixes

The table records security-relevant defects, including verification defects
that made a security check weaker than it claimed. Commit IDs identify the
delivered revision containing the fix.

| ID | Finding | Impact | Fix and regression | Commit |
| --- | --- | --- | --- | --- |
| HS-1 | A start tag without whitespace between attributes (`<r a="1"b="2"/>`) was accepted | Malformed input could be parsed differently from the specification | Start-tag parser now requires a separator before a subsequent attribute; malformed and spaced controls are in the corpus | `8e471dc` |
| HS-2 | The differential compared the oracle's events with fixtures but not the Lean event trace | A wrong Lean event stream could pass the security differential | Lean events are compared to independent fixture expectations; negative controls mutate an event and flip accept/reject | `8e471dc` |
| HS-3 | First characters of names/targets and numeric-reference digits bypassed the token budget | A zero or small token budget could be bypassed with a short name or a numeric reference | Every first character and reference digit is charged before storage; zero/exact/plus-one assertions across chunk splits | `c6dd77c` |
| HS-4 | The undecided XML-declaration prefix was copied quadratically because a retained `ByteArray` was appended through an alias | A long declaration prefix could cause disproportionate CPU use | The retained reference is released before append and the declaration shadow uses the stream's own fields; 1 MiB rows fell from minutes to under a second | `c6dd77c` |
| HS-5 | Calling `XML_ParserCreate` inside a callback deadlocked on a non-recursive Lean mutex | A supported lifecycle call could hang the process | Owner-aware thread-local entry; the bounded test creates a parser in a callback and parses after the outer call returns | `46980d2` |
| HS-6 | Events with no registered handler still copied element names, attributes, declaration strings, comments and PI data | Attacker-controlled input caused avoidable per-event allocations on a no-handler parser | Payloads are validated without callback copies when the handler is absent; the wrapped allocator records 0 shim allocations for the no-handler path and 9 with handlers | `46980d2` |
| HS-7 | The internal wire decoder accepted impossible metadata (offset beyond the fed window, unbounded column, invalid span) | A malformed frame could deliver false locations to a callback | Metadata is bounded against the fed bytes and frame; malformed frames are refused before dispatch; 32-frame wire group includes fabricated cases | `46980d2` |
| HS-8 | A failed callback allocation was reported as `XML_ERROR_MALFORMED_WIRE` (51) instead of `XML_ERROR_NO_MEMORY` (1) | A client could misclassify an out-of-memory failure as a parser/protocol fault | Seven dispatch branches now poison `NO_MEMORY`; malformed/header/UTF-8 stay `MALFORMED_WIRE`; A3 contract observed the pre-fix red and now passes | `4999987` |
| HS-9 | A short internal frame could declare about 2.1 billion attribute pairs and request a ~32 GiB vector before validating the payload | A malformed frame could force an enormous allocation request | Pair count is bounded by the remaining payload (`pairs > (payload.size - payload.pos) / 8`) before allocation; the wire test records and refuses an oversized request | `4999987` |
| HS-10 | `XML_GetParsingStatus` reported `finalBuffer = 0` during callbacks of a final `XML_Parse` | Compatibility bug in status reporting | The flag is set before dispatching final-buffer events; final/non-final callback assertions | `46980d2` |
| HS-11 | Duplicate-attribute failure positions disagreed between byte index and line/column anchors | Inconsistent failure location for the same fault | The fault is anchored at the opening `<`; byte, line and column are asserted together and the difference from Expat is documented | `46980d2` |
| HS-12 | Some tests asserted absence of callbacks without an affirmative control | A detector that never worked could pass an absence assertion | The same detector is exercised on a control parse before the absence assertion; the allocator and end detectors have controls | `46980d2` |
| HS-13 | An instrumented shared candidate could not be loaded into the static-ASan differential fuzzer, and the benchmark reused a process-lifetime RSS value | Differential topology and scaling evidence were weaker than claimed | Both libraries are loaded with `dlopen`/`dlsym`, the exact oracle version is checked, each fixed exception runs in one shared process, and each benchmark entry runs in a forked child with `wait4` RSS and interleaved sides | `4999987` |

Build and documentation issues fixed alongside the security work: a leaked
developer `RUNPATH` from ambient `NIX_LDFLAGS`; a dev-shell `cc` shim from
adding Clang; an inaccurate claim that a bare build was library/proofs only;
and C ABI route wording that was narrowed to the verified subset. None is a
parser memory-safety defect.

## Missing libexpat features

These exist in libexpat but are not implemented in lexpat. The calls listed in
`docs/compatibility.md` are declared and fail closed; absent features are not
simulated.

| Area | Missing from lexpat | Current behavior |
| --- | --- | --- |
| Namespaces | `XML_ParserCreateNS`, namespace declaration handlers, URI/local-name/prefix triplets, `XML_SetReturnNSTriplet` | `XML_ParserCreateNS` returns NULL; names are raw qualified names; namespace handlers poison the parser |
| DTD | `DOCTYPE` parsing, internal/external subsets, element/attlist/entity/notation declarations, parameter entities, conditional sections, content models, attribute defaults, ID/IDREF typing, standalone validation | Every `DOCTYPE` is refused as `XML_ERROR_UNSUPPORTED_DTD`; DTD handlers poison the parser; `XML_GetIdAttributeIndex` is -1 |
| External entities | `XML_ExternalEntityParserCreate`, external entity resolver, base URI (`XML_SetBase`/`XML_GetBase`), system/public identifiers, unparsed entities, catalogs | External parser creation returns NULL; setters poison the parser; no identifier is read; no resolver exists |
| Encodings | `XML_SetUnknownEncodingHandler`, external encoding hint in `XML_ParserCreate`, encodings beyond UTF-8/UTF-16LE/BE/ISO-8859-1/US-ASCII, `XML_SetEncoding` | A non-NULL encoding hint returns NULL; unknown labels are `UNKNOWN_ENCODING`; the unknown-encoding setter poisons the parser |
| Parsing control | `XML_StopParser`, `XML_ResumeParser`, suspending/resuming, parser reset (`XML_ParserReset`) | Stop/resume return an error and poison; reset returns false; `XML_STATUS_SUSPENDED` is never returned |
| Memory/allocator | `XML_ParserCreate_MM`, custom memory suite, `XML_MemMalloc`, `XML_MemRealloc`, `XML_MemFree`, `XML_FreeContentModel` | Create_MM returns NULL; memory calls return NULL or poison; the C shim uses the process allocator |
| Handler families | Default handler (normal and expand), skipped-entity handler, `XML_DefaultCurrent`, DTD/namespace handlers, not-standalone handler, `XML_UseParserAsHandlerArg` | A non-NULL enabling registration poisons the parser; no event is synthesized |
| Location/context | `XML_GetCurrentByteCount`, `XML_GetInputContext`, 64-bit location APIs added in Expat 2.9, `XML_GetBase` | Byte/line/column getters and specified-attribute count are supported; the listed calls return a refusal or poison |
| Security knobs | `XML_SetHashSalt`, `XML_SetHashSalt16Bytes`, `XML_SetReparseDeferralEnabled`, billion-laughs amplification/activation setters, alloc-tracker setters | Fixed budgets replace them; the setters return 0/false and poison the parser; no input-name hash table exists |
| XML version | XML 1.1 and its character/name rules | Only XML 1.0 is parsed |
| DTD-dependent semantics | Entity expansion, attribute defaults, attribute types, notation/unparsed-entity callbacks, validation | Only predefined entities and numeric references are expanded; attributes are CDATA |
| ABI identity | `libexpat.so.1` drop-in identity and the full public symbol set | Versioned `liblexpat.so.1`, 72 `XML_*` exports, private parser layout, `lexpat_0.1.0-cabi1` identity |
| Exact compatibility | Byte-identical event splitting, Expat error strings/offsets, BOM/empty-element location conventions, callback chunk boundaries | Normalized event/code compatibility for the supported subset; differences are documented and tested case by case |

`XML_GetSpecifiedAttributeCount`, `XML_GetCurrentByteIndex`, line and column,
`XML_GetParsingStatus`, `XML_SetParamEntityParsing(NEVER)` and the supported
handler families are present. `XML_GetAttributeInfo` is not a gap: Expat 2.9
removed it.

## CVE classes

The detailed class map, sources, exact expected outcomes and declared
differential exceptions are in [`docs/security.md`](security.md) and
`tests/security/`. In summary:

| Class | Disposition |
| --- | --- |
| DTD/entity/doctype parser memory corruption and integer overflow | Feature absent; input refused before DTD content |
| Namespace prefix/separator bugs | Feature absent; no namespace processing |
| External-entity resolver, base-URI and OOM bugs | Feature absent; no resolver or external parser |
| Unknown/custom encoding callback bugs | Feature absent; unknown encodings refused |
| Suspend/resume, parser-reset and reentrant-call bugs | APIs refused; nested parse is rejected; callback-time create is supported and bounded |
| C parser integer/buffer/pointer arithmetic defects | Structurally removed in the Lean core; the C shim is separate and tested |
| UTF-8/UTF-16 validation defects | Validated and covered by encoding-attack and differential cases |
| Internal callback span/count defects | Span bounds, positions, ordered attribute tables, payload ceiling and UTF-8 bounded before allocation; focused direct-bridge tests |
| Allocation-failure misclassification | Fixed and covered by A3 and the sanitized OOM matrix |
| DoS/quadratic parsing | Token/depth/input budgets and scaling checks; residual risk remains for measured shapes and inputs |
| Hash flooding | No attacker-keyed hash table in the parser; not applicable |
| Windows DLL hijacking, 32-bit overflow | Platform not supported; x86_64-linux only |

Feature absence is not a fix for the corresponding upstream bug; it means the
vulnerable path does not exist in this subset.

## Evidence

Local final checks on commit `4999987` passed:

- `lake build`, `lexpatTrace`, `lexpatEvents`, source-only `clean-build.sh`.
- A1, A2, A3 and S1 contracts; 108-case C ABI differential; 12 exact
  differential exceptions; 12-group C ABI verifier; ASan/UBSan and Valgrind
  memory paths.
- Streaming: 108 cases over 972 partitions; Lean differential 108/108; limits
  10/10; no-admits 11 sources with an affirmative control; decoder proofs only
  `propext` and `Quot.sound`.
- CVE corpus: 21 rows, 18 generated inputs, exact candidate/reference results.
- Injected shim allocation failures: 12 parse callsites plus create,
  reservation and free paths.
- Paired scaling: 80 matched sizes, worst candidate/base 1.062; 58 doublings,
  worst 2.140; drift 0.095; per-entry RSS; machine facts recorded.
- Long campaigns: parser 1,000,000 (608 s), C ABI 1,000,000 (542 s),
  differential 250,000 (410 s), artifact 100,000 (1.1 s); zero crash artifacts
  in all four.
- CI smoke (local): 10,000 / 10,000 / 2,000 / 5,000 inputs in about 166 s
  under the 300 s cap.

Hosted CI for commit `4999987` (`39728569691`) **failed in the bounded security
step** after the fixed-differential stage header, and the job ran for about
19 minutes rather than the intended cap. Local execution of the same security
step passed. The timeout did not terminate the child process group, so the
hosted failure left no stage-level output; the root cause is under
investigation. The hosted result is not claimed as green, and the local
evidence above is not a substitute for it.

## Reproduction

The toolchain is pinned by `flake.nix`/`flake.lock`: Lean 4.35.0, Clang/LLVM
21.1.8 from the locked nixpkgs, and libexpat 2.8.5 as the oracle.

```sh
nix develop -c lake build
nix develop -c bash tests/clean-build.sh
nix develop -c bash tests/c-abi-contract.sh A1
nix develop -c bash tests/c-abi-contract.sh A2
nix develop -c bash tests/c-abi-oom-contract.sh A3
nix develop -c python3 tests/c-abi-verify.py
nix develop -c python3 tests/c-abi-differential.py
nix develop -c bash tests/c-abi-memory.sh
nix develop -c python3 tests/security-cve.py
nix develop -c bash tests/security-differential-fixed.sh --out /tmp/lexpat-diff
nix develop -c bash tests/security-oom-sanitized.sh --out /tmp/lexpat-oom
nix develop -c bash tests/security-benchmark.sh --suite ci --out /tmp/lexpat-bench
nix develop -c bash tests/security-fuzz-smoke.sh --out /tmp/lexpat-fuzz
```

`tests/security-ci.sh --out <absolute-dir>` runs the CVE, fixed differential,
injected OOM, benchmark smoke and fuzz smoke stages in order. Long campaigns
use `tests/security-fuzz-campaign.sh` with the counts and seeds recorded in
`docs/security.md`; they write only under an external output directory. No
campaign corpus, crash file, binary or per-run log is committed.

## Residual limits

- Fuzzing is stochastic and bounded; a clean campaign is not proof of absence.
- The artifact-target fuzz build has harness coverage, not library coverage.
  The instrumented parser/C ABI targets cover generated Lean C and the shim,
  not the optimized shipped binary.
- LSan is disabled in campaigns because of a one-time Lean/libuv startup
  allocation; Valgrind covers only executed release-client paths.
- Only shim-owned allocations are fault-injected. A total Lean-runtime or
  process OOM can abort and is not claimed recoverable.
- Pointer lifetime is a caller obligation: after `XML_ParserFree` the handle is
  undefined, and address reuse cannot be distinguished. `XML_GetUserData`
  dereferences the handle directly.
- Scaling and campaign thresholds apply to the measured shapes, sizes and host;
  they are not a complexity proof.
- The last hosted run, for commit `4999987`, failed in the bounded security
  step and the hosted result is not green. The process-group wrapper, per-stage
  logs, prepared-build identity checks and failure artifact that address it are
  present in the working tree; no hosted run has validated them yet, so they are
  not hosted evidence.
- The C ABI remains a bounded subset, not a drop-in libexpat replacement.

## Change log

| Commit | Scope |
| --- | --- |
| `8e471dc` | Lean XML 1.0 parser core, limits, encodings, differential, proofs |
| `c6dd77c` | Streaming core, chunked parsing, token-budget and declaration-prefix fixes |
| `46980d2` | Bounded C ABI, per-token event wire, callback lifecycle and wire hardening |
| `4999987` | Allocation-error classification, frame pair bound, fuzz/differential/CVE/OOM/scaling harness, threat model |
