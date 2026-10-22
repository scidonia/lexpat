# Repository test decisions

These are the decisions to read before adding or changing a check. They describe
this repository's behavior, not how any particular change was produced.

## Commands

All Lean and C toolchain commands run through the pinned dev shell:

```sh
nix develop -c lake build                      # library, proofs and the C ABI artifact
nix develop -c lake build lexpatTrace          # the demonstration executable
nix develop -c lake build lexpatEvents         # raw-event attribute-order driver
nix develop -c lake env lean --run tests/OneShotPrecedence.lean
nix develop -c lake env lean --run tests/ScannerDecoder.lean
nix develop -c lake env lean --run tests/StreamingCases.lean
nix develop -c lake exe lexpatTrace tests/corpus/basic.xml
nix develop -c lake exe lexpatTrace --chunk-size 1 tests/corpus/basic.xml
nix develop -c bash tests/clean-build.sh
nix develop -c bash tests/c-abi-contract.sh A1
nix develop -c bash tests/c-abi-contract.sh A2
nix develop -c bash tests/c-abi-oom-contract.sh A3
nix develop -c python3 tests/c-abi-differential.py
nix develop -c python3 tests/c-abi-verify.py
nix develop -c python3 tests/c-abi-verify.py --bridge
nix develop -c bash tests/c-abi-memory.sh
nix develop -c python3 tests/streaming.py
nix develop -c python3 tests/differential.py
nix develop -c python3 tests/differential.py --group limits
nix develop -c python3 tests/security-cve.py
nix develop -c bash tests/security-differential-fixed.sh --out /tmp/lexpat-diff
nix develop -c bash tests/security-oom-sanitized.sh --out /tmp/lexpat-oom
nix develop -c bash tests/security-benchmark.sh --suite ci --out /tmp/lexpat-bench
nix develop -c bash tests/security-fuzz-smoke.sh --out /tmp/lexpat-fuzz
nix develop -c bash tests/no-admits.sh
nix develop -c lake env lean LexPat/Encoding/Proofs.lean
```

`lake build` builds the default library, the proofs and the C ABI artifact;
`LexPat/Exe` is excluded and the executable is deliberately not a default
target. `lake build FuzzParser` type-checks the test-only raw parser entry
point used by the fuzz target; it is not a default target and is not part of
the library or the artifact. `.github/workflows/ci.yml` runs the library build,
the clean build, the C ABI contracts A1, A2 and A3, one combined security step
under a 300-second process-group deadline held by
`scripts/run-bounded-security.py`, the C differential, the artifact
verification, the memory checks, the one-shot contract, the streaming checks,
the full differential, the `limits` group, the admit check and the proof audit,
in that order, after installing Nix with flakes enabled. The security step
runs CVE checks, the fixed differential replay, injected shim OOM, the
benchmark smoke and the four-target fuzz smoke. Checkout uses
`fetch-depth: 0` so the corpus identity comparison can resolve the base
revision.

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
and never reads a system identifier. libexpat is a test oracle only; neither the
Lean library, its executable nor the C ABI artifact links system
libexpat.

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

The byte-index scanners are checked against the decoder itself in
`tests/ScannerDecoder.lean`. Bulk markup is limited to the byte-oriented
encodings and to a state with no unfinished decoded scalar: a byte that would
complete or extend a partial scalar belongs to the per-byte machine, which
reports that decoder's own reason and offset. The test pins `decodeUtf8One`'s
accepted scalar and next offset and its rejection reason and offset for every
UTF-8 length and fault class, including a nonzero start index, then requires the
shipped scanner to agree on text, element-name, attribute-name and
attribute-value bytes: the same payload when the bytes decode, and the same
public code, reason and absolute offset when they do not. The declaration label
scan is compared with the label the declaration grammar records for the same
bytes, and its `stop` bound is asserted one byte either side of the value's
closing quote. This is the check that a fast path may not outrun the decoder; a
scanner that consumes a byte the decoder still owns fails here rather than in
the differential.

## C ABI boundary

`include/expat.h` over `liblexpat.so.1` is the bounded C surface;
`docs/compatibility.md` names every supported and refused call, the numeric
error mapping, the buffer rules and the callback positions. The C route is
verified only for that subset and only on x86_64-linux with the pinned Lean
runtime; byte-identical output, Expat's private struct layout and symbols the
header does not declare are not claimed.

The shared object is linked with `-Wl,-z,nodelete`. Module initialization starts
Lean runtime threads whose entry points live in the runtime library, and the
runtime has no shutdown that stops and joins them, so `dlclose` releases the
handle without unmapping either object. A check may repeat a load, parse, free
and close sequence, but it must not assume the mapping goes away, and unloading
is not a supported operation. That repetition is checked only over the finite
lifetime `tests/c-abi-verify.py --abi` exercises: one cycle in each of 16 fresh
processes, each inside a 15-second bound under one 60-second aggregate deadline,
together with the artifact's own `NODELETE` flag. A load/drop loop in one
process, or an unbounded number of processes, is not measured and is not
claimed.

`tests/c-abi-contract.sh` runs the C-boundary scenarios in
`tests/c-abi-contract.md` against the shipped header and shared object, one
scenario per process. A1 binds the `XML_Parse` status and the ordered
start/end records to that call; A2 binds the poisoned parser's refusal and its
zero callbacks to the same detector that observes the unpoisoned control. Each
scenario was observed failing at its own assertion when its handler dispatch was
removed from an isolated copy of the implementation, with the other scenario and
the one-shot contract unchanged. A scenario that passes without its behavior is
vacuous and does not count as evidence.

`tests/c-abi-client.c` is one source compiled twice by
`tests/c-abi-differential.py`: against the candidate header and shared object,
and against the dev shell's Expat header and library. It calls only the subset
both provide, and no `#ifdef` selects a different parser. The harness
materialises every `tests/corpus/cases.json` input in
`TemporaryDirectory(prefix="lexpat-cabi-", dir="/tmp")`, runs both clients under
whole, single-byte, `fixed:7` and one seeded partition per case, and again
through `XML_GetBuffer`/`XML_ParseBuffer`. Accepted documents compare event
order, payloads and ordered attribute pairs, coalescing adjacent text only (never
across a CDATA boundary) because the implementations split characters and text
runs differently. Rejected documents compare accept/reject and the numeric code
for the codes both headers define. The fixture outcome is asserted on each side
independently, every manifest `exception` row must still differ, and an
exception that stops differing fails. Negative controls mutate an event name,
flip an accept flag, make an exception row stop differing, and prove the
side-to-side comparator observes a changed name. A prefix-timing case states the
candidate's per-token callback counts and the system Expat's deferral as separate
expectations; a changed expectation fails the same comparator.

Callback positions are asserted against tables authored from the input bytes in
`tests/c-abi-differential.py` and in `tests/c-abi-verify.py`, not read from either
parser. The candidate's documented differences are the empty-element end anchor
(the opener, where Expat reports the position after the tag) and BOM columns
(not counted by the candidate); they are stated per case. A representative case
is also compared across all partitions to show that chunk cuts do not change the
records or positions.

`tests/c-abi-verify.py` runs one group per criterion: source compatibility and
refused build modes, the pinned `XML_GetUserData` macro over the candidate
library, the exact `XML_*` export allowlist against the header (with an
affirmative symbol control, a mutation control and an absent Expat extension
control), SONAME/NEEDED/RUNPATH plus a real loader launch, public enumerator values,
struct layout and callback typedef signature equality with the pinned header
(with mutation controls), truthful version, version info and feature list,
lifecycle and registry-checked released handles, buffer reservations and
refusals, exact error codes and stable strings, callback positions, every
declared unsupported family, malformed internal callback metadata and
NULL/invalid-length, re-entrant and free-in-callback behavior. The direct-bridge
group (`--bridge`) links the C shim and the Lean module objects into a test
executable and calls the callback-specific receivers the Lean producer calls,
with fabricated Lean payload objects: the affirmative controls show a borrowed
text span, a start tag with an ordered attribute pair, an end tag, a comment, a
processing instruction, CDATA and a declaration reaching their handlers; the
refusal controls show an inverted span, a span past its owner, an absolute
boundary past the bytes fed, an impossible line or column, an overflowing base,
an over-ceiling payload, illegal UTF-8 in each payload kind, an embedded NUL, an
impossible declaration value, and a receiver with no current parser, each
refused before any callback; an armed allocation failure reports
`XML_ERROR_NO_MEMORY`; and a parse whose events have no handlers records zero
payload allocations while the same events with handlers record a positive count.
It is a test target, not an exported bypass. Nothing tests a fabricated
non-NULL address or calls `XML_GetUserData` after a free.

The shim has two kinds of receiver for a start or end tag: one takes owned
parser payloads, the other takes byte ranges of the fed chunk plus that chunk's
absolute base, which it validates against the owner, the bytes fed so far and the
UTF-8 rules before copying the event into one arena. Which one a tag uses depends
on the parser's state, so both are on the shipped path; `tests/c-abi-differential.py`
compares the resulting names, ordered attributes and positions with the pinned
oracle across whole, single-byte, fixed and seeded partitions. The direct-bridge
group's fabricated controls cover the owned-payload receivers; a fabricated range
or count for the range receiver is not yet exercised there.

`tests/c-abi-memory.sh` runs the same client cases under an ASan/UBSan-instrumented
shim and client, then runs the unsanitized client against the shipped shared
object under Valgrind with definite leaks treated as errors. ASan covers only
instrumented C code and its interceptors, not the prebuilt Lean runtime, and its
leak detection is off because this artifact has no runtime-finalize step.
Valgrind covers the whole process including the pinned Lean runtime, but only for
the executed paths; a `possibly lost` block at exit and still-reachable runtime
state are visible in its log rather than suppressed. Neither detector proves
memory safety for every input, and neither is evidence about resident memory.
`tests/c-abi-smoke.sh` is the capability smoke, not the contract.

## Security boundary

`docs/security.md` is the published threat model: supported route, budgets, the
CVE-class table, allocation-failure behavior, pointer lifetime and the limits of
the evidence. The C ABI remains the only supported integration route. The
combined bounded step is run by `scripts/run-bounded-security.py`, which is
invoked outside `nix develop` so its deadline includes Nix startup and every
child the command starts:

```sh
OUT="$(mktemp -d "${TMPDIR:-/tmp}/lexpat-security.XXXXXX")"
python3 scripts/run-bounded-security.py --seconds 300 --grace 5 \
  --log "$OUT/bounded.log" \
  -- nix develop -c bash tests/security-ci.sh --out "$OUT/stages"
```

A timeout exits 124 after terminating and reaping the whole process group; a
child that exits but leaves a descendant behind exits 125 after the same
cleanup; a failed sink or retained log exits 126 instead of reporting the
child's status. The log names the last `security-ci:` stage that started and is
kept on every outcome. The hosted job adds `--build-dir` for a prepared fuzz
build, which the step verifies before any target or parser runs.

The original 108-case `tests/corpus/` tree is unchanged. Security-specific
inputs, provenance and expectations live under `tests/security/` and are driven
by `tests/security-cve.py`; a CVE row is a locally generated input or an
explicit reference to an existing corpus case, never an imported attachment.
`tests/security/differential-exceptions.json` accounts for all twelve corpus
exception rows and resolves each side's expectation from the corpus objects;
`tests/security-differential-fixed.sh` replays them through the same
`dlopen` comparator as the differential fuzz target and requires the pair to
differ. The replay driver runs one `--compare both` invocation per case, so
both libraries are loaded and called in one process rather than in two
separate runs.

The differential targets share one topology: neither parser is linked into the
executable. The candidate (coverage + ASan/UBSan instrumented
`liblexpat-diff.so` for the fuzzer, the shipped `liblexpat.so.1` for the
replay) and the pinned, uninstrumented `libexpat.so.1` are each loaded with
`dlopen(..., RTLD_NOW | RTLD_LOCAL)` and called through their own `dlsym`
table, so the two `XML_*` surfaces cannot collide. The candidate library's
sanitizer references resolve from the static runtime the ASan fuzzer
executable carries; that is why it is linked without `--no-undefined`, while
the shipped artifact keeps that check. The differential fuzzer measures
candidate coverage and sanitizer state for generated documents; the oracle is
never instrumented.

The differential targets require the pinned oracle before comparing:
`pkg-config --modversion expat` must be exactly `2.8.5`,
`XML_ExpatVersion()` must be exactly `expat_2.8.5`, and
`XML_ExpatVersionInfo()` must be exactly `{2,8,5}`. The comparator re-reads
all three on every run; the build/replay drivers repeat the `pkg-config`
identity so a mismatch fails before the targets are produced or replayed.
Both `tests/differential.py` and `tests/c-abi-differential.py` fail on the
same prerequisite. A near match such as `2.8.50`, or a missing
`XML_ExpatVersionInfo`, is a prerequisite failure, not an exception.

Allocation injection is test-only. `tests/security-oom-sanitized.sh` links
`cabi/expat.c` and the Lean module objects directly so `--wrap=malloc/calloc/free`
reaches the shim; the shipped `.so` is not intercepted, LD_PRELOAD is not used,
and no Lean-runtime allocation is faulted. The wrapper's allocation/free ledger
is the cleanup detector because LSan is off for the one-time Lean/libuv startup
allocation. `tests/c-abi-oom-contract.sh A3` is the public-boundary scenario;
`tests/c-abi-verify.py --bridge` covers the receiver's span, count, position and
UTF-8 refusals plus the shim allocation classification.

The fuzz build is reproducible from the locked inputs:
`scripts/security-fuzz-build.sh --out <absolute-directory>` compiles the
generated Lean C and `cabi/expat.c` with the flake-locked Clang 21.1.8 and
Clang coverage + ASan/UBSan. Those objects feed the parser and C ABI targets
directly and are also linked into `liblexpat-diff.so`, which the differential
fuzzer and the replay comparator load with `dlopen` rather than linking. The
script separately links the shipped artifact with only the harness
instrumented, and runs the replay's exact oracle guard before returning. The
parser, C ABI and differential targets therefore observe candidate
instructions; the artifact target's library coverage is absent by
construction. Because the differential executable contains no Lean objects,
its candidate coverage is the `liblexpat-diff.so` module registered at load
time, not the harness alone. `tests/security-fuzz-smoke.sh` runs the fixed CI
budget (parser 10,000; C ABI 10,000; artifact 2,000; differential 5,000
inputs) under per-target caps. `tests/security-fuzz-campaign.sh` records a long
campaign's seed, exact count, elapsed time, resident peak RSS, source revision,
build and initial corpus digests under an external `--out`; a cap reached
before the requested count is incomplete, never a pass. Fuzzing is stochastic
and bounded and does not establish the absence of defects.

The benchmark driver schedules one entry (case, drift control or limit-adjacent
input) at a time. `tests/security-benchmark.sh --pair` walks that plan once and
runs the base and candidate binaries back to back for each entry, alternating
which side goes first; it never runs one side's whole suite before the other.
Within a case the one-shot and 64-byte-chunk trials alternate rather than all
one-shot samples preceding all chunked samples. Each entry is measured in a
forked child and the parent records that child's `wait4` resident peak, so
`rss_kb` is attributable to the entry. The driver records the unpinned or
`pinned=cpu0` note together with `uname`, CPU model, core count, governor and
load average in `flags`; a 1 KiB drift control before and after each family
block fails the run above a 15% shift. Earlier full-suite readings from a
different protocol are not evidence for the current one.

## Performance benchmark

`tests/performance-benchmark.sh` compares the candidate C ABI against a
supplied base source tree and against the pinned libexpat, over the checked-in
eight-case corpus in `tests/performance/corpus/`, the generator
`tests/performance/generate.py` and the declared expectations in
`tests/performance/manifest.json`.

```sh
BASE="$(mktemp -d "${TMPDIR:-/tmp}/lexpat-base.XXXXXX")"
git archive 626761f | tar -x -C "$BASE"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/lexpat-perf.XXXXXX")"
nix develop -c python3 tests/performance/generate.py --out "$OUT/generated"
nix develop -c python3 tests/performance/compare.py --manifest tests/performance/manifest.json --check-corpus --generated "$OUT/generated" --shipped tests/performance/corpus
nix develop -c bash tests/performance-benchmark.sh --candidate-source "$PWD" --out "$OUT/smoke" --phase smoke --samples 3 --warmups 1 --chunk 4096
nix develop -c bash tests/performance-benchmark.sh --base-source "$BASE" --candidate-source "$PWD" --out "$OUT/text" --phase text --samples 9 --warmups 3 --chunk 4096 --enforce
nix develop -c bash tests/performance-benchmark.sh --base-source "$BASE" --candidate-source "$PWD" --out "$OUT/full" --phase full --samples 9 --warmups 3 --chunk 4096 --enforce
```

`BASE` is a `git archive` snapshot of the base revision this comparison is
against -- `626761f` for the readings recorded here -- and carries no build
output: the script runs `lake build lexpatCAbi` in each source tree itself, in
the dev shell the command runs in. `--candidate-source "$PWD"` is the working
tree under test, so both inputs are ready before the first benchmark command.
`--phase text` restricts the run to the literal-text case and `--phase full`
runs all eight. `--base-source` and `--enforce` are required together outside
the smoke phase, and every path must be absolute. The smoke phase runs the same
corpus, handler and oracle preflight with a three-sample diagnostic and no
speed threshold, so it can run on a shared runner.

The preflight is independent of either parser: it checks each side against the
manifest's declared outcome, handler families, payload bytes and ordered
attributes before any timing is accepted, and a timed trial re-checks its
declared counts. An incomplete parse, a wrong callback record or a zero median
invalidates the run. Base and candidate never share a process: every reading
loads exactly one library with `dlopen(..., RTLD_NOW | RTLD_LOCAL)` and calls it
through its own `dlsym` table, and the base and candidate readings are separate
processes. Timing covers `XML_Parse` and its callbacks with a fresh parser per
repetition and excludes creation, free and fixture I/O; short cases use the same
bounded repetition count on both sides, calibrated from the faster side.

Every ratio row states its own unit and construction: `speedup` is a multiplier
of paired same-session medians, `speedup = median base ns / median candidate
ns`; `gap` is a multiplier, `gap = median candidate ns / median pinned expat
ns`; `throughput` is MiB/s, literal body bytes over candidate parse seconds. A
result is conditioned on the recorded session — artifact, oracle and toolchain
hashes, CPU facts, affinity to one CPU and drift controls that make the session
inconclusive above a 15% shift. Ratios are not universal constants, results are
written only under an external `--out`, and a local reading is not hosted
evidence.

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

`lexpatTrace` is a bounded demonstration and differential fixture. The M1/M2
surfaces are not production integration routes: not the executable, not
`LexPat.parseDocument`, not `LexPat.Stream`. The bounded C subset in
`include/expat.h` is separately verified as described above and is the only
advertised C integration route; a change to its header, exported set, public
layouts, error, buffer or location semantics, or its documentation must update
`tests/c-abi-verify.py` and `docs/compatibility.md` together. The event-trace
claims above hold only because the differential compares the Lean events with the
fixtures on every accepted row, and the streaming claims hold only because
`tests/streaming.py` compares every partition with independently declared
expected events and with the one-shot result. Changes to the demonstrated
subset, the trace fields, the chunked modes or the limits must update
`README.md`, `docs/compatibility.md` and the shipped JSONL fixtures together.
The one-shot wrapper and the stream share one earliest-certain-fault rule; a page
must not describe the old decode-everything-first priority as current.
