# Security model

This page describes the security-relevant surface of the bounded C ABI
artifact, the checks that exercise it, and the limits of that evidence. It is a
technical threat model, not a disclosure policy, and it does not claim that the
parser is free of bugs. The findings and fixes, the evidence added, and the
libexpat features that remain absent are recorded in
[`docs/security-hardening.md`](security-hardening.md).

## Supported route

The only supported integration route is the versioned C ABI in `include/expat.h`
over `liblexpat.so.1` on x86_64-linux, built with the pinned Lean 4.35.0
toolchain. It is a bounded subset of Expat and **not a drop-in replacement for
libexpat** outside that subset. The Lean one-shot API, `LexPat.Stream` and the
`lexpatTrace` executable remain inspection and differential surfaces, not
production routes.

The caller supplies a live handle from this library and accessible memory for
every non-NULL pointer and declared length. `XML_GetUserData` dereferences the
handle directly. A handle is undefined after `XML_ParserFree`; a post-free
pointer whose address was reused for another parser cannot be distinguished
from that new parser. These are caller obligations, not parser checks.

## Default budgets

| budget | value | failure code |
| --- | --- | --- |
| raw input per parser | 8 MiB (8388608 bytes) | `LIMIT_INPUT` |
| one name, attribute value, text, comment, CDATA, PI accumulation or numeric-reference digit run | 1 MiB (1048576) decoded characters | `LIMIT_TOKEN` |
| open elements | 256 | `LIMIT_DEPTH` |
| cumulative reference expansion | 1 MiB (1048576) characters | `LIMIT_ENTITY_EXPANSION` |
| internal event frame | 16 MiB | `LIMIT_TOKEN` or malformed-wire refusal |

There is no separate public attribute-count budget; the count is bounded by the
raw-input and frame sizes, and its cost is measured rather than declared zero.
The exact-boundary and boundary-plus-one cases live in `tests/corpus/cases.json`
and the new security set; see `docs/compatibility.md`.

## CVE-class map

| class | source | disposition | evidence |
| --- | --- | --- | --- |
| CVE-2023-52425, large-token reparsing | libexpat `R_2_9_0`, `expat/tests/basic_tests.c::test_big_tokens_scale_linearly` (Expat license) | **existing mitigation/bound**: every token family is accepted at exactly 1 MiB and rejected with `LIMIT_TOKEN` at 1 MiB + 1; cost is measured across doublings | `tests/security-cve.py`; `tests/security-benchmark.sh` |
| CVE-2018-20843, colon-heavy names | public NVD class; no upstream fixture imported | **existing mitigation/bound**: the colon-dense raw name is accepted and its exact callback name is checked at 32 KiB to 1 MiB; per-doubling cost is a separate row with `cve_id=CVE-2018-20843` | `tests/security-cve.py`; `tests/security-benchmark.sh` |
| CVE-2021-45960, attribute-count overflow class | public NVD class; no PoC imported | **existing mitigation/bound**: 32–256 distinct attributes produce exactly the generated ordered pairs; cost is measured and no zero-cost claim is made | `tests/security-cve.py`; `tests/security-benchmark.sh` |
| CVE-2024-8176, long entity chain | libexpat issue #893; no attachment copied | **feature absent**: DTD and entity declarations are refused as `UNSUPPORTED_DTD` before content; a short bounded input is compared with the pinned oracle | `tests/security/cve-cases.json::doctype-entity-chain` |
| CVE-2022-43680, external-entity parser creation under OOM | libexpat issue #649; no attachment copied | **feature absent**: `XML_ExternalEntityParserCreate` returns `NULL` and no resolver, file or network input exists; this is not an OOM guarantee for the Lean runtime | `tests/c-abi-verify.py --unsupported` |
| CVE-2021-46143, DTD content-model group overflow | libexpat issue #532; no attachment copied | **feature absent**: a short `DOCTYPE` form is refused as `UNSUPPORTED_DTD`; the report's approximately 2 GiB input is neither shipped nor run | `tests/security/cve-cases.json::doctype-empty`, `::doctype-model` |
| CVE-2024-50602, resume of an unstarted parser | public NVD class | **feature absent**: `XML_ResumeParser` is refused with `XML_ERROR_UNSUPPORTED_FEATURE` | `tests/c-abi-verify.py --unsupported` |
| CVE-2022-25235, invalid UTF-8 validation class | public NVD class | **existing mitigation/bound**: the 18 `encoding-attack` corpus rows keep their exact expected results; this does not claim coverage of every encoding flaw | `tests/corpus/cases.json`; `tests/differential.py` |

No issue attachment, upstream PoC file or source file is copied into this
repository. Generators and provenance are recorded in
`tests/security/cve-cases.json` and `tests/security/SOURCES.md`.

## Allocation failure

The C shim allocates the parser handle, the registry node, `XML_GetBuffer`
reservations, callback string copies and the start-element attribute vector.
A deterministic test-only allocator wrapper fails exactly one of those
allocations at a time under ASan/UBSan and observes:

* `XML_ParserCreate` returns `NULL` when the parser-struct `calloc` or the
  registry-node `malloc` fails;
* `XML_GetBuffer` returns `NULL` and poisons the parser with
  `XML_ERROR_NO_MEMORY`;
* a failed callback copy makes the same `XML_Parse` call return
  `XML_STATUS_ERROR` and `XML_GetErrorCode` return exactly
  `XML_ERROR_NO_MEMORY` (1), not `XML_ERROR_MALFORMED_WIRE` (51);
* every recorded shim allocation is freed again, including partial attribute
  arrays and copies made before the failing one;
* the first error is terminal and is not replaced by a later call.

**The Lean runtime allocator is not fault-injected.** A total process or Lean
runtime out-of-memory condition can panic or abort; the artifact does not claim
to recover from it. The wrapper reaches only `cabi/expat.c` because the test
links the shim and the Lean module objects directly; `--wrap` does not
intercept the shipped `.so`, and LD_PRELOAD is not compatible with the
sanitizers. LSan is disabled in the fuzz campaigns because the pinned
Lean/libuv startup makes a one-time non-shim allocation; the wrapper's free
ledger and Valgrind over executed release-client paths are the cleanup
detectors.

## Internal frame decoding

The wire decoder runs inside the artifact and is not reachable through a public
caller. Beyond validating the header, source metadata and UTF-8 payloads, it now
rejects an attribute pair count the remaining payload cannot describe
(`pairs > (payload->size - payload->pos) / 8`) before allocating a vector, and
it classifies a failed callback copy as `XML_ERROR_NO_MEMORY` while malformed
payload, header and UTF-8 remain `XML_ERROR_MALFORMED_WIRE`. A fabricated frame
is exercised only by the direct-linked test target, which records the vector
allocation and refuses a request above a fixed cap.

## What the evidence establishes, and what it does not

The suite includes property checks, differential comparisons against the pinned
libexpat 2.8.5, sanitizer-injected allocation failures, limit-adjacent cost
measurements and bounded libFuzzer campaigns over four targets:

| target | instrumentation | establishes |
| --- | --- | --- |
| `parser` | generated Lean C plus Clang coverage/ASan/UBSan | one-shot parser faults and sanitizer termination over bounded inputs |
| `cabi` | generated Lean C, `cabi/expat.c`, harness | C callback/frame and public ABI paths with candidate coverage |
| `artifact` | harness only, shipped `.so` | loader and client smoke; **library coverage is absent** and sanitizer diagnostics do not cover library instructions |
| `differential` | candidate and oracle each loaded with `dlopen` and called through separate `dlsym` tables; candidate is coverage + ASan/UBSan instrumented, oracle is the uninstrumented pinned library | normalized event/code agreement on generated supported-subset documents; any unlisted mismatch fails |

Limits of that evidence:

* Fuzzing is stochastic and bounded. A completed campaign is not a proof of
  absence of defects, and the counts are inputs executed, not inputs proven.
* The instrumented source build differs from the shipped optimization/runtime
  binary; sanitizer findings in the instrumented build do not by themselves
  prove the shipped artifact is affected.
* The oracle is unreachable for parser coverage and is never linked into the
  product or into the differential executable. Before any comparison the
  comparator re-reads `pkg-config --modversion expat`, which must be exactly
  `2.8.5`, and requires `XML_ExpatVersion()` to be exactly `expat_2.8.5` and
  `XML_ExpatVersionInfo()` to be exactly `{2,8,5}`; the drivers repeat the
  `pkg-config` check before building or replaying. A near match is a
  prerequisite failure.
* The differential candidate library is linked without `--no-undefined`
  because its sanitizer references resolve from the fuzzer executable's
  static runtime. That is a property of the instrumented test library, not of
  the shipped `liblexpat.so.1`, which keeps `--no-undefined`.
* Coverage and campaign output live outside the repository; no crash, corpus
  mutation or binary is committed.
* Scaling bounds apply only to the measured shapes, sizes and machine; a
  doubling ratio below the threshold is evidence for those rows, not a
  complexity proof for every input. The paired run interleaves base and
  candidate readings entry by entry and alternates which side runs first, and
  alternates one-shot/chunked trials within a case. Each entry is measured in
  its own forked child, so the recorded `rss_kb` is that entry's `wait4`
  resident peak rather than a process-lifetime high-water mark. Machine, CPU
  model, core count, governor and load average are recorded with the
  pinned-CPU note.
* The CVE set asserts the listed local outcomes and, where safe, the pinned
  reference outcome. A refusal of an absent feature demonstrates only that
  boundary, not a fix for an upstream Expat vulnerability in code this project
  does not contain.

`lexpat` is **not free of bugs**. These checks make specific failure modes
observable and regressions loud; they cannot establish the absence of unknown
defects.

## Reproducing the checks

The toolchain is pinned by `flake.nix`/`flake.lock`: Clang/LLVM 21.1.8 from the
locked nixpkgs, Lean 4.35.0, and libexpat 2.8.5 as the test oracle. Fuzz builds
use the flake-locked Clang, not a registry lookup and not the compiler Lean
bundles.

```sh
nix develop -c bash tests/c-abi-oom-contract.sh A3
nix develop -c python3 tests/c-abi-verify.py --wire
nix develop -c bash tests/security-oom-sanitized.sh --out /tmp/lexpat-oom
nix develop -c python3 tests/security-cve.py
nix develop -c bash tests/security-differential-fixed.sh --out /tmp/lexpat-diff
nix develop -c bash tests/security-benchmark.sh --suite ci --out /tmp/lexpat-bench
nix develop -c bash tests/security-fuzz-smoke.sh --out /tmp/lexpat-fuzz
```

`tests/security-ci.sh` runs the CVE, fixed differential, injected sanitizer,
benchmark and fuzz-smoke stages in that order; CI applies one 300-second outer
cap to the whole command. Long campaigns are run separately with
`tests/security-fuzz-campaign.sh` and write only under an external `--out`
directory.
