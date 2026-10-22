/-
The test-only entry point the pure-parser libFuzzer target calls.

`tests/security/parser-fuzz.c` builds a `ByteArray` from the fuzzer input,
calls `lexpat_fuzz_parse`, and consumes the result. `LexPat.parseDocument` is
one-shot, pure and total, so the target exercises the same parser the library
exposes without a C ABI or an executable in between.

This module is a non-default Lake target. It is not part of the `LexPat`
library globs, it is not in the C ABI artifact, and nothing outside the fuzz
build links it.
-/
import LexPat.Parser

namespace LexPat

/-- Parse one fuzzer input under the default budgets. Returns the number of
events produced, or `UInt32.max` when the input is rejected. -/
@[export lexpat_fuzz_parse]
def fuzzParse (bytes : ByteArray) : UInt32 :=
  match parseDocument bytes with
  | .ok events => UInt32.ofNat events.size
  | .error _ => 0xFFFFFFFF

end LexPat
