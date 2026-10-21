import Lake
open System Lake DSL

package lexpat where
  version := v!"0.1.0"
  description := "XML 1.0 parsing semantics in Lean 4, with a resumable streaming core and a bounded differential fixture against libexpat."
  keywords := #["xml", "parser", "security", "expat", "lean4"]
  /- The library needs this toolchain and no other. Saying so makes `lake update`
  prefer it for downstream packages rather than resolving them onto a toolchain the
  library cannot build on. -/
  fixedToolchain := true

/-- The **library**: the decoder, the XML 1.0 predicates and lexer, the shared
grammar helpers, the resumable streaming core, the one-shot wrapper and the
decoder proofs. It imports nothing from `LexPat/Exe/`, and no C code. -/
@[default_target] lean_lib LexPat where
  globs := #[.one `LexPat,
             .one `LexPat.Types,
             .one `LexPat.Encoding,
             .submodules `LexPat.Encoding,
             .one `LexPat.Lexer,
             .one `LexPat.Grammar,
             .one `LexPat.Stream,
             .one `LexPat.Parser]

/- The executable is **not** a default target: a bare `lake build` is the library and
its proofs and nothing else. `lexpatTrace` is a bounded demonstration and differential
fixture, built on demand with `lake build lexpatTrace`. -/
lean_exe lexpatTrace where
  root := `LexPat.Exe.Trace

/-- The raw-event driver used by `tests/streaming.py` to compare the ordered
attribute arrays of `Event` values, which the rendered trace cannot observe.
Not a default target. -/
lean_exe lexpatEvents where
  root := `tests.StreamingEvents
