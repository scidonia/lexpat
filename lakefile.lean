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
grammar helpers, the resumable streaming core, the one-shot wrapper, the C ABI
bridge and the decoder proofs. It imports nothing from `LexPat/Exe/`. -/
@[default_target] lean_lib LexPat where
  globs := #[.one `LexPat,
             .one `LexPat.Types,
             .one `LexPat.Encoding,
             .submodules `LexPat.Encoding,
             .one `LexPat.Lexer,
             .one `LexPat.Grammar,
             .one `LexPat.Stream,
             .one `LexPat.Parser,
             .one `LexPat.CAbi]

/-- The C ABI artifact: `include/expat.h` over a shared object with
a versioned SONAME. The target collects the Lean module objects with exported
symbols and runs the checked-in build script, which compiles the C shim and
links both halves. Its documented subset is checked by `tests/c-abi-contract.sh`,
`tests/c-abi-differential.py`, `tests/c-abi-verify.py` and `tests/c-abi-memory.sh`. -/
@[default_target] target lexpatCAbi : FilePath := do
  let pkg ← getRootPackage
  let some lib := (← findLeanLib? `LexPat)
    | error "lexpat: the LexPat library is missing"
  let mods ← (← lib.modules.fetch).await
  let objJobs ← mods.flatMapM fun mod =>
    (mod.nativeFacets true).mapM (·.fetch mod)
  let out := pkg.buildDir / "lib" / "liblexpat.so.1"
  let buildScript := pkg.dir / "scripts" / "build-c-abi.sh"
  let extraDepTrace : JobM BuildTrace := do
    let sources := #[pkg.dir / "cabi" / "expat.c",
                     pkg.dir / "cabi" / "exports.map",
                     pkg.dir / "include" / "expat.h",
                     buildScript]
    return mixTraceArray (← sources.mapM (computeTrace ·))
  buildFileAfterDep out (Job.collectArray objJobs "c-abi objects")
      (extraDepTrace := extraDepTrace) fun objs => do
    proc {
      cmd := "bash"
      args := #[buildScript.toString, "--out", out.toString] ++ objs.map (·.toString)
    }

/- The executable is **not** a default target: a bare `lake build` is the library,
its proofs and the C ABI artifact. `lexpatTrace` is a bounded
demonstration and differential fixture, built on demand with
`lake build lexpatTrace`. -/
lean_exe lexpatTrace where
  root := `LexPat.Exe.Trace

/-- The raw-event driver used by `tests/streaming.py` to compare the ordered
attribute arrays of `Event` values, which the rendered trace cannot observe.
Not a default target. -/
lean_exe lexpatEvents where
  root := `tests.StreamingEvents
