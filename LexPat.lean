/-
lexpat — XML 1.0 parsing semantics in Lean 4.

`LexPat.Stream` is the pure, total, resumable core: `Stream.new`, `feed`,
`finish` and `result` decode raw byte chunks incrementally, emit each event as
soon as the bytes determine it, and keep only bounded unfinished state between
calls. `LexPat.parseDocument` is the one-shot entry point, a fold over that
core: raw bytes and explicit budgets in, an ordered event array or a
`ParseError` out, with no event array on failure.

The decoders and the decoder proofs live under `LexPat.Encoding`; the XML
character and name productions live in `LexPat.Lexer`; the grammar helpers
shared by both entry points live in `LexPat.Grammar`. `LexPat.Exe.Trace` is a
bounded demonstration and differential fixture built on this library, not a
production integration route, and neither is the library API itself.
-/
import LexPat.Types
import LexPat.Lexer
import LexPat.Encoding
import LexPat.Grammar
import LexPat.Stream
import LexPat.Parser
