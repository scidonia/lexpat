/-
lexpat — XML 1.0 parsing semantics in Lean 4.

`LexPat.parseDocument` is the library's entry point: raw bytes and explicit
budgets in, an ordered event array or a `ParseError` out. It is documented for
inspection and later design; this milestone supports no production integration
route. The decoders and the
decoder proofs live under `LexPat.Encoding`; the XML character and name
productions live in `LexPat.Lexer`; `LexPat.Parser` is the iterative one-shot
document parser. `LexPat.Exe.Trace` is a bounded demonstration and differential
fixture built on this API, not a production integration route.
-/
import LexPat.Types
import LexPat.Lexer
import LexPat.Encoding
import LexPat.Parser
