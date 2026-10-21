/-
The one-shot XML 1.0 document parser.

`parseDocument` is a fold over the streaming core: feed the whole byte array to
a fresh `LexPat.Stream`, finish it, and return the events only when the stream
completed. A rejected document returns the stream's `ParseError` and no event
array; events the stream would have returned earlier are provisional and are
not part of the one-shot result.

Because the stream rejects only a fault that the bytes already consumed prove,
the one-shot entry point reports the earliest certain fault in input order.
For a document with more than one independent fault this can differ from the
old decode-everything-first order; the single-fault behavior and every
corpus outcome are unchanged.
-/
import LexPat.Grammar
import LexPat.Stream

namespace LexPat

/-- Parse one complete XML 1.0 document from raw bytes under explicit budgets.
Pure, total, one-shot, and free of global state. -/
def parseDocument (bytes : ByteArray) (limits : Limits := {}) :
    Except ParseError (Array Event) :=
  let s := Stream.new limits
  let (s1, events1) := Stream.feed s bytes
  let (s2, events2) := Stream.finish s1
  match Stream.result s2 with
  | some (.ok ()) => .ok (events1 ++ events2)
  | some (.error e) => .error e
  | none => .error ⟨.syntax, "incompleteStream", 0⟩

end LexPat
