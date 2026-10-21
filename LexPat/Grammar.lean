/-
Grammar helpers shared by the streaming core and the one-shot wrapper.

These are the pieces of the XML grammar that do not depend on how the document
is delivered: the document phase, reference digit values, the `EncName`
production and the check that compares a declaration's encoding label with the
encoding the bytes actually selected. The scanners themselves live in the
streaming state machine (`LexPat.Stream`); the one-shot entry point is a fold
over that machine.
-/
import LexPat.Types
import LexPat.Lexer
import LexPat.Encoding

namespace LexPat

/-- Where the parser is in the document grammar. -/
inductive Phase where
  | prolog
  | content
  | epilog
deriving Repr, DecidableEq

/-- The scalar written by a decimal character reference digit. -/
def decDigitValue (n : Nat) : Option Nat :=
  if between n 0x30 0x39 then some (n - 0x30) else none

/-- The scalar written by a hexadecimal character reference digit. -/
def hexDigitValue (n : Nat) : Option Nat :=
  if between n 0x30 0x39 then some (n - 0x30)
  else if between n 0x41 0x46 then some (n - 0x41 + 10)
  else if between n 0x61 0x66 then some (n - 0x61 + 10)
  else none

/-- True when the encoding label is an `EncName`: a letter followed by letters,
digits, `.`, `_` or `-`. -/
def validEncName (label : String) : Bool :=
  match label.toList with
  | [] => false
  | c :: rest =>
    isAsciiLetter c.toNat && rest.all (fun d => isAsciiNameChar d.toNat)

/-- Check the declaration's encoding label against the encoding the bytes
actually selected. `offset` is the diagnostic byte offset of the label. -/
def checkEncodingLabel (detected : Encoding) (label : String) (offset : Nat) :
    Except ParseError Unit :=
  match classifyLabel label with
  | .unknown => .error ⟨.unknownEncoding, "unknownEncoding", offset⟩
  | .utf8 =>
    if detected = .utf8 then .ok ()
    else .error ⟨.incorrectEncoding, "encodingMismatch", offset⟩
  | .ascii =>
    if detected = .ascii then .ok ()
    else .error ⟨.incorrectEncoding, "encodingMismatch", offset⟩
  | .latin1 =>
    if detected = .latin1 then .ok ()
    else .error ⟨.incorrectEncoding, "encodingMismatch", offset⟩
  | .utf16 =>
    if detected = .utf16le ∨ detected = .utf16be then .ok ()
    else .error ⟨.incorrectEncoding, "encodingMismatch", offset⟩
  | .utf16le =>
    if detected = .utf16le then .ok ()
    else .error ⟨.incorrectEncoding, "encodingMismatch", offset⟩
  | .utf16be =>
    if detected = .utf16be then .ok ()
    else .error ⟨.incorrectEncoding, "encodingMismatch", offset⟩

end LexPat
