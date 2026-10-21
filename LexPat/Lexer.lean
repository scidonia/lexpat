/-
XML 1.0 (Fifth Edition) character and name predicates, and the small shared
scanners that do not need parser state.
-/
import LexPat.Types

namespace LexPat

/-- The scalar value at `pos`, if any. -/
def natAt (chars : Array DecodedChar) (pos : Nat) : Option Nat :=
  (chars[pos]?).map (fun c => c.value.n)

/-- The raw byte offset of the character at `pos` (diagnostic only). -/
def offsetAt (chars : Array DecodedChar) (pos : Nat) : Nat :=
  match chars[pos]? with
  | some c => c.byteOffset
  | none =>
    match chars[chars.size - 1]? with
    | some c => c.byteOffset + 1
    | none => 0

def mkError (chars : Array DecodedChar) (pos : Nat) (code : ErrorCode)
    (reason : String) : ParseError :=
  ⟨code, reason, offsetAt chars pos⟩

/-- `lo ≤ n ∧ n ≤ hi`, as a decidable predicate over naturals. -/
def between (n lo hi : Nat) : Bool := decide (lo ≤ n ∧ n ≤ hi)

def isXmlWhitespace (n : Nat) : Bool :=
  n == 0x20 || n == 0x09 || n == 0x0A || n == 0x0D

/-- The XML 1.0 `Char` production:
`#x9 | #xA | #xD | [#x20-#xD7FF] | [#xE000-#xFFFD] | [#x10000-#x10FFFF]`. -/
def isXmlChar (n : Nat) : Bool :=
  n == 0x9 || n == 0xA || n == 0xD || between n 0x20 0xD7FF ||
    between n 0xE000 0xFFFD || between n 0x10000 0x10FFFF

/-- `NameStartChar` without the `:` exclusion; namespace processing is not
implemented, so the raw qualified name is what the parser keeps. -/
def isNameStartChar (n : Nat) : Bool :=
  n == 0x3A || between n 0x41 0x5A || n == 0x5F || between n 0x61 0x7A ||
    between n 0xC0 0xD6 || between n 0xD8 0xF6 || between n 0xF8 0x2FF ||
    between n 0x370 0x37D || between n 0x37F 0x1FFF || between n 0x200C 0x200D ||
    between n 0x2070 0x218F || between n 0x2C00 0x2FEF || between n 0x3001 0xD7FF ||
    between n 0xF900 0xFDCF || between n 0xFDF0 0xFFFD || between n 0x10000 0xEFFFF

/-- The XML 1.0 `NameChar` production. -/
def isNameChar (n : Nat) : Bool :=
  isNameStartChar n || n == 0x2D || n == 0x2E || between n 0x30 0x39 ||
    n == 0xB7 || between n 0x300 0x36F || between n 0x203F 0x2040

def isAsciiLetter (n : Nat) : Bool := between n 0x41 0x5A || between n 0x61 0x7A

def isAsciiDigit (n : Nat) : Bool := between n 0x30 0x39

/-- Characters allowed in an encoding name and in the pseudo-attribute names of
an XML declaration. -/
def isAsciiNameChar (n : Nat) : Bool :=
  isAsciiLetter n || isAsciiDigit n || n == 0x2E || n == 0x5F || n == 0x2D

def skipWhitespace (chars : Array DecodedChar) (pos : Nat) : Nat :=
  Id.run do
    let mut i := pos
    while i < chars.size do
      match chars[i]? with
      | some c => if isXmlWhitespace c.value.n then i := i + 1 else break
      | none => break
    return i

/-- The scalars in `[start, stop)` as a `String`. -/
def charsToString (chars : Array DecodedChar) (start stop : Nat) : String :=
  Id.run do
    let mut buf : Array Char := #[]
    let mut i := start
    while i < stop ∧ i < chars.size do
      match chars[i]? with
      | some c => buf := buf.push c.value.toChar
      | none => pure ()
      i := i + 1
    return String.ofList buf.toList

/-- True when the scalars at `pos` are exactly `pattern`. -/
def matchesAt (chars : Array DecodedChar) (pos : Nat) : List Nat → Bool
  | [] => true
  | n :: rest => (natAt chars pos == some n) && matchesAt chars (pos + 1) rest

/-- Extract the `encoding` pseudo-attribute of an XML declaration, permissively.

This scanner runs over the raw declaration bytes decoded one byte per scalar
(which is what an ASCII-compatible declaration is), and is used only to choose
the decoder for the rest of the document. It never decides well-formedness: the
document parser re-parses the declaration under the XML declaration grammar and
rejects whatever this scanner tolerated. Returns `none` when the document does
not start with `<?xml` followed by whitespace, or when the declaration is not
parseable enough to find the attribute. -/
def scanDeclEncodingLabel (chars : Array DecodedChar) : Option String :=
  Id.run do
    if chars.size < 6 then return none
    if natAt chars 0 != some 0x3C || natAt chars 1 != some 0x3F ||
        natAt chars 2 != some 0x78 || natAt chars 3 != some 0x6D ||
        natAt chars 4 != some 0x6C then
      return none
    match natAt chars 5 with
    | some n => if !isXmlWhitespace n then return none
    | none => return none
    let mut i := 5
    let mut label : Option String := none
    let mut done := false
    while !done && decide (i < chars.size) do
      while (match natAt chars i with
              | some n => isXmlWhitespace n
              | none => false) do
        i := i + 1
      if decide (i + 1 < chars.size) && natAt chars i == some 0x3F &&
          natAt chars (i + 1) == some 0x3E then
        done := true
      else if isAsciiLetter ((natAt chars i).getD 0) then
        let nameStart := i
        while (match natAt chars i with
                | some n => isAsciiNameChar n
                | none => false) do
          i := i + 1
        let name := charsToString chars nameStart i
        while (match natAt chars i with
                | some n => isXmlWhitespace n
                | none => false) do
          i := i + 1
        if natAt chars i == some 0x3D then
          i := i + 1
          while (match natAt chars i with
                  | some n => isXmlWhitespace n
                  | none => false) do
            i := i + 1
          if i < chars.size then
            match natAt chars i with
            | some q =>
              if q == 0x22 || q == 0x27 then
                i := i + 1
                let valueStart := i
                while i < chars.size ∧ natAt chars i ≠ some q do
                  i := i + 1
                if i < chars.size then
                  if name == "encoding" then
                    label := some (charsToString chars valueStart i)
                  i := i + 1
                else
                  done := true
              else
                done := true
            | none => done := true
        else
          done := true
      else
        done := true
    return label

end LexPat
