/-
XML 1.0 (Fifth Edition) character and name predicates, and the small shared
helpers that do not need parser state. The streaming grammar in
`LexPat.Stream` uses these predicates for every decoded scalar; the one-shot
entry point reaches them through the stream.
-/
import LexPat.Types

namespace LexPat

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

/-- The value of the byte at `pos`, if any. -/
private def byteAt (data : ByteArray) (pos : Nat) : Option Nat :=
  (data[pos]?).map UInt8.toNat

/-- The bytes `[start, stop)` as a `String`. Each byte stands for the scalar of
the same value; in an ASCII-compatible declaration every one of them is in
`[0x00, 0x7F]`, and a byte above that range is carried through unchanged so the
label is compared exactly as the document spelled it. -/
private def bytesToString (data : ByteArray) (start stop : Nat) : String :=
  Id.run do
    let mut out := ""
    let mut i := start
    while i < stop ∧ i < data.size do
      match data[i]? with
      | some b => out := out.push (Char.ofNat b.toNat)
      | none => pure ()
      i := i + 1
    return out

/-- Extract the `encoding` pseudo-attribute of an XML declaration, permissively.

This scanner runs over the raw declaration bytes, at byte indices, because an
ASCII-compatible declaration is exactly the case where one byte is one scalar.
It is used only to choose the decoder for the rest of the document; it never
decides well-formedness, which the document parser re-checks under the XML
declaration grammar, rejecting whatever this scanner tolerated. Returns `none`
when the document does not start with `<?xml` followed by whitespace, or when
the declaration is not parseable enough to find the attribute.

`stop` bounds the scan: bytes at or past it are not read. -/
def scanDeclEncodingLabel (data : ByteArray) (stop : Nat) : Option String :=
  Id.run do
    let end' := Nat.min data.size stop
    if end' < 6 then return none
    if byteAt data 0 != some 0x3C || byteAt data 1 != some 0x3F ||
        byteAt data 2 != some 0x78 || byteAt data 3 != some 0x6D ||
        byteAt data 4 != some 0x6C then
      return none
    match byteAt data 5 with
    | some n => if !isXmlWhitespace n then return none
    | none => return none
    let mut i := 5
    let mut label : Option String := none
    let mut done := false
    while !done && decide (i < end') do
      while (match byteAt data i with
              | some n => isXmlWhitespace n
              | none => false) do
        i := i + 1
      if decide (i + 1 < end') && byteAt data i == some 0x3F &&
          byteAt data (i + 1) == some 0x3E then
        done := true
      else if isAsciiLetter ((byteAt data i).getD 0) then
        let nameStart := i
        while (match byteAt data i with
                | some n => isAsciiNameChar n
                | none => false) do
          i := i + 1
        let name := bytesToString data nameStart i
        while (match byteAt data i with
                | some n => isXmlWhitespace n
                | none => false) do
          i := i + 1
        if byteAt data i == some 0x3D then
          i := i + 1
          while (match byteAt data i with
                  | some n => isXmlWhitespace n
                  | none => false) do
            i := i + 1
          if i < end' then
            match byteAt data i with
            | some q =>
              if q == 0x22 || q == 0x27 then
                i := i + 1
                let valueStart := i
                while i < end' ∧ byteAt data i ≠ some q do
                  i := i + 1
                if i < end' then
                  if name == "encoding" then
                    label := some (bytesToString data valueStart i)
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
