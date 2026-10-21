/-
Total, bounds-checked decoding of raw XML bytes.

Every read goes through `data[i]?`; there is no pointer arithmetic and no
unchecked memory operation. UTF-8 rejects invalid leads, invalid continuations,
overlong forms, surrogates, values above `0x10FFFF` and truncation. UTF-16
rejects odd byte counts and unpaired surrogates. ISO-8859-1 maps each byte to
the scalar of the same value; US-ASCII rejects bytes above `0x7F`.

Encoding selection is byte-evidence first: a BOM or a zero-byte UTF-16
signature decides the encoding, and otherwise an ASCII-compatible XML
declaration may name ISO-8859-1 or US-ASCII. A declaration can never
contradict the byte evidence: the document parser re-checks the declaration's
`encoding` value against the encoding actually used. `LexPat.Stream` performs
this decision once, from a bounded undecided prefix, and reuses the decoders
and the declaration-label scanner here; `detectSignature`,
`scanDeclLabel` and the per-scalar decoders are the pieces it shares.
-/
import LexPat.Types
import LexPat.Lexer

namespace LexPat

/-- A UTF-8 continuation byte, `0b10xxxxxx`. -/
def isContByte (b : UInt8) : Bool := decide (0x80 ≤ b.toNat ∧ b.toNat ≤ 0xBF)

/-- The six low bits of a UTF-8 continuation byte. Meaningful only after
`isContByte` accepted the byte, where it equals `b.toNat - 0x80`. -/
def contValue (b : UInt8) : Nat := b.toNat - 0x80

/-- Decode one UTF-8 scalar starting at byte offset `i`. On success it returns
the scalar and the offset just past it. -/
def decodeUtf8One (data : ByteArray) (i : Nat) : Except DecodeError (Scalar × Nat) :=
  match data[i]? with
  | none => .error ⟨.truncated, i⟩
  | some b0 =>
    if hA : b0.toNat < 0x80 then
      .ok (⟨b0.toNat, Or.inl (by omega)⟩, i + 1)
    else if hB : b0.toNat < 0xC0 then
      .error ⟨.invalidLead, i⟩
    else if hC : b0.toNat < 0xC2 then
      .error ⟨.overlong, i⟩
    else if hD : b0.toNat < 0xE0 then
      match data[i + 1]? with
      | none => .error ⟨.truncated, i⟩
      | some b1 =>
        if hE : isContByte b1 = true then
          .ok
            (⟨(b0.toNat - 0xC0) * 0x40 + contValue b1,
              Or.inl (by
                have hb1 := of_decide_eq_true hE
                unfold contValue
                omega)⟩,
              i + 2)
        else
          .error ⟨.invalidContinuation, i + 1⟩
    else if hE : b0.toNat < 0xF0 then
      match data[i + 1]? with
      | none => .error ⟨.truncated, i⟩
      | some b1 =>
        match data[i + 2]? with
        | none => .error ⟨.truncated, i⟩
        | some b2 =>
          if hb1 : isContByte b1 = true then
            if hb2 : isContByte b2 = true then
              if hE0 : b0.toNat = 0xE0 then
                if hlt : b1.toNat < 0xA0 then
                  .error ⟨.overlong, i⟩
                else
                  .ok
                    (⟨(b0.toNat - 0xE0) * 0x1000 + contValue b1 * 0x40 + contValue b2,
                      Or.inl (by
                        have h1' := of_decide_eq_true hb1
                        have h2' := of_decide_eq_true hb2
                        unfold contValue
                        omega)⟩,
                      i + 3)
              else if hED : b0.toNat = 0xED then
                if hge : 0xA0 ≤ b1.toNat then
                  .error ⟨.surrogate, i⟩
                else
                  .ok
                    (⟨(b0.toNat - 0xE0) * 0x1000 + contValue b1 * 0x40 + contValue b2,
                      Or.inl (by
                        have h1' := of_decide_eq_true hb1
                        have h2' := of_decide_eq_true hb2
                        unfold contValue
                        omega)⟩,
                      i + 3)
              else if hltEE : b0.toNat < 0xEE then
                .ok
                  (⟨(b0.toNat - 0xE0) * 0x1000 + contValue b1 * 0x40 + contValue b2,
                    Or.inl (by
                      have h1' := of_decide_eq_true hb1
                      have h2' := of_decide_eq_true hb2
                      unfold contValue
                      omega)⟩,
                    i + 3)
              else
                .ok
                  (⟨(b0.toNat - 0xE0) * 0x1000 + contValue b1 * 0x40 + contValue b2,
                    Or.inr ⟨by
                      have h1' := of_decide_eq_true hb1
                      have h2' := of_decide_eq_true hb2
                      unfold contValue
                      omega,
                    by
                      have h1' := of_decide_eq_true hb1
                      have h2' := of_decide_eq_true hb2
                      unfold contValue
                      omega⟩⟩,
                    i + 3)
            else
              .error ⟨.invalidContinuation, i + 2⟩
          else
            .error ⟨.invalidContinuation, i + 1⟩
    else if hF : b0.toNat < 0xF5 then
      match data[i + 1]?, data[i + 2]?, data[i + 3]? with
      | some b1, some b2, some b3 =>
        if hb1 : isContByte b1 = true then
          if hb2 : isContByte b2 = true then
            if hb3 : isContByte b3 = true then
              if hF0 : b0.toNat = 0xF0 then
                if hlt : b1.toNat < 0x90 then
                  .error ⟨.overlong, i⟩
                else
                  .ok
                    (⟨(b0.toNat - 0xF0) * 0x40000 + contValue b1 * 0x1000 + contValue b2 * 0x40 +
                        contValue b3,
                      Or.inr ⟨by
                        have h1' := of_decide_eq_true hb1
                        have h2' := of_decide_eq_true hb2
                        have h3' := of_decide_eq_true hb3
                        unfold contValue
                        omega,
                      by
                        have h1' := of_decide_eq_true hb1
                        have h2' := of_decide_eq_true hb2
                        have h3' := of_decide_eq_true hb3
                        unfold contValue
                        omega⟩⟩,
                      i + 4)
              else if hF4 : b0.toNat = 0xF4 then
                if hgt : 0x90 ≤ b1.toNat then
                  .error ⟨.outOfRange, i⟩
                else
                  .ok
                    (⟨(b0.toNat - 0xF0) * 0x40000 + contValue b1 * 0x1000 + contValue b2 * 0x40 +
                        contValue b3,
                      Or.inr ⟨by
                        have h1' := of_decide_eq_true hb1
                        have h2' := of_decide_eq_true hb2
                        have h3' := of_decide_eq_true hb3
                        unfold contValue
                        omega,
                      by
                        have h1' := of_decide_eq_true hb1
                        have h2' := of_decide_eq_true hb2
                        have h3' := of_decide_eq_true hb3
                        unfold contValue
                        omega⟩⟩,
                      i + 4)
              else
                .ok
                  (⟨(b0.toNat - 0xF0) * 0x40000 + contValue b1 * 0x1000 + contValue b2 * 0x40 +
                      contValue b3,
                    Or.inr ⟨by
                      have h1' := of_decide_eq_true hb1
                      have h2' := of_decide_eq_true hb2
                      have h3' := of_decide_eq_true hb3
                      unfold contValue
                      omega,
                    by
                      have h1' := of_decide_eq_true hb1
                      have h2' := of_decide_eq_true hb2
                      have h3' := of_decide_eq_true hb3
                      unfold contValue
                      omega⟩⟩,
                    i + 4)
            else
              .error ⟨.invalidContinuation, i + 3⟩
          else
            .error ⟨.invalidContinuation, i + 2⟩
        else
          .error ⟨.invalidContinuation, i + 1⟩
      | _, _, _ => .error ⟨.truncated, i⟩
    else
      .error ⟨.outOfRange, i⟩

/-- The 16-bit code unit at a byte pair, in the requested byte order. -/
def utf16Unit (bigEndian : Bool) (b0 b1 : UInt8) : Nat :=
  if bigEndian then b0.toNat * 0x100 + b1.toNat else b1.toNat * 0x100 + b0.toNat

theorem utf16Unit_lt (bigEndian : Bool) (b0 b1 : UInt8) :
    utf16Unit bigEndian b0 b1 < 0x10000 := by
  have h0 : b0.toNat < 256 := UInt8.toNat_lt b0
  have h1 : b1.toNat < 256 := UInt8.toNat_lt b1
  unfold utf16Unit
  split <;> omega

/-- Decode one UTF-16 code unit (or surrogate pair) at byte offset `i`. -/
def decodeUtf16One (data : ByteArray) (bigEndian : Bool) (i : Nat) :
    Except DecodeError (Scalar × Nat) :=
  match data[i]?, data[i + 1]? with
  | some b0, some b1 =>
    if hBmp : utf16Unit bigEndian b0 b1 < 0xD800 then
      .ok (⟨utf16Unit bigEndian b0 b1, Or.inl hBmp⟩, i + 2)
    else if hSur : utf16Unit bigEndian b0 b1 ≤ 0xDFFF then
      if hHigh : utf16Unit bigEndian b0 b1 < 0xDC00 then
        match data[i + 2]?, data[i + 3]? with
        | some c0, some c1 =>
          if hPair : 0xDC00 ≤ utf16Unit bigEndian c0 c1 ∧
              utf16Unit bigEndian c0 c1 ≤ 0xDFFF then
            .ok
              (⟨0x10000 + (utf16Unit bigEndian b0 b1 - 0xD800) * 0x400 +
                  (utf16Unit bigEndian c0 c1 - 0xDC00),
                Or.inr ⟨by omega, by omega⟩⟩,
                i + 4)
          else
            .error ⟨.unpairedSurrogate, i⟩
        | _, _ => .error ⟨.unpairedSurrogate, i⟩
      else
        .error ⟨.unpairedSurrogate, i⟩
    else
      .ok
        (⟨utf16Unit bigEndian b0 b1,
          Or.inr ⟨by
            have hu := utf16Unit_lt bigEndian b0 b1
            omega,
          by
            have hu := utf16Unit_lt bigEndian b0 b1
            omega⟩⟩,
          i + 2)
  | _, _ => .error ⟨.oddUtf16Length, i⟩

/-- Decode `[start, stop)` as ISO-8859-1: every byte is the scalar of its value. -/
def decodeLatin1Range (data : ByteArray) (start stop : Nat) : Array DecodedChar :=
  Id.run do
    let mut i := start
    let mut acc : Array DecodedChar := #[]
    while i < stop ∧ i < data.size do
      match data[i]? with
      | some b =>
        acc := acc.push ⟨⟨b.toNat, Or.inl (by
            have hb : b.toNat < 256 := UInt8.toNat_lt b
            omega)⟩, i⟩
      | none => pure ()
      i := i + 1
    return acc

/-- Encoding names we recognize, before checking them against the byte
evidence. -/
inductive LabelKind where
  | utf8
  | ascii
  | latin1
  | utf16
  | utf16le
  | utf16be
  | unknown
deriving DecidableEq, Repr

/-- Classify an encoding label case-insensitively. -/
def classifyLabel (label : String) : LabelKind :=
  match label.toLower with
  | "utf-8" | "utf8" => .utf8
  | "us-ascii" | "ascii" => .ascii
  | "iso-8859-1" | "iso8859-1" | "latin1" | "latin-1" => .latin1
  | "utf-16" => .utf16
  | "utf-16le" => .utf16le
  | "utf-16be" => .utf16be
  | _ => .unknown

/-- Byte-order-mark and zero-byte UTF-16 signature detection. Detection comes
before any declaration is read, so a document's declaration cannot choose a
different encoding from the one its first bytes already prove. -/
def detectSignature (data : ByteArray) : Option (Encoding × Nat) :=
  if data[0]? == some 0xEF && data[1]? == some 0xBB && data[2]? == some 0xBF then
    some (.utf8, 3)
  else if data[0]? == some 0xFF && data[1]? == some 0xFE then
    some (.utf16le, 2)
  else if data[0]? == some 0xFE && data[1]? == some 0xFF then
    some (.utf16be, 2)
  else if data[0]? == some 0x00 && data[1]? == some 0x3C then
    some (.utf16be, 0)
  else if data[0]? == some 0x3C && data[1]? == some 0x00 then
    some (.utf16le, 0)
  else
    none

private def isAsciiWs (b : UInt8) : Bool :=
  b == 0x20 || b == 0x09 || b == 0x0A || b == 0x0D

/-- True when `data` starts with `<?xml` followed by a space character. -/
def startsWithDeclOpen (data : ByteArray) : Bool :=
  data[0]? == some 0x3C && data[1]? == some 0x3F && data[2]? == some 0x78 &&
    data[3]? == some 0x6D && data[4]? == some 0x6C &&
    (match data[5]? with
      | some b => isAsciiWs b
      | none => false)

/-- End of the XML declaration in raw bytes (just past `?>`), or the scan limit. -/
def findDeclEnd (data : ByteArray) (limit : Nat) : Nat :=
  Id.run do
    let stop := Nat.min data.size limit
    let mut i := 5
    while i + 1 < stop do
      if data[i]? == some 0x3F && data[i + 1]? == some 0x3E then
        return i + 2
      i := i + 1
    return stop

/-- The declared encoding label of an ASCII-compatible document, if the
document opens with an XML declaration inside the scan limit. -/
def scanDeclLabel (data : ByteArray) (limit : Nat) : Option String :=
  if startsWithDeclOpen data then
    let stop := findDeclEnd data limit
    LexPat.scanDeclEncodingLabel (decodeLatin1Range data 0 stop)
  else
    none

end LexPat
