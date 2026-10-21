/-
Machine-checked properties of the UTF-8 decoder in `LexPat.Encoding`.

These theorems are about the real `decodeUtf8One`; nothing here restates the
decoder's rules as a separate predicate. `#print axioms` at the end reports the
axiom dependencies of each theorem. What they establish is about the encoding
predicate only: end-to-end parser and I/O behaviour is checked by the corpus
and the libexpat differential, not proved here.
-/
import LexPat.Encoding

namespace LexPat

open LexPat

/-- One-byte (ASCII) UTF-8 encoding of a scalar. -/
def encodeAscii (s : Scalar) : ByteArray :=
  ByteArray.mk #[UInt8.ofNat s.n]

/-- A scalar is determined by its value; the validity proofs are irrelevant. -/
theorem scalar_ext {t s : Scalar} (h : t.n = s.n) : t = s := by
  cases t
  cases s
  simp only [Scalar.mk.injEq] at h ⊢
  exact h

/-- The two-byte overlong lead bytes `0xC0` and `0xC1` are rejected as
`overlong` for *every* possible following byte sequence: the check happens
before any continuation byte is consulted. -/
theorem decodeUtf8One_rejects_overlong_two_byte (data : ByteArray) (i : Nat) (b : UInt8)
    (hb : data[i]? = some b) (hlead : b = 0xC0 ∨ b = 0xC1) :
    ∃ off, decodeUtf8One data i = .error { reason := .overlong, offset := off } := by
  rcases hlead with rfl | rfl
  · exact ⟨i, by unfold decodeUtf8One; rw [hb]; rfl⟩
  · exact ⟨i, by unfold decodeUtf8One; rw [hb]; rfl⟩

/-- A byte below `0x80` decodes as a single ASCII scalar. -/
theorem decodeUtf8One_ascii (data : ByteArray) (b : UInt8) (hb : data[0]? = some b)
    (h : b.toNat < 0x80) :
    ∃ (t : Scalar) (next : Nat),
      decodeUtf8One data 0 = .ok (t, next) ∧ t.n = b.toNat ∧ next = 1 := by
  simp only [decodeUtf8One, hb]
  rw [dite_eq_left h]
  exact ⟨⟨b.toNat, Or.inl (by omega)⟩, 1, by congr 1, rfl, rfl⟩

/-- An ASCII scalar encodes to one UTF-8 byte and decodes back to the same
scalar: a non-vacuous round trip on the real encoder and decoder. -/
theorem decodeUtf8One_ascii_roundtrip (s : Scalar) (h : s.n < 0x80) :
    decodeUtf8One (encodeAscii s) 0 = .ok (s, 1) := by
  have h0 : (encodeAscii s)[0]? = some (UInt8.ofNat s.n) := rfl
  have hn : (UInt8.ofNat s.n).toNat = s.n := by
    rw [UInt8.toNat_ofNat']
    omega
  have hlt : (UInt8.ofNat s.n).toNat < 0x80 := by rw [hn]; exact h
  obtain ⟨t, next, hdec, ht, hnext⟩ :=
    decodeUtf8One_ascii (encodeAscii s) (UInt8.ofNat s.n) h0 hlt
  have hts : t.n = s.n := by rw [ht, hn]
  rw [hdec, scalar_ext hts, hnext]

#print axioms decodeUtf8One_rejects_overlong_two_byte
#print axioms decodeUtf8One_ascii_roundtrip

end LexPat
