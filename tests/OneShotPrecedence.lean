import LexPat

/-! The public one-shot entry point on `<r></s>` followed by an invalid UTF-8
continuation. An earlier tag mismatch must be reported ahead of the later
decoding failure. -/

/-- `<r></s>` followed by the invalid UTF-8 continuation `C3 28`. -/
def s1Bytes : ByteArray :=
  ⟨#[0x3C, 0x72, 0x3E, 0x3C, 0x2F, 0x73, 0x3E, 0xC3, 0x28]⟩

def main : IO Unit := do
  match LexPat.parseDocument s1Bytes with
  | .ok events =>
    throw (IO.userError
      s!"S1: expected Except.error with code .tagMismatch, but parseDocument returned .ok with {events.size} event(s)")
  | .error e =>
    if e.code != .tagMismatch || e.reason != "tagMismatch" then
      throw (IO.userError
        s!"S1: expected code .tagMismatch and reason \"tagMismatch\" on the returned error; got code {repr e.code} and reason {repr e.reason} at offset {e.offset}")
    IO.println "S1: parseDocument returned .error with code .tagMismatch and reason \"tagMismatch\""
