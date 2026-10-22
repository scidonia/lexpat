import LexPat

/-!
Equivalence between the byte-index scanners and the UTF-8 decoder.

The parser decides two things at byte indices rather than through a decoded
scalar stream: the `encoding` label of an XML declaration (one byte is one
scalar there, by construction) and the plain-ASCII runs of literal text and
markup. Everything those scanners accept must therefore be accepted by
`LexPat.decodeUtf8One` on the same bytes, and every byte they refuse must be
refused by the decoder at the same absolute offset with the same reason -- the
decoder, not a second rule set, is the oracle for these checks.

The checks are:

* the decoder's own accepted scalar and next offset, and its rejection reason
  and offset, for each UTF-8 length class and fault class, including a nonzero
  start index;
* text, element name, attribute name and attribute value bytes that the shipped
  scanner accepts, with the payload it produces equal to the decoder's scalars;
* the same fields carrying an invalid scalar, where the shipped scanner must
  report the decoder's code, reason and absolute offset;
* the declaration label scanner's result, its `stop` boundary, and its
  agreement with the label the declaration grammar records for the same bytes.

The driver uses no external system: documents are literal byte arrays and the
only IO is the failure message.
-/

namespace LexPat.ScannerDecoder

open LexPat

def bytes (xs : List Nat) : ByteArray :=
  ByteArray.mk (xs.toArray.map UInt8.ofNat)

def fail {α : Type} (message : String) : IO α :=
  throw (IO.userError message)

/-- The scalars the decoder reads from `start` to `stop` as one `String`, or the
decoder's own failure. -/
private def decodeRange (data : ByteArray) (start stop : Nat) :
    Except DecodeError String :=
  Id.run do
    let mut i := start
    let mut acc := ""
    while i < stop do
      match decodeUtf8One data i with
      | .ok (sc, next) =>
        acc := acc.push sc.toChar
        i := next
      | .error e => return .error e
    return .ok acc

/-- `decodeUtf8One` accepts the scalar `value` at `i` and continues at `next`. -/
def expectDecode (label : String) (data : ByteArray) (i value next : Nat) : IO Unit :=
  match decodeUtf8One data i with
  | .ok (sc, n) =>
    if sc.n == value && n == next then pure ()
    else fail s!"{label}: decodeUtf8One gave ({sc.n}, {n}), expected ({value}, {next})"
  | .error e =>
    fail s!"{label}: decodeUtf8One reported {e.reason.name} at {e.offset}, \
      expected the scalar {value} at {i}"

/-- `decodeUtf8One` rejects at `i` with `reason` and the absolute `offset`. -/
def expectDecodeError (label : String) (data : ByteArray) (i : Nat)
    (reason : DecodeReason) (offset : Nat) : IO Unit :=
  match decodeUtf8One data i with
  | .ok (sc, n) =>
    fail s!"{label}: decodeUtf8One accepted the scalar {sc.n} at {i} (next {n}), \
      expected {reason.name} at {offset}"
  | .error e =>
    if e.reason == reason && e.offset == offset then pure ()
    else fail s!"{label}: decodeUtf8One reported {e.reason.name} at {e.offset}, \
      expected {reason.name} at {offset}"

/-- The shipped scanner over `doc` must reach the decoder's own verdict on the
first invalid byte, which the decoder finds at `start`: the same public code,
the same reason and the same absolute byte offset. -/
def expectScannerRejects (label : String) (doc : ByteArray) (start : Nat) : IO Unit :=
  match decodeUtf8One doc start with
  | .ok _ =>
    fail s!"{label}: the byte at {start} decodes; this case needs a decoder rejection"
  | .error e =>
    match parseDocument doc with
    | .ok _ =>
      fail s!"{label}: the scanner accepted bytes the decoder rejects as \
        {e.reason.name} at {e.offset}"
    | .error got =>
      if got.code == e.reason.code && got.reason == e.reason.name &&
          got.offset == e.offset then pure ()
      else
        fail s!"{label}: scanner reported {got.code.name}/{got.reason} at \
          {got.offset}, decoder {e.reason.code.name}/{e.reason.name} at {e.offset}"

def expectEvents (label : String) (doc : ByteArray) (expected : Array Event) :
    IO Unit :=
  match parseDocument doc with
  | .error e =>
    fail s!"{label}: rejected with {e.code.name}/{e.reason} at {e.offset}"
  | .ok evs =>
    if evs == expected then pure ()
    else fail s!"{label}: got {repr evs}, expected {repr expected}"

/-- The decoder's reading of `[start, stop)` in `doc`. -/
private def decodedRange (label : String) (doc : ByteArray) (start stop : Nat) :
    IO String :=
  match decodeRange doc start stop with
  | .ok s => pure s
  | .error e => fail s!"{label}: the decoder rejects at {e.offset} ({e.reason.name})"

def expectRejects (label : String) (doc : ByteArray) (code : ErrorCode)
    (reason : String) : IO Unit :=
  match parseDocument doc with
  | .ok _ => fail s!"{label}: expected {code.name}/{reason}, got success"
  | .error e =>
    if e.code == code && e.reason == reason then pure ()
    else fail s!"{label}: expected {code.name}/{reason}, got {e.code.name}/{e.reason}"

/-! ### The decoder's own contract -/

def testDecoder : IO Unit := do
  expectDecode "ascii" (bytes [0x41]) 0 0x41 1
  expectDecode "ascii-at-offset" (bytes [0x78, 0x78, 0x41]) 2 0x41 3
  expectDecode "two-byte" (bytes [0xC3, 0xA9]) 0 0xE9 2
  expectDecode "three-byte" (bytes [0xE2, 0x82, 0xAC]) 0 0x20AC 3
  expectDecode "four-byte" (bytes [0xF0, 0x9D, 0x84, 0x9E]) 0 0x1D11E 4
  expectDecodeError "overlong-two-byte" (bytes [0xC0, 0x80]) 0 .overlong 0
  expectDecodeError "overlong-two-byte-c1" (bytes [0xC1, 0xBF]) 0 .overlong 0
  expectDecodeError "overlong-three-byte" (bytes [0xE0, 0x80, 0x80]) 0 .overlong 0
  expectDecodeError "overlong-four-byte" (bytes [0xF0, 0x80, 0x80, 0x80]) 0 .overlong 0
  expectDecodeError "surrogate-low" (bytes [0xED, 0xA0, 0x80]) 0 .surrogate 0
  expectDecodeError "surrogate-high" (bytes [0xED, 0xBF, 0xBF]) 0 .surrogate 0
  expectDecodeError "above-range" (bytes [0xF4, 0x90, 0x80, 0x80]) 0 .outOfRange 0
  expectDecodeError "lead-above-range" (bytes [0xF5, 0x80, 0x80, 0x80]) 0 .outOfRange 0
  expectDecodeError "stray-continuation" (bytes [0x80]) 0 .invalidLead 0
  expectDecodeError "stray-continuation-bf" (bytes [0xBF]) 0 .invalidLead 0
  expectDecodeError "bad-continuation-two" (bytes [0xC3, 0x41]) 0 .invalidContinuation 1
  expectDecodeError "bad-continuation-three" (bytes [0xE2, 0x82, 0x41]) 0
    .invalidContinuation 2
  expectDecodeError "bad-continuation-four" (bytes [0xF0, 0x9D, 0x84, 0x41]) 0
    .invalidContinuation 3
  expectDecodeError "truncated-two" (bytes [0xC3]) 0 .truncated 0
  expectDecodeError "truncated-three" (bytes [0xE2, 0x82]) 0 .truncated 0
  expectDecodeError "truncated-four" (bytes [0xF0, 0x9D, 0x84]) 0 .truncated 0
  expectDecodeError "bad-continuation-at-offset"
    (bytes [0x20, 0x20, 0xC3, 0x41]) 2 .invalidContinuation 3
  expectDecodeError "above-range-at-offset" (bytes [0x00, 0xF4, 0x90, 0x80, 0x80]) 1
    .outOfRange 1

/-! ### Accepted scanner fields agree with the decoder -/

def testAcceptedFields : IO Unit := do
  -- One text token that is an ASCII run joined to a decoded scalar and back to
  -- an ASCII run: the span/scalar junction must produce the decoder's scalars.
  let joined := "<r>".toUTF8 ++ "abc".toUTF8 ++ bytes [0xC3, 0xA9] ++
    "def".toUTF8 ++ "</r>".toUTF8
  let expected ← decodedRange "joined-text" joined 3 (joined.size - 4)
  expectEvents "joined-text" joined #[.start "r" #[], .text expected, .end "r"]

  -- The same bytes fed two bytes at a time, and fed so that the cut falls
  -- inside the multibyte scalar: the payload is unchanged.
  let chunks := [joined.extract 0 6, joined.extract 6 joined.size]
  let (st, evs1) := Id.run do
    let mut st := Stream.new {}
    let mut acc : Array Event := #[]
    for chunk in chunks do
      let (st1, es) := Stream.feed st chunk
      st := st1
      for e in es do acc := acc.push e
    return (st, acc)
  let (st2, evs2) := Stream.finish st
  match Stream.result st2 with
  | some (.ok ()) =>
    if evs1 ++ evs2 == #[.start "r" #[], .text expected, .end "r"] then pure ()
    else fail s!"split-text: got {repr (evs1 ++ evs2)}, expected one text event"
  | _ => fail "split-text: the split document did not complete"

  -- Text and names built from each UTF-8 length class.
  let scalars : List (String × List Nat) :=
    [("two-byte", [0xC3, 0xA9]), ("three-byte", [0xE2, 0x82, 0xAC]),
     ("four-byte", [0xF0, 0x9D, 0x84, 0x9E])]
  for (label, raw) in scalars do
    let scalar := bytes raw
    let textDoc := "<r>".toUTF8 ++ scalar ++ "</r>".toUTF8
    let text ← decodedRange s!"{label}-text" textDoc 3 (textDoc.size - 4)
    expectEvents s!"{label}-text" textDoc #[.start "r" #[], .text text, .end "r"]

    let nameDoc := "<".toUTF8 ++ scalar ++ "/>".toUTF8
    let name ← decodedRange s!"{label}-name" nameDoc 1 (nameDoc.size - 2)
    expectEvents s!"{label}-name" nameDoc #[.start name #[], .end name]

    let attrDoc := "<r k=\"".toUTF8 ++ scalar ++ "\"/>".toUTF8
    let value ← decodedRange s!"{label}-attr" attrDoc 6 (attrDoc.size - 3)
    expectEvents s!"{label}-attr" attrDoc #[.start "r" #[("k", value)], .end "r"]

    let attrNameDoc := "<r ".toUTF8 ++ scalar ++ "=\"v\"/>".toUTF8
    let attrName ← decodedRange s!"{label}-attr-name" attrNameDoc 3
      (attrNameDoc.size - 6)
    expectEvents s!"{label}-attr-name" attrNameDoc
      #[.start "r" #[(attrName, "v")], .end "r"]

/-! ### Refused scanner fields report the decoder's fault -/

def testRefusedFields : IO Unit := do
  -- Invalid scalar in text.
  for (label, raw) in
      [("text-invalid-lead", [0x80]), ("text-overlong", [0xE0, 0x80, 0x80]),
       ("text-surrogate", [0xED, 0xA0, 0x80]),
       ("text-above-range", [0xF4, 0x90, 0x80, 0x80]),
       ("text-bad-continuation", [0xC3, 0x41])] do
    let doc := "<r>a".toUTF8 ++ bytes raw ++ "</r>".toUTF8
    expectScannerRejects label doc 4

  -- A scalar cut off by the end of input: the fault is resolved at finish and
  -- still names the decoder's own offset.
  let cut := "<r>a".toUTF8 ++ bytes [0xC3]
  expectScannerRejects "text-truncated" cut 4

  -- Invalid scalar in an element name, an attribute name and an attribute
  -- value. Each byte sits behind an ASCII prefix that the byte-index scan
  -- consumes before the decoder rejects it.
  expectScannerRejects "name-overlong" ("<r".toUTF8 ++ bytes [0xC0, 0x80] ++
    "/>".toUTF8) 2
  expectScannerRejects "name-bad-continuation" ("<r".toUTF8 ++ bytes [0xC3, 0x41] ++
    "/>".toUTF8) 2
  expectScannerRejects "attr-name-bad-continuation" ("<r ".toUTF8 ++
    bytes [0xC3, 0x41] ++ "=\"v\"/>".toUTF8) 3
  expectScannerRejects "attr-value-surrogate" ("<r a=\"".toUTF8 ++
    bytes [0xED, 0xA0, 0x80] ++ "\"/>".toUTF8) 6
  expectScannerRejects "attr-value-stray" ("<r a=\"v".toUTF8 ++ bytes [0xBF] ++
    "\"/>".toUTF8) 7

/-! ### Declaration label scanning -/

/-- The declaration label the byte-index scanner reads from at most `stop`
bytes of `doc`. -/
def expectScanAt (label : String) (doc : ByteArray) (stop : Nat)
    (expected : Option String) : IO Unit :=
  let got := scanDeclLabel doc stop
  if got == expected then pure ()
  else fail s!"{label}: scanDeclLabel at stop {stop} gave {repr got}, expected \
    {repr expected}"

/-- The declaration label the byte-index scanner reads, for the whole document. -/
def expectLabel (label : String) (doc : ByteArray) (expected : Option String) :
    IO Unit :=
  expectScanAt label doc doc.size expected

/-- A document whose declaration the parser accepts: the recorded declaration
event carries `expected`, and the byte-index label scan must find exactly that
same label in the same bytes. -/
def expectDeclEvent (label : String) (doc : ByteArray) (expected : String) :
    IO Unit :=
  let expectLabelMatch : IO Unit :=
    match scanDeclLabel doc doc.size with
    | some got =>
      if got == expected then pure ()
      else fail s!"{label}: byte-index label {repr got} differs from the grammar's \
        {repr expected}"
    | none =>
      fail s!"{label}: the byte-index scanner found no label, the grammar recorded \
        {repr expected}"
  match parseDocument doc with
  | .error e =>
    fail s!"{label}: rejected with {e.code.name}/{e.reason} at {e.offset}"
  | .ok evs =>
    match (evs[0]? : Option Event) with
    | some (.xmlDecl _ enc _) =>
      if enc != some expected then
        fail s!"{label}: the declaration event records {repr enc}, expected {repr expected}"
      else expectLabelMatch
    | _ => fail s!"{label}: the first event is not a declaration: {repr evs}"

def testDeclaration : IO Unit := do
  let plain := "<?xml version=\"1.0\" encoding=\"UTF-8\"?><r/>".toUTF8
  expectDeclEvent "decl-double-quote" plain "UTF-8"
  expectDeclEvent "decl-lower-case" "<?xml version=\"1.0\" encoding=\"utf-8\"?><r/>".toUTF8
    "utf-8"
  expectDeclEvent "decl-single-quote" "<?xml version='1.0' encoding='ISO-8859-1'?><r/>".toUTF8
    "ISO-8859-1"
  expectDeclEvent "decl-spaces" "<?xml version=\"1.0\" encoding = \"US-ASCII\" ?><r/>".toUTF8
    "US-ASCII"
  expectLabel "decl-no-label" "<?xml version=\"1.0\"?><r/>".toUTF8 none
  expectLabel "decl-no-declaration" "<r/>".toUTF8 none

  -- `stop` is exact: the closing quote of the value is the last byte the scan
  -- must see. `findDeclEnd` returns the offset just past `?>`.
  let declStop := findDeclEnd plain plain.size
  expectScanAt "decl-stop-before-quote" plain (declStop - 3) none
  expectScanAt "decl-stop-at-quote" plain (declStop - 2) (some "UTF-8")
  expectScanAt "decl-stop-short" plain 5 none

  -- A label that names no supported encoding is found and then refused by the
  -- encoding choice, so the scanner's own result is the label, not `none`.
  let unknown := "<?xml version=\"1.0\" encoding=\"X-BOGUS\"?><r/>".toUTF8
  expectLabel "decl-unknown-label" unknown (some "X-BOGUS")
  expectRejects "decl-unknown" unknown .unknownEncoding "unknownEncoding"
  let mismatch := "<?xml version=\"1.0\" encoding=\"UTF-16\"?><r/>".toUTF8
  expectLabel "decl-utf16-label" mismatch (some "UTF-16")
  expectRejects "decl-utf16" mismatch .incorrectEncoding "encodingMismatch"

  -- A non-ASCII byte inside the encoding value: the decoder accepts the
  -- scalar, but the declaration field is ASCII-only, so the grammar refuses
  -- the byte and the label scanner reports the byte-for-scalar reading of the
  -- bytes it saw.
  let declHead := "<?xml version=\"1.0\" encoding=\"".toUTF8
  let nonAscii := declHead ++ bytes [0xC3, 0xA9] ++ "\"?><r/>".toUTF8
  match decodeUtf8One nonAscii declHead.size with
  | .ok _ => pure ()
  | .error e =>
    fail s!"decl-nonascii: the decoder rejects the value byte at {e.offset} \
      ({e.reason.name}); this case needs a scalar the decoder accepts"
  match parseDocument nonAscii with
  | .ok _ => fail "decl-nonascii: expected a declaration fault"
  | .error e =>
    if e.code != .xmlDecl || e.reason != "xmlDeclEncodingName" ||
        e.offset != declHead.size then
      fail s!"decl-nonascii: got {e.code.name}/{e.reason} at {e.offset}, expected \
        XML_DECL/xmlDeclEncodingName at {declHead.size}"
    else
      pure ()
  match scanDeclLabel nonAscii nonAscii.size with
  | some got =>
    if got == String.ofList [Char.ofNat 0xC3, Char.ofNat 0xA9] then pure ()
    else fail s!"decl-nonascii: the label is {repr got}, expected the byte-for-scalar \
      reading of the two value bytes"
  | none => fail "decl-nonascii: the label scanner found no value"

/-! ### A label-selected encoding agrees with the decoder's scalars -/

def testSelectedEncodings : IO Unit := do
  -- Latin-1 `0xE9` is the scalar the UTF-8 decoder produces for `C3 A9`; the
  -- declaration's label is what selects the conversion.
  let latin1 := "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><r>".toUTF8 ++
    bytes [0xE9] ++ "</r>".toUTF8
  let expected ← decodedRange "latin1-text" (bytes [0xC3, 0xA9]) 0 2
  expectEvents "latin1-text" latin1 #[.xmlDecl "1.0" (some "ISO-8859-1") none,
    .start "r" #[], .text expected, .end "r"]

  -- A four-byte scalar behind a lower-case `utf-8` label: the label was found
  -- (otherwise the bytes would be invalid UTF-8 document bytes).
  let utf8 := "<?xml version=\"1.0\" encoding=\"utf-8\"?><r>".toUTF8 ++
    bytes [0xF0, 0x9D, 0x84, 0x9E] ++ "</r>".toUTF8
  let scalar ← decodedRange "utf8-text" (bytes [0xF0, 0x9D, 0x84, 0x9E]) 0 4
  expectEvents "utf8-text" utf8 #[.xmlDecl "1.0" (some "utf-8") none,
    .start "r" #[], .text scalar, .end "r"]

def runAll : IO Unit := do
  testDecoder
  testAcceptedFields
  testRefusedFields
  testDeclaration
  testSelectedEncodings
  IO.println "ScannerDecoder: every byte-index scanner case matches decodeUtf8One"

end LexPat.ScannerDecoder

/-- Entry point for `lean --run`. -/
def main : IO Unit := LexPat.ScannerDecoder.runAll
