import LexPat

/-!
Direct assertions on the public streaming API.

Every check goes through `LexPat.Stream.new`, `feed` and `finish` (and
`LexPat.parseDocument` where a one-shot comparison is the point). The driver
uses no external system: documents are literal byte arrays, and the only IO is
the failure message.
-/

namespace LexPat.StreamingCases

open LexPat

def bytes (xs : List Nat) : ByteArray :=
  ByteArray.mk (xs.toArray.map UInt8.ofNat)

def feedAll (limits : Limits) (chunks : List ByteArray) : Stream × Array Event :=
  Id.run do
    let mut st := Stream.new limits
    let mut evs : Array Event := #[]
    for chunk in chunks do
      let (st1, es) := Stream.feed st chunk
      st := st1
      for e in es do evs := evs.push e
    return (st, evs)

def runChunks (limits : Limits) (chunks : List ByteArray) : Stream × Array Event :=
  let (st, evs) := feedAll limits chunks
  let (st2, evs2) := Stream.finish st
  Id.run do
    let mut all := evs
    for e in evs2 do all := all.push e
    return (st2, all)

def resultOf (st : Stream) : Except ParseError Unit :=
  match Stream.result st with
  | some r => r
  | none => .error ⟨.syntax, "notFinished", 0⟩

def allCuts (bs : ByteArray) : List (List ByteArray) :=
  (List.range (bs.size + 1)).map (fun k => [bs.extract 0 k, bs.extract k bs.size])

def oneByteChunks (bs : ByteArray) : List ByteArray :=
  (List.range bs.size).map (fun i => bs.extract i (i + 1))

def fail (message : String) : IO Unit :=
  throw (IO.userError message)

def expectError (label : String) (res : Except ParseError Unit) (code : ErrorCode)
    (reason : String) : IO Unit :=
  match res with
  | .error e =>
    if e.code == code && e.reason == reason then pure ()
    else fail s!"{label}: expected {code.name}/{reason}, got {e.code.name}/{e.reason}"
  | .ok () => fail s!"{label}: expected {code.name}/{reason}, got success"

def expectOk (label : String) (res : Except ParseError Unit) : IO Unit :=
  match res with
  | .ok () => pure ()
  | .error e => fail s!"{label}: expected success, got {e.code.name}/{e.reason}"

def expectActive (label : String) (st : Stream) : IO Unit :=
  match Stream.result st with
  | none => pure ()
  | some (.ok ()) => fail s!"{label}: expected an active stream, got a completed one"
  | some (.error e) =>
    fail s!"{label}: expected an active stream, got {e.code.name}/{e.reason}"

def expectEvents (label : String) (actual expected : Array Event) : IO Unit :=
  if actual == expected then pure ()
  else fail s!"{label}: events differ: got {repr actual}, expected {repr expected}"

/-- Every partition (all two-part cuts, one-byte chunks and the whole input)
must agree with the one-shot result: the exact event sequence on acceptance,
or the exact code and reason on rejection. -/
def expectSameAsOneShot (label : String) (bs : ByteArray) (limits : Limits := {}) :
    IO Unit := do
  let one := parseDocument bs limits
  let partitions := allCuts bs ++ [oneByteChunks bs, [bs]]
  for chunks in partitions do
    let (st, evs) := runChunks limits chunks
    match one, resultOf st with
    | .ok expected, .ok () =>
      expectEvents label evs expected
    | .error e1, .error e2 =>
      if e1.code == e2.code && e1.reason == e2.reason then pure ()
      else fail s!"{label}: stream {e2.code.name}/{e2.reason} != one-shot {e1.code.name}/{e1.reason}"
    | .ok _, .error e =>
      fail s!"{label}: stream rejected an accepted document as {e.code.name}/{e.reason}"
    | .error e, .ok () =>
      fail s!"{label}: stream accepted a document one-shot rejected as {e.code.name}/{e.reason}"

def expectAllPartitionsError (label : String) (bs : ByteArray) (limits : Limits)
    (code : ErrorCode) (reason : String) : IO Unit := do
  for chunks in allCuts bs ++ [oneByteChunks bs, [bs]] do
    let (st, _) := runChunks limits chunks
    expectError label (resultOf st) code reason

/-- Every partition must accept with exactly the expected events. The events
are literal, so acceptance does not rest on the one-shot wrapper agreeing. -/
def expectAllPartitionsOk (label : String) (bs : ByteArray) (limits : Limits)
    (expected : Array Event) : IO Unit := do
  for chunks in allCuts bs ++ [oneByteChunks bs, [bs]] do
    let (st, evs) := runChunks limits chunks
    expectOk label (resultOf st)
    expectEvents label evs expected

/-! ### Encoding selection at every cut -/

def testEncodings : IO Unit := do
  expectSameAsOneShot "utf8-bom" (bytes [0xEF, 0xBB, 0xBF, 0x3C, 0x61, 0x2F, 0x3E])
  expectSameAsOneShot "utf16le-bom"
    (bytes [0xFF, 0xFE, 0x3C, 0x00, 0x61, 0x00, 0x2F, 0x00, 0x3E, 0x00])
  expectSameAsOneShot "utf16be-bom"
    (bytes [0xFE, 0xFF, 0x00, 0x3C, 0x00, 0x61, 0x00, 0x2F, 0x00, 0x3E])
  expectSameAsOneShot "utf16le-signature"
    (bytes [0x3C, 0x00, 0x61, 0x00, 0x2F, 0x00, 0x3E, 0x00])
  expectSameAsOneShot "utf16be-signature"
    (bytes [0x00, 0x3C, 0x00, 0x61, 0x00, 0x2F, 0x00, 0x3E])
  expectSameAsOneShot "latin1-decl"
    ("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><a>".toUTF8 ++ bytes [0xE9] ++
      "</a>".toUTF8)
  expectSameAsOneShot "ascii-decl"
    "<?xml version=\"1.0\" encoding=\"US-ASCII\"?><a>x</a>".toUTF8
  expectSameAsOneShot "utf8-bom-decl"
    (bytes [0xEF, 0xBB, 0xBF] ++
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?><a/>".toUTF8)
  expectSameAsOneShot "utf16le-decl"
    (bytes [0xFF, 0xFE] ++
      bytes [0x3C, 0x00, 0x3F, 0x00, 0x78, 0x00, 0x6D, 0x00, 0x6C, 0x00, 0x20,
        0x00, 0x76, 0x00, 0x65, 0x00, 0x72, 0x00, 0x73, 0x00, 0x69, 0x00,
        0x6F, 0x00, 0x6E, 0x00, 0x3D, 0x00, 0x22, 0x00, 0x31, 0x00, 0x2E,
        0x00, 0x30, 0x00, 0x22, 0x00, 0x3F, 0x00, 0x3E, 0x00, 0x3C, 0x00,
        0x61, 0x00, 0x2F, 0x00, 0x3E, 0x00])

def testUtf8Scalars : IO Unit := do
  expectSameAsOneShot "utf8-two-byte" ("<a>".toUTF8 ++ bytes [0xC3, 0xA9] ++ "</a>".toUTF8)
  expectSameAsOneShot "utf8-four-byte"
    ("<a>".toUTF8 ++ bytes [0xF0, 0x9F, 0x98, 0x80] ++ "</a>".toUTF8)
  expectSameAsOneShot "utf8-invalid-continuation"
    ("<a>".toUTF8 ++ bytes [0xC3, 0x28] ++ "</a>".toUTF8)
  expectSameAsOneShot "utf8-truncated" ("<a>".toUTF8 ++ bytes [0xE2, 0x82])
  expectSameAsOneShot "utf8-overlong" ("<a>".toUTF8 ++ bytes [0xE0, 0x80, 0x80] ++ "</a>".toUTF8)
  expectSameAsOneShot "utf8-surrogate" ("<a>".toUTF8 ++ bytes [0xED, 0xA0, 0x80] ++ "</a>".toUTF8)
  expectSameAsOneShot "utf8-out-of-range"
    ("<a>".toUTF8 ++ bytes [0xF4, 0x90, 0x80, 0x80] ++ "</a>".toUTF8)

def testUtf16Scalars : IO Unit := do
  expectSameAsOneShot "utf16-pair"
    (bytes [0xFF, 0xFE, 0x3C, 0x00, 0x61, 0x00, 0x3E, 0x00, 0x3D, 0xD8, 0x00, 0xDE,
      0x3C, 0x00, 0x2F, 0x00, 0x61, 0x00, 0x3E, 0x00])
  expectSameAsOneShot "utf16-unpaired-high"
    (bytes [0xFF, 0xFE, 0x3C, 0x00, 0x61, 0x00, 0x3E, 0x00, 0x00, 0xD8, 0x3C, 0x00,
      0x2F, 0x00, 0x61, 0x00, 0x3E, 0x00])
  expectSameAsOneShot "utf16-lone-low"
    (bytes [0xFF, 0xFE, 0x3C, 0x00, 0x61, 0x00, 0x3E, 0x00, 0x00, 0xDC, 0x3C, 0x00,
      0x2F, 0x00, 0x61, 0x00, 0x3E, 0x00])
  expectSameAsOneShot "utf16-odd"
    (bytes [0xFF, 0xFE, 0x3C, 0x00, 0x61, 0x00, 0x2F, 0x00, 0x3E, 0x00, 0x41])

/-! ### Markup, attributes, references and normalization -/

def testMarkup : IO Unit := do
  expectSameAsOneShot "tags" "<r><a/><b></b></r>".toUTF8
  expectSameAsOneShot "spaced-attributes" "<r a = \"1\" b='2'   />".toUTF8
  expectSameAsOneShot "attr-space-before-close" "<r a=\"1\" ><s /></r>".toUTF8
  expectSameAsOneShot "duplicate-attribute" "<r x=\"1\" x=\"2\"/>".toUTF8
  expectSameAsOneShot "missing-separator" "<r a=\"1\"b=\"2\"/>".toUTF8
  expectSameAsOneShot "unquoted-attribute" "<r a=1/>".toUTF8
  expectSameAsOneShot "lt-in-attribute" "<r a=\"<\"/>".toUTF8
  expectSameAsOneShot "references" "<a>&amp;&lt;&gt;&apos;&quot;&#65;&#x41;</a>".toUTF8
  expectSameAsOneShot "reference-overflow" "<a>&#x110000;</a>".toUTF8
  expectSameAsOneShot "reference-zero" "<a>&#0;</a>".toUTF8
  expectSameAsOneShot "undefined-entity" "<a>&foo;</a>".toUTF8
  expectSameAsOneShot "comment" "<a><!--x--y--></a>".toUTF8
  expectSameAsOneShot "comment-trailing-hyphen" "<a><!--x---></a>".toUTF8
  expectSameAsOneShot "cdata" "<a><![CDATA[x]]]]><![CDATA[]]></a>".toUTF8
  expectSameAsOneShot "cdata-end-in-text" "<a>]]></a>".toUTF8
  expectSameAsOneShot "pi" "<a><?p ?x?><?q?></a>".toUTF8
  expectSameAsOneShot "crlf-text" "<a>x\r\ny\rz\n</a>".toUTF8
  expectSameAsOneShot "crlf-attribute" "<a v=\"x\r\ny\rz\tq\"/>".toUTF8
  expectSameAsOneShot "crlf-cdata" "<a><![CDATA[x\r\ny\rz]]></a>".toUTF8
  expectSameAsOneShot "crlf-comment" "<a><!--x\r\ny\rz--></a>".toUTF8
  expectSameAsOneShot "crlf-pi" "<a><?p x\r\ny\rz?></a>".toUTF8
  expectSameAsOneShot "doctype" "<!DOCTYPE a><a/>".toUTF8

/-! ### Multi-fault precedence pins -/

def testPrecedence : IO Unit := do
  let s1 := bytes [0x3C, 0x72, 0x3E, 0x3C, 0x2F, 0x73, 0x3E, 0xC3, 0x28]
  expectAllPartitionsError "S1-partitions" s1 {} .tagMismatch "tagMismatch"
  match LexPat.parseDocument s1 with
  | .error e =>
    if e.code != .tagMismatch || e.reason != "tagMismatch" then
      fail s!"S1-one-shot: got {e.code.name}/{e.reason}"
  | .ok _ => fail "S1-one-shot: expected an error"

  let cap8 : Limits := { maxInputBytes := 8 }
  expectAllPartitionsError "cap8-tag-mismatch" (s1 ++ "xx".toUTF8) cap8
    .tagMismatch "tagMismatch"
  match LexPat.parseDocument (s1 ++ "xx".toUTF8) cap8 with
  | .error e =>
    if e.code != .tagMismatch || e.reason != "tagMismatch" then
      fail s!"cap8-one-shot: got {e.code.name}/{e.reason}"
  | .ok _ => fail "cap8-one-shot: expected an error"

  let pending := "<a>".toUTF8 ++ bytes [0xE2, 0x82]
  expectAllPartitionsError "eof-pending" pending {} .partialChar "truncated"

/-! ### Ambiguous prefixes pause, and only `finish` diagnoses them -/

structure Ambiguous where
  label : String
  input : ByteArray
  code : ErrorCode
  reason : String

def ambiguousCases : List Ambiguous :=
  [ ⟨"EF", bytes [0xEF], .partialChar, "truncated"⟩,
    ⟨"EF BB", bytes [0xEF, 0xBB], .partialChar, "truncated"⟩,
    ⟨"FF", bytes [0xFF], .invalidToken, "outOfRange"⟩,
    ⟨"FE", bytes [0xFE], .invalidToken, "outOfRange"⟩,
    ⟨"00", bytes [0x00], .invalidToken, "textBeforeRoot"⟩,
    ⟨"<", "<".toUTF8, .invalidToken, "unexpectedEnd"⟩,
    ⟨"<?", "<?".toUTF8, .invalidToken, "expectedName"⟩,
    ⟨"<?x", "<?x".toUTF8, .unclosedToken, "unclosedPi"⟩,
    ⟨"<?xml", "<?xml".toUTF8, .unclosedToken, "unclosedXmlDecl"⟩,
    ⟨"<?xml ", "<?xml ".toUTF8, .unclosedToken, "unclosedXmlDecl"⟩,
    ⟨"<!", "<!".toUTF8, .syntax, "unknownMarkup"⟩,
    ⟨"<!-", "<!-".toUTF8, .syntax, "unknownMarkup"⟩,
    ⟨"content <![CD", "<a><![CD".toUTF8, .invalidToken, "unknownMarkup"⟩,
    ⟨"<a", "<a".toUTF8, .unclosedToken, "unclosedStartTag"⟩,
    ⟨"<a ", "<a ".toUTF8, .unclosedToken, "unclosedStartTag"⟩,
    ⟨"<a x", "<a x".toUTF8, .invalidToken, "missingEquals"⟩,
    ⟨"<a x=", "<a x=".toUTF8, .unclosedToken, "unclosedStartTag"⟩,
    ⟨"<a x=\"1", "<a x=\"1".toUTF8, .unclosedToken, "unclosedAttributeValue"⟩,
    ⟨"<a x=\"1\"", "<a x=\"1\"".toUTF8, .unclosedToken, "unclosedStartTag"⟩,
    ⟨"<a/", "<a/".toUTF8, .invalidToken, "badEmptyTag"⟩,
    ⟨"<a></", "<a></".toUTF8, .invalidToken, "expectedName"⟩,
    ⟨"<a></b", "<a></b".toUTF8, .unclosedToken, "unclosedEndTag"⟩,
    ⟨"<a></b ", "<a></b ".toUTF8, .unclosedToken, "unclosedEndTag"⟩,
    ⟨"<a>]", "<a>]".toUTF8, .noElements, "unclosedElement"⟩,
    ⟨"<a>]]", "<a>]]".toUTF8, .noElements, "unclosedElement"⟩,
    ⟨"<a><!--", "<a><!--".toUTF8, .unclosedToken, "unclosedComment"⟩,
    ⟨"<a><!--x-", "<a><!--x-".toUTF8, .unclosedToken, "unclosedComment"⟩,
    ⟨"<a><!--x--", "<a><!--x--".toUTF8, .invalidToken, "doubleHyphenInComment"⟩,
    ⟨"<a><![CDATA[", "<a><![CDATA[".toUTF8, .unclosedCdataSection, "unclosedCdata"⟩,
    ⟨"<a><![CDATA[x]", "<a><![CDATA[x]".toUTF8, .unclosedCdataSection, "unclosedCdata"⟩,
    ⟨"<a><![CDATA[x]]", "<a><![CDATA[x]]".toUTF8, .unclosedCdataSection, "unclosedCdata"⟩,
    ⟨"<a>&", "<a>&".toUTF8, .invalidToken, "unterminatedReference"⟩,
    ⟨"<a>&a", "<a>&a".toUTF8, .invalidToken, "unterminatedReference"⟩,
    ⟨"<a>&am", "<a>&am".toUTF8, .invalidToken, "unterminatedReference"⟩,
    ⟨"<a>&#", "<a>&#".toUTF8, .invalidToken, "malformedCharRef"⟩,
    ⟨"<a>&#x", "<a>&#x".toUTF8, .invalidToken, "malformedCharRef"⟩,
    ⟨"<a>&#x4", "<a>&#x4".toUTF8, .invalidToken, "unterminatedCharRef"⟩,
    ⟨"<a><?p", "<a><?p".toUTF8, .unclosedToken, "unclosedPi"⟩,
    ⟨"<a><?p ", "<a><?p ".toUTF8, .unclosedToken, "unclosedPi"⟩,
    ⟨"<a><?p?", "<a><?p?".toUTF8, .invalidToken, "piSyntax"⟩]

def testAmbiguousPrefixes : IO Unit := do
  for c in ambiguousCases do
    let (st, _) := feedAll {} [c.input]
    expectActive c.label st
    let (st2, _) := Stream.finish st
    expectError c.label (resultOf st2) c.code c.reason

/-! ### Early emission, terminal inertness and bounded carried state -/

def testEarlyEmission : IO Unit := do
  let (st, evs) := Stream.feed (Stream.new {}) "<root><a/>".toUTF8
  expectActive "early" st
  expectEvents "early-prefix" evs
    #[.start "root" #[], .start "a" #[], .end "a"]
  let (st2, evs2) := Stream.feed st "</root>".toUTF8
  expectEvents "early-tail" evs2 #[.end "root"]
  let (st3, evs3) := Stream.finish st2
  expectEvents "early-finish" evs3 #[]
  expectOk "early-result" (resultOf st3)
  let (st4, evs4) := Stream.feed st3 "x".toUTF8
  expectEvents "done-feed-inert" evs4 #[]
  let (st5, evs5) := Stream.finish st4
  expectEvents "done-finish-inert" evs5 #[]
  expectOk "done-result" (resultOf st5)

  let (cs, cevs) := Stream.feed (Stream.new {}) "<root><!--x".toUTF8
  expectEvents "comment-prefix" cevs #[.start "root" #[]]
  let (cs2, cevs2) := Stream.finish cs
  expectEvents "comment-finish" cevs2 #[]
  expectError "comment-only-on-finish" (resultOf cs2) .unclosedToken "unclosedComment"

  let (ds, devs) := Stream.feed (Stream.new {}) "<a><![CDATA[".toUTF8
  expectEvents "cdata-start-early" devs #[.start "a" #[], .cdataStart]
  let (ds2, devs2) := Stream.feed ds "x]]></a>".toUTF8
  expectEvents "cdata-text-at-close" devs2
    #[.text "x", .cdataEnd, .end "a"]
  let (ds3, devs3) := Stream.finish ds2
  expectEvents "cdata-finish" devs3 #[]
  expectOk "cdata-result" (resultOf ds3)

def testTerminalAndState : IO Unit := do
  let (st, evs) := Stream.feed (Stream.new {}) "<a>text<b/>rest".toUTF8
  expectEvents "bounded-prefix" evs
    #[.start "a" #[], .text "text", .start "b" #[], .end "b"]
  if st.buf.size != 4 then fail s!"bounded: buf size {st.buf.size}"
  if String.ofList st.buf.toList != "rest" then
    fail s!"bounded: buf is {repr (String.ofList st.buf.toList)}"
  if st.stack.size != 1 then fail "bounded: unexpected stack"
  if st.pending.size != 0 then fail "bounded: pending decoder bytes retained"
  if st.rawConsumed != "<a>text<b/>rest".toUTF8.size then
    fail "bounded: byte counter"
  match st.enc with
  | .decided _ => pure ()
  | _ => fail "bounded: encoding still undecided after the first byte"
  let (st2, _) := Stream.finish st
  expectError "bounded-finish" (resultOf st2) .noElements "unclosedElement"
  let (st3, evs3) := Stream.feed st2 "</a>".toUTF8
  expectEvents "failed-feed-inert" evs3 #[]
  let (st4, evs4) := Stream.finish st3
  expectEvents "failed-finish-inert" evs4 #[]
  expectError "failed-sticky" (resultOf st4) .noElements "unclosedElement"

/-! ### Budgets persist across chunks and reject at the first excess -/

def testLimits : IO Unit := do
  let input4 : Limits := { maxInputBytes := 4 }
  expectSameAsOneShot "input-exact" "<a/>".toUTF8 input4
  expectAllPartitionsError "input-over" "<a/> ".toUTF8 input4 .limitInput "limitInput"

  let token4 : Limits := { maxTokenChars := 4 }
  expectSameAsOneShot "token-exact" "<a>abcd</a>".toUTF8 token4
  expectAllPartitionsError "token-over" "<a>abcde</a>".toUTF8 token4
    .limitToken "limitToken"
  expectSameAsOneShot "name-token-exact" "<abcd/>".toUTF8 token4
  expectAllPartitionsError "name-token-over" "<abcde/>".toUTF8 token4
    .limitToken "limitToken"

  let depth1 : Limits := { maxDepth := 1 }
  expectSameAsOneShot "depth-exact" "<e><f/></e>".toUTF8 depth1
  expectAllPartitionsError "depth-over" "<e><f></f></e>".toUTF8 depth1
    .limitDepth "limitDepth"

  let ref1 : Limits := { maxEntityExpansion := 1 }
  expectSameAsOneShot "reference-exact" "<a>&amp;</a>".toUTF8 ref1
  expectAllPartitionsError "reference-over" "<a>&amp;&amp;</a>".toUTF8 ref1
    .limitEntityExpansion "limitEntityExpansion"

  let zeroToken : Limits := { maxTokenChars := 0 }
  expectAllPartitionsError "zero-token-empty-tag" "<a/>".toUTF8 zeroToken
    .limitToken "limitToken"
  expectAllPartitionsError "zero-token-text" "<a>x</a>".toUTF8 zeroToken
    .limitToken "limitToken"

  let zeroDepth : Limits := { maxDepth := 0 }
  expectSameAsOneShot "zero-depth-empty" "<a/>".toUTF8 zeroDepth
  expectAllPartitionsError "zero-depth-root" "<a></a>".toUTF8 zeroDepth
    .limitDepth "limitDepth"

  let zeroRef : Limits := { maxEntityExpansion := 0 }
  expectAllPartitionsError "zero-reference" "<a>&amp;</a>".toUTF8 zeroRef
    .limitEntityExpansion "limitEntityExpansion"

  let zeroInput : Limits := { maxInputBytes := 0 }
  expectSameAsOneShot "zero-input-empty" "".toUTF8 zeroInput
  expectAllPartitionsError "zero-input" "<a/>".toUTF8 zeroInput
    .limitInput "limitInput"

  -- The first error in a feed is sticky and later calls return no events.
  let (st, evs) := Stream.feed (Stream.new token4) "<a>abcde</a>".toUTF8
  expectEvents "limit-events" evs #[.start "a" #[]]
  expectError "limit-first" (resultOf st) .limitToken "limitToken"
  let (st2, evs2) := Stream.feed st "</a>".toUTF8
  expectEvents "limit-inert" evs2 #[]
  let (st3, evs3) := Stream.finish st2
  expectEvents "limit-finish" evs3 #[]
  expectError "limit-sticky" (resultOf st3) .limitToken "limitToken"

/-! ### Token budgets charge every first character and reference digit -/

def testTokenBoundaries : IO Unit := do
  -- A zero budget rejects the root element name's first character; no
  -- document shape can store a one-character token directly and pass.
  let zero : Limits := { maxTokenChars := 0 }
  for doc in ["<a/>", "<a></a>", "<a b=\"1\"/>", "<a><?p?></a>",
              "<a>&#65;</a>", "<a>&amp;</a>", "<a><!--x--></a>",
              "<a><![CDATA[x]]></a>", "<a>x</a>"] do
    expectAllPartitionsError s!"zero-token {doc}" doc.toUTF8 zero
      .limitToken "limitToken"

  -- One token exactly: every one-character token is accepted.
  let one : Limits := { maxTokenChars := 1 }
  expectAllPartitionsOk "one-element-name" "<a/>".toUTF8 one
    #[.start "a" #[], .end "a"]
  expectAllPartitionsOk "one-end-name" "<a></a>".toUTF8 one
    #[.start "a" #[], .end "a"]
  expectAllPartitionsOk "one-attribute" "<a b=\"1\"/>".toUTF8 one
    #[.start "a" #[("b", "1")], .end "a"]
  expectAllPartitionsOk "one-pi" "<a><?p?></a>".toUTF8 one
    #[.start "a" #[], .pi "p" "", .end "a"]
  expectAllPartitionsError "one-numeric-digits-over" "<a>&#12345;</a>".toUTF8 one
    .limitToken "limitToken"

  -- Two tokens exactly, then the first excess character of each token kind.
  let two : Limits := { maxTokenChars := 2 }
  expectAllPartitionsOk "two-element-name" "<ab/>".toUTF8 two
    #[.start "ab" #[], .end "ab"]
  expectAllPartitionsError "two-element-name-over" "<abc/>".toUTF8 two
    .limitToken "limitToken"
  expectAllPartitionsOk "two-end-name" "<ab></ab>".toUTF8 two
    #[.start "ab" #[], .end "ab"]
  expectAllPartitionsError "two-end-name-over" "<ab></abc>".toUTF8 two
    .limitToken "limitToken"
  expectAllPartitionsOk "two-attribute-name" "<a bc=\"1\"/>".toUTF8 two
    #[.start "a" #[("bc", "1")], .end "a"]
  expectAllPartitionsError "two-attribute-name-over" "<a bcd=\"1\"/>".toUTF8 two
    .limitToken "limitToken"
  expectAllPartitionsOk "two-attribute-value" "<a b=\"xy\"/>".toUTF8 two
    #[.start "a" #[("b", "xy")], .end "a"]
  expectAllPartitionsError "two-attribute-value-over" "<a b=\"xyz\"/>".toUTF8 two
    .limitToken "limitToken"
  expectAllPartitionsOk "two-pi-target" "<a><?pi?></a>".toUTF8 two
    #[.start "a" #[], .pi "pi" "", .end "a"]
  expectAllPartitionsError "two-pi-target-over" "<a><?pij?></a>".toUTF8 two
    .limitToken "limitToken"
  expectAllPartitionsOk "two-pi-data" "<a><?p xy?></a>".toUTF8 two
    #[.start "a" #[], .pi "p" "xy", .end "a"]
  expectAllPartitionsError "two-pi-data-over" "<a><?p xyz?></a>".toUTF8 two
    .limitToken "limitToken"
  expectAllPartitionsOk "two-comment" "<a><!--xy--></a>".toUTF8 two
    #[.start "a" #[], .comment "xy", .end "a"]
  expectAllPartitionsError "two-comment-over" "<a><!--xyz--></a>".toUTF8 two
    .limitToken "limitToken"
  expectAllPartitionsOk "two-cdata" "<a><![CDATA[xy]]></a>".toUTF8 two
    #[.start "a" #[], .cdataStart, .text "xy", .cdataEnd, .end "a"]
  expectAllPartitionsError "two-cdata-over" "<a><![CDATA[xyz]]></a>".toUTF8 two
    .limitToken "limitToken"
  expectAllPartitionsOk "two-text" "<a>xy</a>".toUTF8 two
    #[.start "a" #[], .text "xy", .end "a"]
  expectAllPartitionsError "two-text-over" "<a>xyz</a>".toUTF8 two
    .limitToken "limitToken"

  -- Numeric digits fill the token budget; named references keep charging
  -- their name characters as before.
  expectAllPartitionsOk "two-numeric-digits" "<a>&#65;</a>".toUTF8 two
    #[.start "a" #[], .text "A", .end "a"]
  expectAllPartitionsError "two-numeric-digits-over" "<a>&#123;</a>".toUTF8 two
    .limitToken "limitToken"
  expectAllPartitionsOk "two-hex-digits" "<a>&#x41;</a>".toUTF8 two
    #[.start "a" #[], .text "A", .end "a"]
  expectAllPartitionsError "two-hex-digits-over" "<a>&#x412;</a>".toUTF8 two
    .limitToken "limitToken"
  let three : Limits := { maxTokenChars := 3 }
  expectAllPartitionsOk "three-named-reference" "<a>&amp;</a>".toUTF8 three
    #[.start "a" #[], .text "&", .end "a"]
  expectAllPartitionsError "two-named-reference-over" "<a>&amp;</a>".toUTF8 two
    .limitToken "limitToken"

  -- Leading zeros are digits for the budget even though they do not change the
  -- referenced value.
  let digits : Limits := { maxTokenChars := 5 }
  expectAllPartitionsOk "leading-zero-digits" "<a>&#00065;</a>".toUTF8 digits
    #[.start "a" #[], .text "A", .end "a"]
  expectAllPartitionsError "leading-zero-digits-over" "<a>&#000065;</a>".toUTF8 digits
    .limitToken "limitToken"

/-! ### A certain declaration fault precedes the raw-input limit -/

def testDeclFaultPrecedence : IO Unit := do
  -- The closed `version="2.0"` value at offset 18 is already invalid when the
  -- 20th byte would exceed a 19-byte input budget.
  let decl := "<?xml version=\"2.0\"?><a/>".toUTF8
  let cap19 : Limits := { maxInputBytes := 19 }
  expectAllPartitionsError "decl-fault-cap19" decl cap19 .xmlDecl "xmlDeclVersionValue"
  match parseDocument decl cap19 with
  | .error e =>
    if e.code != .xmlDecl || e.reason != "xmlDeclVersionValue" then
      fail s!"decl-cap19-one-shot: got {e.code.name}/{e.reason}"
  | .ok _ => fail "decl-cap19-one-shot: expected an error"

  -- Without the cap the same fault is reported.
  expectAllPartitionsError "decl-fault" decl {} .xmlDecl "xmlDeclVersionValue"

  -- A valid declaration has no earlier fault, so the input limit still wins.
  expectAllPartitionsError "decl-valid-cap19" "<?xml version=\"1.0\"?><a/>".toUTF8
    cap19 .limitInput "limitInput"

  -- An incomplete value is not a certain fault: feeding stays active, the
  -- limit is not preempted, and only finish reports the unfinished token.
  let openValue := "<?xml version=\"2.0".toUTF8
  let (openState, _) := Stream.feed (Stream.new {}) openValue
  expectActive "decl-open-value-active" openState
  expectAllPartitionsError "decl-open-value-cap17" openValue
    { maxInputBytes := 17 } .limitInput "limitInput"
  expectAllPartitionsError "decl-open-value-eof" openValue {}
    .unclosedToken "unclosedXmlDecl"
  let closedValue := "<?xml version=\"1.0\"".toUTF8
  let (closedState, _) := Stream.feed (Stream.new {}) closedValue
  expectActive "decl-closed-value-active" closedState
  expectAllPartitionsError "decl-closed-value-eof" closedValue {}
    .unclosedToken "unclosedXmlDecl"

/-! ### A non-ASCII byte in an ASCII-constrained declaration field -/

def testDeclNonAsciiField : IO Unit := do
  -- `<?xml version="é"?><a/>`: a version value can only be the ASCII text
  -- `1.0`, so its first non-ASCII byte (raw index 15) is a certain declaration
  -- fault under every supported encoding, before either later input cap can be
  -- crossed and whatever the eventual encoding label would have been.
  let doc := "<?xml version=\"é\"?><a/>".toUTF8
  expectAllPartitionsError "decl-nonascii" doc {} .xmlDecl "xmlDeclVersionValue"
  expectAllPartitionsError "decl-nonascii-cap16" doc { maxInputBytes := 16 }
    .xmlDecl "xmlDeclVersionValue"
  expectAllPartitionsError "decl-nonascii-cap18" doc { maxInputBytes := 18 }
    .xmlDecl "xmlDeclVersionValue"
  for limits in [{}, { maxInputBytes := 16 }, { maxInputBytes := 18 }] do
    match parseDocument doc limits with
    | .error e =>
      if e.code != .xmlDecl || e.reason != "xmlDeclVersionValue" then
        fail s!"decl-nonascii-one-shot: got {e.code.name}/{e.reason}"
    | .ok _ => fail "decl-nonascii-one-shot: expected an error"

  -- The same certainty applies to each other ASCII-constrained field, and the
  -- reason names the field the byte disqualified.
  expectAllPartitionsError "decl-nonascii-version-name"
    "<?xml verséion=\"1.0\"?><a/>".toUTF8 {} .xmlDecl "xmlDeclVersion"
  expectAllPartitionsError "decl-nonascii-encoding-name"
    "<?xml version=\"1.0\" encoding=\"UTF-8é\"?><a/>".toUTF8 {}
    .xmlDecl "xmlDeclEncodingName"
  expectAllPartitionsError "decl-nonascii-standalone-value"
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yés\"?><a/>".toUTF8 {}
    .xmlDecl "xmlDeclStandalone"
  expectAllPartitionsError "decl-nonascii-third-name"
    "<?xml version=\"1.0\" encoding=\"UTF-8\" standaléne=\"yes\"?><a/>".toUTF8 {}
    .xmlDecl "xmlDeclAttribute"

  -- Before the first non-ASCII byte the stream stays active.
  let head15 := "<?xml version=\"".toUTF8
  let (head15State, _) := Stream.feed (Stream.new { maxInputBytes := 16 }) head15
  expectActive "decl-nonascii-head15-active" head15State

  -- A two-byte partition places the deciding byte in the feed that follows the
  -- opening quote, so the declaration fault is reported before the cap.
  let twoByte := (List.range ((doc.size + 1) / 2)).map fun i =>
    doc.extract (2 * i) (min doc.size (2 * i + 2))
  let (twoByteState, _) := feedAll { maxInputBytes := 16 } twoByte
  expectError "decl-nonascii-two-byte" (resultOf twoByteState)
    .xmlDecl "xmlDeclVersionValue"

  -- An incomplete multibyte scalar outside such a field still waits: the
  -- attribute value holds two bytes of a three-byte scalar, so only finish can
  -- resolve it.
  let outside := "<?xml version=\"1.0\"?><a x=\"".toUTF8 ++ bytes [0xE2, 0x82]
  let (outsideState, _) := Stream.feed (Stream.new {}) outside
  expectActive "decl-nonascii-outside-active" outsideState
  let (outsideDone, _) := Stream.finish outsideState
  expectError "decl-nonascii-outside-finish" (resultOf outsideDone)
    .partialChar "truncated"

def runAll : IO Unit := do
  testEncodings
  testUtf8Scalars
  testUtf16Scalars
  testMarkup
  testPrecedence
  testAmbiguousPrefixes
  testEarlyEmission
  testTerminalAndState
  testLimits
  testTokenBoundaries
  testDeclFaultPrecedence
  testDeclNonAsciiField
  IO.println "StreamingCases: all direct stream assertions passed"

end LexPat.StreamingCases

/-- Entry point for `lean --run`. -/
def main : IO Unit := LexPat.StreamingCases.runAll
