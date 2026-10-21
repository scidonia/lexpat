/-
The resumable streaming core.

A `Stream` owns exactly the state that cannot be recovered from the caller's
later chunks: the budgets, the cumulative byte and reference counts, the
encoding decision or the bounded prefix still waiting for it, at most three
pending decoder bytes, the grammar mode, the unfinished lexical value and the
open-element stack. Events are returned by `feed` and `finish`; the state never
accumulates output or earlier input chunks.

Encoding is selected once from byte evidence and, for an ASCII-compatible
document, from the bounded declaration prefix (`min(maxInputBytes,
maxTokenChars)` plus the fixed `<?xml` discriminator). Reaching that storage
ceiling is not itself an error: the prefix is handed to the grammar, which
reports the declaration token budget exactly as the one-shot parser did.

A permanent error is returned only when the bytes already consumed prove it for
every continuation. Incomplete signatures, multibyte scalars, references,
tags and markup delimiters pause instead of guessing. A fault completed earlier
in the input wins over a later decoding or input-budget fault: a buffered
declaration prefix is validated as it arrives, so a completed declaration token
that the grammar already rejects is reported before a later byte can exhaust the
input budget. A non-ASCII byte inside an ASCII-constrained declaration
pseudo-attribute name or value is such a completed fault, decided even while the
encoding choice is still open. At `finish`, a pending decoder fault is resolved
before EOF-only grammar faults. Events
already returned are a provisional prefix: on success they are the document's
events, and on rejection they remain a prefix of the input that was accepted.

The parser emits only determined events: a text run at the next `<` or at a
successful EOF, a start or end tag at `>` or `/>`, a declaration, comment or
processing instruction at its closing delimiter, and `cdataStart` at the CDATA
opener with the CDATA text and `cdataEnd` at `]]>`.
-/
import LexPat.Types
import LexPat.Lexer
import LexPat.Encoding
import LexPat.Grammar

namespace LexPat

/-- The lifecycle of a stream. -/
inductive StreamStatus where
  /-- More bytes may still change or complete the document. -/
  | active
  /-- A permanent error: `feed` and `finish` are inert. -/
  | failed (error : ParseError)
  /-- A complete document: `feed` and `finish` are inert. -/
  | done
deriving Repr

/-- Encoding selection. `probing` holds the undecided opening prefix,
`declaration` holds a recognized `<?xml ` prefix until `?>` or the scan
ceiling, and `decided` is the encoding actually used. -/
inductive EncPhase where
  | probing (bytes : ByteArray)
  | declaration (bytes : ByteArray)
  | decided (encoding : Encoding)

/-- Where a successful reference's character belongs. -/
inductive RefCtx where
  | text
  | attribute (quote : Char)
deriving Repr

/-- The sub-state of the XML declaration grammar. -/
inductive DeclMode where
  | needWs1
  | versionNameSkipWs
  | versionName
  | versionAfterName
  | versionAfterEq
  | versionValue (quote : Char)
  | versionDone (sawSep : Bool)
  | versionQ (sawSep : Bool)
  | secondName
  | secondAfterName
  | secondAfterEq
  | secondValue (quote : Char)
  | standaloneDone (which : Nat)
  | standaloneQ (which : Nat)
  | encodingDone (sawSep : Bool)
  | encodingQ (sawSep : Bool)
  | thirdName
  | thirdAfterName
  | thirdAfterEq
  | thirdValue (quote : Char)
  | thirdDone
  | thirdQ
deriving Repr

/-- Which pseudo-attribute name just completed. -/
inductive DeclNameStage where
  | version
  | second
  | third
deriving Repr

/-- The grammar mode. Modes carry only fixed lookahead; unfinished values live
in `Stream.buf` or `Stream.refBuf`, each bounded by `maxTokenChars`. -/
inductive Mode where
  | prologStart
  | epilogStart
  | contentStart
  | text
  | textBracket1
  | textBracket2
  | markup
  | bang
  | bangDash
  | bangCdata (matched : Nat)
  | bangDoctype (matched : Nat)
  | endName
  | endNameRest
  | endClose (name : String)
  | piTarget
  | piTargetRest
  | piAfterTarget (target : String)
  | piSkipWs (target : String)
  | piQInit (target : String)
  | piData (target : String)
  | piQ (target : String)
  | comment
  | commentDash1
  | commentDash2
  | cdata
  | cdataBracket1
  | cdataBracket2
  | startNameRest
  | startAfterName
  | startSlash
  | attrNameRest
  | attrAfterName
  | attrAfterEq
  | attrValue (quote : Char)
  | refAfterAmp
  | refNameRest
  | refNumOptX
  | refNumDigits (hex : Bool) (value : Nat) (digits : Nat) (overflow : Bool)
  | decl (stage : DeclMode)
deriving Repr

/-- The complete state of one document parse. -/
structure Stream where
  /-- Per-document budgets, fixed at construction. -/
  limits : Limits
  status : StreamStatus := .active
  phase : Phase := .prolog
  mode : Mode := .prologStart
  enc : EncPhase := .probing ByteArray.empty
  /-- While a recognized declaration prefix is buffered, `mode`, `buf` and the
  `decl*` fields hold that prefix's declaration grammar state, so a completed
  token the grammar already rejects is reported before the raw-input budget can
  stop the scan. Replaying the prefix through the chosen decoder resets them.
  A non-ASCII byte outside the ASCII-constrained pseudo-attribute names and
  values clears the flag, because the buffered bytes no longer determine the
  declaration; inside such a field it is a certain fault instead. The flag is
  also `false` once a completed declaration makes the shadow unnecessary,
  because all supported encodings agree on ASCII bytes. -/
  declShadow : Bool := true
  /-- Unconsumed bytes of the next decoded scalar (at most three UTF-8 bytes or
  an odd UTF-16 byte or high-surrogate unit). -/
  pending : ByteArray := ByteArray.empty
  pendingOffset : Nat := 0
  /-- The unfinished lexical value: text, name, attribute value, comment,
  CDATA, PI data or declaration value. -/
  buf : Array Char := #[]
  stack : Array String := #[]
  entityUsed : Nat := 0
  elemName : String := ""
  attrs : Array (String × String) := #[]
  attrName : String := ""
  startNameOffset : Nat := 0
  markupOffset : Nat := 0
  markupIndex : Nat := 0
  spaced : Bool := false
  /-- A literal CR whose normalized character waits for an optional LF. -/
  pendingCR : Bool := false
  refCtx : RefCtx := .text
  refStartOffset : Nat := 0
  refBuf : Array Char := #[]
  declEncoding : Option String := none
  declStandalone : Option Bool := none
  /-- `some true` for `encoding`, `some false` for `standalone`. -/
  declSecond : Option Bool := none
  /-- Decoded characters consumed so far; used for the declaration-position
  check, not as a byte offset. -/
  charIndex : Nat := 0
  /-- Raw bytes charged against the input budget, including signature bytes
  and an undecided prefix. -/
  rawConsumed : Nat := 0

namespace Stream

/-- A fresh stream under the given budgets. -/
def new (limits : Limits := {}) : Stream :=
  { limits := limits }

/-- The final result, once `finish` has done its work. `none` means the stream
is still active and the document may still change. -/
def result (s : Stream) : Option (Except ParseError Unit) :=
  match s.status with
  | .active => none
  | .failed e => some (.error e)
  | .done => some (.ok ())

private def isActive (s : Stream) : Bool :=
  match s.status with
  | .active => true
  | _ => false

private def failedWith (s : Stream) (e : ParseError) : Stream :=
  { s with status := .failed e }

private def failCode (s : Stream) (code : ErrorCode) (reason : String) (offset : Nat) :
    Stream :=
  failedWith s ⟨code, reason, offset⟩

private def pushEvents (acc : Array Event) (evs : Array Event) : Array Event :=
  Id.run do
    let mut out := acc
    for e in evs do
      out := out.push e
    return out

private def bufferString (buf : Array Char) : String :=
  String.ofList buf.toList

private def appendChar (s : Stream) (ch : Char) (offset : Nat) :
    Stream × Option ParseError :=
  if s.buf.size ≥ s.limits.maxTokenChars then
    (s, some ⟨.limitToken, "limitToken", offset⟩)
  else
    ({ s with buf := s.buf.push ch }, none)

private def appendRefChar (s : Stream) (ch : Char) (offset : Nat) :
    Stream × Option ParseError :=
  if s.refBuf.size ≥ s.limits.maxTokenChars then
    (s, some ⟨.limitToken, "limitToken", offset⟩)
  else
    ({ s with refBuf := s.refBuf.push ch }, none)

/-- Charge one numeric-character-reference digit against the token budget.
Digits are parsed into a number rather than stored in `refBuf`, so their run
length is counted directly: a reference with more digits than `maxTokenChars`
exceeds the same per-token budget as a name or value of that length. -/
private def chargeRefDigit (s : Stream) (digits : Nat) (offset : Nat) :
    Option ParseError :=
  if digits ≥ s.limits.maxTokenChars then
    some ⟨.limitToken, "limitToken", offset⟩
  else none

private def flushText (s : Stream) (evs : Array Event) : Stream × Array Event :=
  if s.buf.isEmpty then
    (s, evs)
  else
    let text := bufferString s.buf
    ({ s with buf := #[] }, evs.push (.text text))

/-- The mode that resumes the current phase after a comment, PI or similar
construct. -/
private def resumeMode (phase : Phase) : Mode :=
  match phase with
  | .prolog => .prologStart
  | .content => .contentStart
  | .epilog => .epilogStart

private def unknownMarkupError (s : Stream) : ParseError :=
  match s.phase with
  | .prolog => ⟨.syntax, "unknownMarkup", s.markupOffset⟩
  | .content => ⟨.invalidToken, "unknownMarkup", s.markupOffset⟩
  | .epilog => ⟨.junkAfterDocElement, "junkAfterRoot", s.markupOffset⟩

private def detectedEncoding (s : Stream) : Encoding :=
  match s.enc with
  | .decided enc => enc
  | _ => .utf8

/-! ## Start and end tags -/

private def completeStartTag (s : Stream) (empty : Bool) : Stream × Array Event :=
  let ordered := s.attrs.qsort (fun a b => a.1 < b.1)
  let duplicate := Id.run do
    let mut found := false
    let mut k := 1
    while k < ordered.size do
      match ordered[k]?, ordered[k - 1]? with
      | some a, some b => if a.1 == b.1 then found := true
      | _, _ => pure ()
      k := k + 1
    return found
  if duplicate then
    (failCode s .duplicateAttribute "duplicateAttribute" s.startNameOffset, #[])
  else if !empty && s.stack.size ≥ s.limits.maxDepth then
    (failCode s .limitDepth "limitDepth" s.markupOffset, #[])
  else
    let name := s.elemName
    let attrs := s.attrs
    let started : Array Event := #[.start name attrs]
    if empty then
      let evs := started.push (.end name)
      let phase := if s.phase == .prolog then Phase.epilog else s.phase
      ({ s with phase := phase, mode := resumeMode phase, stack := s.stack,
                elemName := "", attrs := #[], buf := #[], spaced := false }, evs)
    else
      ({ s with phase := .content, mode := .contentStart,
                stack := s.stack.push name,
                elemName := "", attrs := #[], buf := #[], spaced := false }, started)

private def finishEndTag (s : Stream) (name : String) : Stream × Array Event :=
  match s.stack.back? with
  | some top =>
    if top == name then
      let stack := s.stack.pop
      let evs : Array Event := #[.end name]
      if stack.isEmpty then
        ({ s with stack := stack, phase := .epilog, mode := .epilogStart }, evs)
      else
        ({ s with stack := stack, mode := .contentStart }, evs)
    else
      (failCode s .tagMismatch "tagMismatch" s.markupOffset, #[])
  | none => (failCode s .invalidToken "strayEndTag" s.markupOffset, #[])

private def startTagFirst (s : Stream) (c : DecodedChar) : Stream × Array Event :=
  if isNameStartChar c.value.n then
    let fresh := { s with buf := #[], startNameOffset := c.byteOffset,
                          elemName := "", attrs := #[], spaced := false }
    match appendChar fresh c.value.toChar c.byteOffset with
    | (s1, some e) => (failedWith s1 e, #[])
    | (s1, none) => ({ s1 with mode := .startNameRest }, #[])
  else (failCode s .invalidToken "invalidNameStart" c.byteOffset, #[])

/-! ## XML declaration -/

private def emitXmlDecl (s : Stream) : Stream × Array Event :=
  ({ s with mode := .prologStart },
    #[.xmlDecl "1.0" s.declEncoding s.declStandalone])

private def startDeclName (s : Stream) (rest : DeclMode) (c : DecodedChar) :
    Stream × Option ParseError :=
  if isAsciiLetter c.value.n then
    match appendChar { s with buf := #[] } c.value.toChar c.byteOffset with
    | (s1, some err) => (s1, some err)
    | (s1, none) => ({ s1 with mode := .decl rest }, none)
  else
    (s, some ⟨.xmlDecl, "xmlDeclName", c.byteOffset⟩)

private def declNameDone (s : Stream) (stage : DeclNameStage) (offset : Nat) :
    Stream × Option ParseError :=
  let name := bufferString s.buf
  let s1 := { s with buf := #[] }
  match stage with
  | .version =>
    if name != "version" then
      (s1, some ⟨.xmlDecl, "xmlDeclVersion", offset⟩)
    else
      ({ s1 with mode := .decl .versionAfterName }, none)
  | .second =>
    if name == "standalone" then
      ({ s1 with mode := .decl .secondAfterName, declSecond := some false }, none)
    else if name == "encoding" then
      ({ s1 with mode := .decl .secondAfterName, declSecond := some true }, none)
    else
      (s1, some ⟨.xmlDecl, "xmlDeclAttribute", offset⟩)
  | .third =>
    if name != "standalone" then
      (s1, some ⟨.xmlDecl, "xmlDeclAttribute", offset⟩)
    else
      ({ s1 with mode := .decl .thirdAfterName }, none)

/-- The declaration fault a non-ASCII byte is certain to cause when it arrives
inside an ASCII-constrained pseudo-attribute name or value. Such a field can
only hold ASCII, so no later byte and no encoding label can make the
declaration valid; the field's own grammar decides the code and reason. A byte
after an already complete name is a separator attempt, so it reports the
separator fault the grammar would report. `none` means the byte is outside such
a field and the shadow cannot decide it. -/
private def nonAsciiDeclFault (s : Stream) : Option (ErrorCode × String) :=
  match s.mode with
  | .decl (.versionName) =>
    if bufferString s.buf == "version" then some (.xmlDecl, "xmlDeclEquals")
    else some (.xmlDecl, "xmlDeclVersion")
  | .decl (.secondName) =>
    let name := bufferString s.buf
    if name == "encoding" || name == "standalone" then
      some (.xmlDecl, "xmlDeclEquals")
    else some (.xmlDecl, "xmlDeclAttribute")
  | .decl (.thirdName) =>
    if bufferString s.buf == "standalone" then some (.xmlDecl, "xmlDeclEquals")
    else some (.xmlDecl, "xmlDeclAttribute")
  | .decl (.versionValue _) => some (.xmlDecl, "xmlDeclVersionValue")
  | .decl (.secondValue _) =>
    match s.declSecond with
    | some true => some (.xmlDecl, "xmlDeclEncodingName")
    | some false => some (.xmlDecl, "xmlDeclStandalone")
    | none => some (.xmlDecl, "xmlDeclAttribute")
  | .decl (.thirdValue _) => some (.xmlDecl, "xmlDeclStandalone")
  | _ => none

/-- The CDATA opener after `<![`: each element is the next expected byte. -/
private def cdataPat : Nat → Option Nat
  | 0 => some 0x5B
  | 1 => some 0x43
  | 2 => some 0x44
  | 3 => some 0x41
  | 4 => some 0x54
  | 5 => some 0x41
  | 6 => some 0x5B
  | _ => none

/-- The DOCTYPE keyword after `<!`. -/
private def doctypePat : Nat → Option Nat
  | 0 => some 0x44
  | 1 => some 0x4F
  | 2 => some 0x43
  | 3 => some 0x54
  | 4 => some 0x59
  | 5 => some 0x50
  | 6 => some 0x45
  | _ => none

/-- Resolve a complete reference and append its character in the context that
started it. The reference budget is charged first, matching the one-shot
scanner's order. -/
private def finishReference (s : Stream) (sc : Scalar) : Stream × Array Event :=
  if s.entityUsed + 1 > s.limits.maxEntityExpansion then
    (failCode s .limitEntityExpansion "limitEntityExpansion" s.refStartOffset, #[])
  else
    let s1 := { s with entityUsed := s.entityUsed + 1 }
    match s.refCtx with
    | .text =>
      match appendChar s1 sc.toChar s.refStartOffset with
      | (s2, some e) => (failedWith s2 e, #[])
      | (s2, none) => ({ s2 with mode := .text }, #[])
    | .attribute quote =>
      match appendChar s1 sc.toChar s.refStartOffset with
      | (s2, some e) => (failedWith s2 e, #[])
      | (s2, none) => ({ s2 with mode := .attrValue quote }, #[])

/-- The XML declaration sub-state. `cont` re-processes the current character in
a mode that the completed token introduces. -/
private def declStep (cont : Stream → Stream × Array Event) (s : Stream)
    (c : DecodedChar) (stage : DeclMode) : Stream × Array Event :=
  match stage with
  | .needWs1 =>
    if isXmlWhitespace c.value.n then ({ s with mode := .decl .versionNameSkipWs }, #[])
    else (failCode s .xmlDecl "xmlDeclWhitespace" c.byteOffset, #[])
  | .versionNameSkipWs =>
    if isXmlWhitespace c.value.n then (s, #[])
    else
      match startDeclName s .versionName c with
      | (s1, some e) => (failedWith s1 e, #[])
      | (s1, none) => (s1, #[])
  | .versionName =>
    if isAsciiLetter c.value.n then
      match appendChar s c.value.toChar c.byteOffset with
      | (s1, some e) => (failedWith s1 e, #[])
      | (s1, none) => (s1, #[])
    else
      match declNameDone s .version c.byteOffset with
      | (s1, some e) => (failedWith s1 e, #[])
      | (s1, none) => cont s1
  | .versionAfterName =>
    if isXmlWhitespace c.value.n then (s, #[])
    else if c.value.n == 0x3D then ({ s with mode := .decl .versionAfterEq }, #[])
    else (failCode s .xmlDecl "xmlDeclEquals" c.byteOffset, #[])
  | .versionAfterEq =>
    if isXmlWhitespace c.value.n then (s, #[])
    else if c.value.n == 0x22 || c.value.n == 0x27 then
      ({ s with buf := #[], mode := .decl (.versionValue (Char.ofNat c.value.n)) }, #[])
    else (failCode s .xmlDecl "xmlDeclQuote" c.byteOffset, #[])
  | .versionValue quote =>
    if c.value.n == quote.toNat then
      let value := bufferString s.buf
      let s1 := { s with buf := #[] }
      if value != "1.0" then
        (failCode s1 .xmlDecl "xmlDeclVersionValue" c.byteOffset, #[])
      else ({ s1 with mode := .decl (.versionDone false) }, #[])
    else if isXmlChar c.value.n then
      match appendChar s c.value.toChar c.byteOffset with
      | (s1, some e) => (failedWith s1 e, #[])
      | (s1, none) => (s1, #[])
    else (failCode s .xmlDecl "xmlDeclValue" c.byteOffset, #[])
  | .versionDone sawSep =>
    if isXmlWhitespace c.value.n then ({ s with mode := .decl (.versionDone true) }, #[])
    else if c.value.n == 0x3F then ({ s with mode := .decl (.versionQ sawSep) }, #[])
    else if !sawSep then (failCode s .xmlDecl "xmlDeclSeparator" c.byteOffset, #[])
    else
      match startDeclName s .secondName c with
      | (s1, some e) => (failedWith s1 e, #[])
      | (s1, none) => (s1, #[])
  | .versionQ sawSep =>
    if c.value.n == 0x3E then emitXmlDecl s
    else if !sawSep then (failCode s .xmlDecl "xmlDeclSeparator" c.byteOffset, #[])
    else (failCode s .xmlDecl "xmlDeclName" c.byteOffset, #[])
  | .secondName =>
    if isAsciiLetter c.value.n then
      match appendChar s c.value.toChar c.byteOffset with
      | (s1, some e) => (failedWith s1 e, #[])
      | (s1, none) => (s1, #[])
    else
      match declNameDone s .second c.byteOffset with
      | (s1, some e) => (failedWith s1 e, #[])
      | (s1, none) => cont s1
  | .secondAfterName =>
    if isXmlWhitespace c.value.n then (s, #[])
    else if c.value.n == 0x3D then ({ s with mode := .decl .secondAfterEq }, #[])
    else (failCode s .xmlDecl "xmlDeclEquals" c.byteOffset, #[])
  | .secondAfterEq =>
    if isXmlWhitespace c.value.n then (s, #[])
    else if c.value.n == 0x22 || c.value.n == 0x27 then
      ({ s with buf := #[], mode := .decl (.secondValue (Char.ofNat c.value.n)) }, #[])
    else (failCode s .xmlDecl "xmlDeclQuote" c.byteOffset, #[])
  | .secondValue quote =>
    if c.value.n == quote.toNat then
      let value := bufferString s.buf
      let s1 := { s with buf := #[] }
      match s.declSecond with
      | some false =>
        if value == "yes" then
          ({ s1 with declStandalone := some true,
                     mode := .decl (.standaloneDone 2) }, #[])
        else if value == "no" then
          ({ s1 with declStandalone := some false,
                     mode := .decl (.standaloneDone 2) }, #[])
        else (failCode s1 .xmlDecl "xmlDeclStandalone" c.byteOffset, #[])
      | some true =>
        if !validEncName value then
          (failCode s1 .xmlDecl "xmlDeclEncodingName" c.byteOffset, #[])
        else
          match checkEncodingLabel (detectedEncoding s1) value c.byteOffset with
          | .error e => (failedWith s1 e, #[])
          | .ok () =>
            ({ s1 with declEncoding := some value,
                       mode := .decl (.encodingDone false) }, #[])
      | none => (failCode s1 .xmlDecl "xmlDeclAttribute" c.byteOffset, #[])
    else if isXmlChar c.value.n then
      match appendChar s c.value.toChar c.byteOffset with
      | (s1, some e) => (failedWith s1 e, #[])
      | (s1, none) => (s1, #[])
    else (failCode s .xmlDecl "xmlDeclValue" c.byteOffset, #[])
  | .standaloneDone which =>
    if isXmlWhitespace c.value.n then (s, #[])
    else if c.value.n == 0x3F then
      ({ s with mode := .decl (.standaloneQ which) }, #[])
    else (failCode s .xmlDecl "xmlDeclEnd" c.byteOffset, #[])
  | .standaloneQ _ =>
    if c.value.n == 0x3E then emitXmlDecl s
    else (failCode s .xmlDecl "xmlDeclEnd" c.byteOffset, #[])
  | .encodingDone sawSep =>
    if isXmlWhitespace c.value.n then
      ({ s with mode := .decl (.encodingDone true) }, #[])
    else if c.value.n == 0x3F then
      ({ s with mode := .decl (.encodingQ sawSep) }, #[])
    else if !sawSep then
      (failCode s .xmlDecl "xmlDeclSeparator" c.byteOffset, #[])
    else
      match startDeclName s .thirdName c with
      | (s1, some e) => (failedWith s1 e, #[])
      | (s1, none) => (s1, #[])
  | .encodingQ sawSep =>
    if c.value.n == 0x3E then emitXmlDecl s
    else if !sawSep then (failCode s .xmlDecl "xmlDeclSeparator" c.byteOffset, #[])
    else (failCode s .xmlDecl "xmlDeclName" c.byteOffset, #[])
  | .thirdName =>
    if isAsciiLetter c.value.n then
      match appendChar s c.value.toChar c.byteOffset with
      | (s1, some e) => (failedWith s1 e, #[])
      | (s1, none) => (s1, #[])
    else
      match declNameDone s .third c.byteOffset with
      | (s1, some e) => (failedWith s1 e, #[])
      | (s1, none) => cont s1
  | .thirdAfterName =>
    if isXmlWhitespace c.value.n then (s, #[])
    else if c.value.n == 0x3D then ({ s with mode := .decl .thirdAfterEq }, #[])
    else (failCode s .xmlDecl "xmlDeclEquals" c.byteOffset, #[])
  | .thirdAfterEq =>
    if isXmlWhitespace c.value.n then (s, #[])
    else if c.value.n == 0x22 || c.value.n == 0x27 then
      ({ s with buf := #[], mode := .decl (.thirdValue (Char.ofNat c.value.n)) }, #[])
    else (failCode s .xmlDecl "xmlDeclQuote" c.byteOffset, #[])
  | .thirdValue quote =>
    if c.value.n == quote.toNat then
      let value := bufferString s.buf
      let s1 := { s with buf := #[] }
      if value == "yes" then
        ({ s1 with declStandalone := some true, mode := .decl .thirdDone }, #[])
      else if value == "no" then
        ({ s1 with declStandalone := some false, mode := .decl .thirdDone }, #[])
      else (failCode s1 .xmlDecl "xmlDeclStandalone" c.byteOffset, #[])
    else if isXmlChar c.value.n then
      match appendChar s c.value.toChar c.byteOffset with
      | (s1, some e) => (failedWith s1 e, #[])
      | (s1, none) => (s1, #[])
    else (failCode s .xmlDecl "xmlDeclValue" c.byteOffset, #[])
  | .thirdDone =>
    if isXmlWhitespace c.value.n then (s, #[])
    else if c.value.n == 0x3F then ({ s with mode := .decl .thirdQ }, #[])
    else (failCode s .xmlDecl "xmlDeclEnd" c.byteOffset, #[])
  | .thirdQ =>
    if c.value.n == 0x3E then emitXmlDecl s
    else (failCode s .xmlDecl "xmlDeclEnd" c.byteOffset, #[])

/-! ## Character step -/

/-- One decoded character through the grammar. The fuel covers re-processing a
delimiter in the mode it introduces; no character is processed more than a few
times. -/
private def runStep : Nat → Stream → DecodedChar → Stream × Array Event
  | 0, s, _ => (s, #[])
  | fuel + 1, s, c =>
    if !isActive s then (s, #[])
    else if s.pendingCR then
      let mapped : Char := match s.mode with
        | .attrValue _ => ' '
        | _ => '\n'
      match appendChar s mapped c.byteOffset with
      | (s1, some e) => (failedWith s1 e, #[])
      | (s1, none) =>
        let s2 := { s1 with pendingCR := false }
        if c.value.n == 0x0A then (s2, #[])
        else runStep fuel s2 c
    else
      let reprocess (s1 : Stream) : Stream × Array Event := runStep fuel s1 c
      match s.mode with
      | .prologStart =>
        if isXmlWhitespace c.value.n then (s, #[])
        else if c.value.n == 0x3C then
          ({ s with mode := .markup, markupOffset := c.byteOffset,
                    markupIndex := s.charIndex - 1 }, #[])
        else (failCode s .invalidToken "textBeforeRoot" c.byteOffset, #[])
      | .epilogStart =>
        if isXmlWhitespace c.value.n then (s, #[])
        else if c.value.n == 0x3C then
          ({ s with mode := .markup, markupOffset := c.byteOffset,
                    markupIndex := s.charIndex - 1 }, #[])
        else (failCode s .junkAfterDocElement "textAfterRoot" c.byteOffset, #[])
      | .contentStart =>
        if c.value.n == 0x3C then
          ({ s with mode := .markup, markupOffset := c.byteOffset,
                    markupIndex := s.charIndex - 1 }, #[])
        else reprocess ({ s with mode := .text })
      | .text =>
        if c.value.n == 0x3C then
          let (s1, evs) := flushText s #[]
          ({ s1 with mode := .markup, markupOffset := c.byteOffset,
                     markupIndex := s.charIndex - 1 }, evs)
        else if c.value.n == 0x26 then
          ({ s with mode := .refAfterAmp, refCtx := .text,
                    refStartOffset := c.byteOffset, refBuf := #[] }, #[])
        else if c.value.n == 0x5D then
          ({ s with mode := .textBracket1 }, #[])
        else if c.value.n == 0x0D then
          ({ s with pendingCR := true }, #[])
        else if isXmlChar c.value.n then
          match appendChar s c.value.toChar c.byteOffset with
          | (s1, some e) => (failedWith s1 e, #[])
          | (s1, none) => (s1, #[])
        else (failCode s .invalidToken "illegalXmlChar" c.byteOffset, #[])
      | .textBracket1 =>
        if c.value.n == 0x5D then ({ s with mode := .textBracket2 }, #[])
        else
          match appendChar s ']' c.byteOffset with
          | (s1, some e) => (failedWith s1 e, #[])
          | (s1, none) => reprocess ({ s1 with mode := .text })
      | .textBracket2 =>
        if c.value.n == 0x3E then
          (failCode s .invalidToken "cdataEndInText" c.byteOffset, #[])
        else if c.value.n == 0x5D then
          match appendChar s ']' c.byteOffset with
          | (s1, some e) => (failedWith s1 e, #[])
          | (s1, none) => ({ s1 with mode := .textBracket2 }, #[])
        else
          match appendChar s ']' c.byteOffset with
          | (s1, some e) => (failedWith s1 e, #[])
          | (s1, none) =>
            match appendChar s1 ']' c.byteOffset with
            | (s2, some e) => (failedWith s2 e, #[])
            | (s2, none) => reprocess ({ s2 with mode := .text })
      | .markup =>
        match s.phase with
        | .prolog =>
          if c.value.n == 0x3F then ({ s with mode := .piTarget }, #[])
          else if c.value.n == 0x21 then ({ s with mode := .bang }, #[])
          else if c.value.n == 0x2F then
            (failCode s .invalidToken "strayEndTag" s.markupOffset, #[])
          else startTagFirst s c
        | .content =>
          if c.value.n == 0x3F then ({ s with mode := .piTarget }, #[])
          else if c.value.n == 0x21 then ({ s with mode := .bang }, #[])
          else if c.value.n == 0x2F then ({ s with mode := .endName }, #[])
          else startTagFirst s c
        | .epilog =>
          if c.value.n == 0x3F then ({ s with mode := .piTarget }, #[])
          else if c.value.n == 0x21 then ({ s with mode := .bang }, #[])
          else if c.value.n == 0x2F then
            (failCode s .invalidToken "strayEndTag" s.markupOffset, #[])
          else (failCode s .junkAfterDocElement "junkAfterRoot" s.markupOffset, #[])
      | .bang =>
        match s.phase with
        | .epilog =>
          if c.value.n == 0x2D then ({ s with mode := .bangDash }, #[])
          else (failCode s .junkAfterDocElement "junkAfterRoot" s.markupOffset, #[])
        | .prolog | .content =>
          if c.value.n == 0x2D then ({ s with mode := .bangDash }, #[])
          else if c.value.n == 0x44 then ({ s with mode := .bangDoctype 1 }, #[])
          else if c.value.n == 0x5B && s.phase == .content then
            ({ s with mode := .bangCdata 1 }, #[])
          else (failedWith s (unknownMarkupError s), #[])
      | .bangDash =>
        if c.value.n == 0x2D then ({ s with mode := .comment }, #[])
        else (failedWith s (unknownMarkupError s), #[])
      | .bangCdata matched =>
        match cdataPat matched with
        | some expected =>
          if c.value.n == expected then
            if matched + 1 == 7 then
              ({ s with mode := .cdata, buf := #[] }, #[.cdataStart])
            else ({ s with mode := .bangCdata (matched + 1) }, #[])
          else (failedWith s (unknownMarkupError s), #[])
        | none => (failedWith s (unknownMarkupError s), #[])
      | .bangDoctype matched =>
        match doctypePat matched with
        | some expected =>
          if c.value.n == expected then
            if matched + 1 == 7 then
              (failCode s .unsupportedDtd "unsupportedDtd" s.markupOffset, #[])
            else ({ s with mode := .bangDoctype (matched + 1) }, #[])
          else (failedWith s (unknownMarkupError s), #[])
        | none => (failedWith s (unknownMarkupError s), #[])
      | .comment =>
        if c.value.n == 0x2D then ({ s with mode := .commentDash1 }, #[])
        else if c.value.n == 0x0D then ({ s with pendingCR := true }, #[])
        else if isXmlChar c.value.n then
          match appendChar s c.value.toChar c.byteOffset with
          | (s1, some e) => (failedWith s1 e, #[])
          | (s1, none) => (s1, #[])
        else (failCode s .invalidToken "illegalXmlChar" c.byteOffset, #[])
      | .commentDash1 =>
        if c.value.n == 0x2D then ({ s with mode := .commentDash2 }, #[])
        else
          match appendChar s '-' c.byteOffset with
          | (s1, some e) => (failedWith s1 e, #[])
          | (s1, none) => reprocess ({ s1 with mode := .comment })
      | .commentDash2 =>
        if c.value.n == 0x3E then
          let data := bufferString s.buf
          ({ s with mode := resumeMode s.phase, buf := #[] }, #[.comment data])
        else (failCode s .invalidToken "doubleHyphenInComment" c.byteOffset, #[])
      | .cdata =>
        if c.value.n == 0x5D then ({ s with mode := .cdataBracket1 }, #[])
        else if c.value.n == 0x0D then ({ s with pendingCR := true }, #[])
        else if isXmlChar c.value.n then
          match appendChar s c.value.toChar c.byteOffset with
          | (s1, some e) => (failedWith s1 e, #[])
          | (s1, none) => (s1, #[])
        else (failCode s .invalidToken "illegalXmlChar" c.byteOffset, #[])
      | .cdataBracket1 =>
        if c.value.n == 0x5D then ({ s with mode := .cdataBracket2 }, #[])
        else
          match appendChar s ']' c.byteOffset with
          | (s1, some e) => (failedWith s1 e, #[])
          | (s1, none) => reprocess ({ s1 with mode := .cdata })
      | .cdataBracket2 =>
        if c.value.n == 0x3E then
          let data := bufferString s.buf
          let evs : Array Event :=
            if data.isEmpty then #[.cdataEnd] else #[.text data, .cdataEnd]
          ({ s with mode := .contentStart, buf := #[] }, evs)
        else if c.value.n == 0x5D then
          match appendChar s ']' c.byteOffset with
          | (s1, some e) => (failedWith s1 e, #[])
          | (s1, none) => ({ s1 with mode := .cdataBracket2 }, #[])
        else
          match appendChar s ']' c.byteOffset with
          | (s1, some e) => (failedWith s1 e, #[])
          | (s1, none) =>
            match appendChar s1 ']' c.byteOffset with
            | (s2, some e) => (failedWith s2 e, #[])
            | (s2, none) => reprocess ({ s2 with mode := .cdata })
      | .startNameRest =>
        if isNameChar c.value.n then
          match appendChar s c.value.toChar c.byteOffset with
          | (s1, some e) => (failedWith s1 e, #[])
          | (s1, none) => (s1, #[])
        else
          let name := bufferString s.buf
          reprocess ({ s with elemName := name, buf := #[], mode := .startAfterName, spaced := false })
      | .startAfterName =>
        if isXmlWhitespace c.value.n then ({ s with spaced := true }, #[])
        else if c.value.n == 0x3E then completeStartTag s false
        else if c.value.n == 0x2F then ({ s with mode := .startSlash }, #[])
        else if !s.spaced then
          (failCode s .invalidToken "missingAttributeSeparator" c.byteOffset, #[])
        else if isNameStartChar c.value.n then
          match appendChar { s with buf := #[] } c.value.toChar c.byteOffset with
          | (s1, some e) => (failedWith s1 e, #[])
          | (s1, none) => ({ s1 with mode := .attrNameRest }, #[])
        else (failCode s .invalidToken "invalidNameStart" c.byteOffset, #[])
      | .startSlash =>
        if c.value.n == 0x3E then completeStartTag s true
        else (failCode s .invalidToken "badEmptyTag" c.byteOffset, #[])
      | .attrNameRest =>
        if isNameChar c.value.n then
          match appendChar s c.value.toChar c.byteOffset with
          | (s1, some e) => (failedWith s1 e, #[])
          | (s1, none) => (s1, #[])
        else
          let name := bufferString s.buf
          reprocess ({ s with attrName := name, buf := #[], mode := .attrAfterName })
      | .attrAfterName =>
        if isXmlWhitespace c.value.n then (s, #[])
        else if c.value.n == 0x3D then ({ s with mode := .attrAfterEq }, #[])
        else (failCode s .invalidToken "missingEquals" c.byteOffset, #[])
      | .attrAfterEq =>
        if isXmlWhitespace c.value.n then (s, #[])
        else if c.value.n == 0x22 || c.value.n == 0x27 then
          ({ s with buf := #[], mode := .attrValue (Char.ofNat c.value.n) }, #[])
        else (failCode s .invalidToken "unquotedAttribute" c.byteOffset, #[])
      | .attrValue quote =>
        if c.value.n == quote.toNat then
          let value := bufferString s.buf
          ({ s with attrs := s.attrs.push (s.attrName, value), buf := #[],
                    mode := .startAfterName, spaced := false, attrName := "" }, #[])
        else if c.value.n == 0x26 then
          ({ s with mode := .refAfterAmp, refCtx := RefCtx.attribute quote,
                    refStartOffset := c.byteOffset, refBuf := #[] }, #[])
        else if c.value.n == 0x3C then
          (failCode s .invalidToken "ltInAttribute" c.byteOffset, #[])
        else if c.value.n == 0x0D then
          ({ s with pendingCR := true }, #[])
        else if c.value.n == 0x0A || c.value.n == 0x09 || c.value.n == 0x20 then
          match appendChar s ' ' c.byteOffset with
          | (s1, some e) => (failedWith s1 e, #[])
          | (s1, none) => (s1, #[])
        else if isXmlChar c.value.n then
          match appendChar s c.value.toChar c.byteOffset with
          | (s1, some e) => (failedWith s1 e, #[])
          | (s1, none) => (s1, #[])
        else (failCode s .invalidToken "illegalXmlChar" c.byteOffset, #[])
      | .endName =>
        if isNameStartChar c.value.n then
          match appendChar { s with buf := #[] } c.value.toChar c.byteOffset with
          | (s1, some e) => (failedWith s1 e, #[])
          | (s1, none) => ({ s1 with mode := .endNameRest }, #[])
        else (failCode s .invalidToken "invalidNameStart" c.byteOffset, #[])
      | .endNameRest =>
        if isNameChar c.value.n then
          match appendChar s c.value.toChar c.byteOffset with
          | (s1, some e) => (failedWith s1 e, #[])
          | (s1, none) => (s1, #[])
        else
          let name := bufferString s.buf
          reprocess ({ s with buf := #[], mode := .endClose name })
      | .endClose name =>
        if isXmlWhitespace c.value.n then (s, #[])
        else if c.value.n == 0x3E then finishEndTag s name
        else (failCode s .invalidToken "badEndTag" c.byteOffset, #[])
      | .piTarget =>
        if isNameStartChar c.value.n then
          match appendChar { s with buf := #[] } c.value.toChar c.byteOffset with
          | (s1, some e) => (failedWith s1 e, #[])
          | (s1, none) => ({ s1 with mode := .piTargetRest }, #[])
        else (failCode s .invalidToken "invalidNameStart" c.byteOffset, #[])
      | .piTargetRest =>
        if isNameChar c.value.n then
          match appendChar s c.value.toChar c.byteOffset with
          | (s1, some e) => (failedWith s1 e, #[])
          | (s1, none) => (s1, #[])
        else
          let target := bufferString s.buf
          let s1 := { s with buf := #[] }
          if target == "xml" then
            if s.phase == .prolog && s.markupIndex == 0 then
              reprocess ({ s1 with mode := .decl .needWs1 })
            else (failCode s1 .misplacedXmlPi "misplacedXmlDecl" s.markupOffset, #[])
          else if target.toLower == "xml" then
            (failCode s1 .invalidToken "reservedPiTarget" s.markupOffset, #[])
          else reprocess ({ s1 with mode := .piAfterTarget target })
      | .piAfterTarget target =>
        if c.value.n == 0x3F then ({ s with mode := .piQInit target }, #[])
        else if isXmlWhitespace c.value.n then ({ s with mode := .piSkipWs target }, #[])
        else (failCode s .invalidToken "piSyntax" c.byteOffset, #[])
      | .piSkipWs target =>
        if isXmlWhitespace c.value.n then (s, #[])
        else reprocess ({ s with mode := .piData target })
      | .piQInit target =>
        if c.value.n == 0x3E then
          ({ s with mode := resumeMode s.phase }, #[.pi target ""])
        else (failCode s .invalidToken "piSyntax" c.byteOffset, #[])
      | .piData target =>
        if c.value.n == 0x3F then ({ s with mode := .piQ target }, #[])
        else if c.value.n == 0x0D then ({ s with pendingCR := true }, #[])
        else if isXmlChar c.value.n then
          match appendChar s c.value.toChar c.byteOffset with
          | (s1, some e) => (failedWith s1 e, #[])
          | (s1, none) => (s1, #[])
        else (failCode s .invalidToken "illegalXmlChar" c.byteOffset, #[])
      | .piQ target =>
        if c.value.n == 0x3E then
          let data := bufferString s.buf
          ({ s with mode := resumeMode s.phase, buf := #[] }, #[.pi target data])
        else
          match appendChar s '?' c.byteOffset with
          | (s1, some e) => (failedWith s1 e, #[])
          | (s1, none) => reprocess ({ s1 with mode := .piData target })
      | .refAfterAmp =>
        if c.value.n == 0x23 then ({ s with mode := .refNumOptX }, #[])
        else if isNameChar c.value.n then
          match appendRefChar s c.value.toChar c.byteOffset with
          | (s1, some e) => (failedWith s1 e, #[])
          | (s1, none) => ({ s1 with mode := .refNameRest }, #[])
        else (failCode s .invalidToken "malformedReference" c.byteOffset, #[])
      | .refNameRest =>
        if isNameChar c.value.n then
          match appendRefChar s c.value.toChar c.byteOffset with
          | (s1, some e) => (failedWith s1 e, #[])
          | (s1, none) => (s1, #[])
        else if c.value.n == 0x3B then
          let name := bufferString s.refBuf
          let s1 := { s with refBuf := #[] }
          let resolved : Option Scalar :=
            if name == "amp" then some ⟨0x26, by decide⟩
            else if name == "lt" then some ⟨0x3C, by decide⟩
            else if name == "gt" then some ⟨0x3E, by decide⟩
            else if name == "apos" then some ⟨0x27, by decide⟩
            else if name == "quot" then some ⟨0x22, by decide⟩
            else none
          match resolved with
          | some sc => finishReference s1 sc
          | none => (failCode s1 .undefinedEntity "undefinedEntity" s.refStartOffset, #[])
        else (failCode s .invalidToken "unterminatedReference" c.byteOffset, #[])
      | .refNumOptX =>
        if c.value.n == 0x78 then
          ({ s with mode := .refNumDigits true 0 0 false }, #[])
        else
          match decDigitValue c.value.n with
          | some dv =>
            match chargeRefDigit s 0 c.byteOffset with
            | some e => (failedWith s e, #[])
            | none => ({ s with mode := .refNumDigits false dv 1 false }, #[])
          | none => (failCode s .invalidToken "malformedCharRef" c.byteOffset, #[])
      | .refNumDigits hex value digits overflow =>
        let d := if hex then hexDigitValue c.value.n else decDigitValue c.value.n
        match d with
        | some dv =>
          match chargeRefDigit s digits c.byteOffset with
          | some e => (failedWith s e, #[])
          | none =>
            if overflow then
              ({ s with mode := .refNumDigits hex value (digits + 1) true }, #[])
            else
              let nextValue := value * (if hex then 16 else 10) + dv
              let saturated := nextValue > 0x10FFFF
              let nextMode := Mode.refNumDigits hex
                (if saturated then value else nextValue) (digits + 1) saturated
              ({ s with mode := nextMode }, #[])
        | none =>
          if digits == 0 then
            (failCode s .invalidToken "malformedCharRef" c.byteOffset, #[])
          else if c.value.n == 0x3B then
            if overflow then
              (failCode s .badCharRef "badCharRef" c.byteOffset, #[])
            else if isXmlChar value then
              if h : Nat.isValidChar value then
                finishReference { s with refBuf := #[] } ⟨value, h⟩
              else (failCode s .badCharRef "badCharRef" c.byteOffset, #[])
            else (failCode s .badCharRef "badCharRef" c.byteOffset, #[])
          else (failCode s .invalidToken "unterminatedCharRef" c.byteOffset, #[])
      | .decl stage => declStep reprocess s c stage

private def stepChar (s : Stream) (c : DecodedChar) : Stream × Array Event :=
  runStep 8 { s with charIndex := s.charIndex + 1 } c

/-- The encoding a declaration label selects on its own, when it names one of
the ASCII-compatible encodings. The label's encoding is also what the pending
encoding choice will adopt, so the shadow can compare a label against it. -/
private def labelEncoding (buf : Array Char) : Option Encoding :=
  match classifyLabel (bufferString buf) with
  | .utf8 => some .utf8
  | .ascii => some .ascii
  | .latin1 => some .latin1
  | _ => none

/-! ## Decoder -/

private inductive ByteOutcome where
  | needMore (s : Stream)
  | progressed (s : Stream) (evs : Array Event)
  | failed (s : Stream) (evs : Array Event)

private def charStep (s : Stream) (c : DecodedChar) : ByteOutcome :=
  let (s1, evs) := stepChar s c
  match s1.status with
  | .active => .progressed s1 evs
  | _ => .failed s1 evs

private def decodeUtf8Pending (s : Stream) : ByteOutcome :=
  match decodeUtf8One s.pending 0 with
  | .ok (sc, next) =>
    if next == s.pending.size then
      charStep { s with pending := ByteArray.empty } ⟨sc, s.pendingOffset⟩
    else
      .failed (failCode s .invalidToken "invalidLead" s.pendingOffset) #[]
  | .error e =>
    if e.reason == .truncated then
      .needMore s
    else
      .failed
        (failCode s e.reason.code e.reason.name (s.pendingOffset + e.offset)) #[]

private def decodeUtf16Pending (s : Stream) (bigEndian : Bool) : ByteOutcome :=
  match s.pending.size with
  | 2 =>
    match s.pending[0]?, s.pending[1]? with
    | some b0, some b1 =>
      let u := utf16Unit bigEndian b0 b1
      if u < 0xD800 then
        match decodeUtf16One s.pending bigEndian 0 with
        | .ok (sc, _) =>
          charStep { s with pending := ByteArray.empty } ⟨sc, s.pendingOffset⟩
        | .error e =>
          .failed
            (failCode s e.reason.code e.reason.name (s.pendingOffset + e.offset)) #[]
      else if u < 0xDC00 then
        .needMore s
      else
        .failed (failCode s .invalidToken "unpairedSurrogate" s.pendingOffset) #[]
    | _, _ => .needMore s
  | 4 =>
    match decodeUtf16One s.pending bigEndian 0 with
    | .ok (sc, _) =>
      charStep { s with pending := ByteArray.empty } ⟨sc, s.pendingOffset⟩
    | .error e =>
      .failed
        (failCode s e.reason.code e.reason.name (s.pendingOffset + e.offset)) #[]
  | _ => .needMore s

private def decodeByte (s : Stream) (b : UInt8) (off : Nat) : ByteOutcome :=
  match s.enc with
  | .decided enc =>
    match enc with
    | .utf8 =>
      if s.pending.isEmpty then
        if h : b.toNat < 0x80 then
          charStep s ⟨⟨b.toNat, Or.inl (by omega)⟩, off⟩
        else
          decodeUtf8Pending
            { s with pending := ByteArray.mk #[b], pendingOffset := off }
      else
        decodeUtf8Pending { s with pending := s.pending.push b }
    | .utf16le =>
      let base := if s.pending.isEmpty then off else s.pendingOffset
      decodeUtf16Pending
        { s with pending := s.pending.push b, pendingOffset := base } false
    | .utf16be =>
      let base := if s.pending.isEmpty then off else s.pendingOffset
      decodeUtf16Pending
        { s with pending := s.pending.push b, pendingOffset := base } true
    | .latin1 =>
      charStep s ⟨⟨b.toNat, Or.inl (by
        have hb := UInt8.toNat_lt b
        omega)⟩, off⟩
    | .ascii =>
      if h : b.toNat < 0x80 then
        charStep s ⟨⟨b.toNat, Or.inl (by omega)⟩, off⟩
      else
        .failed (failCode s .invalidToken "invalidAscii" off) #[]
  | _ => .failed (failCode s .syntax "decoderNotReady" off) #[]

private def feedDecoded (s : Stream) (evs : Array Event) (data : ByteArray)
    (base : Nat) : Stream × Array Event :=
  Id.run do
    let mut st := s
    let mut acc := evs
    let mut j := 0
    let mut stop := false
    while !stop && j < data.size do
      if !isActive st then
        stop := true
      else
        match data[j]? with
        | some b =>
          j := j + 1
          match decodeByte st b (base + (j - 1)) with
          | .needMore st' => st := st'
          | .progressed st' evs' => st := st'; acc := pushEvents acc evs'
          | .failed st' evs' => st := st'; acc := pushEvents acc evs'; stop := true
        | none => stop := true
    return (st, acc)

/-! ## Encoding selection -/

/-- Choose the encoding a complete (or bounded-prefix) byte sequence proves.
This is the same decision the one-shot decoder made: byte evidence first, then
the declaration label. -/
private def chooseEncoding (bytes : ByteArray) (limit : Nat) :
    Except ParseError (Encoding × Nat) :=
  match detectSignature bytes with
  | some (enc, off) => .ok (enc, off)
  | none =>
    match scanDeclLabel bytes limit with
    | none => .ok (.utf8, 0)
    | some label =>
      match classifyLabel label with
      | .utf8 => .ok (.utf8, 0)
      | .ascii => .ok (.ascii, 0)
      | .latin1 => .ok (.latin1, 0)
      | .utf16 => .error ⟨.incorrectEncoding, "encodingMismatch", 0⟩
      | .utf16le => .error ⟨.incorrectEncoding, "encodingMismatch", 0⟩
      | .utf16be => .error ⟨.incorrectEncoding, "encodingMismatch", 0⟩
      | .unknown => .error ⟨.unknownEncoding, "unknownEncoding", 0⟩

private inductive ProbeAction where
  | wait
  | decide
  | declaration
  | signature (enc : Encoding) (skip : Nat)

private def probeAction (buf : ByteArray) : ProbeAction :=
  if buf[0]? == some 0xEF then
    if buf[1]? == some 0xBB then
      if buf[2]? == some 0xBF then .signature .utf8 3
      else if buf.size ≥ 3 then .decide else .wait
    else if buf.size ≥ 2 then .decide else .wait
  else if buf[0]? == some 0xFF then
    if buf[1]? == some 0xFE then .signature .utf16le 2
    else if buf.size ≥ 2 then .decide else .wait
  else if buf[0]? == some 0xFE then
    if buf[1]? == some 0xFF then .signature .utf16be 2
    else if buf.size ≥ 2 then .decide else .wait
  else if buf[0]? == some 0x00 then
    if buf[1]? == some 0x3C then .signature .utf16be 0
    else if buf.size ≥ 2 then .decide else .wait
  else if buf[0]? == some 0x3C then
    if buf[1]? == some 0x00 then .signature .utf16le 0
    else if buf.size < 2 then .wait
    else if buf[1]? != some 0x3F then .decide
    else if buf.size < 3 then .wait
    else if buf[2]? != some 0x78 then .decide
    else if buf.size < 4 then .wait
    else if buf[3]? != some 0x6D then .decide
    else if buf.size < 5 then .wait
    else if buf[4]? != some 0x6C then .decide
    else if buf.size < 6 then .wait
    else
      match buf[5]? with
      | some w => if isXmlWhitespace w.toNat then .declaration else .decide
      | none => .wait
  else .decide

private def replayProbe (s : Stream) (enc : Encoding) (skip : Nat)
    (buf : ByteArray) : Stream × Array Event :=
  let fresh : Stream :=
    { s with enc := .decided enc, mode := .prologStart, buf := #[],
             declShadow := true, declEncoding := none, declStandalone := none,
             declSecond := none, spaced := false }
  feedDecoded fresh #[] (buf.extract skip buf.size) skip

private def decideFromProbe (s : Stream) (buf : ByteArray) : Stream × Array Event :=
  match chooseEncoding buf s.limits.maxTokenChars with
  | .error e => (failedWith s e, #[])
  | .ok (enc, skip) => replayProbe s enc skip buf

/-- Feed one chunk. Events determined by this chunk are returned immediately; a
failure in this call still returns the events determined before it. -/
def feed (s : Stream) (chunk : ByteArray) : Stream × Array Event :=
  match s.status with
  | .active =>
    if chunk.size == 0 then (s, #[])
    else
      Id.run do
        let mut st := s
        let mut acc : Array Event := #[]
        let mut i := 0
        let mut stop := false
        while !stop && i < chunk.size do
          if !isActive st then
            stop := true
          else if st.rawConsumed ≥ st.limits.maxInputBytes then
            st := failCode st .limitInput "limitInput" st.rawConsumed
            stop := true
          else
            match chunk[i]? with
            | none => stop := true
            | some b =>
              let off := st.rawConsumed
              i := i + 1
              st := { st with rawConsumed := st.rawConsumed + 1 }
              match st.enc with
              | .probing buf =>
                let buf' := buf.push b
                match probeAction buf' with
                | .wait => st := { st with enc := .probing buf' }
                | .declaration =>
                  -- The whitespace that identified the declaration is already
                  -- consumed, so the shadow resumes at the version name.
                  st := { st with enc := .declaration buf',
                                   mode := .decl .versionNameSkipWs }
                | .signature enc skip =>
                  let (st', evs') := replayProbe st enc skip buf'
                  st := st'
                  acc := pushEvents acc evs'
                  if !isActive st then stop := true
                | .decide =>
                  let (st', evs') := decideFromProbe st buf'
                  st := st'
                  acc := pushEvents acc evs'
                  if !isActive st then stop := true
              | .declaration buf =>
                -- Drop the stream's reference to the prefix before appending, so
                -- the append is the sole owner of the buffer and stays linear.
                st := { st with enc := .probing ByteArray.empty }
                let buf' := buf.push b
                let j := buf'.size - 1
                -- The declaration grammar runs synchronously on the buffered
                -- ASCII bytes, using the lexical fields the undecided encoding
                -- leaves unused. Reusing `st` itself keeps the character buffer
                -- uniquely owned, so this stays linear in the prefix length.
                let hint : Option Encoding :=
                  match st.mode with
                  | .decl (.secondValue quote) =>
                    if b.toNat == quote.toNat then labelEncoding st.buf
                    else none
                  | _ => none
                let st1 : Stream :=
                  if !st.declShadow then
                    { st with enc := .declaration buf', declShadow := false }
                  else if h : b.toNat < 0x80 then
                    match hint with
                    | some enc =>
                      -- One copy of the value buffer: the label decides the
                      -- encoding the declaration will be checked against.
                      let (s', _) :=
                        runStep 8 { st with enc := .decided enc }
                          ⟨⟨b.toNat, Or.inl (by omega)⟩, off⟩
                      { s' with enc := .declaration buf' }
                    | none =>
                      let (s', _) := runStep 8 st
                        ⟨⟨b.toNat, Or.inl (by omega)⟩, off⟩
                      { s' with enc := .declaration buf' }
                  else
                    match nonAsciiDeclFault st with
                    | some (code, reason) => failCode st code reason off
                    | none => { st with enc := .declaration buf', declShadow := false }
                let shadowLive :=
                  st1.declShadow &&
                    (match st1.mode with
                      | .decl _ => true
                      | _ => false)
                st := { st1 with declShadow := shadowLive }
                if !isActive st then
                  stop := true
                else if j ≥ 6 && buf'[j - 1]? == some 0x3F && b == 0x3E &&
                    j < st.limits.maxTokenChars then
                  let (st', evs') := decideFromProbe st buf'
                  st := st'
                  acc := pushEvents acc evs'
                  if !isActive st then stop := true
                else if buf'.size ≥ st.limits.maxTokenChars then
                  let (st', evs') := decideFromProbe st buf'
                  st := st'
                  acc := pushEvents acc evs'
                  if !isActive st then stop := true
              | .decided _ =>
                match decodeByte st b off with
                | .needMore st' => st := st'
                | .progressed st' evs' => st := st'; acc := pushEvents acc evs'
                | .failed st' evs' =>
                  st := st'; acc := pushEvents acc evs'; stop := true
        return (st, acc)
  | _ => (s, #[])

/-! ## Finish -/

private def finishWithAppend (s : Stream) (ch : Char) (code : ErrorCode)
    (reason : String) (evs : Array Event) : Stream × Array Event :=
  match appendChar s ch s.rawConsumed with
  | (s1, some e) => (failedWith s1 e, evs)
  | (s1, none) => (failedWith s1 ⟨code, reason, s.rawConsumed⟩, evs)

private def finishWithAppend2 (s : Stream) (code : ErrorCode) (reason : String)
    (evs : Array Event) : Stream × Array Event :=
  match appendChar s ']' s.rawConsumed with
  | (s1, some e) => (failedWith s1 e, evs)
  | (s1, none) =>
    match appendChar s1 ']' s.rawConsumed with
    | (s2, some e) => (failedWith s2 e, evs)
    | (s2, none) => (failedWith s2 ⟨code, reason, s.rawConsumed⟩, evs)

private def finishDecl (s : Stream) (stage : DeclMode) (evs : Array Event) :
    Stream × Array Event :=
  let fail (code : ErrorCode) (reason : String) : Stream × Array Event :=
    (failCode s code reason s.rawConsumed, evs)
  match stage with
  | .needWs1 => fail .unclosedToken "unclosedXmlDecl"
  | .versionNameSkipWs => fail .unclosedToken "unclosedXmlDecl"
  | .versionName =>
    match declNameDone s .version s.rawConsumed with
    | (s1, some e) => (failedWith s1 e, evs)
    | (s1, none) => (failCode s1 .xmlDecl "xmlDeclEquals" s1.rawConsumed, evs)
  | .versionAfterName => fail .xmlDecl "xmlDeclEquals"
  | .versionAfterEq => fail .unclosedToken "unclosedXmlDecl"
  | .versionValue _ => fail .unclosedToken "unclosedXmlDecl"
  | .versionDone _ => fail .unclosedToken "unclosedXmlDecl"
  | .versionQ sawSep =>
    if sawSep then fail .xmlDecl "xmlDeclName" else fail .xmlDecl "xmlDeclSeparator"
  | .secondName =>
    match declNameDone s .second s.rawConsumed with
    | (s1, some e) => (failedWith s1 e, evs)
    | (s1, none) => (failCode s1 .xmlDecl "xmlDeclEquals" s1.rawConsumed, evs)
  | .secondAfterName => fail .xmlDecl "xmlDeclEquals"
  | .secondAfterEq => fail .unclosedToken "unclosedXmlDecl"
  | .secondValue _ => fail .unclosedToken "unclosedXmlDecl"
  | .standaloneDone _ => fail .unclosedToken "unclosedXmlDecl"
  | .standaloneQ _ => fail .xmlDecl "xmlDeclEnd"
  | .encodingDone _ => fail .unclosedToken "unclosedXmlDecl"
  | .encodingQ sawSep =>
    if sawSep then fail .xmlDecl "xmlDeclName" else fail .xmlDecl "xmlDeclSeparator"
  | .thirdName =>
    match declNameDone s .third s.rawConsumed with
    | (s1, some e) => (failedWith s1 e, evs)
    | (s1, none) => (failCode s1 .xmlDecl "xmlDeclEquals" s1.rawConsumed, evs)
  | .thirdAfterName => fail .xmlDecl "xmlDeclEquals"
  | .thirdAfterEq => fail .unclosedToken "unclosedXmlDecl"
  | .thirdValue _ => fail .unclosedToken "unclosedXmlDecl"
  | .thirdDone => fail .unclosedToken "unclosedXmlDecl"
  | .thirdQ => fail .xmlDecl "xmlDeclEnd"

private def finishMode (s : Stream) (evs : Array Event) : Stream × Array Event :=
  let fail (code : ErrorCode) (reason : String) : Stream × Array Event :=
    (failCode s code reason s.rawConsumed, evs)
  match s.mode with
  | .prologStart => fail .noElements "noRoot"
  | .epilogStart => ({ s with status := .done }, evs)
  | .contentStart => fail .noElements "unclosedElement"
  | .text => fail .noElements "unclosedElement"
  | .textBracket1 => finishWithAppend s ']' .noElements "unclosedElement" evs
  | .textBracket2 => finishWithAppend2 s .noElements "unclosedElement" evs
  | .markup =>
    match s.phase with
    | .epilog => fail .junkAfterDocElement "junkAfterRoot"
    | _ => fail .invalidToken "unexpectedEnd"
  | .bang =>
    match s.phase with
    | .epilog => fail .junkAfterDocElement "junkAfterRoot"
    | _ => (failedWith s (unknownMarkupError s), evs)
  | .bangDash =>
    match s.phase with
    | .epilog => fail .junkAfterDocElement "junkAfterRoot"
    | _ => (failedWith s (unknownMarkupError s), evs)
  | .bangCdata _ => (failedWith s (unknownMarkupError s), evs)
  | .bangDoctype _ => (failedWith s (unknownMarkupError s), evs)
  | .endName => fail .invalidToken "expectedName"
  | .endNameRest => fail .unclosedToken "unclosedEndTag"
  | .endClose _ => fail .unclosedToken "unclosedEndTag"
  | .piTarget => fail .invalidToken "expectedName"
  | .piTargetRest =>
    let target := bufferString s.buf
    if target == "xml" then
      if s.phase == .prolog && s.markupIndex == 0 then
        fail .unclosedToken "unclosedXmlDecl"
      else fail .misplacedXmlPi "misplacedXmlDecl"
    else if target.toLower == "xml" then fail .invalidToken "reservedPiTarget"
    else fail .unclosedToken "unclosedPi"
  | .piAfterTarget _ => fail .unclosedToken "unclosedPi"
  | .piSkipWs _ => fail .unclosedToken "unclosedPi"
  | .piQInit _ => fail .invalidToken "piSyntax"
  | .piData _ => fail .unclosedToken "unclosedPi"
  | .piQ _ => finishWithAppend s '?' .unclosedToken "unclosedPi" evs
  | .comment => fail .unclosedToken "unclosedComment"
  | .commentDash1 => finishWithAppend s '-' .unclosedToken "unclosedComment" evs
  | .commentDash2 => fail .invalidToken "doubleHyphenInComment"
  | .cdata => fail .unclosedCdataSection "unclosedCdata"
  | .cdataBracket1 => finishWithAppend s ']' .unclosedCdataSection "unclosedCdata" evs
  | .cdataBracket2 =>
    finishWithAppend2 s .unclosedCdataSection "unclosedCdata" evs
  | .startNameRest => fail .unclosedToken "unclosedStartTag"
  | .startAfterName => fail .unclosedToken "unclosedStartTag"
  | .startSlash => fail .invalidToken "badEmptyTag"
  | .attrNameRest => fail .invalidToken "missingEquals"
  | .attrAfterName => fail .invalidToken "missingEquals"
  | .attrAfterEq => fail .unclosedToken "unclosedStartTag"
  | .attrValue _ => fail .unclosedToken "unclosedAttributeValue"
  | .refAfterAmp => fail .invalidToken "unterminatedReference"
  | .refNameRest => fail .invalidToken "unterminatedReference"
  | .refNumOptX => fail .invalidToken "malformedCharRef"
  | .refNumDigits _ _ digits _ =>
    if digits == 0 then fail .invalidToken "malformedCharRef"
    else fail .invalidToken "unterminatedCharRef"
  | .decl stage => finishDecl s stage evs

private def finishGrammar (s : Stream) (evs : Array Event) : Stream × Array Event :=
  if s.pendingCR then
    let mapped : Char := match s.mode with
      | .attrValue _ => ' '
      | _ => '\n'
    match appendChar s mapped s.rawConsumed with
    | (s1, some e) => (failedWith s1 e, evs)
    | (s1, none) => finishMode { s1 with pendingCR := false } evs
  else
    finishMode s evs

private def finishUtf16 (s : Stream) (evs : Array Event) (bigEndian : Bool) :
    Stream × Array Event :=
  match s.pending.size with
  | 0 => finishGrammar s evs
  | 1 => (failCode s .partialChar "oddUtf16Length" s.pendingOffset, evs)
  | 2 =>
    match s.pending[0]?, s.pending[1]? with
    | some b0, some b1 =>
      let u := utf16Unit bigEndian b0 b1
      if u < 0xD800 then
        match decodeUtf16One s.pending bigEndian 0 with
        | .ok (sc, _) =>
          let (s1, evs1) := stepChar { s with pending := ByteArray.empty }
            ⟨sc, s.pendingOffset⟩
          match s1.status with
          | .active => finishGrammar s1 (pushEvents evs evs1)
          | _ => (s1, pushEvents evs evs1)
        | .error e =>
          (failCode s e.reason.code e.reason.name (s.pendingOffset + e.offset), evs)
      else (failCode s .invalidToken "unpairedSurrogate" s.pendingOffset, evs)
    | _, _ => (failCode s .partialChar "oddUtf16Length" s.pendingOffset, evs)
  | _ => (failCode s .partialChar "oddUtf16Length" s.pendingOffset, evs)

private def finishDecoded (s : Stream) (evs : Array Event) : Stream × Array Event :=
  match s.enc with
  | .decided enc =>
    match enc with
    | .utf8 =>
      if s.pending.isEmpty then finishGrammar s evs
      else
        match decodeUtf8One s.pending 0 with
        | .ok (sc, _) =>
          let (s1, evs1) := stepChar { s with pending := ByteArray.empty }
            ⟨sc, s.pendingOffset⟩
          match s1.status with
          | .active => finishGrammar s1 (pushEvents evs evs1)
          | _ => (s1, pushEvents evs evs1)
        | .error e =>
          (failCode s e.reason.code e.reason.name (s.pendingOffset + e.offset), evs)
    | .utf16le => finishUtf16 s evs false
    | .utf16be => finishUtf16 s evs true
    | .latin1 => finishGrammar s evs
    | .ascii => finishGrammar s evs
  | _ => finishGrammar s evs

/-- Finish the document. A pending decoder fault is resolved before EOF-only
grammar faults. A completed or failed stream is inert. -/
def finish (s : Stream) : Stream × Array Event :=
  match s.status with
  | .active =>
    match s.enc with
    | .probing buf =>
      match chooseEncoding buf s.limits.maxTokenChars with
      | .error e => (failedWith s e, #[])
      | .ok (enc, skip) =>
        let (s1, evs) := replayProbe s enc skip buf
        match s1.status with
        | .active => finishDecoded s1 evs
        | _ => (s1, evs)
    | .declaration buf =>
      match chooseEncoding buf s.limits.maxTokenChars with
      | .error e => (failedWith s e, #[])
      | .ok (enc, skip) =>
        let (s1, evs) := replayProbe s enc skip buf
        match s1.status with
        | .active => finishDecoded s1 evs
        | _ => (s1, evs)
    | .decided _ => finishDecoded s #[]
  | _ => (s, #[])

end Stream

end LexPat
