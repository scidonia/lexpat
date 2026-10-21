/-
The one-shot XML 1.0 document parser.

The parser is a single iterative loop over the decoded scalars with an explicit
element-name stack, so attacker-controlled nesting cannot consume the call
stack. Every loop either advances the cursor or terminates, every read is
bounds-checked, and every budget is tested before the corresponding append.
-/
import LexPat.Types
import LexPat.Lexer
import LexPat.Encoding

namespace LexPat

inductive Phase where
  | prolog
  | content
  | epilog
deriving Repr

/-- The scalar written by a decimal or hexadecimal character reference. -/
def decDigitValue (n : Nat) : Option Nat :=
  if between n 0x30 0x39 then some (n - 0x30) else none

def hexDigitValue (n : Nat) : Option Nat :=
  if between n 0x30 0x39 then some (n - 0x30)
  else if between n 0x41 0x46 then some (n - 0x41 + 10)
  else if between n 0x61 0x66 then some (n - 0x61 + 10)
  else none

/-- Scan an XML `Name`, enforcing the token budget. `pos` is at the first
character of the name. -/
def scanName (chars : Array DecodedChar) (limits : Limits) (pos : Nat) :
    Except ParseError (String × Nat) :=
  Id.run do
    let mut i := pos
    let mut buf : Array Scalar := #[]
    let mut err : Option ParseError := none
    match chars[i]? with
    | none => err := some (mkError chars i .invalidToken "expectedName")
    | some c =>
      if isNameStartChar c.value.n then
        buf := buf.push c.value
        i := i + 1
      else
        err := some (mkError chars i .invalidToken "invalidNameStart")
    while err.isNone && decide (i < chars.size) do
      match chars[i]? with
      | some c =>
        if isNameChar c.value.n then
          if buf.size ≥ limits.maxTokenChars then
            err := some (mkError chars i .limitToken "limitToken")
          else
            buf := buf.push c.value
            i := i + 1
        else
          break
      | none => break
    match err with
    | some e => return .error e
    | none => return .ok (String.ofList (buf.toList.map (fun s => s.toChar)), i)

/-- Resolve one predefined or numeric reference. `pos` is at `&`. The returned
count is the cumulative number of reference characters used. -/
def scanReference (chars : Array DecodedChar) (limits : Limits) (pos : Nat)
    (entityUsed : Nat) : Except ParseError (Scalar × Nat × Nat) :=
  Id.run do
    let mut i := pos + 1
    let mut err : Option ParseError := none
    let mut result : Option Scalar := none
    match natAt chars i with
    | none => err := some (mkError chars i .invalidToken "unterminatedReference")
    | some n =>
      if n == 0x23 then
        i := i + 1
        let mut hex := false
        match natAt chars i with
        | some hx =>
          if hx == 0x78 then
            hex := true
            i := i + 1
        | none => pure ()
        let mut value := 0
        let mut digits := 0
        let mut overflow := false
        let mut scanning := true
        while scanning && decide (i < chars.size) do
          match chars[i]? with
          | some c =>
            let d := if hex then hexDigitValue c.value.n else decDigitValue c.value.n
            match d with
            | some dv =>
              if digits ≥ 8 then
                overflow := true
              else
                value := value * (if hex then 16 else 10) + dv
              digits := digits + 1
              i := i + 1
            | none => scanning := false
          | none => scanning := false
        if digits == 0 then
          err := some (mkError chars i .invalidToken "malformedCharRef")
        else if i ≥ chars.size then
          err := some (mkError chars i .invalidToken "unterminatedCharRef")
        else if natAt chars i != some 0x3B then
          err := some (mkError chars i .invalidToken "unterminatedCharRef")
        else
          i := i + 1
          if overflow then
            err := some (mkError chars i .badCharRef "badCharRef")
          else if _hv : isXmlChar value = true then
            if hs : Nat.isValidChar value then
              result := some ⟨value, hs⟩
            else
              err := some (mkError chars i .badCharRef "badCharRef")
          else
            err := some (mkError chars i .badCharRef "badCharRef")
      else
        let mut buf : Array Scalar := #[]
        let mut scanning := true
        while scanning && decide (i < chars.size) do
          match chars[i]? with
          | some c =>
            if isNameChar c.value.n then
              if buf.size ≥ limits.maxTokenChars then
                err := some (mkError chars i .limitToken "limitToken")
                scanning := false
              else
                buf := buf.push c.value
                i := i + 1
            else
              scanning := false
          | none => scanning := false
        if err.isNone then
          if buf.isEmpty then
            err := some (mkError chars i .invalidToken "malformedReference")
          else if i ≥ chars.size then
            err := some (mkError chars i .invalidToken "unterminatedReference")
          else if natAt chars i != some 0x3B then
            err := some (mkError chars i .invalidToken "unterminatedReference")
          else
            i := i + 1
            let nm := String.ofList (buf.toList.map (fun s => s.toChar))
            if nm == "amp" then
              result := some ⟨0x26, by decide⟩
            else if nm == "lt" then
              result := some ⟨0x3C, by decide⟩
            else if nm == "gt" then
              result := some ⟨0x3E, by decide⟩
            else if nm == "apos" then
              result := some ⟨0x27, by decide⟩
            else if nm == "quot" then
              result := some ⟨0x22, by decide⟩
            else
              err := some (mkError chars pos .undefinedEntity "undefinedEntity")
    match err, result with
    | some e, _ => return .error e
    | none, some s =>
      if entityUsed + 1 > limits.maxEntityExpansion then
        return .error (mkError chars pos .limitEntityExpansion "limitEntityExpansion")
      else
        return .ok (s, i, entityUsed + 1)
    | none, none =>
      return .error (mkError chars pos .invalidToken "malformedReference")

/-- Scan character data up to the next `<`, normalizing literal line endings and
expanding references. -/
def scanText (chars : Array DecodedChar) (limits : Limits) (pos : Nat)
    (entityUsed : Nat) : Except ParseError (String × Nat × Nat) :=
  Id.run do
    let mut i := pos
    let mut buf : Array Scalar := #[]
    let mut used := entityUsed
    let mut err : Option ParseError := none
    let mut done := false
    while !done && err.isNone && decide (i < chars.size) do
      match chars[i]? with
      | none => done := true
      | some c =>
        let n := c.value.n
        if n == 0x3C then
          done := true
        else if n == 0x26 then
          match scanReference chars limits i used with
          | .error e => err := some e
          | .ok (s, next, used') =>
            if buf.size ≥ limits.maxTokenChars then
              err := some (mkError chars i .limitToken "limitToken")
            else
              buf := buf.push s
              used := used'
              i := next
        else if n == 0x5D then
          if natAt chars (i + 1) == some 0x5D && natAt chars (i + 2) == some 0x3E then
            err := some (mkError chars i .invalidToken "cdataEndInText")
          else if buf.size ≥ limits.maxTokenChars then
            err := some (mkError chars i .limitToken "limitToken")
          else
            buf := buf.push c.value
            i := i + 1
        else if n == 0x0D then
          if natAt chars (i + 1) == some 0x0A then
            i := i + 1
          if buf.size ≥ limits.maxTokenChars then
            err := some (mkError chars i .limitToken "limitToken")
          else
            buf := buf.push ⟨0x0A, by decide⟩
            i := i + 1
        else if hc : isXmlChar n = true then
          if buf.size ≥ limits.maxTokenChars then
            err := some (mkError chars i .limitToken "limitToken")
          else
            buf := buf.push c.value
            i := i + 1
        else
          err := some (mkError chars i .invalidToken "illegalXmlChar")
    match err with
    | some e => return .error e
    | none => return .ok (String.ofList (buf.toList.map (fun s => s.toChar)), i, used)

/-- Scan one attribute value. `pos` is just past the opening quote and `quote`
is that quote's scalar value. Returns the normalized value, the position after
the closing quote, and the cumulative reference count. -/
def scanAttrValue (chars : Array DecodedChar) (limits : Limits) (quote : Nat)
    (pos : Nat) (entityUsed : Nat) : Except ParseError (String × Nat × Nat) :=
  Id.run do
    let mut i := pos
    let mut buf : Array Scalar := #[]
    let mut used := entityUsed
    let mut err : Option ParseError := none
    let mut done := false
    while !done && err.isNone && decide (i < chars.size) do
      match chars[i]? with
      | none => done := true
      | some c =>
        let n := c.value.n
        if n == quote then
          i := i + 1
          done := true
        else if n == 0x26 then
          match scanReference chars limits i used with
          | .error e => err := some e
          | .ok (s, next, used') =>
            if buf.size ≥ limits.maxTokenChars then
              err := some (mkError chars i .limitToken "limitToken")
            else
              buf := buf.push s
              used := used'
              i := next
        else if n == 0x3C then
          err := some (mkError chars i .invalidToken "ltInAttribute")
        else if n == 0x0D then
          if natAt chars (i + 1) == some 0x0A then
            i := i + 1
          if buf.size ≥ limits.maxTokenChars then
            err := some (mkError chars i .limitToken "limitToken")
          else
            buf := buf.push ⟨0x20, by decide⟩
            i := i + 1
        else if n == 0x0A || n == 0x09 || n == 0x20 then
          if buf.size ≥ limits.maxTokenChars then
            err := some (mkError chars i .limitToken "limitToken")
          else
            buf := buf.push ⟨0x20, by decide⟩
            i := i + 1
        else if hc : isXmlChar n = true then
          if buf.size ≥ limits.maxTokenChars then
            err := some (mkError chars i .limitToken "limitToken")
          else
            buf := buf.push c.value
            i := i + 1
        else
          err := some (mkError chars i .invalidToken "illegalXmlChar")
    if err.isNone && !done then
      err := some (mkError chars i .unclosedToken "unclosedAttributeValue")
    match err with
    | some e => return .error e
    | none => return .ok (String.ofList (buf.toList.map (fun s => s.toChar)), i, used)

/-- Scan a comment body. `pos` is just past `<!--`; returns the position after
`-->`. -/
def scanComment (chars : Array DecodedChar) (limits : Limits) (pos : Nat) :
    Except ParseError (String × Nat) :=
  Id.run do
    let mut i := pos
    let mut buf : Array Scalar := #[]
    let mut err : Option ParseError := none
    let mut done := false
    while !done && err.isNone && decide (i < chars.size) do
      match chars[i]? with
      | none => done := true
      | some c =>
        let n := c.value.n
        if n == 0x2D then
          if natAt chars (i + 1) == some 0x2D then
            if natAt chars (i + 2) == some 0x3E then
              i := i + 3
              done := true
            else
              err := some (mkError chars i .invalidToken "doubleHyphenInComment")
          else if buf.size ≥ limits.maxTokenChars then
            err := some (mkError chars i .limitToken "limitToken")
          else
            buf := buf.push c.value
            i := i + 1
        else if n == 0x0D then
          if natAt chars (i + 1) == some 0x0A then
            i := i + 1
          if buf.size ≥ limits.maxTokenChars then
            err := some (mkError chars i .limitToken "limitToken")
          else
            buf := buf.push ⟨0x0A, by decide⟩
            i := i + 1
        else if hc : isXmlChar n = true then
          if buf.size ≥ limits.maxTokenChars then
            err := some (mkError chars i .limitToken "limitToken")
          else
            buf := buf.push c.value
            i := i + 1
        else
          err := some (mkError chars i .invalidToken "illegalXmlChar")
    if err.isNone && !done then
      err := some (mkError chars i .unclosedToken "unclosedComment")
    match err with
    | some e => return .error e
    | none => return .ok (String.ofList (buf.toList.map (fun s => s.toChar)), i)

/-- Scan a CDATA section. `pos` is at the `<` of `<![CDATA[`; returns the
position after `]]>`. -/
def scanCData (chars : Array DecodedChar) (limits : Limits) (pos : Nat) :
    Except ParseError (String × Nat) :=
  Id.run do
    let mut i := pos + 9
    let mut buf : Array Scalar := #[]
    let mut err : Option ParseError := none
    let mut done := false
    while !done && err.isNone && decide (i < chars.size) do
      match chars[i]? with
      | none => done := true
      | some c =>
        let n := c.value.n
        if n == 0x5D && natAt chars (i + 1) == some 0x5D &&
            natAt chars (i + 2) == some 0x3E then
          i := i + 3
          done := true
        else if n == 0x0D then
          if natAt chars (i + 1) == some 0x0A then
            i := i + 1
          if buf.size ≥ limits.maxTokenChars then
            err := some (mkError chars i .limitToken "limitToken")
          else
            buf := buf.push ⟨0x0A, by decide⟩
            i := i + 1
        else if hc : isXmlChar n = true then
          if buf.size ≥ limits.maxTokenChars then
            err := some (mkError chars i .limitToken "limitToken")
          else
            buf := buf.push c.value
            i := i + 1
        else
          err := some (mkError chars i .invalidToken "illegalXmlChar")
    if err.isNone && !done then
      err := some (mkError chars i .unclosedCdataSection "unclosedCdata")
    match err with
    | some e => return .error e
    | none => return .ok (String.ofList (buf.toList.map (fun s => s.toChar)), i)

/-- Scan PI data. `pos` is just past the target. Leading white space is the
separator and is not part of the data, as in Expat. -/
def scanPIData (chars : Array DecodedChar) (limits : Limits) (target : String)
    (pos : Nat) : Except ParseError (String × String × Nat) :=
  Id.run do
    let mut i := pos
    let mut buf : Array Scalar := #[]
    let mut err : Option ParseError := none
    let mut done := false
    if i ≥ chars.size then
      err := some (mkError chars i .unclosedToken "unclosedPi")
    else if natAt chars i == some 0x3F && natAt chars (i + 1) == some 0x3E then
      i := i + 2
      done := true
    else
      match natAt chars i with
      | some n =>
        if isXmlWhitespace n then
          i := skipWhitespace chars i
          while !done && err.isNone && decide (i < chars.size) do
            match chars[i]? with
            | none => done := true
            | some c =>
              let m := c.value.n
              if m == 0x3F && natAt chars (i + 1) == some 0x3E then
                i := i + 2
                done := true
              else if m == 0x0D then
                if natAt chars (i + 1) == some 0x0A then
                  i := i + 1
                if buf.size ≥ limits.maxTokenChars then
                  err := some (mkError chars i .limitToken "limitToken")
                else
                  buf := buf.push ⟨0x0A, by decide⟩
                  i := i + 1
              else if hc : isXmlChar m = true then
                if buf.size ≥ limits.maxTokenChars then
                  err := some (mkError chars i .limitToken "limitToken")
                else
                  buf := buf.push c.value
                  i := i + 1
              else
                err := some (mkError chars i .invalidToken "illegalXmlChar")
        else
          err := some (mkError chars i .invalidToken "piSyntax")
      | none => err := some (mkError chars i .unclosedToken "unclosedPi")
    if err.isNone && !done then
      err := some (mkError chars i .unclosedToken "unclosedPi")
    match err with
    | some e => return .error e
    | none => return .ok (target, String.ofList (buf.toList.map (fun s => s.toChar)), i)

/-- Scan a PI and its data. `pos` is at the `<` of `<?`. -/
def scanPI (chars : Array DecodedChar) (limits : Limits) (pos : Nat) :
    Except ParseError (String × String × Nat) :=
  match scanName chars limits (pos + 2) with
  | .error e => .error e
  | .ok (target, p) => scanPIData chars limits target p

/-- True when the encoding label is an `EncName`: a letter followed by letters,
digits, `.`, `_` or `-`. -/
def validEncName (label : String) : Bool :=
  match label.toList with
  | [] => false
  | c :: rest =>
    isAsciiLetter c.toNat && rest.all (fun d => isAsciiNameChar d.toNat)

/-- Check the declaration's encoding label against the encoding the bytes
actually selected. -/
def checkEncodingLabel (chars : Array DecodedChar) (pos : Nat) (detected : Encoding)
    (label : String) : Except ParseError Unit :=
  match classifyLabel label with
  | .unknown => .error (mkError chars pos .unknownEncoding "unknownEncoding")
  | .utf8 =>
    if detected = .utf8 then .ok () else .error (mkError chars pos .incorrectEncoding "encodingMismatch")
  | .ascii =>
    if detected = .ascii then .ok () else .error (mkError chars pos .incorrectEncoding "encodingMismatch")
  | .latin1 =>
    if detected = .latin1 then .ok () else .error (mkError chars pos .incorrectEncoding "encodingMismatch")
  | .utf16 =>
    if detected = .utf16le ∨ detected = .utf16be then .ok ()
    else .error (mkError chars pos .incorrectEncoding "encodingMismatch")
  | .utf16le =>
    if detected = .utf16le then .ok () else .error (mkError chars pos .incorrectEncoding "encodingMismatch")
  | .utf16be =>
    if detected = .utf16be then .ok () else .error (mkError chars pos .incorrectEncoding "encodingMismatch")

/-- Require at least one white-space character at `pos`, then skip white space. -/
def expectWhitespace (chars : Array DecodedChar) (pos : Nat) : Except ParseError Nat :=
  match natAt chars pos with
  | some n =>
    if isXmlWhitespace n then .ok (skipWhitespace chars pos)
    else .error (mkError chars pos .xmlDecl "xmlDeclWhitespace")
  | none => .error (mkError chars pos .unclosedToken "unclosedXmlDecl")

/-- Parse `Name` of a declaration pseudo-attribute (ASCII letters only). The
token budget is charged before every append, including the first character. -/
def parsePseudoName (chars : Array DecodedChar) (limits : Limits) (pos : Nat) :
    Except ParseError (String × Nat) :=
  Id.run do
    let mut i := pos
    let mut buf : Array Char := #[]
    let mut err : Option ParseError := none
    match natAt chars i with
    | some n =>
      if isAsciiLetter n then
        if buf.size ≥ limits.maxTokenChars then
          err := some (mkError chars i .limitToken "limitToken")
        else
          buf := buf.push (Char.ofNat n)
          i := i + 1
          while err.isNone && i < chars.size do
            match natAt chars i with
            | some m =>
              if isAsciiLetter m then
                if buf.size ≥ limits.maxTokenChars then
                  err := some (mkError chars i .limitToken "limitToken")
                else
                  buf := buf.push (Char.ofNat m)
                  i := i + 1
              else
                break
            | none => break
      else
        err := some (mkError chars i .xmlDecl "xmlDeclName")
    | none => err := some (mkError chars i .unclosedToken "unclosedXmlDecl")
    match err with
    | some e => return .error e
    | none => return .ok (String.ofList buf.toList, i)

/-- Parse `= "value"` of a declaration pseudo-attribute. -/
def parsePseudoValue (chars : Array DecodedChar) (limits : Limits) (pos : Nat) :
    Except ParseError (String × Nat) :=
  Id.run do
    let mut i := skipWhitespace chars pos
    if natAt chars i != some 0x3D then
      return .error (mkError chars i .xmlDecl "xmlDeclEquals")
    i := skipWhitespace chars (i + 1)
    match natAt chars i with
    | some q =>
      if q == 0x22 || q == 0x27 then
        i := i + 1
        let start := i
        let mut err : Option ParseError := none
        while i < chars.size ∧ natAt chars i ≠ some q do
          match natAt chars i with
          | some m =>
            if isXmlChar m then
              if i - start ≥ limits.maxTokenChars then
                err := some (mkError chars i .limitToken "limitToken")
              i := i + 1
            else
              err := some (mkError chars i .xmlDecl "xmlDeclValue")
          | none => pure ()
        if err.isSome then
          return .error (err.getD ⟨.xmlDecl, "xmlDeclValue", 0⟩)
        if i ≥ chars.size then
          return .error (mkError chars i .unclosedToken "unclosedXmlDecl")
        return .ok (charsToString chars start i, i + 1)
      else
        return .error (mkError chars i .xmlDecl "xmlDeclQuote")
    | none => return .error (mkError chars i .unclosedToken "unclosedXmlDecl")

/-- Parse an XML declaration. `pos` is just past the target `xml`. -/
def parseXmlDecl (chars : Array DecodedChar) (limits : Limits) (detected : Encoding)
    (pos : Nat) : Except ParseError (Event × Nat) := do
  let p ← expectWhitespace chars pos
  let (n1, p1) ← parsePseudoName chars limits p
  if n1 != "version" then
    throw (mkError chars p1 .xmlDecl "xmlDeclVersion")
  let (ver, p2) ← parsePseudoValue chars limits p1
  if ver != "1.0" then
    throw (mkError chars p2 .xmlDecl "xmlDeclVersionValue")
  let q := skipWhitespace chars p2
  if q ≥ chars.size then
    throw (mkError chars q .unclosedToken "unclosedXmlDecl")
  if natAt chars q == some 0x3F && natAt chars (q + 1) == some 0x3E then
    return (.xmlDecl "1.0" none none, q + 2)
  if q == p2 then
    throw (mkError chars q .xmlDecl "xmlDeclSeparator")
  let (n2, q1) ← parsePseudoName chars limits q
  if n2 == "standalone" then
    let (sv, q2) ← parsePseudoValue chars limits q1
    let sa ←
      match sv with
      | "yes" => pure true
      | "no" => pure false
      | _ => throw (mkError chars q2 .xmlDecl "xmlDeclStandalone")
    let r := skipWhitespace chars q2
    if r ≥ chars.size then
      throw (mkError chars r .unclosedToken "unclosedXmlDecl")
    if natAt chars r == some 0x3F && natAt chars (r + 1) == some 0x3E then
      return (.xmlDecl "1.0" none (some sa), r + 2)
    throw (mkError chars r .xmlDecl "xmlDeclEnd")
  if n2 != "encoding" then
    throw (mkError chars q1 .xmlDecl "xmlDeclAttribute")
  let (label, q2) ← parsePseudoValue chars limits q1
  if !validEncName label then
    throw (mkError chars q2 .xmlDecl "xmlDeclEncodingName")
  checkEncodingLabel chars q2 detected label
  let r := skipWhitespace chars q2
  if r ≥ chars.size then
    throw (mkError chars r .unclosedToken "unclosedXmlDecl")
  if natAt chars r == some 0x3F && natAt chars (r + 1) == some 0x3E then
    return (.xmlDecl "1.0" (some label) none, r + 2)
  if r == q2 then
    throw (mkError chars r .xmlDecl "xmlDeclSeparator")
  let (n3, r1) ← parsePseudoName chars limits r
  if n3 != "standalone" then
    throw (mkError chars r1 .xmlDecl "xmlDeclAttribute")
  let (sv, r2) ← parsePseudoValue chars limits r1
  let sa ←
    match sv with
    | "yes" => pure true
    | "no" => pure false
    | _ => throw (mkError chars r2 .xmlDecl "xmlDeclStandalone")
  let t := skipWhitespace chars r2
  if t ≥ chars.size then
    throw (mkError chars t .unclosedToken "unclosedXmlDecl")
  if natAt chars t == some 0x3F && natAt chars (t + 1) == some 0x3E then
    return (.xmlDecl "1.0" (some label) (some sa), t + 2)
  throw (mkError chars t .xmlDecl "xmlDeclEnd")

/-- Parse a start tag. `pos` is at the first character of the element name.
Returns the raw name, the attributes in document order, whether the tag was
empty, the position after the tag, and the cumulative reference count.
Attributes are sorted only for duplicate detection; rendering sorts them. -/
def parseStartTag (chars : Array DecodedChar) (limits : Limits) (pos : Nat)
    (entityUsed : Nat) :
    Except ParseError (String × Array (String × String) × Bool × Nat × Nat) :=
  Id.run do
    let mut i := pos
    let mut attrs : Array (String × String) := #[]
    let mut used := entityUsed
    let mut emptyTag := false
    let mut err : Option ParseError := none
    let mut done := false
    let mut name := ""
    match scanName chars limits i with
    | .error e => return .error e
    | .ok (nm, p) =>
      name := nm
      i := p
      while !done && err.isNone do
        let spaceStart := i
        i := skipWhitespace chars i
        let spaced := i > spaceStart
        match natAt chars i with
        | none =>
          err := some (mkError chars i .unclosedToken "unclosedStartTag")
          done := true
        | some n =>
          if n == 0x3E then
            i := i + 1
            done := true
          else if n == 0x2F then
            if natAt chars (i + 1) == some 0x3E then
              i := i + 2
              emptyTag := true
              done := true
            else
              err := some (mkError chars i .invalidToken "badEmptyTag")
              done := true
          else if !spaced then
            err := some (mkError chars i .invalidToken "missingAttributeSeparator")
            done := true
          else
            match scanName chars limits i with
            | .error e =>
              err := some e
              done := true
            | .ok (an, p2) =>
              i := skipWhitespace chars p2
              if natAt chars i != some 0x3D then
                err := some (mkError chars i .invalidToken "missingEquals")
                done := true
              else
                i := skipWhitespace chars (i + 1)
                match natAt chars i with
                | some q =>
                  if q == 0x22 || q == 0x27 then
                    match scanAttrValue chars limits q (i + 1) used with
                    | .error e =>
                      err := some e
                      done := true
                    | .ok (v, p3, used') =>
                      attrs := attrs.push (an, v)
                      used := used'
                      i := p3
                  else
                    err := some (mkError chars i .invalidToken "unquotedAttribute")
                    done := true
                | none =>
                  err := some (mkError chars i .unclosedToken "unclosedStartTag")
                  done := true
    match err with
    | some e => return .error e
    | none =>
      -- Duplicate detection needs an ordering; the event keeps document order.
      let sorted := attrs.qsort (fun a b => a.1 < b.1)
      let mut k := 1
      let mut dup := false
      while k < sorted.size do
        match sorted[k]?, sorted[k - 1]? with
        | some a, some b => if a.1 == b.1 then dup := true
        | _, _ => pure ()
        k := k + 1
      if dup then
        return .error (mkError chars pos .duplicateAttribute "duplicateAttribute")
      else
        return .ok (name, attrs, emptyTag, i, used)

/-- Parse an end tag. `pos` is at the first character of the element name. -/
def parseEndTag (chars : Array DecodedChar) (limits : Limits) (pos : Nat) :
    Except ParseError (String × Nat) :=
  match scanName chars limits pos with
  | .error e => .error e
  | .ok (name, p) =>
    let i := skipWhitespace chars p
    if natAt chars i == some 0x3E then
      .ok (name, i + 1)
    else if i ≥ chars.size then
      .error (mkError chars i .unclosedToken "unclosedEndTag")
    else
      .error (mkError chars i .invalidToken "badEndTag")

/-- Parse the decoded document. `detected` is the encoding the decoder used; it
is checked against the declaration's `encoding` value. -/
def parseChars (chars : Array DecodedChar) (limits : Limits) (detected : Encoding) :
    Except ParseError (Array Event) :=
  Id.run do
    let mut pos := 0
    let mut events : Array Event := #[]
    let mut stack : Array String := #[]
    let mut entityUsed := 0
    let mut phase := Phase.prolog
    let mut err : Option ParseError := none
    while err.isNone do
      if pos ≥ chars.size then
        match phase with
        | .prolog => err := some (mkError chars pos .noElements "noRoot")
        | .content => err := some (mkError chars pos .noElements "unclosedElement")
        | .epilog => pure ()
        break
      match phase with
      | .content =>
        match chars[pos]? with
        | none => break
        | some c =>
          if c.value.n == 0x3C then
            match natAt chars (pos + 1) with
            | none => err := some (mkError chars pos .invalidToken "unexpectedEnd")
            | some n =>
              if n == 0x2F then
                match parseEndTag chars limits (pos + 2) with
                | .error e => err := some e
                | .ok (name, p) =>
                  match stack.back? with
                  | some top =>
                    if top == name then
                      stack := stack.pop
                      events := events.push (.end name)
                      pos := p
                      if stack.isEmpty then
                        phase := .epilog
                    else
                      err := some (mkError chars pos .tagMismatch "tagMismatch")
                  | none =>
                    err := some (mkError chars pos .invalidToken "strayEndTag")
              else if n == 0x3F then
                match scanPI chars limits pos with
                | .error e => err := some e
                | .ok (target, data, p) =>
                  if target == "xml" then
                    err := some (mkError chars pos .misplacedXmlPi "misplacedXmlDecl")
                  else if target.toLower == "xml" then
                    err := some (mkError chars pos .invalidToken "reservedPiTarget")
                  else
                    events := events.push (.pi target data)
                    pos := p
              else if n == 0x21 then
                if matchesAt chars pos [0x3C, 0x21, 0x2D, 0x2D] then
                  match scanComment chars limits (pos + 4) with
                  | .error e => err := some e
                  | .ok (data, p) =>
                    events := events.push (.comment data)
                    pos := p
                else if matchesAt chars pos [0x3C, 0x21, 0x5B, 0x43, 0x44, 0x41, 0x54, 0x41, 0x5B] then
                  match scanCData chars limits pos with
                  | .error e => err := some e
                  | .ok (data, p) =>
                    events := events.push .cdataStart
                    if data.length > 0 then
                      events := events.push (.text data)
                    events := events.push .cdataEnd
                    pos := p
                else if matchesAt chars pos [0x3C, 0x21, 0x44, 0x4F, 0x43, 0x54, 0x59, 0x50, 0x45] then
                  err := some (mkError chars pos .unsupportedDtd "unsupportedDtd")
                else
                  err := some (mkError chars pos .invalidToken "unknownMarkup")
              else
                match parseStartTag chars limits (pos + 1) entityUsed with
                | .error e => err := some e
                | .ok (name, attrs, emptyTag, p, used) =>
                  entityUsed := used
                  if !emptyTag && stack.size ≥ limits.maxDepth then
                    err := some (mkError chars pos .limitDepth "limitDepth")
                  else
                    events := events.push (.start name attrs)
                    if emptyTag then
                      events := events.push (.end name)
                      pos := p
                    else
                      stack := stack.push name
                      pos := p
          else
            match scanText chars limits pos entityUsed with
            | .error e => err := some e
            | .ok (data, p, used) =>
              if data.length > 0 then
                events := events.push (.text data)
              entityUsed := used
              pos := p
      | .prolog =>
        pos := skipWhitespace chars pos
        if pos < chars.size then
          match chars[pos]? with
          | none => pure ()
          | some c =>
            if c.value.n != 0x3C then
              err := some (mkError chars pos .invalidToken "textBeforeRoot")
            else
              match natAt chars (pos + 1) with
              | none => err := some (mkError chars pos .invalidToken "unexpectedEnd")
              | some n =>
                if n == 0x3F then
                  match scanName chars limits (pos + 2) with
                  | .error e => err := some e
                  | .ok (target, p) =>
                    if target == "xml" then
                      if pos == 0 then
                        match parseXmlDecl chars limits detected p with
                        | .error e => err := some e
                        | .ok (ev, p2) =>
                          events := events.push ev
                          pos := p2
                      else
                        err := some (mkError chars pos .misplacedXmlPi "misplacedXmlDecl")
                    else if target.toLower == "xml" then
                      err := some (mkError chars pos .invalidToken "reservedPiTarget")
                    else
                      match scanPIData chars limits target p with
                      | .error e => err := some e
                      | .ok (tg, data, p2) =>
                        events := events.push (.pi tg data)
                        pos := p2
                else if n == 0x21 then
                  if matchesAt chars pos [0x3C, 0x21, 0x2D, 0x2D] then
                    match scanComment chars limits (pos + 4) with
                    | .error e => err := some e
                    | .ok (data, p) =>
                      events := events.push (.comment data)
                      pos := p
                  else if matchesAt chars pos [0x3C, 0x21, 0x44, 0x4F, 0x43, 0x54, 0x59, 0x50, 0x45] then
                    err := some (mkError chars pos .unsupportedDtd "unsupportedDtd")
                  else
                    err := some (mkError chars pos .syntax "unknownMarkup")
                else if n == 0x2F then
                  err := some (mkError chars pos .invalidToken "strayEndTag")
                else
                  match parseStartTag chars limits (pos + 1) entityUsed with
                  | .error e => err := some e
                  | .ok (name, attrs, emptyTag, p, used) =>
                    entityUsed := used
                    if !emptyTag && stack.size ≥ limits.maxDepth then
                      err := some (mkError chars pos .limitDepth "limitDepth")
                    else
                      events := events.push (.start name attrs)
                      if emptyTag then
                        events := events.push (.end name)
                        pos := p
                        phase := .epilog
                      else
                        stack := stack.push name
                        pos := p
                        phase := .content
      | .epilog =>
        pos := skipWhitespace chars pos
        if pos < chars.size then
          match chars[pos]? with
          | none => pure ()
          | some c =>
            if c.value.n != 0x3C then
              err := some (mkError chars pos .junkAfterDocElement "textAfterRoot")
            else
              match natAt chars (pos + 1) with
              | none => err := some (mkError chars pos .junkAfterDocElement "junkAfterRoot")
              | some n =>
                if n == 0x3F then
                  match scanPI chars limits pos with
                  | .error e => err := some e
                  | .ok (target, data, p) =>
                    if target == "xml" then
                      err := some (mkError chars pos .misplacedXmlPi "misplacedXmlDecl")
                    else if target.toLower == "xml" then
                      err := some (mkError chars pos .invalidToken "reservedPiTarget")
                    else
                      events := events.push (.pi target data)
                      pos := p
                else if n == 0x21 then
                  if matchesAt chars pos [0x3C, 0x21, 0x2D, 0x2D] then
                    match scanComment chars limits (pos + 4) with
                    | .error e => err := some e
                    | .ok (data, p) =>
                      events := events.push (.comment data)
                      pos := p
                  else
                    err := some (mkError chars pos .junkAfterDocElement "junkAfterRoot")
                else if n == 0x2F then
                  err := some (mkError chars pos .invalidToken "strayEndTag")
                else
                  err := some (mkError chars pos .junkAfterDocElement "junkAfterRoot")
    match err with
    | some e => return .error e
    | none => return .ok events

/-- Parse one complete XML 1.0 document from raw bytes under explicit budgets.
Pure, total, one-shot, and free of global state. -/
def parseDocument (bytes : ByteArray) (limits : Limits := {}) :
    Except ParseError (Array Event) :=
  if bytes.size > limits.maxInputBytes then
    .error ⟨.limitInput, "limitInput", 0⟩
  else
    match decodeDocument bytes limits with
    | .error e => .error ⟨e.reason.code, e.reason.name, e.offset⟩
    | .ok d => parseChars d.chars limits d.encoding

end LexPat
