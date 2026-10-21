import LexPat
/-!
`lexpatTrace` — a bounded demonstration and differential fixture.

It reads one binary XML file under the library's default budgets and writes
deterministic JSON Lines to standard output. Every object carries `"format":1`.
It is not a production integration route, and neither is any other surface in
this milestone: `LexPat.parseDocument` is the library's entry point for
inspection and later design, not a supported integration route. This executable
exists so documents and their traces can be compared against libexpat.
-/


namespace LexPat.Trace

/-- Lower-case hexadecimal digit. -/
def hexDigitChar (n : Nat) : Char :=
  if n < 10 then Char.ofNat (0x30 + n) else Char.ofNat (0x61 + n - 10)

def escapeChar (c : Char) : List Char :=
  if c == '"' then ['\\', '"']
  else if c == '\\' then ['\\', '\\']
  else if c == '\n' then ['\\', 'n']
  else if c == '\r' then ['\\', 'r']
  else if c == '\t' then ['\\', 't']
  else if c.toNat < 0x20 then
    ['\\', 'u', '0', '0', hexDigitChar (c.toNat / 16), hexDigitChar (c.toNat % 16)]
  else [c]

def needsEscape (c : Char) : Bool :=
  c == '"' || c == '\\' || decide (c.toNat < 0x20)

/-- JSON string escaping. Input without special characters is returned as is. -/
def escapeJson (s : String) : String :=
  if s.toList.any needsEscape then
    String.ofList (s.toList.flatMap escapeChar)
  else
    s

def jsonString (s : String) : String := "\"" ++ escapeJson s ++ "\""

def renderStandalone : Option Bool → String
  | none => "null"
  | some true => "true"
  | some false => "false"

/-- Render an attribute object with keys sorted by raw name.

The event carries attributes in document order; sorting here is what makes the
rendered trace independent of the order the document wrote them in. -/
def renderAttributes (attrs : Array (String × String)) : String :=
  let ordered := attrs.qsort (fun a b => a.1 < b.1)
  "{" ++
    String.intercalate ","
      (ordered.toList.map fun (k, v) => jsonString k ++ ":" ++ jsonString v) ++
    "}"

def renderEvent : Event → String
  | .xmlDecl version enc standalone =>
    "{\"format\":1,\"type\":\"xmlDecl\",\"version\":" ++ jsonString version ++
      ",\"encoding\":" ++
      (match enc with
        | some e => jsonString e
        | none => "null") ++
      ",\"standalone\":" ++ renderStandalone standalone ++ "}"
  | .start name attrs =>
    "{\"format\":1,\"type\":\"start\",\"name\":" ++ jsonString name ++
      ",\"attributes\":" ++ renderAttributes attrs ++ "}"
  | .end name => "{\"format\":1,\"type\":\"end\",\"name\":" ++ jsonString name ++ "}"
  | .text data => "{\"format\":1,\"type\":\"text\",\"data\":" ++ jsonString data ++ "}"
  | .cdataStart => "{\"format\":1,\"type\":\"cdataStart\"}"
  | .cdataEnd => "{\"format\":1,\"type\":\"cdataEnd\"}"
  | .comment data => "{\"format\":1,\"type\":\"comment\",\"data\":" ++ jsonString data ++ "}"
  | .pi target data =>
    "{\"format\":1,\"type\":\"pi\",\"target\":" ++ jsonString target ++
      ",\"data\":" ++ jsonString data ++ "}"

def renderResultOk : String := "{\"format\":1,\"type\":\"result\",\"ok\":true}"

def renderResultError (e : ParseError) : String :=
  "{\"format\":1,\"type\":\"result\",\"ok\":false,\"code\":" ++ jsonString e.code.name ++
    ",\"reason\":" ++ jsonString e.reason ++ "}"

def usage : String :=
  "usage: lexpatTrace <file>\n" ++
    "       lexpatTrace --help\n" ++
    "\n" ++
    "Reads at most 8388609 bytes of <file> and writes JSON Lines to stdout.\n" ++
    "Every object carries \"format\":1; the last object is a result.\n" ++
    "Exit status: 0 accepted, 1 rejected, 2 usage or I/O error.\n"

def help : String :=
  usage ++ "\n" ++
    "limits (defaults, not configurable by this executable):\n" ++
    "  raw input              8388608 bytes\n" ++
    "  one name/value/text/  1048576 characters\n" ++
    "  comment/CDATA/PI\n" ++
    "  open elements          256\n" ++
    "  reference expansion    1048576 characters\n" ++
    "\n" ++
    "supported XML subset:\n" ++
    "  XML declaration version 1.0 with optional encoding and standalone;\n" ++
    "  UTF-8, UTF-16LE/BE (BOM or zero-byte signature), ISO-8859-1 and\n" ++
    "  US-ASCII; elements, attributes, text, CDATA, comments, processing\n" ++
    "  instructions; the predefined entities and numeric character references.\n" ++
    "\n" ++
    "not supported (rejected, never simulated):\n" ++
    "  DOCTYPE and any DTD, non-predefined named entities, external entities,\n" ++
    "  namespace URI processing, other encodings, XML 1.1, streaming input,\n" ++
    "  and the C API.\n" ++
    "\n" ++
    "This executable is a demonstration and differential fixture, not a\n" ++
    "supported production integration route.\n"

/-- Read at most `cap` bytes. An oversized file is detected without being
loaded in full: only `cap` bytes ever reach memory, and the library's own input
budget then rejects the document before decoding. -/
def readBounded (path : System.FilePath) (cap : Nat) : IO ByteArray :=
  IO.FS.withFile path .read fun h => do
    let mut acc : Array UInt8 := Array.mkEmpty 65536
    let mut done := false
    while !done && acc.size < cap do
      let want := cap - acc.size
      let chunkSize := if want < 65536 then want else 65536
      let chunk ← h.read (USize.ofNat chunkSize)
      if chunk.size == 0 then
        done := true
      else
        for i in [0:chunk.size] do
          match chunk[i]? with
          | some b => acc := acc.push b
          | none => pure ()
    return ByteArray.mk acc

def runFile (path : System.FilePath) : IO Unit := do
  let limits : Limits := {}
  let cap := limits.maxInputBytes + 1
  let bytes ←
    try
      readBounded path cap
    catch e =>
      IO.eprintln s!"lexpatTrace: cannot read {path}: {e}"
      IO.Process.exit 2
  let stdout ← IO.getStdout
  match parseDocument bytes limits with
  | .ok events =>
    for ev in events do
      stdout.putStr (renderEvent ev ++ "\n")
    stdout.putStr (renderResultOk ++ "\n")
    stdout.flush
  | .error e =>
    stdout.putStr (renderResultError e ++ "\n")
    stdout.flush
    IO.Process.exit 1

def runMain (args : List String) : IO Unit := do
  match args with
  | ["--help"] =>
    let stdout ← IO.getStdout
    stdout.putStr help
    stdout.flush
  | [path] => runFile path
  | _ =>
    IO.eprintln usage
    IO.Process.exit 2

end LexPat.Trace

/-- Entry point. Lean's executable wrapper looks for `main` at the root of the
root module, not inside the module's namespace. -/
def main (args : List String) : IO Unit := LexPat.Trace.runMain args
