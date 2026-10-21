import LexPat
/-!
`lexpatTrace` — a bounded demonstration and differential fixture.

It reads one binary XML file under the library's default budgets and writes
deterministic JSON Lines to standard output. Every object carries `"format":1`.

The default mode is the one-shot trace: the whole file is parsed and either the
document's events or a single error result is printed. The structural
`--chunk-size` modes feed the same bytes to `LexPat.Stream` and print each
event as soon as it is returned, so they demonstrate the resumable core and
chunk-boundary invariance. A rejected stream may already have printed prefix
events; the one-shot mode cannot.

This executable is a demonstration and differential fixture, not a production
integration route. `LexPat.parseDocument` and `LexPat.Stream` exist for
inspection and later design, not as supported integration routes. The separate
C ABI artifact (`include/expat.h` and `liblexpat.so.1`) is a verified integration
route for its documented `XML_*` subset; this executable does not use it and
defines no C entry point.
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
    "       lexpatTrace --chunk-size N <file>\n" ++
    "       lexpatTrace --chunk-size whole <file>\n" ++
    "       lexpatTrace --chunk-size N --chunk-seed SEED <file>\n" ++
    "       lexpatTrace --help\n" ++
    "\n" ++
    "Reads one binary XML file and writes JSON Lines to stdout.\n" ++
    "The default and whole modes read at most 8388609 bytes; numeric and\n" ++
    "seeded modes read 64 KiB blocks and stop once the stream is terminal.\n" ++
    "Every object carries \"format\":1; the last object is a result.\n" ++
    "Exit status: 0 accepted, 1 rejected, 2 usage or I/O error.\n"

def help : String :=
  usage ++ "\n" ++
    "modes:\n" ++
    "  <file>                    one-shot parse (the default trace)\n" ++
    "  --chunk-size N             feed the file in N-byte chunks;\n" ++
    "                             N is a decimal integer in [1,65536]\n" ++
    "  --chunk-size whole         feed the file in one chunk\n" ++
    "  --chunk-size N --chunk-seed SEED\n" ++
    "                             N as above and SEED a decimal integer in\n" ++
    "                             [0,4294967295]; lengths vary per feed:\n" ++
    "                             s := (1664525*s + 1013904223) mod 4294967296\n" ++
    "                             once per feed, then length 1 + s mod N\n" ++
    "                             (a final shorter chunk may carry the tail)\n" ++
    "  A nondecimal or out-of-range number, --chunk-seed without a numeric\n" ++
    "  --chunk-size, and --chunk-size whole with --chunk-seed are usage\n" ++
    "  errors (exit 2); no flag is silently ignored.\n" ++
    "\n" ++
    "Streaming modes print each event as it is returned and then one result.\n" ++
    "A rejected stream may already have printed prefix events; the one-shot\n" ++
    "mode returns no event array on rejection.\n" ++
    "\n" ++
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
    "  namespace URI processing, other encodings, XML 1.1 and C calls outside\n" ++
    "  the documented include/expat.h subset.\n" ++
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

/-- Fill a block of `want` bytes, or stop at end of file. Short incidental
reads do not change the partition. -/
def readBlock (h : IO.FS.Handle) (want : Nat) : IO ByteArray := do
  let mut acc : ByteArray := ByteArray.empty
  let mut done := false
  while !done && acc.size < want do
    let need := want - acc.size
    let chunk ← h.read (USize.ofNat need)
    if chunk.size == 0 then
      done := true
    else
      acc := acc ++ chunk
  return acc

def printEvents (stdout : IO.FS.Stream) (evs : Array Event) : IO Unit := do
  for ev in evs do
    stdout.putStr (renderEvent ev ++ "\n")

/-- Print the terminal result and exit 1 when it is an error. `finish` is
inert on an already terminal stream, so one result is always printed. -/
def finishAndPrint (stdout : IO.FS.Stream) (st : Stream) : IO Unit := do
  let (st2, evs) := Stream.finish st
  printEvents stdout evs
  match Stream.result st2 with
  | some (.ok ()) =>
    stdout.putStr (renderResultOk ++ "\n")
    stdout.flush
  | some (.error e) =>
    stdout.putStr (renderResultError e ++ "\n")
    stdout.flush
    IO.Process.exit 1
  | none =>
    IO.eprintln "lexpatTrace: stream did not finish"
    IO.Process.exit 2

/-- The default one-shot trace. -/
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

/-- One feed of the whole bounded input. -/
def runWhole (path : System.FilePath) : IO Unit := do
  let limits : Limits := {}
  let cap := limits.maxInputBytes + 1
  let bytes ←
    try
      readBounded path cap
    catch e =>
      IO.eprintln s!"lexpatTrace: cannot read {path}: {e}"
      IO.Process.exit 2
  let stdout ← IO.getStdout
  let (st, evs) := Stream.feed (Stream.new limits) bytes
  printEvents stdout evs
  finishAndPrint stdout st

/-- Feed fixed `size`-byte chunks assembled from 64 KiB IO blocks. -/
def runFixed (path : System.FilePath) (size : Nat) : IO Unit := do
  let stdout ← IO.getStdout
  let limits : Limits := {}
  let st ←
    try
      IO.FS.withFile path .read fun h => do
        let mut state := Stream.new limits
        let mut carry : ByteArray := ByteArray.empty
        let mut done := false
        while !done do
          let block ← readBlock h 65536
          let data := carry ++ block
          let mut pos := 0
          let mut stop := false
          while !stop && data.size - pos ≥ size do
            let piece := data.extract pos (pos + size)
            pos := pos + size
            let (state1, evs) := Stream.feed state piece
            state := state1
            printEvents stdout evs
            match Stream.result state with
            | some _ => stop := true
            | none => pure ()
          carry := data.extract pos data.size
          if block.size == 0 then
            if !stop && carry.size > 0 then
              let (state1, evs) := Stream.feed state carry
              state := state1
              printEvents stdout evs
            done := true
          else if stop then
            done := true
        return state
    catch e =>
      IO.eprintln s!"lexpatTrace: cannot read {path}: {e}"
      IO.Process.exit 2
  finishAndPrint stdout st

/-- Feed chunks whose length is drawn from the specified PRNG rule. -/
def runSeeded (path : System.FilePath) (size seed : Nat) : IO Unit := do
  let stdout ← IO.getStdout
  let limits : Limits := {}
  let st ←
    try
      IO.FS.withFile path .read fun h => do
        let mut state := Stream.new limits
        let mut carry : ByteArray := ByteArray.empty
        let mut prng := seed
        let mut done := false
        while !done do
          let block ← readBlock h 65536
          let data := carry ++ block
          let mut pos := 0
          let mut stop := false
          while !stop do
            let nextPrng := (1664525 * prng + 1013904223) % 4294967296
            let len := 1 + nextPrng % size
            if data.size - pos ≥ len then
              prng := nextPrng
              let piece := data.extract pos (pos + len)
              pos := pos + len
              let (state1, evs) := Stream.feed state piece
              state := state1
              printEvents stdout evs
              match Stream.result state with
              | some _ => stop := true
              | none => pure ()
            else
              stop := true
          carry := data.extract pos data.size
          if block.size == 0 then
            if carry.size > 0 then
              prng := (1664525 * prng + 1013904223) % 4294967296
              let (state1, evs) := Stream.feed state carry
              state := state1
              printEvents stdout evs
            done := true
          else
            match Stream.result state with
            | some _ => done := true
            | none => pure ()
        return state
    catch e =>
      IO.eprintln s!"lexpatTrace: cannot read {path}: {e}"
      IO.Process.exit 2
  finishAndPrint stdout st

/-- A decimal integer, or `none` for empty, signed, or nondecimal text. -/
def parseDecimal (s : String) : Option Nat :=
  if s.isEmpty then none
  else
    Id.run do
      let mut acc := 0
      let mut ok := true
      for c in s.toList do
        let d := c.toNat
        if d < 0x30 || d > 0x39 then
          ok := false
        else
          acc := acc * 10 + (d - 0x30)
      if ok then return some acc else return none

/-- The structural chunk modes accepted on the command line. -/
inductive ChunkSpec where
  | whole
  | fixed (size : Nat)
  | seeded (size : Nat) (seed : Nat)
deriving Repr

/-- Parse `--chunk-size`/`--chunk-seed` arguments. Any unsupported combination
is a usage error rather than an ignored flag. -/
def parseChunkSpec (sizeArg : String) (seedArg : Option String) : Option ChunkSpec :=
  if sizeArg == "whole" then
    match seedArg with
    | none => some .whole
    | some _ => none
  else
    match parseDecimal sizeArg with
    | some n =>
      if n ≥ 1 && n ≤ 65536 then
        match seedArg with
        | none => some (.fixed n)
        | some seedText =>
          match parseDecimal seedText with
          | some seed => if seed ≤ 4294967295 then some (.seeded n seed) else none
          | none => none
      else none
    | none => none

def usageError : IO Unit := do
  IO.eprintln usage
  IO.Process.exit 2

def runMain (args : List String) : IO Unit := do
  match args with
  | ["--help"] =>
    let stdout ← IO.getStdout
    stdout.putStr help
    stdout.flush
  | [path] => runFile path
  | ["--chunk-size", sizeArg, path] =>
    match parseChunkSpec sizeArg none with
    | some .whole => runWhole path
    | some (.fixed n) => runFixed path n
    | some (.seeded _ _) => usageError
    | none => usageError
  | ["--chunk-size", sizeArg, "--chunk-seed", seedArg, path] =>
    match parseChunkSpec sizeArg (some seedArg) with
    | some (.seeded n seed) => runSeeded path n seed
    | some .whole => usageError
    | some (.fixed _) => usageError
    | none => usageError
  | _ => usageError

end LexPat.Trace

/-- Entry point. Lean's executable wrapper looks for `main` at the root of the
root module, not inside the module's namespace. -/
def main (args : List String) : IO Unit := LexPat.Trace.runMain args
