import LexPat
import Lean.Data.Json

/-!
Independent expected raw events and attribute order.

`tests/streaming.py` expands the explicit event recipes in
`tests/corpus/cases.json`, applies the checked-in order overlay
`tests/corpus/raw-attribute-order.json` to every start event with two or more
attributes, and writes the result to a temporary JSON file. The expected arrays
therefore come from the fixtures and the overlay: neither the rendered JSON
trace (which sorts attributes) nor this parser produced them.

This driver reads that file and compares all nine partitions of every accepted
input (`whole`, fixed sizes 1, 2, 3, 5, 7, 13 and 64, and one seeded partition)
positionally against the typed `Array Event`. The one-shot `parseDocument`
result is also compared, as a secondary check: it is a consumer of the same
stream, so it can never be the source of the expectation.

Two controls use the same comparator: the unmodified expected array must
compare equal to the events the whole-input partition returned, and reversing
the attributes of an expected multi-attribute start must be detected.

The expected file is created by `python3 tests/streaming.py`; it is not a
shipped input, so no standalone command is documented for it.
-/

namespace LexPat.StreamingEvents

open Lean (Json)
open LexPat

def fail {α : Type} (message : String) : IO α :=
  throw (IO.userError message)

def orThrow {α : Type} : Except String α → IO α
  | .ok a => pure a
  | .error e => throw (IO.userError e)

/-- The largest IO block the chunked CLI assembles before splitting it under
`--chunk-seed`; the seeded partition here reproduces that rule. -/
def blockSize : Nat := 65536

/-- Fixed and seeded partition sizes the external harness also runs. -/
def fixedSizes : List Nat := [1, 2, 3, 5, 7, 13, 64]

def seededSize : Nat := 64

/-- How the driver delivers one input's bytes. -/
inductive Partition where
  | whole
  | fixed (size : Nat)
  | seeded (seed : Nat)

def partitionLabel : Partition → String
  | .whole => "whole"
  | .fixed size => s!"size-{size}"
  | .seeded seed => s!"seeded-{seed}"

def partitions (seed : Nat) : List Partition :=
  [.whole] ++ fixedSizes.map Partition.fixed ++ [.seeded seed]

private def collect (st : Stream) (events : Array Event) : Stream × Array Event :=
  let (st2, tail) := Stream.finish st
  Id.run do
    let mut out := events
    for e in tail do
      out := out.push e
    return (st2, out)

/-- Feed one chunk, stopping at a terminal result, and finish. -/
private def feedOne (st : Stream) (out : Array Event) (chunk : ByteArray) :
    Stream × Array Event × Bool :=
  let (st1, evs) := Stream.feed st chunk
  let out1 := Id.run do
    let mut acc := out
    for e in evs do acc := acc.push e
    return acc
  match Stream.result st1 with
  | some _ => (st1, out1, true)
  | none => (st1, out1, false)

/-- Fixed-size chunks over the whole input, with a final shorter chunk. -/
private def runFixed (data : ByteArray) (size : Nat) : Stream × Array Event :=
  Id.run do
    let mut st := Stream.new
    let mut out : Array Event := #[]
    let mut pos := 0
    let mut stop := false
    while !stop && pos < data.size do
      let n := min size (data.size - pos)
      let (st1, out1, terminal) := feedOne st out (data.extract pos (pos + n))
      st := st1
      out := out1
      pos := pos + n
      stop := terminal
    return collect st out

/-- The CLI's seeded rule: draw a length once per actual feed, assembling at
most `blockSize` bytes per IO block and carrying the remainder forward. -/
private def runSeeded (data : ByteArray) (size seed : Nat) : Stream × Array Event :=
  Id.run do
    let mut st := Stream.new
    let mut out : Array Event := #[]
    let mut carry : ByteArray := ByteArray.empty
    let mut prng := seed
    let mut off := 0
    let mut done := false
    while !done do
      let block := data.extract off (min data.size (off + blockSize))
      off := off + block.size
      let full := carry ++ block
      let mut pos := 0
      let mut stop := false
      while !stop do
        let next := (1664525 * prng + 1013904223) % 4294967296
        let len := 1 + next % size
        if full.size - pos ≥ len then
          prng := next
          let (st1, out1, terminal) := feedOne st out (full.extract pos (pos + len))
          st := st1
          out := out1
          pos := pos + len
          stop := terminal
        else
          stop := true
      carry := full.extract pos full.size
      if block.size == 0 then
        if carry.size > 0 then
          let (st1, out1, _) := feedOne st out carry
          st := st1
          out := out1
        done := true
      else
        match Stream.result st with
        | some _ => done := true
        | none => pure ()
    return collect st out

def runPartition (data : ByteArray) (part : Partition) : Stream × Array Event :=
  match part with
  | .whole =>
    let (st, events) := Stream.feed (Stream.new {}) data
    collect st events
  | .fixed size => runFixed data size
  | .seeded seed => runSeeded data seededSize seed

/-- A summary of the expected event array. -/
structure Summary where
  starts : Nat := 0
  multiAttributeStarts : Nat := 0

def summarize (events : Array Event) : Summary :=
  Id.run do
    let mut out : Summary := {}
    for e in events do
      match e with
      | .start _ attrs =>
        out := { out with starts := out.starts + 1 }
        if attrs.size ≥ 2 then
          out := { out with multiAttributeStarts := out.multiAttributeStarts + 1 }
      | _ => pure ()
    return out

def hasMultiAttribute (e : Event) : Bool :=
  match e with
  | .start _ attrs => attrs.size ≥ 2
  | _ => false

/-- The typed comparison: two event arrays are the same exactly when they are
equal positionally, including every attribute array's order. -/
def differs (expected actual : Array Event) : Bool := expected != actual

private def firstDifference (actual expected : Array Event) : String :=
  Id.run do
    let n := min actual.size expected.size
    let mut i := 0
    while i < n do
      match actual[i]?, expected[i]? with
      | some a, some e =>
        if a != e then
          return s!"event {i}: actual {repr a} != expected {repr e}"
      | _, _ => pure ()
      i := i + 1
    return s!"event counts: actual {actual.size} != expected {expected.size}"

private def checkEvents (label : String) (expected actual : Array Event) : IO Unit := do
  if differs expected actual then
    fail (label ++ " differs from the independently declared expected events: " ++
      firstDifference actual expected)

private def jsonString (s : String) : String := "\"" ++ s ++ "\""

/-- Read one expected event. Start attributes arrive as an ordered array of
key/value pairs, so their order is the declared order. -/
def parseEvent (j : Json) : Except String Event := do
  let kind ← j.getObjValAs? String "type"
  match kind with
  | "xmlDecl" =>
    let version ← j.getObjValAs? String "version"
    let encoding ← j.getObjValAs? (Option String) "encoding"
    let standalone ← j.getObjValAs? (Option Bool) "standalone"
    pure (.xmlDecl version encoding standalone)
  | "start" =>
    let name ← j.getObjValAs? String "name"
    let pairs ← j.getObjValAs? (Array (Array String)) "attributes"
    let attrs ← pairs.mapM fun pair =>
      match pair.toList with
      | [key, value] => pure (key, value)
      | other => throw s!"start attribute {repr other} is not a key/value pair"
    pure (.start name attrs)
  | "end" => return .end (← j.getObjValAs? String "name")
  | "text" => return .text (← j.getObjValAs? String "data")
  | "cdataStart" => pure .cdataStart
  | "cdataEnd" => pure .cdataEnd
  | "comment" => return .comment (← j.getObjValAs? String "data")
  | "pi" =>
    let target ← j.getObjValAs? String "target"
    let data ← j.getObjValAs? String "data"
    pure (.pi target data)
  | other => throw s!"unknown expected event type {other}"

/-- Read the whole expected-event file: format 1 and one typed array per accepted
case ID. -/
def parseExpected (path : System.FilePath) : IO (Array (String × Array Event)) := do
  let text ← IO.FS.readFile path
  let json ← orThrow (Json.parse text)
  let format ← orThrow (json.getObjValAs? Nat "format")
  if format != 1 then
    throw (IO.userError s!"{path}: expected \"format\":1, got {format}")
  let cases ← orThrow (json.getObjValAs? Json "cases")
  let entries ← orThrow (cases.getObj?)
  let parsed ← entries.toList.mapM fun (id, value) => do
    let array ← orThrow (value.getArr?)
    let events ← array.mapM fun event => orThrow (parseEvent event)
    pure (id, events)
  return parsed.toArray

/-- Reverse the first expected start whose attribute array has two or more
entries; every XML document orders distinct attribute names, so the result can
never equal the unmodified array. -/
def reverseFirstMultiAttribute (events : Array Event) : Array Event :=
  Id.run do
    let mut done := false
    let mut out : Array Event := #[]
    for e in events do
      match e with
      | .start name attrs =>
        if !done && attrs.size ≥ 2 then
          done := true
          out := out.push (.start name attrs.reverse)
        else out := out.push e
      | _ => out := out.push e
    return out

/-- Compare every partition of one accepted input with its independently
declared expected events, then the one-shot wrapper as a secondary check. -/
def checkFile (id : String) (path : System.FilePath) (seed : Nat)
    (expected : Array Event) : IO Unit := do
  let data ← IO.FS.readBinFile path
  for part in partitions seed do
    let (st, events) := runPartition data part
    match Stream.result st with
    | some (.ok ()) => checkEvents s!"{id}: {partitionLabel part}" expected events
    | some (.error e) =>
      fail s!"{id}: {partitionLabel part} rejected as {e.code.name}/{e.reason}"
    | none => fail s!"{id}: {partitionLabel part} did not finish"
  match parseDocument data {} with
  | .ok events => checkEvents s!"{id}: one-shot (secondary)" expected events
  | .error e =>
    fail s!"{id}: one-shot rejected an accepted input as {e.code.name}/{e.reason}"
  let summary := summarize expected
  IO.println ("{\"id\":" ++ jsonString id ++ ",\"ok\":true" ++
    ",\"partitions\":" ++ toString (partitions seed).length ++
    ",\"starts\":" ++ toString summary.starts ++
    ",\"multiAttributeStarts\":" ++ toString summary.multiAttributeStarts ++ "}")
  if expected.any hasMultiAttribute then
    let (st, whole) := runPartition data .whole
    match Stream.result st with
    | some (.ok ()) =>
      checkEvents s!"{id}: control (unmodified)" expected whole
      IO.println ("{\"control\":\"expected-events\",\"id\":" ++ jsonString id ++
        ",\"equal\":true}")
      if !differs (reverseFirstMultiAttribute expected) whole then
        fail s!"{id}: control: the reversed expected attribute array was not detected"
      IO.println ("{\"control\":\"expected-attribute-order\",\"id\":" ++ jsonString id ++
        ",\"reversedDetected\":true}")
    | _ => fail s!"{id}: control whole-input partition did not finish"

def parseArgument (arg : String) : Except String (String × System.FilePath × Nat) :=
  match arg.splitOn "=" with
  | [id, path, seed] =>
    match seed.toNat? with
    | some n => .ok (id, path, n)
    | none => .error s!"{arg}: seed is not a decimal integer"
  | _ => .error s!"{arg}: expected id=path=seed"

def usage : String := "usage: lexpatEvents --expected EVENTS.json id=path=seed ..."

def main (args : List String) : IO Unit := do
  try
    let (expectedPath, rest) ←
      match args with
      | "--expected" :: path :: rest => pure (path, rest)
      | _ => fail usage
    if rest.isEmpty then fail usage
    let expected ← parseExpected expectedPath
    if !(expected.any fun entry => entry.2.any hasMultiAttribute) then
      fail s!"{expectedPath}: no expected multi-attribute start to reorder"
    let mut files : Array (String × System.FilePath × Nat) := #[]
    for arg in rest do
      match parseArgument arg with
      | .ok (id, path, seed) =>
        if files.any (fun entry => entry.1 == id) then
          fail s!"{arg}: duplicate case id"
        files := files.push (id, path, seed)
      | .error message => fail message
    if files.size != expected.size then
      fail s!"{expectedPath}: {expected.size} expected event arrays for {files.size} inputs"
    for entry in files do
      let id := entry.1
      match expected.find? (fun pair => pair.1 == id) with
      | some (_, events) => checkFile id entry.2.1 entry.2.2 events
      | none => fail s!"{id}: no expected event array in {expectedPath}"
    (← IO.getStdout).flush
  catch e =>
    (← IO.getStdout).flush
    IO.eprintln s!"StreamingEvents: {e}"
    IO.Process.exit 1

end LexPat.StreamingEvents

def main (args : List String) : IO Unit := LexPat.StreamingEvents.main args
