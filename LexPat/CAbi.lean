/-
The C ABI bridge.

This module is the Lean side of the `liblexpat.so.1` artifact. It
turns each `LocatedEvent` the streaming core determines into one self-contained
versioned byte frame and hands that frame to a receiver compiled into the same
shared object. The receiver dispatches the parsed event to the C handlers the
application registered; no Lean constructor tags, object shapes or globals are
visible to the client.

The wire format (version 1) is:

```
"LXEV" | version:u8 | tag:u8 | reserved:u16 | length:u32
       | byteOffset:u64 | line:u64 | column:u64 | tokenBytes:u32
       | attributePairs:u32 | payload
```

All integers are little-endian and `length` includes the 44-byte header. Event
tags are `0` XML declaration, `1` start, `2` end, `3` text, `4` CDATA start,
`5` CDATA end, `6` comment, `7` processing instruction. Payload strings are a
`u32` byte length followed by exact UTF-8 bytes; a declaration's optional
encoding is a presence byte followed by its string, and its standalone value is
a signed byte `-1`, `0` or `1`. Start payload is the element name followed by a
`u32` pair count and the name/value strings in source order. A frame longer
than 16 MiB is refused rather than truncated.
-/
import LexPat.Stream

namespace LexPat.CAbi

/-- Hand one frame to the C receiver. Returns `0` to continue and nonzero when
the receiver aborted the parse. -/
@[extern "lexpat_cabi_emit_frame"]
opaque emitFrame (frame : ByteArray) : UInt64

/-- Report that a serialized event exceeded the 16 MiB frame bound; the
receiver poisons its parser with `XML_ERROR_LIMIT_TOKEN`. -/
@[extern "lexpat_cabi_reject_frame"]
opaque rejectFrame (size : UInt64) : UInt64

/-- Publish the stream's terminal status, error and cursor to the receiver.
`code` is the event error index, or `255` when the stream has no error. -/
@[extern "lexpat_cabi_report_status"]
opaque reportStatus (status code offset line column rawConsumed : UInt64) : UInt64

/-- The maximum frame, matching the C decoder's bound. -/
def maxFrameBytes : Nat := 16 * 1024 * 1024

private def pushU32 (out : ByteArray) (n : UInt32) : ByteArray :=
  let v := n.toNat
  out.push (UInt8.ofNat (v % 256))
    |>.push (UInt8.ofNat ((v / 256) % 256))
    |>.push (UInt8.ofNat ((v / 65536) % 256))
    |>.push (UInt8.ofNat (v / 16777216 % 256))

private def pushU64 (out : ByteArray) (n : UInt64) : ByteArray :=
  let v := n.toNat
  out.push (UInt8.ofNat (v % 256))
    |>.push (UInt8.ofNat ((v / 256) % 256))
    |>.push (UInt8.ofNat ((v / 65536) % 256))
    |>.push (UInt8.ofNat ((v / 16777216) % 256))
    |>.push (UInt8.ofNat ((v / 4294967296) % 256))
    |>.push (UInt8.ofNat ((v / 1099511627776) % 256))
    |>.push (UInt8.ofNat ((v / 281474976710656) % 256))
    |>.push (UInt8.ofNat (v / 72057594037927936 % 256))

private def pushString (out : ByteArray) (s : String) : ByteArray :=
  let bytes := s.toUTF8
  (pushU32 out (UInt32.ofNat bytes.size)).append bytes

/-- The event tag of the wire format. -/
def eventTag : Event → UInt8
  | .xmlDecl .. => 0
  | .start .. => 1
  | .end .. => 2
  | .text .. => 3
  | .cdataStart => 4
  | .cdataEnd => 5
  | .comment .. => 6
  | .pi .. => 7

private def payload (event : Event) : ByteArray :=
  match event with
  | .xmlDecl version encoding standalone =>
    let out := pushString ByteArray.empty version
    let out :=
      match encoding with
      | none => out.push 0
      | some name => (out.push 1).append (pushString ByteArray.empty name)
    out.push (match standalone with
      | none => 0xFF
      | some false => 0
      | some true => 1)
  | .start name attrs =>
    let out := pushString ByteArray.empty name
    let out := pushU32 out (UInt32.ofNat attrs.size)
    attrs.foldl (init := out) fun acc (attrName, value) =>
      pushString (pushString acc attrName) value
  | .end name => pushString ByteArray.empty name
  | .text data => pushString ByteArray.empty data
  | .cdataStart => ByteArray.empty
  | .cdataEnd => ByteArray.empty
  | .comment data => pushString ByteArray.empty data
  | .pi target data => pushString (pushString ByteArray.empty target) data

/-- Serialize one located event as a version-1 frame. -/
def encodeFrame (located : LocatedEvent) : ByteArray :=
  let body := payload located.event
  let total := 44 + body.size
  let tokenBytes : UInt32 :=
    match located.tokenBytes with
    | some n => UInt32.ofNat n
    | none => 0xFFFFFFFF
  let header :=
    ByteArray.empty.append "LXEV".toUTF8
      |>.push 1
      |>.push (eventTag located.event)
      |>.push 0
      |>.push 0
      |>.append (pushU32 ByteArray.empty (UInt32.ofNat total))
      |>.append (pushU64 ByteArray.empty (UInt64.ofNat located.byteOffset))
      |>.append (pushU64 ByteArray.empty (UInt64.ofNat located.line))
      |>.append (pushU64 ByteArray.empty (UInt64.ofNat located.column))
      |>.append (pushU32 ByteArray.empty tokenBytes)
      |>.append (pushU32 ByteArray.empty (UInt32.ofNat located.specifiedAttrs))
  header.append body

private def sink (located : LocatedEvent) : Bool :=
  let frame := encodeFrame located
  if frame.size > maxFrameBytes then
    -- Consume the receiver's result so the call survives compilation even
    -- though the sink's answer is already false.
    rejectFrame (UInt64.ofNat frame.size) == 0xFFFFFFFFFFFFFFFF
  else emitFrame frame == 0

private def statusCode (s : Stream) : UInt64 :=
  match s.status with
  | .active => 0
  | .done => 1
  | .failed _ => 2

/-- The error index understood by the C receiver. The order follows
`LexPat.ErrorCode` and the receiver maps each index to its public `XML_Error`
value. -/
def errorIndex : ErrorCode → UInt64
  | .syntax => 0
  | .noElements => 1
  | .invalidToken => 2
  | .unclosedToken => 3
  | .partialChar => 4
  | .tagMismatch => 5
  | .duplicateAttribute => 6
  | .junkAfterDocElement => 7
  | .undefinedEntity => 8
  | .badCharRef => 9
  | .misplacedXmlPi => 10
  | .unknownEncoding => 11
  | .incorrectEncoding => 12
  | .unclosedCdataSection => 13
  | .xmlDecl => 14
  | .unsupportedDtd => 15
  | .limitInput => 16
  | .limitToken => 17
  | .limitDepth => 18
  | .limitEntityExpansion => 19

/-- Publish the stream summary. The receiver's result is compared so the
opaque call is not discarded as an unused pure result; no stream passes the
sentinel branch. -/
private def report (s : Stream) : Stream :=
  let code :=
    match s.status with
    | .failed e => errorIndex e.code
    | _ => 255
  let offset :=
    match s.status with
    | .failed e => e.offset
    | _ => s.rawConsumed
  let line :=
    match s.status with
    | .failed _ => s.failLine
    | _ => s.line
  let column :=
    match s.status with
    | .failed _ => s.failColumn
    | _ => s.column
  let result := reportStatus (statusCode s) code (UInt64.ofNat offset)
    (UInt64.ofNat line) (UInt64.ofNat column) (UInt64.ofNat s.rawConsumed)
  if result == 0xFFFFFFFFFFFFFFFF then { s with failSet := true } else s

/-- Create a fresh stream under the default budgets. -/
@[export lexpat_cabi_stream_new]
def streamNew (_hint : UInt64) : Stream :=
  Stream.new

/-- Feed one chunk. The stream and the chunk buffer are consumed and the
continuation is returned owned by the caller. -/
@[export lexpat_cabi_stream_feed]
def streamFeed (s : Stream) (bytes : ByteArray) : Stream :=
  report (Stream.feedSink sink s bytes)

/-- Finish the document and return the terminal continuation. -/
@[export lexpat_cabi_stream_finish]
def streamFinish (s : Stream) : Stream :=
  report (Stream.finishSink sink s)

end LexPat.CAbi
