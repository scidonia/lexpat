/-
The C ABI bridge.

This module is the Lean side of the `liblexpat.so.1` artifact. Each determined
event is delivered by calling one private, callback-specific receiver function
compiled into the same shared object; nothing is serialized into a byte frame
and no Lean constructor tag, object shape or global is visible to the client.

A text payload that is still one contiguous literal span of the chunk being fed
is handed over as `(owner, start, stop)` together with the absolute offset of
the chunk's first byte, so the receiver passes a borrowed pointer and an
explicit length to the character data handler without materializing a `String`.
The owner stays alive for the duration of the synchronous call. Every payload
that the C contract requires as a NUL-terminated string -- an element, attribute,
declaration, comment or processing-instruction name or value -- arrives as an
owned `String`, and the receiver copies it into bounded storage that lives for
that callback only.

The receiver validates the location, the span bounds and the ordered attribute
table before it allocates or invokes a handler. A failed allocation is reported
as `XML_ERROR_NO_MEMORY`; malformed metadata is reported through the stable
`XML_ERROR_MALFORMED_WIRE` code before any callback runs.
-/
import LexPat.Stream

namespace LexPat.CAbi

@[extern "lexpat_cabi_emit_xml_decl"]
opaque emitXmlDecl (version : String) (encoding : String) (hasEncoding : UInt8)
  (standalone : Int64) (byteOffset line column : UInt64) : UInt64

@[extern "lexpat_cabi_emit_start"]
opaque emitStart (name : String) (attrs : Array (String × String))
  (byteOffset line column : UInt64) : UInt64

/-- Deliver a start event whose element name and ordered attribute pairs are
still spans of `owner`. `ranges` holds four owner-relative numbers per pair
(name start, name stop, value start, value stop) and `base` is the absolute
offset of `owner`'s first byte. The receiver validates every range and copies the
whole event once. -/
@[extern "lexpat_cabi_emit_start_slice"]
opaque emitStartSlice (owner : ByteArray) (nameStart nameStop base : UInt64)
  (ranges : Array UInt64) (byteOffset line column : UInt64) : UInt64

@[extern "lexpat_cabi_emit_end"]
opaque emitEnd (name : String) (byteOffset line column : UInt64) : UInt64

/-- Deliver an end event whose name is still a span of `owner`. -/
@[extern "lexpat_cabi_emit_end_slice"]
opaque emitEndSlice (owner : ByteArray) (nameStart nameStop base : UInt64)
  (byteOffset line column : UInt64) : UInt64

/-- Deliver literal character data as a span of `owner`. `base` is the absolute
byte offset of `owner`'s first byte, and the receiver requires
`base + start` and `base + stop` to lie inside the bytes fed to this parser. -/
@[extern "lexpat_cabi_emit_text"]
opaque emitText (owner : ByteArray) (start stop base : UInt64)
  (byteOffset line column : UInt64) : UInt64

/-- Deliver character data that had to be materialized: a reference expansion, a
normalized line ending or a token that crossed a feed boundary. -/
@[extern "lexpat_cabi_emit_text_string"]
opaque emitTextString (data : String) (byteOffset line column : UInt64) : UInt64

/-- Deliver materialized character data as the byte array that holds it. The
receiver reads it with an explicit length and validates it before the callback,
so no `String` has to be built for a token that already arrived as bytes. -/
@[extern "lexpat_cabi_emit_text_bytes"]
opaque emitTextBytes (data : ByteArray) (byteOffset line column : UInt64) : UInt64

@[extern "lexpat_cabi_emit_cdata_start"]
opaque emitCdataStart (byteOffset line column : UInt64) : UInt64

@[extern "lexpat_cabi_emit_cdata_end"]
opaque emitCdataEnd (byteOffset line column : UInt64) : UInt64

@[extern "lexpat_cabi_emit_comment"]
opaque emitComment (data : String) (byteOffset line column : UInt64) : UInt64

@[extern "lexpat_cabi_emit_pi"]
opaque emitPi (target : String) (data : String) (byteOffset line column : UInt64) :
  UInt64

/-- Publish the stream's terminal status, error and cursor to the receiver.
`code` is the event error index, or `255` when the stream has no error. -/
@[extern "lexpat_cabi_report_status"]
opaque reportStatus (status code offset line column rawConsumed : UInt64) : UInt64

private def standaloneValue : Option Bool → Int64
  | none => -1
  | some false => 0
  | some true => 1

/-- Offer one event to the receiver. `base` is the absolute offset of `owner`'s
first byte; it is only read for a borrowed text span. -/
private def emit (base : Nat) (owner : ByteArray) (e : LocatedEvent) : Bool :=
  let off := UInt64.ofNat e.byteOffset
  let line := UInt64.ofNat e.line
  let col := UInt64.ofNat e.column
  match e.event with
  | .text data =>
    match e.textSpan, e.textBytes with
    | some sp, _ =>
      emitText owner (UInt64.ofNat sp.start) (UInt64.ofNat sp.stop)
        (UInt64.ofNat base) off line col == 0
    | none, some bytes => emitTextBytes bytes off line col == 0
    | none, none => emitTextString data off line col == 0
  | .start name attrs =>
    match e.nameSpan, e.attrRanges with
    | some sp, some ranges =>
      emitStartSlice owner (UInt64.ofNat sp.start) (UInt64.ofNat sp.stop)
        (UInt64.ofNat e.sliceBase) ranges off line col == 0
    | _, _ => emitStart name attrs off line col == 0
  | .end name =>
    match e.nameSpan with
    | some sp =>
      emitEndSlice owner (UInt64.ofNat sp.start) (UInt64.ofNat sp.stop)
        (UInt64.ofNat e.sliceBase) off line col == 0
    | none => emitEnd name off line col == 0
  | .comment data => emitComment data off line col == 0
  | .pi target data => emitPi target data off line col == 0
  | .cdataStart => emitCdataStart off line col == 0
  | .cdataEnd => emitCdataEnd off line col == 0
  | .xmlDecl version encoding standalone =>
    match encoding with
    | some enc => emitXmlDecl version enc 1 (standaloneValue standalone) off line col == 0
    | none => emitXmlDecl version "" 0 (standaloneValue standalone) off line col == 0

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
continuation is returned owned by the caller. Span indices name this chunk, so
the base is the absolute offset of its first byte: everything before it is the
stream's own consumed prefix plus any tag prefix it still holds unconsumed. -/
@[export lexpat_cabi_stream_feed]
def streamFeed (s : Stream) (bytes : ByteArray) : Stream :=
  let base := s.rawConsumed + s.tagCarry.size
  report (Stream.feedSink (emit base) s bytes)

/-- Finish the document and return the terminal continuation. Every payload is
materialized at this point: no chunk is being fed, so no span can be borrowed. -/
@[export lexpat_cabi_stream_finish]
def streamFinish (s : Stream) : Stream :=
  report (Stream.finishSink (fun _ e => emit 0 ByteArray.empty e) s)

end LexPat.CAbi
