/-
Core model types for the lexpat XML 1.0 parser.

The model keeps encoding validation and XML character legality separate:
`Scalar` is a Unicode scalar value, which every decoded byte sequence must
produce; `LexPat.isXmlChar` (see `LexPat.Lexer`) is the narrower XML 1.0
`Char` production that the document parser enforces on top of it.
-/
namespace LexPat

/-- A Unicode scalar value: a natural number below the surrogate block or in
`[0xE000, 0x110000)`. Carrying the proof rather than a bare `Nat` is what keeps
`Char.ofNat` from silently turning an invalid code point into NUL. -/
structure Scalar where
  n : Nat
  valid : Nat.isValidChar n

namespace Scalar

instance : Inhabited Scalar := ⟨⟨0x41, by decide⟩⟩
instance : Repr Scalar := ⟨fun s _ => repr s.n⟩
instance : BEq Scalar := ⟨fun a b => a.n == b.n⟩

/-- The `Char` this scalar denotes. Total because `n` is a valid scalar value. -/
def toChar (s : Scalar) : Char := Char.ofNat s.n

end Scalar

/-- A decoded scalar together with the byte offset of its first byte in the
raw input. The offset feeds the internal location metadata used by the
C bridge; the public Lean event arrays expose no offsets and make
no compatibility promise about them. -/
structure DecodedChar where
  value : Scalar
  byteOffset : Nat
deriving Repr

/-- The encoding a document was decoded from. -/
inductive Encoding where
  | utf8
  | utf16le
  | utf16be
  | latin1
  | ascii
deriving DecidableEq, Repr

namespace Encoding

/-- The name used in diagnostics for an encoding. -/
def name : Encoding → String
  | .utf8 => "UTF-8"
  | .utf16le => "UTF-16LE"
  | .utf16be => "UTF-16BE"
  | .latin1 => "ISO-8859-1"
  | .ascii => "US-ASCII"

end Encoding

/-- Public error categories. The first group uses the `XML_Error` names of
`expat/lib/expat.h`; the second group is local to this parser, because Expat has
no equivalent (it has a DTD and an application entity resolver, and no
configurable budgets). -/
inductive ErrorCode where
  | syntax
  | noElements
  | invalidToken
  | unclosedToken
  | partialChar
  | tagMismatch
  | duplicateAttribute
  | junkAfterDocElement
  | undefinedEntity
  | badCharRef
  | misplacedXmlPi
  | unknownEncoding
  | incorrectEncoding
  | unclosedCdataSection
  | xmlDecl
  | unsupportedDtd
  | limitInput
  | limitToken
  | limitDepth
  | limitEntityExpansion
deriving DecidableEq, Repr

namespace ErrorCode

/-- Stable short name used in the JSON Lines trace. -/
def name : ErrorCode → String
  | .syntax => "SYNTAX"
  | .noElements => "NO_ELEMENTS"
  | .invalidToken => "INVALID_TOKEN"
  | .unclosedToken => "UNCLOSED_TOKEN"
  | .partialChar => "PARTIAL_CHAR"
  | .tagMismatch => "TAG_MISMATCH"
  | .duplicateAttribute => "DUPLICATE_ATTRIBUTE"
  | .junkAfterDocElement => "JUNK_AFTER_DOC_ELEMENT"
  | .undefinedEntity => "UNDEFINED_ENTITY"
  | .badCharRef => "BAD_CHAR_REF"
  | .misplacedXmlPi => "MISPLACED_XML_PI"
  | .unknownEncoding => "UNKNOWN_ENCODING"
  | .incorrectEncoding => "INCORRECT_ENCODING"
  | .unclosedCdataSection => "UNCLOSED_CDATA_SECTION"
  | .xmlDecl => "XML_DECL"
  | .unsupportedDtd => "UNSUPPORTED_DTD"
  | .limitInput => "LIMIT_INPUT"
  | .limitToken => "LIMIT_TOKEN"
  | .limitDepth => "LIMIT_DEPTH"
  | .limitEntityExpansion => "LIMIT_ENTITY_EXPANSION"

end ErrorCode

/-- Why a byte sequence could not be decoded. Each reason names one concrete
decoding failure, so a rejected document's trace says which rule it broke. -/
inductive DecodeReason where
  | invalidLead
  | invalidContinuation
  | overlong
  | surrogate
  | outOfRange
  | truncated
  | oddUtf16Length
  | unpairedSurrogate
  | invalidAscii
  | unknownEncoding
  | encodingMismatch
deriving DecidableEq, Repr

namespace DecodeReason

def name : DecodeReason → String
  | .invalidLead => "invalidLead"
  | .invalidContinuation => "invalidContinuation"
  | .overlong => "overlong"
  | .surrogate => "surrogate"
  | .outOfRange => "outOfRange"
  | .truncated => "truncated"
  | .oddUtf16Length => "oddUtf16Length"
  | .unpairedSurrogate => "unpairedSurrogate"
  | .invalidAscii => "invalidAscii"
  | .unknownEncoding => "unknownEncoding"
  | .encodingMismatch => "encodingMismatch"

/-- The public error category a decoding failure maps to. -/
def code : DecodeReason → ErrorCode
  | .invalidLead => .invalidToken
  | .invalidContinuation => .invalidToken
  | .overlong => .invalidToken
  | .surrogate => .invalidToken
  | .outOfRange => .invalidToken
  | .truncated => .partialChar
  | .oddUtf16Length => .partialChar
  | .unpairedSurrogate => .invalidToken
  | .invalidAscii => .invalidToken
  | .unknownEncoding => .unknownEncoding
  | .encodingMismatch => .incorrectEncoding

end DecodeReason

/-- A decoding failure. `offset` is the raw byte offset of the offending byte. -/
structure DecodeError where
  reason : DecodeReason
  offset : Nat
deriving DecidableEq, Repr

/-- A parse failure: the public category, the concrete rule that failed, and
the raw byte offset of the failed token. The Lean trace treats the offset as
diagnostic; the C bridge reports it as `XML_GetCurrentByteIndex`
after a failure. -/
structure ParseError where
  code : ErrorCode
  reason : String
  offset : Nat
deriving Repr

/-- Budgets for attacker-controlled work. The defaults are the documented
limits; every check is performed before the corresponding allocation or append.
Lengths of tokens, attribute values, text, comments, CDATA and PI data are
counted in decoded characters, and the reference budget counts decoded
characters contributed by predefined and numeric references. -/
structure Limits where
  maxInputBytes : Nat := 8 * 1024 * 1024
  maxTokenChars : Nat := 1024 * 1024
  maxDepth : Nat := 256
  maxEntityExpansion : Nat := 1024 * 1024
deriving Repr, DecidableEq, Inhabited

/-- A document event. Event order is document order; attributes carry their raw
qualified names and the rendered trace orders them by raw name. -/
inductive Event where
  | xmlDecl (version : String) (encoding : Option String) (standalone : Option Bool)
  | start (name : String) (attributes : Array (String × String))
  | end (name : String)
  | text (data : String)
  | cdataStart
  | cdataEnd
  | comment (data : String)
  | pi (target : String) (data : String)
deriving Repr, DecidableEq, BEq

/-- A byte span into the byte array that owns it. Constructor of the span is
the caller's responsibility; every consumer validates `start ≤ stop ≤ size`. -/
structure Span where
  start : Nat
  stop : Nat
deriving Repr, DecidableEq

/-- An `Event` together with the source coordinates recorded when the token was
emitted. `byteOffset` is the raw byte index of the token's first byte,
`tokenBytes` its raw byte span when the emitter knows it, `line` is 1-based,
`column` is a 0-based scalar column, and `specifiedAttrs` is the number of
explicit attribute pairs (nonzero only for a start event). The streaming core
uses this for its optional event sink; the public `Event` array is unchanged.

`textSpan` is set when the text payload is still a contiguous literal span of
the chunk being fed: the event then carries an empty `text` payload and the
sink may read the bytes in place while the chunk is alive. `textBytes` is set
when the token's bytes had to be owned -- a token that crossed a feed boundary,
a reference expansion or a normalized line ending -- and the sink may read them
in place for the callback. At most one of the two is set. A consumer that needs
an owned `String` -- the public `feed`/`finish` result -- materializes whichever
it finds before use. -/
structure LocatedEvent where
  event : Event
  byteOffset : Nat
  tokenBytes : Option Nat
  line : Nat
  column : Nat
  specifiedAttrs : Nat
  textSpan : Option Span := none
  /-- The token's own UTF-8 bytes when no chunk span can name them. It is read
  with an explicit length, so it needs no NUL terminator, and it stays owned by
  the event until the event is released. -/
  textBytes : Option ByteArray := none
  /-- For a start event whose element name and ordered attribute pairs are still
  spans of the buffer that was scanned: the name's byte range and, for each
  attribute pair, four numbers (name start, name stop, value start, value stop),
  all relative to that buffer. A consumer that needs owned text uses the `Event`
  payload the emitter already built; a consumer that copies into its own arena
  can read these ranges and copy once. -/
  nameSpan : Option Span := none
  attrRanges : Option (Array UInt64) := none
  /-- The absolute offset of the first byte of the buffer `nameSpan` and
  `attrRanges` are relative to. It differs from the feeding chunk's base when a
  start tag was committed from bytes held over a feed boundary. Text spans always
  refer to the chunk being fed. -/
  sliceBase : Nat := 0

/-- A text event's owned payload has no `Repr`, so it is reported by length. -/
private def reprTextBytes : Option ByteArray → String
  | none => "none"
  | some bytes => s!"some ({bytes.size} bytes)"

instance : Repr LocatedEvent where
  reprPrec e prec :=
    reprPrec (e.event, e.byteOffset, e.tokenBytes, e.line, e.column,
              e.specifiedAttrs, e.textSpan, reprTextBytes e.textBytes, e.nameSpan,
              e.attrRanges, e.sliceBase) prec

end LexPat
