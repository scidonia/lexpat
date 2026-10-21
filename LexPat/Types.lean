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
raw input. Offsets are diagnostic only; they are not part of any compatibility
contract. -/
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
the raw byte offset (diagnostic only). -/
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
deriving Repr

end LexPat
