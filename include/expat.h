/*
 * lexpat — a bounded, source-compatible XML_* C call surface.
 *
 * This header describes the bounded `liblexpat.so.1` artifact built from
 * the Lean streaming core. It is not the Expat header and does not claim
 * compatibility outside the declared subset: only these functions are exported, the
 * private `XML_ParserStruct` layout is not Expat's, and unsupported calls
 * refuse deterministically instead of pretending to work.
 *
 * The supported subset is parser lifecycle and user data, element, character
 * data, PI, comment, CDATA and XML-declaration handlers, `XML_Parse`,
 * `XML_GetBuffer`/`XML_ParseBuffer`, error and location queries, parsing
 * status, version/features, `XML_SetParamEntityParsing` with the safe NEVER
 * setting, and the specified-attribute and ID-index queries. Everything else
 * declared here fails closed as documented in `docs/compatibility.md`.
 *
 * Preconditions: every non-NULL pointer argument must refer to accessible
 * memory for its declared size. `XML_GetUserData` is the pinned Expat macro
 * `(*(void **)(parser))`: it dereferences the handle directly, has no registry
 * check, and is undefined after `XML_ParserFree`.
 */

#ifndef LexPat_Expat_INCLUDED
#  define LexPat_Expat_INCLUDED 1

#  include <stdint.h>
#  include <stdlib.h>

/* -------------------------------------------------------------------------
 * Build modes. This artifact is UTF-8, default-size, x86_64-linux only, and
 * has no attribute-info extension. Refuse other modes instead of compiling a
 * silently different ABI.
 * ---------------------------------------------------------------------- */

#  if defined(XML_UNICODE) || defined(XML_UNICODE_WCHAR_T)
#    error "lexpat: XML_UNICODE and XML_UNICODE_WCHAR_T are not supported; XML_Char is char"
#  endif
#  if defined(XML_LARGE_SIZE)
#    error "lexpat: XML_LARGE_SIZE is not supported; XML_Index is long"
#  endif
#  if defined(XML_ATTR_INFO)
#    error "lexpat: XML_ATTR_INFO is not supported; XML_GetAttributeInfo is absent"
#  endif
#  if !defined(__linux__) || !defined(__x86_64__)
#    error "lexpat: this artifact is built for x86_64-linux only"
#  endif

#  ifdef __cplusplus
extern "C" {
#  endif

#  ifndef XMLCALL
#    define XMLCALL
#  endif

#  ifndef XMLIMPORT
#    if defined(__GNUC__)
#      define XMLIMPORT __attribute__((visibility("default")))
#    else
#      define XMLIMPORT
#    endif
#  endif

#  define XMLPARSEAPI(type) XMLIMPORT type XMLCALL

#  if defined(__GNUC__) && (__GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 96))
#    define XML_ATTR_MALLOC __attribute__((__malloc__))
#  else
#    define XML_ATTR_MALLOC
#  endif
#  if defined(__GNUC__) && ((__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3))
#    define XML_ATTR_ALLOC_SIZE(x) __attribute__((__alloc_size__(x)))
#  else
#    define XML_ATTR_ALLOC_SIZE(x)
#  endif

typedef char XML_Char;
typedef char XML_LChar;
typedef long XML_Index;
typedef unsigned long XML_Size;

struct XML_ParserStruct;
typedef struct XML_ParserStruct *XML_Parser;

typedef unsigned char XML_Bool;
#  define XML_TRUE ((XML_Bool)1)
#  define XML_FALSE ((XML_Bool)0)

enum XML_Status {
  XML_STATUS_ERROR = 0,
#  define XML_STATUS_ERROR XML_STATUS_ERROR
  XML_STATUS_OK = 1,
#  define XML_STATUS_OK XML_STATUS_OK
  XML_STATUS_SUSPENDED = 2
#  define XML_STATUS_SUSPENDED XML_STATUS_SUSPENDED
};

/* Values 0..44 are Expat's public numbering. Values above 44 are lexpat's
 * explicitly named extensions; a client that compares against Expat's enum
 * must not read them as one of Expat's own codes. */
enum XML_Error {
  XML_ERROR_NONE,
  XML_ERROR_NO_MEMORY,
  XML_ERROR_SYNTAX,
  XML_ERROR_NO_ELEMENTS,
  XML_ERROR_INVALID_TOKEN,
  XML_ERROR_UNCLOSED_TOKEN,
  XML_ERROR_PARTIAL_CHAR,
  XML_ERROR_TAG_MISMATCH,
  XML_ERROR_DUPLICATE_ATTRIBUTE,
  XML_ERROR_JUNK_AFTER_DOC_ELEMENT,
  XML_ERROR_PARAM_ENTITY_REF,
  XML_ERROR_UNDEFINED_ENTITY,
  XML_ERROR_RECURSIVE_ENTITY_REF,
  XML_ERROR_ASYNC_ENTITY,
  XML_ERROR_BAD_CHAR_REF,
  XML_ERROR_BINARY_ENTITY_REF,
  XML_ERROR_ATTRIBUTE_EXTERNAL_ENTITY_REF,
  XML_ERROR_MISPLACED_XML_PI,
  XML_ERROR_UNKNOWN_ENCODING,
  XML_ERROR_INCORRECT_ENCODING,
  XML_ERROR_UNCLOSED_CDATA_SECTION,
  XML_ERROR_EXTERNAL_ENTITY_HANDLING,
  XML_ERROR_NOT_STANDALONE,
  XML_ERROR_UNEXPECTED_STATE,
  XML_ERROR_ENTITY_DECLARED_IN_PE,
  XML_ERROR_FEATURE_REQUIRES_XML_DTD,
  XML_ERROR_CANT_CHANGE_FEATURE_ONCE_PARSING,
  XML_ERROR_UNBOUND_PREFIX,
  XML_ERROR_UNDECLARING_PREFIX,
  XML_ERROR_INCOMPLETE_PE,
  XML_ERROR_XML_DECL,
  XML_ERROR_TEXT_DECL,
  XML_ERROR_PUBLICID,
  XML_ERROR_SUSPENDED,
  XML_ERROR_NOT_SUSPENDED,
  XML_ERROR_ABORTED,
  XML_ERROR_FINISHED,
  XML_ERROR_SUSPEND_PE,
  XML_ERROR_RESERVED_PREFIX_XML,
  XML_ERROR_RESERVED_PREFIX_XMLNS,
  XML_ERROR_RESERVED_NAMESPACE_URI,
  XML_ERROR_INVALID_ARGUMENT,
  XML_ERROR_NO_BUFFER,
  XML_ERROR_AMPLIFICATION_LIMIT_BREACH,
  XML_ERROR_NOT_STARTED,
  /* lexpat extensions, never reported as an Expat code. */
  XML_ERROR_UNSUPPORTED_DTD = 45,
  XML_ERROR_LIMIT_INPUT = 46,
  XML_ERROR_LIMIT_TOKEN = 47,
  XML_ERROR_LIMIT_DEPTH = 48,
  XML_ERROR_LIMIT_ENTITY_EXPANSION = 49,
  XML_ERROR_UNSUPPORTED_FEATURE = 50,
  XML_ERROR_MALFORMED_WIRE = 51,
  XML_ERROR_REENTRANT_CALL = 52
};

enum XML_Content_Type {
  XML_CTYPE_EMPTY = 1,
  XML_CTYPE_ANY,
  XML_CTYPE_MIXED,
  XML_CTYPE_NAME,
  XML_CTYPE_CHOICE,
  XML_CTYPE_SEQ
};

enum XML_Content_Quant { XML_CQUANT_NONE, XML_CQUANT_OPT, XML_CQUANT_REP, XML_CQUANT_PLUS };

typedef struct XML_cp XML_Content;

struct XML_cp {
  enum XML_Content_Type type;
  enum XML_Content_Quant quant;
  XML_Char *name;
  unsigned int numchildren;
  XML_Content *children;
};

typedef struct {
  void *(*malloc_fcn)(size_t size);
  void *(*realloc_fcn)(void *ptr, size_t size);
  void (*free_fcn)(void *ptr);
} XML_Memory_Handling_Suite;

/* -------------------------------------------------------------------------
 * Callback types. Signatures match the pinned Expat header; this artifact
 * invokes only the element, text, PI, comment, CDATA and declaration ones.
 * ---------------------------------------------------------------------- */

typedef void(XMLCALL *XML_StartElementHandler)(void *userData, const XML_Char *name,
                                               const XML_Char **atts);
typedef void(XMLCALL *XML_EndElementHandler)(void *userData, const XML_Char *name);
typedef void(XMLCALL *XML_CharacterDataHandler)(void *userData, const XML_Char *s, int len);
typedef void(XMLCALL *XML_ProcessingInstructionHandler)(void *userData,
                                                        const XML_Char *target,
                                                        const XML_Char *data);
typedef void(XMLCALL *XML_CommentHandler)(void *userData, const XML_Char *data);
typedef void(XMLCALL *XML_StartCdataSectionHandler)(void *userData);
typedef void(XMLCALL *XML_EndCdataSectionHandler)(void *userData);
typedef void(XMLCALL *XML_XmlDeclHandler)(void *userData, const XML_Char *version,
                                           const XML_Char *encoding, int standalone);

typedef void(XMLCALL *XML_ElementDeclHandler)(void *userData, const XML_Char *name,
                                              XML_Content *model);
typedef void(XMLCALL *XML_AttlistDeclHandler)(void *userData, const XML_Char *elname,
                                              const XML_Char *attname,
                                              const XML_Char *att_type,
                                              const XML_Char *dflt, int isrequired);
typedef void(XMLCALL *XML_EntityDeclHandler)(
    void *userData, const XML_Char *entityName, int is_parameter_entity,
    const XML_Char *value, int value_length, const XML_Char *base,
    const XML_Char *systemId, const XML_Char *publicId, const XML_Char *notationName);
typedef void(XMLCALL *XML_UnparsedEntityDeclHandler)(
    void *userData, const XML_Char *entityName, const XML_Char *base,
    const XML_Char *systemId, const XML_Char *publicId, const XML_Char *notationName);
typedef void(XMLCALL *XML_NotationDeclHandler)(void *userData,
                                               const XML_Char *notationName,
                                               const XML_Char *base,
                                               const XML_Char *systemId,
                                               const XML_Char *publicId);
typedef void(XMLCALL *XML_StartNamespaceDeclHandler)(void *userData,
                                                     const XML_Char *prefix,
                                                     const XML_Char *uri);
typedef void(XMLCALL *XML_EndNamespaceDeclHandler)(void *userData,
                                                   const XML_Char *prefix);
typedef int(XMLCALL *XML_NotStandaloneHandler)(void *userData);
typedef int(XMLCALL *XML_ExternalEntityRefHandler)(XML_Parser parser,
                                                   const XML_Char *context,
                                                   const XML_Char *base,
                                                   const XML_Char *systemId,
                                                   const XML_Char *publicId);
typedef void(XMLCALL *XML_SkippedEntityHandler)(void *userData,
                                                const XML_Char *entityName,
                                                int is_parameter_entity);
typedef void(XMLCALL *XML_DefaultHandler)(void *userData, const XML_Char *s, int len);
typedef void(XMLCALL *XML_StartDoctypeDeclHandler)(void *userData,
                                                   const XML_Char *doctypeName,
                                                   const XML_Char *sysid,
                                                   const XML_Char *pubid,
                                                   int has_internal_subset);
typedef void(XMLCALL *XML_EndDoctypeDeclHandler)(void *userData);

typedef struct {
  int map[256];
  void *data;
  int(XMLCALL *convert)(void *data, const char *s);
  void(XMLCALL *release)(void *data);
} XML_Encoding;

typedef int(XMLCALL *XML_UnknownEncodingHandler)(void *encodingHandlerData,
                                                 const XML_Char *name,
                                                 XML_Encoding *info);

enum XML_ParamEntityParsing {
  XML_PARAM_ENTITY_PARSING_NEVER,
  XML_PARAM_ENTITY_PARSING_UNLESS_STANDALONE,
  XML_PARAM_ENTITY_PARSING_ALWAYS
};

enum XML_Parsing { XML_INITIALIZED, XML_PARSING, XML_FINISHED, XML_SUSPENDED };

typedef struct {
  enum XML_Parsing parsing;
  XML_Bool finalBuffer;
} XML_ParsingStatus;

typedef struct {
  int major;
  int minor;
  int micro;
} XML_Expat_Version;

enum XML_FeatureEnum {
  XML_FEATURE_END = 0,
  XML_FEATURE_UNICODE,
  XML_FEATURE_UNICODE_WCHAR_T,
  XML_FEATURE_DTD,
  XML_FEATURE_CONTEXT_BYTES,
  XML_FEATURE_MIN_SIZE,
  XML_FEATURE_SIZEOF_XML_CHAR,
  XML_FEATURE_SIZEOF_XML_LCHAR,
  XML_FEATURE_NS,
  XML_FEATURE_LARGE_SIZE,
  XML_FEATURE_ATTR_INFO,
  XML_FEATURE_BILLION_LAUGHS_ATTACK_PROTECTION_MAXIMUM_AMPLIFICATION_DEFAULT,
  XML_FEATURE_BILLION_LAUGHS_ATTACK_PROTECTION_ACTIVATION_THRESHOLD_DEFAULT,
  XML_FEATURE_GE,
  XML_FEATURE_ALLOC_TRACKER_MAXIMUM_AMPLIFICATION_DEFAULT,
  XML_FEATURE_ALLOC_TRACKER_ACTIVATION_THRESHOLD_DEFAULT
};

typedef struct {
  enum XML_FeatureEnum feature;
  const XML_LChar *name;
  long int value;
} XML_Feature;

/* -------------------------------------------------------------------------
 * Supported calls.
 * ---------------------------------------------------------------------- */

XMLPARSEAPI(XML_Parser) XML_ParserCreate(const XML_Char *encoding);
XMLPARSEAPI(void) XML_ParserFree(XML_Parser parser);
XMLPARSEAPI(void) XML_SetUserData(XML_Parser parser, void *userData);
#  define XML_GetUserData(parser) (*(void **)(parser))

XMLPARSEAPI(void) XML_SetElementHandler(XML_Parser parser,
                                        XML_StartElementHandler start,
                                        XML_EndElementHandler end);
XMLPARSEAPI(void) XML_SetStartElementHandler(XML_Parser parser,
                                             XML_StartElementHandler handler);
XMLPARSEAPI(void) XML_SetEndElementHandler(XML_Parser parser,
                                           XML_EndElementHandler handler);
XMLPARSEAPI(void) XML_SetCharacterDataHandler(XML_Parser parser,
                                              XML_CharacterDataHandler handler);
XMLPARSEAPI(void) XML_SetProcessingInstructionHandler(
    XML_Parser parser, XML_ProcessingInstructionHandler handler);
XMLPARSEAPI(void) XML_SetCommentHandler(XML_Parser parser, XML_CommentHandler handler);
XMLPARSEAPI(void) XML_SetCdataSectionHandler(XML_Parser parser,
                                             XML_StartCdataSectionHandler start,
                                             XML_EndCdataSectionHandler end);
XMLPARSEAPI(void) XML_SetStartCdataSectionHandler(XML_Parser parser,
                                                  XML_StartCdataSectionHandler start);
XMLPARSEAPI(void) XML_SetEndCdataSectionHandler(XML_Parser parser,
                                                XML_EndCdataSectionHandler end);
XMLPARSEAPI(void) XML_SetXmlDeclHandler(XML_Parser parser, XML_XmlDeclHandler handler);

XMLPARSEAPI(enum XML_Status) XML_Parse(XML_Parser parser, const char *s, int len,
                                       int isFinal);
XMLPARSEAPI(void *) XML_GetBuffer(XML_Parser parser, int len);
XMLPARSEAPI(enum XML_Status) XML_ParseBuffer(XML_Parser parser, int len, int isFinal);

XMLPARSEAPI(enum XML_Error) XML_GetErrorCode(XML_Parser parser);
XMLPARSEAPI(const XML_LChar *) XML_ErrorString(enum XML_Error code);
XMLPARSEAPI(XML_Size) XML_GetCurrentLineNumber(XML_Parser parser);
XMLPARSEAPI(XML_Size) XML_GetCurrentColumnNumber(XML_Parser parser);
XMLPARSEAPI(XML_Index) XML_GetCurrentByteIndex(XML_Parser parser);

#  define XML_GetErrorLineNumber XML_GetCurrentLineNumber
#  define XML_GetErrorColumnNumber XML_GetCurrentColumnNumber
#  define XML_GetErrorByteIndex XML_GetCurrentByteIndex

XMLPARSEAPI(const XML_LChar *) XML_ExpatVersion(void);
XMLPARSEAPI(XML_Expat_Version) XML_ExpatVersionInfo(void);
XMLPARSEAPI(const XML_Feature *) XML_GetFeatureList(void);

XMLPARSEAPI(int) XML_SetParamEntityParsing(XML_Parser parser,
                                           enum XML_ParamEntityParsing parsing);
XMLPARSEAPI(void) XML_GetParsingStatus(XML_Parser parser, XML_ParsingStatus *status);
XMLPARSEAPI(int) XML_GetSpecifiedAttributeCount(XML_Parser parser);
XMLPARSEAPI(int) XML_GetIdAttributeIndex(XML_Parser parser);

/* -------------------------------------------------------------------------
 * Declared unsupported calls. Each refuses deterministically; the comment
 * names the refusal. Registering a non-NULL handler for a mode this parser
 * does not implement poisons the parser with XML_ERROR_UNSUPPORTED_FEATURE.
 * ---------------------------------------------------------------------- */

XMLPARSEAPI(XML_Parser) XML_ParserCreateNS(const XML_Char *encoding,
                                           XML_Char namespaceSeparator);
XMLPARSEAPI(XML_Parser) XML_ParserCreate_MM(const XML_Char *encoding,
                                            const XML_Memory_Handling_Suite *memsuite,
                                            const XML_Char *namespaceSeparator);
XMLPARSEAPI(XML_Bool) XML_ParserReset(XML_Parser parser, const XML_Char *encoding);
XMLPARSEAPI(XML_Parser) XML_ExternalEntityParserCreate(XML_Parser parser,
                                                       const XML_Char *context,
                                                       const XML_Char *encoding);

XMLPARSEAPI(enum XML_Status) XML_SetEncoding(XML_Parser parser, const XML_Char *encoding);
XMLPARSEAPI(enum XML_Status) XML_SetBase(XML_Parser parser, const XML_Char *base);
XMLPARSEAPI(const XML_Char *) XML_GetBase(XML_Parser parser);
XMLPARSEAPI(enum XML_Error) XML_UseForeignDTD(XML_Parser parser, XML_Bool useDTD);
XMLPARSEAPI(enum XML_Status) XML_StopParser(XML_Parser parser, XML_Bool resumable);
XMLPARSEAPI(enum XML_Status) XML_ResumeParser(XML_Parser parser);
XMLPARSEAPI(void) XML_DefaultCurrent(XML_Parser parser);
XMLPARSEAPI(const char *) XML_GetInputContext(XML_Parser parser, int *offset, int *size);
XMLPARSEAPI(int) XML_GetCurrentByteCount(XML_Parser parser);

XMLPARSEAPI(int) XML_SetHashSalt(XML_Parser parser, unsigned long hash_salt);
XMLPARSEAPI(XML_Bool) XML_SetHashSalt16Bytes(XML_Parser parser,
                                             const uint8_t entropy[16]);
XMLPARSEAPI(XML_Bool) XML_SetReparseDeferralEnabled(XML_Parser parser, XML_Bool enabled);
XMLPARSEAPI(XML_Bool) XML_SetBillionLaughsAttackProtectionMaximumAmplification(
    XML_Parser parser, float maximumAmplificationFactor);
XMLPARSEAPI(XML_Bool) XML_SetBillionLaughsAttackProtectionActivationThreshold(
    XML_Parser parser, unsigned long long activationThresholdBytes);
XMLPARSEAPI(XML_Bool) XML_SetAllocTrackerMaximumAmplification(
    XML_Parser parser, float maximumAmplificationFactor);
XMLPARSEAPI(XML_Bool) XML_SetAllocTrackerActivationThreshold(
    XML_Parser parser, unsigned long long activationThresholdBytes);

XMLPARSEAPI(void *) XML_MemMalloc(XML_Parser parser, size_t size);
XMLPARSEAPI(void *) XML_MemRealloc(XML_Parser parser, void *ptr, size_t size);
XMLPARSEAPI(void) XML_MemFree(XML_Parser parser, void *ptr);
XMLPARSEAPI(void) XML_FreeContentModel(XML_Parser parser, XML_Content *model);

XMLPARSEAPI(void) XML_SetDefaultHandler(XML_Parser parser, XML_DefaultHandler handler);
XMLPARSEAPI(void) XML_SetDefaultHandlerExpand(XML_Parser parser,
                                              XML_DefaultHandler handler);
XMLPARSEAPI(void) XML_SetDoctypeDeclHandler(XML_Parser parser,
                                            XML_StartDoctypeDeclHandler start,
                                            XML_EndDoctypeDeclHandler end);
XMLPARSEAPI(void) XML_SetStartDoctypeDeclHandler(XML_Parser parser,
                                                 XML_StartDoctypeDeclHandler start);
XMLPARSEAPI(void) XML_SetEndDoctypeDeclHandler(XML_Parser parser,
                                               XML_EndDoctypeDeclHandler end);
XMLPARSEAPI(void) XML_SetElementDeclHandler(XML_Parser parser,
                                            XML_ElementDeclHandler eldecl);
XMLPARSEAPI(void) XML_SetAttlistDeclHandler(XML_Parser parser,
                                            XML_AttlistDeclHandler attdecl);
XMLPARSEAPI(void) XML_SetEntityDeclHandler(XML_Parser parser,
                                           XML_EntityDeclHandler handler);
XMLPARSEAPI(void) XML_SetUnparsedEntityDeclHandler(
    XML_Parser parser, XML_UnparsedEntityDeclHandler handler);
XMLPARSEAPI(void) XML_SetNotationDeclHandler(XML_Parser parser,
                                             XML_NotationDeclHandler handler);
XMLPARSEAPI(void) XML_SetNamespaceDeclHandler(XML_Parser parser,
                                              XML_StartNamespaceDeclHandler start,
                                              XML_EndNamespaceDeclHandler end);
XMLPARSEAPI(void) XML_SetStartNamespaceDeclHandler(XML_Parser parser,
                                                   XML_StartNamespaceDeclHandler start);
XMLPARSEAPI(void) XML_SetEndNamespaceDeclHandler(XML_Parser parser,
                                                 XML_EndNamespaceDeclHandler end);
XMLPARSEAPI(void) XML_SetNotStandaloneHandler(XML_Parser parser,
                                              XML_NotStandaloneHandler handler);
XMLPARSEAPI(void) XML_SetExternalEntityRefHandler(XML_Parser parser,
                                                  XML_ExternalEntityRefHandler handler);
XMLPARSEAPI(void) XML_SetExternalEntityRefHandlerArg(XML_Parser parser, void *arg);
XMLPARSEAPI(void) XML_SetSkippedEntityHandler(XML_Parser parser,
                                              XML_SkippedEntityHandler handler);
XMLPARSEAPI(void) XML_SetUnknownEncodingHandler(XML_Parser parser,
                                                XML_UnknownEncodingHandler handler,
                                                void *encodingHandlerData);
XMLPARSEAPI(void) XML_UseParserAsHandlerArg(XML_Parser parser);
XMLPARSEAPI(void) XML_SetReturnNSTriplet(XML_Parser parser, int do_nst);

/* Compile-time identity: truthful lexpat version, not Expat's. */
#  define XML_MAJOR_VERSION 0
#  define XML_MINOR_VERSION 1
#  define XML_MICRO_VERSION 0

#  ifdef __cplusplus
}
#  endif

#endif /* LexPat_Expat_INCLUDED */
