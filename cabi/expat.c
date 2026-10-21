/*
 * The C half of the liblexpat.so.1 artifact.
 *
 * This file owns the opaque parser handle, the handle registry, the Lean
 * runtime entry points, the version-1 event-frame decoder and the dispatch to
 * the handlers a client registered. It is compiled with hidden visibility and
 * linked against the Lean module objects; the version script publishes only
 * the XML_* manifest.
 *
 * Every non-NULL pointer passed through the public API is assumed to refer to
 * accessible memory for its declared size. `XML_GetUserData` is the pinned
 * Expat macro and dereferences the handle directly; it is undefined after
 * `XML_ParserFree` and on a fabricated address.
 */

#include "expat.h"

#include <lean/lean.h>

#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* The C ABI artifact's maximum input, matching LexPat.Limits.maxInputBytes. */
#define LEXPAT_MAX_INPUT ((size_t)(8 * 1024 * 1024))
/* The maximum event frame, matching LexPat.CAbi.maxFrameBytes. */
#define LEXPAT_MAX_FRAME ((size_t)(16 * 1024 * 1024))
#define LEXPAT_WIRE_HEADER 44u

/* Lean bridge exports and receiver externals. The receiver symbols are
 * defined in this file; the module initialiser and stream exports come from
 * the generated Lean objects. */
extern lean_object *initialize_lexpat_LexPat_CAbi(uint8_t builtin);
extern lean_object *lexpat_cabi_stream_new(uint64_t hint);
extern lean_object *lexpat_cabi_stream_feed(lean_object *stream, lean_object *bytes);
extern lean_object *lexpat_cabi_stream_finish(lean_object *stream);

uint64_t lexpat_cabi_emit_frame(lean_object *frame);
uint64_t lexpat_cabi_reject_frame(uint64_t size);
uint64_t lexpat_cabi_report_status(uint64_t status, uint64_t code, uint64_t offset,
                                   uint64_t line, uint64_t column,
                                   uint64_t raw_consumed);

struct XML_ParserStruct {
  /* Offset zero: the pinned XML_GetUserData macro reads this field. */
  void *userData;

  XML_StartElementHandler startHandler;
  XML_EndElementHandler endHandler;
  XML_CharacterDataHandler characterHandler;
  XML_ProcessingInstructionHandler piHandler;
  XML_CommentHandler commentHandler;
  XML_StartCdataSectionHandler startCdataHandler;
  XML_EndCdataSectionHandler endCdataHandler;
  XML_XmlDeclHandler xmlDeclHandler;

  lean_object *stream;
  enum XML_Parsing status;
  XML_Bool finalBuffer;
  enum XML_Error error;
  XML_Index byteIndex;
  XML_Size line;
  XML_Size column;
  size_t rawConsumed;
  /* Total bytes handed to the parser through the end of the current call; the
   * upper bound for any source position a frame may name. */
  size_t fedEnd;
  int specifiedAttrs;

  int inParse;
  int inCallback;
  int deferredFree;
  int started;

  char *reservation;
  size_t reservationCapacity;
  int hasReservation;
};

_Static_assert(offsetof(struct XML_ParserStruct, userData) == 0,
               "XML_GetUserData reads userData at offset zero");

typedef struct ParserNode {
  XML_Parser parser;
  struct ParserNode *next;
} ParserNode;

static pthread_once_t g_lean_once = PTHREAD_ONCE_INIT;
static int g_lean_ready = 0;
static pthread_mutex_t g_lean_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_registry_mutex = PTHREAD_MUTEX_INITIALIZER;
static ParserNode *g_parsers = NULL;

/* The receiver runs inside the Lean entry for the parser being fed. Lean
 * entries are serialized, but a thread-local keeps the association explicit. */
static _Thread_local XML_Parser g_currentParser = NULL;
static _Thread_local int g_inLean = 0;

static void initLeanOnce(void) {
  lean_object *result = initialize_lexpat_LexPat_CAbi(1);
  if (!lean_io_result_is_ok(result)) {
    lean_io_result_show_error(result);
    lean_dec_ref(result);
    return;
  }
  lean_dec_ref(result);
  lean_io_mark_end_initialization();
  g_lean_ready = 1;
}

static int ensureLean(void) {
  if (pthread_once(&g_lean_once, initLeanOnce) != 0)
    return 0;
  return g_lean_ready;
}

static int registerParser(XML_Parser parser) {
  ParserNode *node = (ParserNode *)malloc(sizeof(ParserNode));
  if (node == NULL)
    return 0;
  node->parser = parser;
  pthread_mutex_lock(&g_registry_mutex);
  node->next = g_parsers;
  g_parsers = node;
  pthread_mutex_unlock(&g_registry_mutex);
  return 1;
}

static int unregisterParser(XML_Parser parser) {
  int found = 0;
  pthread_mutex_lock(&g_registry_mutex);
  ParserNode **link = &g_parsers;
  while (*link != NULL) {
    if ((*link)->parser == parser) {
      ParserNode *dead = *link;
      *link = dead->next;
      free(dead);
      found = 1;
      break;
    }
    link = &(*link)->next;
  }
  pthread_mutex_unlock(&g_registry_mutex);
  return found;
}

/* Does not dereference the handle, so an immediately repeated free or an
 * address that was never registered is rejected without touching memory. */
static int validParser(XML_Parser parser) {
  int found = 0;
  if (parser == NULL)
    return 0;
  pthread_mutex_lock(&g_registry_mutex);
  for (ParserNode *node = g_parsers; node != NULL; node = node->next) {
    if (node->parser == parser) {
      found = 1;
      break;
    }
  }
  pthread_mutex_unlock(&g_registry_mutex);
  return found;
}

static void poison(XML_Parser parser, enum XML_Error error) {
  if (parser->error == XML_ERROR_NONE)
    parser->error = error;
  parser->status = XML_FINISHED;
}

static void releaseParser(XML_Parser parser) {
  unregisterParser(parser);
  free(parser->reservation);
  parser->reservation = NULL;
  if (parser->stream != NULL)
    lean_dec_ref(parser->stream);
  free(parser);
}

/* Creating a parser inside a callback runs on a thread that already owns
 * `g_lean_mutex` for the duration of its Lean entry; locking it again would
 * deadlock. `g_inLean` is that ownership marker, so the nested call reuses the
 * held lock and leaves the thread's Lean state as it found it. */
static lean_object *leanNewStream(void) {
  if (g_inLean)
    return lexpat_cabi_stream_new(0);
  pthread_mutex_lock(&g_lean_mutex);
  int previous = g_inLean;
  g_inLean = 1;
  lean_object *stream = lexpat_cabi_stream_new(0);
  g_inLean = previous;
  pthread_mutex_unlock(&g_lean_mutex);
  return stream;
}

static void enterLean(XML_Parser parser) {
  pthread_mutex_lock(&g_lean_mutex);
  g_inLean = 1;
  g_currentParser = parser;
  parser->inParse = 1;
}

static void leaveLean(XML_Parser parser) {
  parser->inParse = 0;
  g_currentParser = NULL;
  g_inLean = 0;
  pthread_mutex_unlock(&g_lean_mutex);
}

static enum XML_Error errorFromIndex(uint64_t index) {
  switch (index) {
  case 0:
    return XML_ERROR_SYNTAX;
  case 1:
    return XML_ERROR_NO_ELEMENTS;
  case 2:
    return XML_ERROR_INVALID_TOKEN;
  case 3:
    return XML_ERROR_UNCLOSED_TOKEN;
  case 4:
    return XML_ERROR_PARTIAL_CHAR;
  case 5:
    return XML_ERROR_TAG_MISMATCH;
  case 6:
    return XML_ERROR_DUPLICATE_ATTRIBUTE;
  case 7:
    return XML_ERROR_JUNK_AFTER_DOC_ELEMENT;
  case 8:
    return XML_ERROR_UNDEFINED_ENTITY;
  case 9:
    return XML_ERROR_BAD_CHAR_REF;
  case 10:
    return XML_ERROR_MISPLACED_XML_PI;
  case 11:
    return XML_ERROR_UNKNOWN_ENCODING;
  case 12:
    return XML_ERROR_INCORRECT_ENCODING;
  case 13:
    return XML_ERROR_UNCLOSED_CDATA_SECTION;
  case 14:
    return XML_ERROR_XML_DECL;
  case 15:
    return XML_ERROR_UNSUPPORTED_DTD;
  case 16:
    return XML_ERROR_LIMIT_INPUT;
  case 17:
    return XML_ERROR_LIMIT_TOKEN;
  case 18:
    return XML_ERROR_LIMIT_DEPTH;
  case 19:
    return XML_ERROR_LIMIT_ENTITY_EXPANSION;
  default:
    return XML_ERROR_UNEXPECTED_STATE;
  }
}

/* -------------------------------------------------------------------------
 * Version-1 event frame decoding.
 * ---------------------------------------------------------------------- */

typedef struct Reader {
  const unsigned char *bytes;
  size_t size;
  size_t pos;
} Reader;

static int readBytes(Reader *reader, const unsigned char **out, size_t length) {
  if (length > reader->size - reader->pos)
    return 0;
  *out = reader->bytes + reader->pos;
  reader->pos += length;
  return 1;
}

static int readU8(Reader *reader, uint8_t *out) {
  const unsigned char *bytes;
  if (!readBytes(reader, &bytes, 1))
    return 0;
  *out = bytes[0];
  return 1;
}

static int readU32(Reader *reader, uint32_t *out) {
  const unsigned char *bytes;
  if (!readBytes(reader, &bytes, 4))
    return 0;
  *out = (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
         ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
  return 1;
}

static int readU64(Reader *reader, uint64_t *out) {
  const unsigned char *bytes;
  if (!readBytes(reader, &bytes, 8))
    return 0;
  *out = (uint64_t)bytes[0] | ((uint64_t)bytes[1] << 8) | ((uint64_t)bytes[2] << 16) |
         ((uint64_t)bytes[3] << 24) | ((uint64_t)bytes[4] << 32) |
         ((uint64_t)bytes[5] << 40) | ((uint64_t)bytes[6] << 48) |
         ((uint64_t)bytes[7] << 56);
  return 1;
}

/* XML forbids NUL inside a name or character value, and the payload must be
 * well-formed UTF-8 before it is handed to a C string callback. */
static int validUtf8(const unsigned char *bytes, size_t size) {
  size_t i = 0;
  while (i < size) {
    unsigned char lead = bytes[i];
    if (lead == 0)
      return 0;
    if (lead < 0x80) {
      i++;
      continue;
    }
    size_t continuation;
    uint32_t codepoint;
    uint32_t minimum;
    if ((lead & 0xE0) == 0xC0) {
      continuation = 1;
      codepoint = lead & 0x1Fu;
      minimum = 0x80;
    } else if ((lead & 0xF0) == 0xE0) {
      continuation = 2;
      codepoint = lead & 0x0Fu;
      minimum = 0x800;
    } else if ((lead & 0xF8) == 0xF0) {
      continuation = 3;
      codepoint = lead & 0x07u;
      minimum = 0x10000;
    } else {
      return 0;
    }
    if (i + continuation >= size)
      return 0;
    for (size_t k = 1; k <= continuation; k++) {
      unsigned char next = bytes[i + k];
      if ((next & 0xC0) != 0x80)
        return 0;
      codepoint = (codepoint << 6) | (uint32_t)(next & 0x3F);
    }
    if (codepoint < minimum || codepoint > 0x10FFFF ||
        (codepoint >= 0xD800 && codepoint <= 0xDFFF))
      return 0;
    i += continuation + 1;
  }
  return 1;
}

typedef struct WireString {
  const unsigned char *bytes;
  uint32_t length;
} WireString;

static int readString(Reader *reader, WireString *out) {
  uint32_t length;
  if (!readU32(reader, &length))
    return 0;
  if (!readBytes(reader, &out->bytes, (size_t)length))
    return 0;
  out->length = length;
  return validUtf8(out->bytes, (size_t)length);
}

static char *copyString(WireString value) {
  char *copy = (char *)malloc((size_t)value.length + 1);
  if (copy == NULL)
    return NULL;
  if (value.length > 0)
    memcpy(copy, value.bytes, value.length);
  copy[value.length] = '\0';
  return copy;
}

static void beginCallback(XML_Parser parser) { parser->inCallback = 1; }
static void endCallback(XML_Parser parser) { parser->inCallback = 0; }

static int dispatchStart(XML_Parser parser, WireString name, Reader *payload,
                         uint32_t expectedPairs) {
  uint32_t pairs;
  if (!readU32(payload, &pairs) || pairs != expectedPairs)
    return 0;
  if (pairs > (UINT32_MAX - 1) / 2)
    return 0;

  /* A parser without a start handler still validates the frame, but nothing
   * consumes copies of the name or the attribute vector. */
  if (parser->startHandler == NULL) {
    for (uint32_t i = 0; i < pairs; i++) {
      WireString attrName;
      WireString attrValue;
      if (!readString(payload, &attrName) || !readString(payload, &attrValue))
        return 0;
    }
    return payload->pos == payload->size;
  }

  char *elementName = copyString(name);
  if (elementName == NULL)
    return 0;

  size_t slots = (size_t)pairs * 2 + 1;
  char **atts = (char **)calloc(slots, sizeof(char *));
  if (atts == NULL) {
    free(elementName);
    return 0;
  }

  int ok = 1;
  for (uint32_t i = 0; i < pairs && ok; i++) {
    WireString attrName;
    WireString attrValue;
    if (!readString(payload, &attrName) || !readString(payload, &attrValue)) {
      ok = 0;
      break;
    }
    atts[i * 2] = copyString(attrName);
    atts[i * 2 + 1] = copyString(attrValue);
    if (atts[i * 2] == NULL || atts[i * 2 + 1] == NULL)
      ok = 0;
  }
  atts[slots - 1] = NULL;

  if (ok && payload->pos != payload->size)
    ok = 0;

  if (ok && parser->startHandler != NULL) {
    parser->specifiedAttrs = (int)(pairs * 2);
    beginCallback(parser);
    parser->startHandler(parser->userData, elementName, (const XML_Char **)atts);
    endCallback(parser);
    parser->specifiedAttrs = 0;
  }

  for (size_t i = 0; i < slots; i++)
    free(atts[i]);
  free(atts);
  free(elementName);
  return ok;
}

static int dispatchWire(XML_Parser parser, const unsigned char *bytes, size_t size) {
  Reader reader = {bytes, size, 0};
  const unsigned char *magic;
  uint8_t version;
  uint8_t tag;
  uint8_t reserved0;
  uint8_t reserved1;
  uint32_t length;
  uint64_t offset;
  uint64_t line;
  uint64_t column;
  uint32_t tokenBytes;
  uint32_t attributePairs;

  if (size < LEXPAT_WIRE_HEADER || size > LEXPAT_MAX_FRAME)
    return 0;
  if (!readBytes(&reader, &magic, 4) || magic[0] != 'L' || magic[1] != 'X' ||
      magic[2] != 'E' || magic[3] != 'V')
    return 0;
  if (!readU8(&reader, &version) || version != 1)
    return 0;
  if (!readU8(&reader, &tag) || tag > 7)
    return 0;
  if (!readU8(&reader, &reserved0) || !readU8(&reader, &reserved1) ||
      reserved0 != 0 || reserved1 != 0)
    return 0;
  if (!readU32(&reader, &length) || length != size)
    return 0;
  /* Every frame describes a position in the bytes actually handed to this
   * parser. An opener at or beyond `fed` has not been fed, a line cannot pass
   * the byte count, and a column is a scalar offset on its line. */
  const uint64_t fed = (uint64_t)parser->fedEnd;
  if (!readU64(&reader, &offset) || offset >= fed)
    return 0;
  if (!readU64(&reader, &line) || line < 1 || line > fed + 1)
    return 0;
  if (!readU64(&reader, &column) || column > fed)
    return 0;
  if (!readU32(&reader, &tokenBytes))
    return 0;
  if (!readU32(&reader, &attributePairs))
    return 0;
  /* A text event reports no span; every markup token reports the non-empty
   * span from its opener through the last byte it consumed. */
  if (tag == 3 ? tokenBytes != UINT32_MAX
               : tokenBytes == 0 || tokenBytes == UINT32_MAX ||
                     (uint64_t)tokenBytes > fed - offset)
    return 0;
  if (tag != 1 && attributePairs != 0)
    return 0;

  /* Every frame updates the current position, even when no handler is set. */
  parser->byteIndex = (XML_Index)offset;
  parser->line = (XML_Size)line;
  parser->column = (XML_Size)column;

  switch (tag) {
  case 0: { /* XML declaration */
    WireString versionString;
    WireString encodingString;
    uint8_t presence;
    uint8_t standalone;
    if (!readString(&reader, &versionString) || !readU8(&reader, &presence) ||
        presence > 1)
      return 0;
    int haveEncoding = presence == 1;
    if (haveEncoding && !readString(&reader, &encodingString))
      return 0;
    if (!readU8(&reader, &standalone))
      return 0;
    if (standalone != 0xFF && standalone != 0 && standalone != 1)
      return 0;
    if (reader.pos != reader.size)
      return 0;
    if (parser->xmlDeclHandler == NULL)
      return 1;
    char *versionCopy = copyString(versionString);
    char *encodingCopy = haveEncoding ? copyString(encodingString) : NULL;
    if (versionCopy == NULL || (haveEncoding && encodingCopy == NULL)) {
      free(versionCopy);
      free(encodingCopy);
      return 0;
    }
    {
      int standaloneValue = standalone == 0xFF ? -1 : (standalone == 1 ? 1 : 0);
      beginCallback(parser);
      parser->xmlDeclHandler(parser->userData, versionCopy, encodingCopy,
                             standaloneValue);
      endCallback(parser);
    }
    free(versionCopy);
    free(encodingCopy);
    return 1;
  }
  case 1: { /* start element */
    WireString name;
    if (!readString(&reader, &name))
      return 0;
    return dispatchStart(parser, name, &reader, attributePairs);
  }
  case 2: { /* end element */
    WireString name;
    if (!readString(&reader, &name) || reader.pos != reader.size)
      return 0;
    if (parser->endHandler == NULL)
      return 1;
    char *copy = copyString(name);
    if (copy == NULL)
      return 0;
    beginCallback(parser);
    parser->endHandler(parser->userData, copy);
    endCallback(parser);
    free(copy);
    return 1;
  }
  case 3: { /* character data */
    WireString data;
    if (!readString(&reader, &data) || reader.pos != reader.size)
      return 0;
    if (data.length > (uint32_t)INT_MAX)
      return 0;
    if (parser->characterHandler != NULL) {
      beginCallback(parser);
      parser->characterHandler(parser->userData, (const XML_Char *)data.bytes,
                               (int)data.length);
      endCallback(parser);
    }
    return 1;
  }
  case 4: /* CDATA start */
    if (reader.pos != reader.size)
      return 0;
    if (parser->startCdataHandler != NULL) {
      beginCallback(parser);
      parser->startCdataHandler(parser->userData);
      endCallback(parser);
    }
    return 1;
  case 5: /* CDATA end */
    if (reader.pos != reader.size)
      return 0;
    if (parser->endCdataHandler != NULL) {
      beginCallback(parser);
      parser->endCdataHandler(parser->userData);
      endCallback(parser);
    }
    return 1;
  case 6: { /* comment */
    WireString data;
    if (!readString(&reader, &data) || reader.pos != reader.size)
      return 0;
    if (parser->commentHandler == NULL)
      return 1;
    char *copy = copyString(data);
    if (copy == NULL)
      return 0;
    beginCallback(parser);
    parser->commentHandler(parser->userData, copy);
    endCallback(parser);
    free(copy);
    return 1;
  }
  case 7: { /* processing instruction */
    WireString target;
    WireString data;
    if (!readString(&reader, &target) || !readString(&reader, &data) ||
        reader.pos != reader.size)
      return 0;
    if (parser->piHandler == NULL)
      return 1;
    char *targetCopy = copyString(target);
    char *dataCopy = copyString(data);
    if (targetCopy == NULL || dataCopy == NULL) {
      free(targetCopy);
      free(dataCopy);
      return 0;
    }
    beginCallback(parser);
    parser->piHandler(parser->userData, targetCopy, dataCopy);
    endCallback(parser);
    free(targetCopy);
    free(dataCopy);
    return 1;
  }
  default:
    return 0;
  }
}

uint64_t lexpat_cabi_emit_frame(lean_object *frame) {
  XML_Parser parser = g_currentParser;
  if (parser == NULL) {
    lean_dec_ref(frame);
    return 1;
  }
  size_t size = lean_sarray_size(frame);
  const unsigned char *bytes = lean_sarray_cptr(frame);
  int ok = dispatchWire(parser, bytes, size);
  lean_dec_ref(frame);
  if (!ok) {
    if (parser->error == XML_ERROR_NONE)
      poison(parser, XML_ERROR_MALFORMED_WIRE);
    return 1;
  }
  if (parser->deferredFree || parser->error != XML_ERROR_NONE)
    return 1;
  return 0;
}

uint64_t lexpat_cabi_reject_frame(uint64_t size) {
  (void)size;
  XML_Parser parser = g_currentParser;
  if (parser != NULL)
    poison(parser, XML_ERROR_LIMIT_TOKEN);
  return 1;
}

uint64_t lexpat_cabi_report_status(uint64_t status, uint64_t code, uint64_t offset,
                                   uint64_t line, uint64_t column,
                                   uint64_t rawConsumed) {
  XML_Parser parser = g_currentParser;
  if (parser == NULL)
    return 0;
  if (rawConsumed <= (uint64_t)LEXPAT_MAX_INPUT)
    parser->rawConsumed = (size_t)rawConsumed;
  if (parser->error != XML_ERROR_NONE)
    return 0;
  switch (status) {
  case 2:
    parser->error = errorFromIndex(code);
    parser->byteIndex = (XML_Index)offset;
    parser->line = (XML_Size)line;
    parser->column = (XML_Size)column;
    parser->status = XML_FINISHED;
    break;
  case 1:
    parser->status = XML_FINISHED;
    break;
  default:
    parser->status = XML_PARSING;
    break;
  }
  return 0;
}

/* -------------------------------------------------------------------------
 * Feed and finish.
 * ---------------------------------------------------------------------- */

static int copyIntoLean(const char *data, size_t length, lean_object **out) {
  lean_object *bytes = lean_alloc_sarray(1, length, length);
  if (bytes == NULL)
    return 0;
  if (length > 0)
    memcpy(lean_sarray_cptr(bytes), data, length);
  *out = bytes;
  return 1;
}

static void runFeed(XML_Parser parser, const char *data, size_t length) {
  lean_object *bytes = NULL;
  if (!copyIntoLean(data, length, &bytes)) {
    poison(parser, XML_ERROR_NO_MEMORY);
    return;
  }
  enterLean(parser);
  parser->stream = lexpat_cabi_stream_feed(parser->stream, bytes);
  leaveLean(parser);
}

static void runFinish(XML_Parser parser) {
  enterLean(parser);
  parser->stream = lexpat_cabi_stream_finish(parser->stream);
  leaveLean(parser);
}

static enum XML_Status doParse(XML_Parser parser, const char *data, size_t length,
                               int isFinal) {
  if (!validParser(parser))
    return XML_STATUS_ERROR;
  if (parser->error != XML_ERROR_NONE)
    return XML_STATUS_ERROR;
  if (parser->status == XML_FINISHED) {
    poison(parser, XML_ERROR_FINISHED);
    return XML_STATUS_ERROR;
  }
  if (parser->inParse || g_inLean) {
    poison(parser, XML_ERROR_REENTRANT_CALL);
    return XML_STATUS_ERROR;
  }
  if (length > 0 && data == NULL) {
    poison(parser, XML_ERROR_INVALID_ARGUMENT);
    return XML_STATUS_ERROR;
  }
  if (length > LEXPAT_MAX_INPUT || length > LEXPAT_MAX_INPUT - parser->rawConsumed) {
    poison(parser, XML_ERROR_LIMIT_INPUT);
    return XML_STATUS_ERROR;
  }

  parser->started = 1;
  parser->status = XML_PARSING;
  /* The flag describes the call whose callbacks are running, so it is set
   * before the feed: final callbacks see XML_TRUE and non-final ones see
   * XML_FALSE. */
  parser->finalBuffer = isFinal ? XML_TRUE : XML_FALSE;
  parser->fedEnd = parser->rawConsumed + length;
  runFeed(parser, data, length);
  if (parser->deferredFree) {
    releaseParser(parser);
    return XML_STATUS_ERROR;
  }
  if (isFinal && parser->error == XML_ERROR_NONE)
    runFinish(parser);

  if (parser->deferredFree) {
    releaseParser(parser);
    return XML_STATUS_ERROR;
  }
  return parser->error == XML_ERROR_NONE ? XML_STATUS_OK : XML_STATUS_ERROR;
}

/* -------------------------------------------------------------------------
 * Lifecycle.
 * ---------------------------------------------------------------------- */

XML_Parser XML_ParserCreate(const XML_Char *encoding) {
  if (encoding != NULL)
    return NULL;
  if (!ensureLean())
    return NULL;
  XML_Parser parser = (XML_Parser)calloc(1, sizeof(struct XML_ParserStruct));
  if (parser == NULL)
    return NULL;
  parser->status = XML_INITIALIZED;
  parser->error = XML_ERROR_NONE;
  parser->byteIndex = -1;
  parser->line = 0;
  parser->column = 0;
  parser->finalBuffer = XML_FALSE;
  parser->stream = leanNewStream();
  if (parser->stream == NULL) {
    free(parser);
    return NULL;
  }
  if (!registerParser(parser)) {
    lean_dec_ref(parser->stream);
    free(parser);
    return NULL;
  }
  return parser;
}

void XML_ParserFree(XML_Parser parser) {
  if (!validParser(parser))
    return;
  if (parser->inParse || parser->inCallback) {
    parser->deferredFree = 1;
    unregisterParser(parser);
    return;
  }
  releaseParser(parser);
}

void XML_SetUserData(XML_Parser parser, void *userData) {
  if (!validParser(parser))
    return;
  parser->userData = userData;
}

/* -------------------------------------------------------------------------
 * Handler registration.
 * ---------------------------------------------------------------------- */

void XML_SetElementHandler(XML_Parser parser, XML_StartElementHandler start,
                           XML_EndElementHandler end) {
  if (!validParser(parser))
    return;
  parser->startHandler = start;
  parser->endHandler = end;
}

void XML_SetStartElementHandler(XML_Parser parser, XML_StartElementHandler handler) {
  if (!validParser(parser))
    return;
  parser->startHandler = handler;
}

void XML_SetEndElementHandler(XML_Parser parser, XML_EndElementHandler handler) {
  if (!validParser(parser))
    return;
  parser->endHandler = handler;
}

void XML_SetCharacterDataHandler(XML_Parser parser, XML_CharacterDataHandler handler) {
  if (!validParser(parser))
    return;
  parser->characterHandler = handler;
}

void XML_SetProcessingInstructionHandler(XML_Parser parser,
                                         XML_ProcessingInstructionHandler handler) {
  if (!validParser(parser))
    return;
  parser->piHandler = handler;
}

void XML_SetCommentHandler(XML_Parser parser, XML_CommentHandler handler) {
  if (!validParser(parser))
    return;
  parser->commentHandler = handler;
}

void XML_SetCdataSectionHandler(XML_Parser parser,
                                XML_StartCdataSectionHandler start,
                                XML_EndCdataSectionHandler end) {
  if (!validParser(parser))
    return;
  parser->startCdataHandler = start;
  parser->endCdataHandler = end;
}

void XML_SetStartCdataSectionHandler(XML_Parser parser,
                                     XML_StartCdataSectionHandler start) {
  if (!validParser(parser))
    return;
  parser->startCdataHandler = start;
}

void XML_SetEndCdataSectionHandler(XML_Parser parser,
                                   XML_EndCdataSectionHandler end) {
  if (!validParser(parser))
    return;
  parser->endCdataHandler = end;
}

void XML_SetXmlDeclHandler(XML_Parser parser, XML_XmlDeclHandler handler) {
  if (!validParser(parser))
    return;
  parser->xmlDeclHandler = handler;
}

/* -------------------------------------------------------------------------
 * Parse and buffer entry points.
 * ---------------------------------------------------------------------- */

enum XML_Status XML_Parse(XML_Parser parser, const char *s, int len, int isFinal) {
  if (len < 0) {
    if (validParser(parser))
      poison(parser, XML_ERROR_INVALID_ARGUMENT);
    return XML_STATUS_ERROR;
  }
  return doParse(parser, s, (size_t)len, isFinal);
}

void *XML_GetBuffer(XML_Parser parser, int len) {
  if (!validParser(parser))
    return NULL;
  if (parser->error != XML_ERROR_NONE)
    return NULL;
  if (parser->status == XML_FINISHED) {
    poison(parser, XML_ERROR_FINISHED);
    return NULL;
  }
  if (parser->inParse || g_inLean) {
    poison(parser, XML_ERROR_REENTRANT_CALL);
    return NULL;
  }
  if (len < 0 || (size_t)len > LEXPAT_MAX_INPUT - parser->rawConsumed) {
    poison(parser, XML_ERROR_INVALID_ARGUMENT);
    return NULL;
  }
  free(parser->reservation);
  parser->reservation = NULL;
  parser->reservationCapacity = 0;
  parser->hasReservation = 0;
  size_t capacity = (size_t)len;
  char *reservation = (char *)malloc(capacity == 0 ? 1 : capacity);
  if (reservation == NULL) {
    poison(parser, XML_ERROR_NO_MEMORY);
    return NULL;
  }
  parser->reservation = reservation;
  parser->reservationCapacity = capacity;
  parser->hasReservation = 1;
  return reservation;
}

enum XML_Status XML_ParseBuffer(XML_Parser parser, int len, int isFinal) {
  if (!validParser(parser))
    return XML_STATUS_ERROR;
  if (parser->error != XML_ERROR_NONE)
    return XML_STATUS_ERROR;
  if (parser->status == XML_FINISHED) {
    poison(parser, XML_ERROR_FINISHED);
    return XML_STATUS_ERROR;
  }
  if (parser->inParse || g_inLean) {
    poison(parser, XML_ERROR_REENTRANT_CALL);
    return XML_STATUS_ERROR;
  }
  if (!parser->hasReservation) {
    poison(parser, XML_ERROR_NO_BUFFER);
    return XML_STATUS_ERROR;
  }
  if (len < 0 || (size_t)len > parser->reservationCapacity) {
    free(parser->reservation);
    parser->reservation = NULL;
    parser->reservationCapacity = 0;
    parser->hasReservation = 0;
    poison(parser, XML_ERROR_INVALID_ARGUMENT);
    return XML_STATUS_ERROR;
  }

  char *data = parser->reservation;
  size_t length = (size_t)len;
  parser->reservation = NULL;
  parser->reservationCapacity = 0;
  parser->hasReservation = 0;
  enum XML_Status status = doParse(parser, data, length, isFinal);
  free(data);
  return status;
}

/* -------------------------------------------------------------------------
 * Error, location and status queries.
 * ---------------------------------------------------------------------- */

enum XML_Error XML_GetErrorCode(XML_Parser parser) {
  if (!validParser(parser))
    return XML_ERROR_INVALID_ARGUMENT;
  return parser->error;
}

XML_Size XML_GetCurrentLineNumber(XML_Parser parser) {
  if (!validParser(parser))
    return 0;
  return parser->line;
}

XML_Size XML_GetCurrentColumnNumber(XML_Parser parser) {
  if (!validParser(parser))
    return 0;
  return parser->column;
}

XML_Index XML_GetCurrentByteIndex(XML_Parser parser) {
  if (!validParser(parser))
    return -1;
  return parser->byteIndex;
}

int XML_GetSpecifiedAttributeCount(XML_Parser parser) {
  if (!validParser(parser))
    return -1;
  return parser->specifiedAttrs;
}

int XML_GetIdAttributeIndex(XML_Parser parser) {
  if (!validParser(parser))
    return -1;
  return -1;
}

void XML_GetParsingStatus(XML_Parser parser, XML_ParsingStatus *status) {
  if (!validParser(parser))
    return;
  if (status == NULL) {
    poison(parser, XML_ERROR_INVALID_ARGUMENT);
    return;
  }
  status->parsing = parser->status;
  status->finalBuffer = parser->finalBuffer;
}

int XML_SetParamEntityParsing(XML_Parser parser,
                              enum XML_ParamEntityParsing parsing) {
  if (!validParser(parser))
    return 0;
  if (parser->started || parser->inParse)
    return 0;
  if (parsing == XML_PARAM_ENTITY_PARSING_NEVER)
    return 1;
  poison(parser, XML_ERROR_UNSUPPORTED_FEATURE);
  return 0;
}

/* -------------------------------------------------------------------------
 * Identity.
 * ---------------------------------------------------------------------- */

const XML_LChar *XML_ExpatVersion(void) { return "lexpat_0.1.0-cabi1"; }

XML_Expat_Version XML_ExpatVersionInfo(void) {
  XML_Expat_Version version = {0, 1, 0};
  return version;
}

static const XML_Feature g_features[] = {
    {XML_FEATURE_SIZEOF_XML_CHAR, "XML_Char", (long)sizeof(XML_Char)},
    {XML_FEATURE_SIZEOF_XML_LCHAR, "XML_LChar", (long)sizeof(XML_LChar)},
    {XML_FEATURE_END, NULL, 0},
};

const XML_Feature *XML_GetFeatureList(void) { return g_features; }

const XML_LChar *XML_ErrorString(enum XML_Error code) {
  switch (code) {
  case XML_ERROR_NONE:
    return "no error";
  case XML_ERROR_NO_MEMORY:
    return "out of memory";
  case XML_ERROR_SYNTAX:
    return "syntax error";
  case XML_ERROR_NO_ELEMENTS:
    return "no element found";
  case XML_ERROR_INVALID_TOKEN:
    return "not well-formed (invalid token)";
  case XML_ERROR_UNCLOSED_TOKEN:
    return "unclosed token";
  case XML_ERROR_PARTIAL_CHAR:
    return "partial character";
  case XML_ERROR_TAG_MISMATCH:
    return "mismatched tag";
  case XML_ERROR_DUPLICATE_ATTRIBUTE:
    return "duplicate attribute";
  case XML_ERROR_JUNK_AFTER_DOC_ELEMENT:
    return "junk after document element";
  case XML_ERROR_PARAM_ENTITY_REF:
    return "illegal parameter entity reference";
  case XML_ERROR_UNDEFINED_ENTITY:
    return "undefined entity";
  case XML_ERROR_RECURSIVE_ENTITY_REF:
    return "recursive entity reference";
  case XML_ERROR_ASYNC_ENTITY:
    return "asynchronous entity";
  case XML_ERROR_BAD_CHAR_REF:
    return "reference to invalid character number";
  case XML_ERROR_BINARY_ENTITY_REF:
    return "reference to binary entity";
  case XML_ERROR_ATTRIBUTE_EXTERNAL_ENTITY_REF:
    return "reference to external entity in attribute";
  case XML_ERROR_MISPLACED_XML_PI:
    return "XML or text declaration not at start of entity";
  case XML_ERROR_UNKNOWN_ENCODING:
    return "unknown encoding";
  case XML_ERROR_INCORRECT_ENCODING:
    return "encoding specified in XML declaration is incorrect";
  case XML_ERROR_UNCLOSED_CDATA_SECTION:
    return "unclosed CDATA section";
  case XML_ERROR_EXTERNAL_ENTITY_HANDLING:
    return "error in processing external entity reference";
  case XML_ERROR_NOT_STANDALONE:
    return "document is not standalone";
  case XML_ERROR_UNEXPECTED_STATE:
    return "unexpected parser state - please send a bug report";
  case XML_ERROR_ENTITY_DECLARED_IN_PE:
    return "entity declared in parameter entity";
  case XML_ERROR_FEATURE_REQUIRES_XML_DTD:
    return "requested feature requires XML_DTD support in Expat";
  case XML_ERROR_CANT_CHANGE_FEATURE_ONCE_PARSING:
    return "cannot change setting once parsing has begun";
  case XML_ERROR_UNBOUND_PREFIX:
    return "unbound prefix";
  case XML_ERROR_UNDECLARING_PREFIX:
    return "must not undeclare prefix";
  case XML_ERROR_INCOMPLETE_PE:
    return "incomplete markup in parameter entity";
  case XML_ERROR_XML_DECL:
    return "XML declaration not well-formed";
  case XML_ERROR_TEXT_DECL:
    return "text declaration not well-formed";
  case XML_ERROR_PUBLICID:
    return "illegal character(s) in public id";
  case XML_ERROR_SUSPENDED:
    return "parser suspended";
  case XML_ERROR_NOT_SUSPENDED:
    return "parser not suspended";
  case XML_ERROR_ABORTED:
    return "parsing aborted";
  case XML_ERROR_FINISHED:
    return "parsing finished";
  case XML_ERROR_SUSPEND_PE:
    return "cannot suspend in external parameter entity";
  case XML_ERROR_RESERVED_PREFIX_XML:
    return "reserved prefix (xml) must not be undeclared or bound to another name";
  case XML_ERROR_RESERVED_PREFIX_XMLNS:
    return "reserved prefix (xmlns) must not be declared or undeclared";
  case XML_ERROR_RESERVED_NAMESPACE_URI:
    return "prefix must not be bound to one of the reserved namespace names";
  case XML_ERROR_INVALID_ARGUMENT:
    return "invalid argument";
  case XML_ERROR_NO_BUFFER:
    return "a successful prior call to function XML_GetBuffer is required";
  case XML_ERROR_AMPLIFICATION_LIMIT_BREACH:
    return "limit on input amplification factor (from DTD and entities) breached";
  case XML_ERROR_NOT_STARTED:
    return "parser not started";
  case XML_ERROR_UNSUPPORTED_DTD:
    return "DTD processing is not supported";
  case XML_ERROR_LIMIT_INPUT:
    return "input byte budget exhausted";
  case XML_ERROR_LIMIT_TOKEN:
    return "token budget or event frame bound exhausted";
  case XML_ERROR_LIMIT_DEPTH:
    return "element depth budget exhausted";
  case XML_ERROR_LIMIT_ENTITY_EXPANSION:
    return "reference expansion budget exhausted";
  case XML_ERROR_UNSUPPORTED_FEATURE:
    return "feature is not supported by this artifact";
  case XML_ERROR_MALFORMED_WIRE:
    return "malformed internal event record";
  case XML_ERROR_REENTRANT_CALL:
    return "re-entrant parse call";
  default:
    return NULL;
  }
}

/* -------------------------------------------------------------------------
 * Deterministic refusals.
 * ---------------------------------------------------------------------- */

static void refuseHandler(XML_Parser parser, const void *handler) {
  if (handler != NULL && validParser(parser))
    poison(parser, XML_ERROR_UNSUPPORTED_FEATURE);
}

XML_Parser XML_ParserCreateNS(const XML_Char *encoding, XML_Char namespaceSeparator) {
  (void)encoding;
  (void)namespaceSeparator;
  return NULL;
}

XML_Parser XML_ParserCreate_MM(const XML_Char *encoding,
                               const XML_Memory_Handling_Suite *memsuite,
                               const XML_Char *namespaceSeparator) {
  (void)encoding;
  (void)memsuite;
  (void)namespaceSeparator;
  return NULL;
}

XML_Bool XML_ParserReset(XML_Parser parser, const XML_Char *encoding) {
  (void)parser;
  (void)encoding;
  return XML_FALSE;
}

XML_Parser XML_ExternalEntityParserCreate(XML_Parser parser, const XML_Char *context,
                                          const XML_Char *encoding) {
  (void)parser;
  (void)context;
  (void)encoding;
  return NULL;
}

enum XML_Status XML_SetEncoding(XML_Parser parser, const XML_Char *encoding) {
  (void)encoding;
  if (!validParser(parser))
    return XML_STATUS_ERROR;
  poison(parser, XML_ERROR_UNSUPPORTED_FEATURE);
  return XML_STATUS_ERROR;
}

enum XML_Status XML_SetBase(XML_Parser parser, const XML_Char *base) {
  (void)base;
  if (!validParser(parser))
    return XML_STATUS_ERROR;
  poison(parser, XML_ERROR_UNSUPPORTED_FEATURE);
  return XML_STATUS_ERROR;
}

const XML_Char *XML_GetBase(XML_Parser parser) {
  if (!validParser(parser))
    return NULL;
  poison(parser, XML_ERROR_UNSUPPORTED_FEATURE);
  return NULL;
}

enum XML_Error XML_UseForeignDTD(XML_Parser parser, XML_Bool useDTD) {
  (void)useDTD;
  if (!validParser(parser))
    return XML_ERROR_INVALID_ARGUMENT;
  poison(parser, XML_ERROR_UNSUPPORTED_FEATURE);
  return XML_ERROR_UNSUPPORTED_FEATURE;
}

enum XML_Status XML_StopParser(XML_Parser parser, XML_Bool resumable) {
  (void)resumable;
  if (!validParser(parser))
    return XML_STATUS_ERROR;
  poison(parser, XML_ERROR_UNSUPPORTED_FEATURE);
  return XML_STATUS_ERROR;
}

enum XML_Status XML_ResumeParser(XML_Parser parser) {
  if (!validParser(parser))
    return XML_STATUS_ERROR;
  poison(parser, XML_ERROR_UNSUPPORTED_FEATURE);
  return XML_STATUS_ERROR;
}

void XML_DefaultCurrent(XML_Parser parser) {
  if (!validParser(parser))
    return;
  poison(parser, XML_ERROR_UNSUPPORTED_FEATURE);
}

const char *XML_GetInputContext(XML_Parser parser, int *offset, int *size) {
  if (offset != NULL)
    *offset = 0;
  if (size != NULL)
    *size = 0;
  if (!validParser(parser))
    return NULL;
  poison(parser, XML_ERROR_UNSUPPORTED_FEATURE);
  return NULL;
}

int XML_GetCurrentByteCount(XML_Parser parser) {
  if (!validParser(parser))
    return -1;
  poison(parser, XML_ERROR_UNSUPPORTED_FEATURE);
  return -1;
}

int XML_SetHashSalt(XML_Parser parser, unsigned long hash_salt) {
  (void)hash_salt;
  if (!validParser(parser))
    return 0;
  poison(parser, XML_ERROR_UNSUPPORTED_FEATURE);
  return 0;
}

XML_Bool XML_SetHashSalt16Bytes(XML_Parser parser, const uint8_t entropy[16]) {
  (void)entropy;
  if (!validParser(parser))
    return XML_FALSE;
  poison(parser, XML_ERROR_UNSUPPORTED_FEATURE);
  return XML_FALSE;
}

XML_Bool XML_SetReparseDeferralEnabled(XML_Parser parser, XML_Bool enabled) {
  (void)enabled;
  if (!validParser(parser))
    return XML_FALSE;
  poison(parser, XML_ERROR_UNSUPPORTED_FEATURE);
  return XML_FALSE;
}

XML_Bool XML_SetBillionLaughsAttackProtectionMaximumAmplification(
    XML_Parser parser, float maximumAmplificationFactor) {
  (void)maximumAmplificationFactor;
  if (!validParser(parser))
    return XML_FALSE;
  poison(parser, XML_ERROR_UNSUPPORTED_FEATURE);
  return XML_FALSE;
}

XML_Bool XML_SetBillionLaughsAttackProtectionActivationThreshold(
    XML_Parser parser, unsigned long long activationThresholdBytes) {
  (void)activationThresholdBytes;
  if (!validParser(parser))
    return XML_FALSE;
  poison(parser, XML_ERROR_UNSUPPORTED_FEATURE);
  return XML_FALSE;
}

XML_Bool XML_SetAllocTrackerMaximumAmplification(
    XML_Parser parser, float maximumAmplificationFactor) {
  (void)maximumAmplificationFactor;
  if (!validParser(parser))
    return XML_FALSE;
  poison(parser, XML_ERROR_UNSUPPORTED_FEATURE);
  return XML_FALSE;
}

XML_Bool XML_SetAllocTrackerActivationThreshold(
    XML_Parser parser, unsigned long long activationThresholdBytes) {
  (void)activationThresholdBytes;
  if (!validParser(parser))
    return XML_FALSE;
  poison(parser, XML_ERROR_UNSUPPORTED_FEATURE);
  return XML_FALSE;
}

void *XML_MemMalloc(XML_Parser parser, size_t size) {
  (void)size;
  if (validParser(parser))
    poison(parser, XML_ERROR_UNSUPPORTED_FEATURE);
  return NULL;
}

void *XML_MemRealloc(XML_Parser parser, void *ptr, size_t size) {
  (void)ptr;
  (void)size;
  if (validParser(parser))
    poison(parser, XML_ERROR_UNSUPPORTED_FEATURE);
  return NULL;
}

void XML_MemFree(XML_Parser parser, void *ptr) {
  (void)ptr;
  if (validParser(parser))
    poison(parser, XML_ERROR_UNSUPPORTED_FEATURE);
}

void XML_FreeContentModel(XML_Parser parser, XML_Content *model) {
  (void)model;
  if (validParser(parser))
    poison(parser, XML_ERROR_UNSUPPORTED_FEATURE);
}

void XML_SetDefaultHandler(XML_Parser parser, XML_DefaultHandler handler) {
  refuseHandler(parser, (const void *)handler);
}

void XML_SetDefaultHandlerExpand(XML_Parser parser, XML_DefaultHandler handler) {
  refuseHandler(parser, (const void *)handler);
}

void XML_SetDoctypeDeclHandler(XML_Parser parser,
                               XML_StartDoctypeDeclHandler start,
                               XML_EndDoctypeDeclHandler end) {
  refuseHandler(parser, (const void *)start);
  refuseHandler(parser, (const void *)end);
}

void XML_SetStartDoctypeDeclHandler(XML_Parser parser,
                                    XML_StartDoctypeDeclHandler start) {
  refuseHandler(parser, (const void *)start);
}

void XML_SetEndDoctypeDeclHandler(XML_Parser parser,
                                  XML_EndDoctypeDeclHandler end) {
  refuseHandler(parser, (const void *)end);
}

void XML_SetElementDeclHandler(XML_Parser parser, XML_ElementDeclHandler eldecl) {
  refuseHandler(parser, (const void *)eldecl);
}

void XML_SetAttlistDeclHandler(XML_Parser parser, XML_AttlistDeclHandler attdecl) {
  refuseHandler(parser, (const void *)attdecl);
}

void XML_SetEntityDeclHandler(XML_Parser parser, XML_EntityDeclHandler handler) {
  refuseHandler(parser, (const void *)handler);
}

void XML_SetUnparsedEntityDeclHandler(XML_Parser parser,
                                      XML_UnparsedEntityDeclHandler handler) {
  refuseHandler(parser, (const void *)handler);
}

void XML_SetNotationDeclHandler(XML_Parser parser, XML_NotationDeclHandler handler) {
  refuseHandler(parser, (const void *)handler);
}

void XML_SetNamespaceDeclHandler(XML_Parser parser,
                                 XML_StartNamespaceDeclHandler start,
                                 XML_EndNamespaceDeclHandler end) {
  refuseHandler(parser, (const void *)start);
  refuseHandler(parser, (const void *)end);
}

void XML_SetStartNamespaceDeclHandler(XML_Parser parser,
                                      XML_StartNamespaceDeclHandler start) {
  refuseHandler(parser, (const void *)start);
}

void XML_SetEndNamespaceDeclHandler(XML_Parser parser,
                                    XML_EndNamespaceDeclHandler end) {
  refuseHandler(parser, (const void *)end);
}

void XML_SetNotStandaloneHandler(XML_Parser parser,
                                 XML_NotStandaloneHandler handler) {
  refuseHandler(parser, (const void *)handler);
}

void XML_SetExternalEntityRefHandler(XML_Parser parser,
                                     XML_ExternalEntityRefHandler handler) {
  refuseHandler(parser, (const void *)handler);
}

void XML_SetExternalEntityRefHandlerArg(XML_Parser parser, void *arg) {
  refuseHandler(parser, arg);
}

void XML_SetSkippedEntityHandler(XML_Parser parser,
                                 XML_SkippedEntityHandler handler) {
  refuseHandler(parser, (const void *)handler);
}

void XML_SetUnknownEncodingHandler(XML_Parser parser,
                                   XML_UnknownEncodingHandler handler,
                                   void *encodingHandlerData) {
  (void)encodingHandlerData;
  refuseHandler(parser, (const void *)handler);
}

void XML_UseParserAsHandlerArg(XML_Parser parser) {
  if (!validParser(parser))
    return;
  poison(parser, XML_ERROR_UNSUPPORTED_FEATURE);
}

void XML_SetReturnNSTriplet(XML_Parser parser, int do_nst) {
  if (do_nst != 0)
    refuseHandler(parser, (const void *)&do_nst);
}
