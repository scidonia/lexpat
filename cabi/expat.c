/*
 * The C half of the liblexpat.so.1 artifact.
 *
 * This file owns the opaque parser handle, the handle registry, the Lean
 * runtime entry points, the direct event receivers and the dispatch to the
 * handlers a client registered. It is compiled with hidden visibility and
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
/* The maximum logical event payload the receiver copies or borrows in one
 * callback: the same 16 MiB ceiling the serialized frame enforced, applied to
 * one event's bytes. */
#define LEXPAT_MAX_PAYLOAD ((size_t)(16 * 1024 * 1024))

/* Lean bridge exports and receiver externals. The receiver symbols are
 * defined in this file; the module initialiser and stream exports come from
 * the generated Lean objects. */
extern lean_object *initialize_lexpat_LexPat_CAbi(uint8_t builtin);
extern lean_object *lexpat_cabi_stream_new(uint64_t hint);
extern lean_object *lexpat_cabi_stream_feed(lean_object *stream, lean_object *bytes);
extern lean_object *lexpat_cabi_stream_finish(lean_object *stream);

uint64_t lexpat_cabi_emit_xml_decl(lean_object *version, lean_object *encoding,
                                   uint8_t has_encoding, int64_t standalone,
                                   uint64_t offset, uint64_t line, uint64_t column);
uint64_t lexpat_cabi_emit_start(lean_object *name, lean_object *attrs, uint64_t offset,
                                uint64_t line, uint64_t column);
uint64_t lexpat_cabi_emit_start_slice(lean_object *owner, uint64_t name_start,
                                     uint64_t name_stop, uint64_t base,
                                     lean_object *ranges, uint64_t offset,
                                     uint64_t line, uint64_t column);
uint64_t lexpat_cabi_emit_end(lean_object *name, uint64_t offset, uint64_t line,
                              uint64_t column);
uint64_t lexpat_cabi_emit_end_slice(lean_object *owner, uint64_t name_start,
                                    uint64_t name_stop, uint64_t base,
                                    uint64_t offset, uint64_t line, uint64_t column);
uint64_t lexpat_cabi_emit_text(lean_object *owner, uint64_t start, uint64_t stop,
                               uint64_t base, uint64_t offset, uint64_t line,
                               uint64_t column);
uint64_t lexpat_cabi_emit_text_string(lean_object *data, uint64_t offset,
                                      uint64_t line, uint64_t column);
uint64_t lexpat_cabi_emit_cdata_start(uint64_t offset, uint64_t line, uint64_t column);
uint64_t lexpat_cabi_emit_cdata_end(uint64_t offset, uint64_t line, uint64_t column);
uint64_t lexpat_cabi_emit_comment(lean_object *data, uint64_t offset, uint64_t line,
                                  uint64_t column);
uint64_t lexpat_cabi_emit_pi(lean_object *target, lean_object *data, uint64_t offset,
                             uint64_t line, uint64_t column);
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
 * Direct event receivers.
 *
 * One callback-specific function per event kind. A receiver validates the
 * location, the payload bounds and the ordered attribute table before it
 * allocates or invokes a handler, sets the current position even when no
 * handler is installed, and allocates payload storage only for a handler that
 * exists. A failed allocation is XML_ERROR_NO_MEMORY; malformed metadata is
 * XML_ERROR_MALFORMED_WIRE, raised before any handler runs.
 *
 * Strings are copied into NUL-terminated storage that lives for the duration
 * of the synchronous callback. Literal character data borrows the Lean array
 * that owns the fed chunk and passes an explicit length; nothing is copied.
 * ---------------------------------------------------------------------- */

/* XML forbids NUL inside a name or character value, and a payload must be
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

static void beginCallback(XML_Parser parser) { parser->inCallback = 1; }
static void endCallback(XML_Parser parser) { parser->inCallback = 0; }

/* Byte length of a Lean string. `lean_string_size` counts the bytes including
 * the terminating NUL, while `lean_string_len` counts UTF-8 characters; every
 * payload bound and copy here is in bytes. */
static size_t stringBytes(lean_object *value) { return lean_string_size(value) - 1; }

/* Record the current position. Every receiver calls this first, so a handler
 * that queries the position sees the event's own coordinates even when no
 * other handler is installed. */
static int setPosition(XML_Parser parser, uint64_t offset, uint64_t line,
                       uint64_t column) {
  const uint64_t fed = (uint64_t)parser->fedEnd;
  if (offset >= fed)
    return 0;
  if (line < 1 || line > fed + 1)
    return 0;
  if (column > fed)
    return 0;
  parser->byteIndex = (XML_Index)offset;
  parser->line = (XML_Size)line;
  parser->column = (XML_Size)column;
  return 1;
}

/* Refuse a payload the receiver cannot accept. */
static uint64_t refuse(XML_Parser parser, enum XML_Error error) {
  if (parser != NULL && parser->error == XML_ERROR_NONE)
    poison(parser, error);
  return 1;
}

/* The receiver's answer after a callback: continue only while the parser still
 * wants more input and was not freed from inside the callback. */
static uint64_t aborted(XML_Parser parser) {
  if (parser->deferredFree || parser->error != XML_ERROR_NONE)
    return 1;
  return 0;
}

/* Validate one payload string and charge its bytes to the event's ceiling. */
static int validatePayload(lean_object *value, size_t *bytes, size_t *total) {
  size_t n = stringBytes(value);
  *total += n;
  if (*total > LEXPAT_MAX_PAYLOAD)
    return 0;
  if (!validUtf8((const unsigned char *)lean_string_cstr(value), n))
    return 0;
  if (bytes != NULL)
    *bytes = n;
  return 1;
}

/* Copy a validated payload string into NUL-terminated storage. */
static char *copyPayload(lean_object *value, size_t *length, int *failed) {
  size_t len = stringBytes(value);
  char *copy = (char *)malloc(len + 1);
  if (copy == NULL) {
    *failed = 1;
    return NULL;
  }
  memcpy(copy, lean_string_cstr(value), len + 1);
  if (length != NULL)
    *length = len;
  return copy;
}

/* Validate the ordered attribute table: every name and value is a legal
 * payload and the whole event stays inside the ceiling. */
static int validateAttributes(lean_object *attrs, size_t *out_pairs) {
  size_t pairs = lean_array_size(attrs);
  size_t total = 0;
  for (size_t i = 0; i < pairs; i++) {
    lean_object *pair = lean_array_get_core(attrs, i);
    for (unsigned side = 0; side < 2; side++) {
      if (!validatePayload(lean_ctor_get(pair, side), NULL, &total))
        return 0;
    }
  }
  *out_pairs = pairs;
  return 1;
}

/* Copy a validated attribute table into a NUL-terminated vector. */
static int copyAttributes(lean_object *attrs, char ***out_pairs, size_t *out_count,
                          int *failed) {
  size_t pairs = lean_array_size(attrs);
  if (pairs > (SIZE_MAX - 1) / (2 * sizeof(char *))) {
    *failed = 0;
    return 0;
  }
  char **result = (char **)calloc(pairs * 2 + 1, sizeof(char *));
  if (result == NULL) {
    *failed = 1;
    return 0;
  }
  for (size_t i = 0; i < pairs; i++) {
    lean_object *pair = lean_array_get_core(attrs, i);
    for (unsigned side = 0; side < 2; side++) {
      result[i * 2 + side] = copyPayload(lean_ctor_get(pair, side), NULL, failed);
      if (result[i * 2 + side] == NULL) {
        for (size_t k = 0; k < i * 2 + side; k++)
          free(result[k]);
        free(result);
        return 0;
      }
    }
  }
  *out_pairs = result;
  *out_count = pairs;
  return 1;
}

uint64_t lexpat_cabi_emit_xml_decl(lean_object *version, lean_object *encoding,
                                   uint8_t has_encoding, int64_t standalone,
                                   uint64_t offset, uint64_t line, uint64_t column) {
  XML_Parser parser = g_currentParser;
  if (parser == NULL) {
    lean_dec_ref(version);
    lean_dec_ref(encoding);
    return 1;
  }
  int malformed = 0;
  size_t total = 0;
  if (!setPosition(parser, offset, line, column) ||
      (standalone != -1 && standalone != 0 && standalone != 1) ||
      !validatePayload(version, NULL, &total))
    malformed = 1;
  if (!malformed && has_encoding && !validatePayload(encoding, NULL, &total))
    malformed = 1;
  if (malformed) {
    lean_dec_ref(version);
    lean_dec_ref(encoding);
    return refuse(parser, XML_ERROR_MALFORMED_WIRE);
  }
  if (parser->xmlDeclHandler == NULL) {
    lean_dec_ref(version);
    lean_dec_ref(encoding);
    return 0;
  }
  int failed = 0;
  char *version_copy = copyPayload(version, NULL, &failed);
  char *encoding_copy = NULL;
  if (!failed && has_encoding)
    encoding_copy = copyPayload(encoding, NULL, &failed);
  lean_dec_ref(version);
  lean_dec_ref(encoding);
  if (failed) {
    free(version_copy);
    free(encoding_copy);
    return refuse(parser, XML_ERROR_NO_MEMORY);
  }
  beginCallback(parser);
  parser->xmlDeclHandler(parser->userData, version_copy, encoding_copy,
                         (int)standalone);
  endCallback(parser);
  free(version_copy);
  free(encoding_copy);
  return aborted(parser);
}

/* Validate one range of `owner` as a payload: inside the owner, inside the bytes
 * fed so far, legal UTF-8, and charged to the event's logical ceiling. */
static int slicePayload(lean_object *owner, size_t size, uint64_t base,
                        uint64_t start, uint64_t stop, uint64_t fed,
                        size_t *total, const char **out, size_t *out_len) {
  if (start > stop || stop > (uint64_t)size)
    return 0;
  if (base > UINT64_MAX - stop || base + stop > fed)
    return 0;
  size_t n = (size_t)(stop - start);
  if (*total > LEXPAT_MAX_PAYLOAD - n)
    return 0;
  const char *bytes = (const char *)(lean_sarray_cptr(owner) + (size_t)start);
  if (!validUtf8((const unsigned char *)bytes, n))
    return 0;
  *total += n;
  *out = bytes;
  *out_len = n;
  return 1;
}

/* A start tag whose element name and ordered attribute pairs are still spans of
 * `owner`: `ranges` holds four numbers per pair (name start, name stop, value
 * start, value stop), all relative to `owner`, and `base` is the absolute offset
 * of `owner`'s first byte. Every range is validated before anything is
 * allocated, and the whole event is copied into one NUL-terminated arena plus
 * one pointer vector, so an attribute-heavy tag costs two allocations instead of
 * one per string. */
uint64_t lexpat_cabi_emit_start_slice(lean_object *owner, uint64_t name_start,
                                      uint64_t name_stop, uint64_t base,
                                      lean_object *ranges, uint64_t offset,
                                      uint64_t line, uint64_t column) {
  XML_Parser parser = g_currentParser;
  if (parser == NULL) {
    lean_dec_ref(owner);
    lean_dec_ref(ranges);
    return 1;
  }
  size_t size = lean_sarray_size(owner);
  size_t count = lean_array_size(ranges);
  uint64_t fed = (uint64_t)parser->fedEnd;
  int malformed = 0;
  size_t pairs = 0;
  size_t total = 0;
  const char *element = NULL;
  size_t element_len = 0;
  if (!setPosition(parser, offset, line, column))
    malformed = 1;
  if (!malformed && count % 4 != 0)
    malformed = 1;
  if (!malformed && !slicePayload(owner, size, base, name_start, name_stop, fed,
                                  &total, &element, &element_len))
    malformed = 1;
  if (!malformed) {
    pairs = count / 4;
    for (size_t i = 0; !malformed && i < pairs; i++) {
      const char *ignored = NULL;
      size_t ignored_len = 0;
      for (unsigned side = 0; side < 2; side++) {
        uint64_t start = lean_unbox_uint64(lean_array_get_core(ranges, 4 * i + 2 * side));
        uint64_t stop = lean_unbox_uint64(lean_array_get_core(ranges, 4 * i + 2 * side + 1));
        if (!slicePayload(owner, size, base, start, stop, fed, &total, &ignored,
                          &ignored_len)) {
          malformed = 1;
          break;
        }
      }
    }
  }
  if (malformed) {
    lean_dec_ref(owner);
    lean_dec_ref(ranges);
    return refuse(parser, XML_ERROR_MALFORMED_WIRE);
  }
  if (parser->startHandler == NULL) {
    lean_dec_ref(owner);
    lean_dec_ref(ranges);
    return 0;
  }
  size_t strings = pairs * 2 + 1;
  if (total > SIZE_MAX - strings ||
      pairs > (SIZE_MAX - 1) / (2 * sizeof(char *))) {
    lean_dec_ref(owner);
    lean_dec_ref(ranges);
    return refuse(parser, XML_ERROR_NO_MEMORY);
  }
  char *arena = (char *)malloc(total + strings);
  char **atts = (char **)calloc(pairs * 2 + 1, sizeof(char *));
  if (arena == NULL || atts == NULL) {
    free(arena);
    free(atts);
    lean_dec_ref(owner);
    lean_dec_ref(ranges);
    return refuse(parser, XML_ERROR_NO_MEMORY);
  }
  size_t used = 0;
  memcpy(arena + used, element, element_len);
  arena[used + element_len] = '\0';
  char *element_copy = arena + used;
  used += element_len + 1;
  for (size_t i = 0; i < pairs * 2; i++) {
    uint64_t start = lean_unbox_uint64(lean_array_get_core(ranges, 2 * i));
    uint64_t stop = lean_unbox_uint64(lean_array_get_core(ranges, 2 * i + 1));
    size_t n = (size_t)(stop - start);
    memcpy(arena + used, (const char *)(lean_sarray_cptr(owner) + (size_t)start), n);
    arena[used + n] = '\0';
    atts[i] = arena + used;
    used += n + 1;
  }
  lean_dec_ref(owner);
  lean_dec_ref(ranges);
  parser->specifiedAttrs = (int)(pairs * 2);
  beginCallback(parser);
  parser->startHandler(parser->userData, element_copy, (const XML_Char **)atts);
  endCallback(parser);
  parser->specifiedAttrs = 0;
  free(atts);
  free(arena);
  return aborted(parser);
}

uint64_t lexpat_cabi_emit_start(lean_object *name, lean_object *attrs,
                                uint64_t offset, uint64_t line, uint64_t column) {
  XML_Parser parser = g_currentParser;
  if (parser == NULL) {
    lean_dec_ref(name);
    lean_dec_ref(attrs);
    return 1;
  }
  int malformed = 0;
  size_t total = 0;
  size_t pairs = 0;
  if (!setPosition(parser, offset, line, column) ||
      !validatePayload(name, NULL, &total) || !validateAttributes(attrs, &pairs))
    malformed = 1;
  if (malformed) {
    lean_dec_ref(name);
    lean_dec_ref(attrs);
    return refuse(parser, XML_ERROR_MALFORMED_WIRE);
  }
  if (parser->startHandler == NULL) {
    lean_dec_ref(name);
    lean_dec_ref(attrs);
    return 0;
  }
  int failed = 0;
  char *element = copyPayload(name, NULL, &failed);
  char **atts = NULL;
  size_t copied = 0;
  if (!failed && !copyAttributes(attrs, &atts, &copied, &failed))
    failed = failed || 1;
  lean_dec_ref(name);
  lean_dec_ref(attrs);
  if (failed) {
    free(element);
    return refuse(parser, XML_ERROR_NO_MEMORY);
  }
  parser->specifiedAttrs = (int)(copied * 2);
  beginCallback(parser);
  parser->startHandler(parser->userData, element, (const XML_Char **)atts);
  endCallback(parser);
  parser->specifiedAttrs = 0;
  for (size_t i = 0; i < copied * 2; i++)
    free(atts[i]);
  free(atts);
  free(element);
  return aborted(parser);
}

uint64_t lexpat_cabi_emit_end(lean_object *name, uint64_t offset, uint64_t line,
                              uint64_t column) {
  XML_Parser parser = g_currentParser;
  if (parser == NULL) {
    lean_dec_ref(name);
    return 1;
  }
  int malformed = 0;
  size_t total = 0;
  if (!setPosition(parser, offset, line, column) ||
      !validatePayload(name, NULL, &total))
    malformed = 1;
  if (malformed) {
    lean_dec_ref(name);
    return refuse(parser, XML_ERROR_MALFORMED_WIRE);
  }
  if (parser->endHandler == NULL) {
    lean_dec_ref(name);
    return 0;
  }
  int failed = 0;
  char *element = copyPayload(name, NULL, &failed);
  lean_dec_ref(name);
  if (failed) {
    free(element);
    return refuse(parser, XML_ERROR_NO_MEMORY);
  }
  beginCallback(parser);
  parser->endHandler(parser->userData, element);
  endCallback(parser);
  free(element);
  return aborted(parser);
}

/* An end tag whose name is still a span of `owner`. */
uint64_t lexpat_cabi_emit_end_slice(lean_object *owner, uint64_t name_start,
                                    uint64_t name_stop, uint64_t base,
                                    uint64_t offset, uint64_t line, uint64_t column) {
  XML_Parser parser = g_currentParser;
  if (parser == NULL) {
    lean_dec_ref(owner);
    return 1;
  }
  size_t size = lean_sarray_size(owner);
  size_t total = 0;
  const char *name = NULL;
  size_t name_len = 0;
  int malformed =
      !setPosition(parser, offset, line, column) ||
      !slicePayload(owner, size, base, name_start, name_stop,
                    (uint64_t)parser->fedEnd, &total, &name, &name_len);
  if (malformed) {
    lean_dec_ref(owner);
    return refuse(parser, XML_ERROR_MALFORMED_WIRE);
  }
  if (parser->endHandler == NULL) {
    lean_dec_ref(owner);
    return 0;
  }
  char *copy = (char *)malloc(name_len + 1);
  if (copy == NULL) {
    lean_dec_ref(owner);
    return refuse(parser, XML_ERROR_NO_MEMORY);
  }
  memcpy(copy, name, name_len);
  copy[name_len] = '\0';
  lean_dec_ref(owner);
  beginCallback(parser);
  parser->endHandler(parser->userData, copy);
  endCallback(parser);
  free(copy);
  return aborted(parser);
}

/* Literal character data. The payload is borrowed from the Lean array that
 * owns the fed chunk and passed with an explicit length; nothing is copied. */
uint64_t lexpat_cabi_emit_text(lean_object *owner, uint64_t start, uint64_t stop,
                               uint64_t base, uint64_t offset, uint64_t line,
                               uint64_t column) {
  XML_Parser parser = g_currentParser;
  if (parser == NULL) {
    lean_dec_ref(owner);
    return 1;
  }
  int malformed = 0;
  size_t size = lean_sarray_size(owner);
  uint64_t length = 0;
  if (!setPosition(parser, offset, line, column))
    malformed = 1;
  if (!malformed && (start > stop || stop > (uint64_t)size))
    malformed = 1;
  if (!malformed && start > UINT64_MAX - base)
    malformed = 1;
  if (!malformed) {
    length = stop - start;
    uint64_t absolute_start = base + start;
    uint64_t absolute_stop = base + stop;
    if (absolute_start < offset || absolute_stop > (uint64_t)parser->fedEnd)
      malformed = 1;
    else if (length > (uint64_t)LEXPAT_MAX_PAYLOAD || length > (uint64_t)INT_MAX)
      malformed = 1;
    else if (!validUtf8(lean_sarray_cptr(owner) + start, (size_t)length))
      malformed = 1;
  }
  if (malformed) {
    lean_dec_ref(owner);
    return refuse(parser, XML_ERROR_MALFORMED_WIRE);
  }
  if (parser->characterHandler != NULL) {
    beginCallback(parser);
    parser->characterHandler(parser->userData,
                             (const XML_Char *)(lean_sarray_cptr(owner) + start),
                             (int)length);
    endCallback(parser);
  }
  lean_dec_ref(owner);
  return aborted(parser);
}

/* Character data that had to be materialized: a reference expansion, a
 * normalized line ending or a token that crossed a feed boundary.
 *
 * The payload is a Lean string, which owns its UTF-8 bytes and stays referenced
 * for this call, so the length-delimited handler reads it in place: character
 * data has no NUL-termination requirement and no copy is needed. */
uint64_t lexpat_cabi_emit_text_string(lean_object *data, uint64_t offset,
                                      uint64_t line, uint64_t column) {
  XML_Parser parser = g_currentParser;
  if (parser == NULL) {
    lean_dec_ref(data);
    return 1;
  }
  size_t length = stringBytes(data);
  int malformed =
      !setPosition(parser, offset, line, column) ||
      length > (size_t)LEXPAT_MAX_PAYLOAD || length > (size_t)INT_MAX ||
      !validUtf8((const unsigned char *)lean_string_cstr(data), length);
  if (malformed) {
    lean_dec_ref(data);
    return refuse(parser, XML_ERROR_MALFORMED_WIRE);
  }
  if (parser->characterHandler != NULL) {
    beginCallback(parser);
    parser->characterHandler(parser->userData,
                             (const XML_Char *)lean_string_cstr(data), (int)length);
    endCallback(parser);
  }
  lean_dec_ref(data);
  return aborted(parser);
}

/* Materialized character data held by the stream as its own byte array: a
 * reference expansion, a normalized line ending or a token that crossed a feed
 * boundary. The array owns its bytes and stays referenced for this call, so the
 * length-delimited handler reads them in place: character data has no
 * NUL-termination requirement and no copy is needed. */
uint64_t lexpat_cabi_emit_text_bytes(lean_object *data, uint64_t offset,
                                     uint64_t line, uint64_t column) {
  XML_Parser parser = g_currentParser;
  if (parser == NULL) {
    lean_dec_ref(data);
    return 1;
  }
  size_t length = lean_sarray_size(data);
  const unsigned char *bytes = lean_sarray_cptr(data);
  int malformed =
      !setPosition(parser, offset, line, column) ||
      length > (size_t)LEXPAT_MAX_PAYLOAD || length > (size_t)INT_MAX ||
      !validUtf8(bytes, length);
  if (malformed) {
    lean_dec_ref(data);
    return refuse(parser, XML_ERROR_MALFORMED_WIRE);
  }
  if (parser->characterHandler != NULL) {
    beginCallback(parser);
    parser->characterHandler(parser->userData, (const XML_Char *)bytes,
                             (int)length);
    endCallback(parser);
  }
  lean_dec_ref(data);
  return aborted(parser);
}

uint64_t lexpat_cabi_emit_cdata_start(uint64_t offset, uint64_t line,
                                      uint64_t column) {
  XML_Parser parser = g_currentParser;
  if (parser == NULL)
    return 1;
  if (!setPosition(parser, offset, line, column))
    return refuse(parser, XML_ERROR_MALFORMED_WIRE);
  if (parser->startCdataHandler != NULL) {
    beginCallback(parser);
    parser->startCdataHandler(parser->userData);
    endCallback(parser);
  }
  return aborted(parser);
}

uint64_t lexpat_cabi_emit_cdata_end(uint64_t offset, uint64_t line, uint64_t column) {
  XML_Parser parser = g_currentParser;
  if (parser == NULL)
    return 1;
  if (!setPosition(parser, offset, line, column))
    return refuse(parser, XML_ERROR_MALFORMED_WIRE);
  if (parser->endCdataHandler != NULL) {
    beginCallback(parser);
    parser->endCdataHandler(parser->userData);
    endCallback(parser);
  }
  return aborted(parser);
}

uint64_t lexpat_cabi_emit_comment(lean_object *data, uint64_t offset, uint64_t line,
                                  uint64_t column) {
  XML_Parser parser = g_currentParser;
  if (parser == NULL) {
    lean_dec_ref(data);
    return 1;
  }
  int malformed = 0;
  size_t total = 0;
  if (!setPosition(parser, offset, line, column) ||
      !validatePayload(data, NULL, &total))
    malformed = 1;
  if (malformed) {
    lean_dec_ref(data);
    return refuse(parser, XML_ERROR_MALFORMED_WIRE);
  }
  if (parser->commentHandler == NULL) {
    lean_dec_ref(data);
    return 0;
  }
  int failed = 0;
  char *copy = copyPayload(data, NULL, &failed);
  lean_dec_ref(data);
  if (failed) {
    free(copy);
    return refuse(parser, XML_ERROR_NO_MEMORY);
  }
  beginCallback(parser);
  parser->commentHandler(parser->userData, copy);
  endCallback(parser);
  free(copy);
  return aborted(parser);
}

uint64_t lexpat_cabi_emit_pi(lean_object *target, lean_object *data, uint64_t offset,
                             uint64_t line, uint64_t column) {
  XML_Parser parser = g_currentParser;
  if (parser == NULL) {
    lean_dec_ref(target);
    lean_dec_ref(data);
    return 1;
  }
  int malformed = 0;
  size_t total = 0;
  if (!setPosition(parser, offset, line, column) ||
      !validatePayload(target, NULL, &total) ||
      !validatePayload(data, NULL, &total))
    malformed = 1;
  if (malformed) {
    lean_dec_ref(target);
    lean_dec_ref(data);
    return refuse(parser, XML_ERROR_MALFORMED_WIRE);
  }
  if (parser->piHandler == NULL) {
    lean_dec_ref(target);
    lean_dec_ref(data);
    return 0;
  }
  int failed = 0;
  char *target_copy = copyPayload(target, NULL, &failed);
  char *data_copy = NULL;
  if (!failed)
    data_copy = copyPayload(data, NULL, &failed);
  lean_dec_ref(target);
  lean_dec_ref(data);
  if (failed) {
    free(target_copy);
    free(data_copy);
    return refuse(parser, XML_ERROR_NO_MEMORY);
  }
  beginCallback(parser);
  parser->piHandler(parser->userData, target_copy, data_copy);
  endCallback(parser);
  free(target_copy);
  free(data_copy);
  return aborted(parser);
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
  /* The upper bound for any source position a callback may name: the bytes
   * handed to this parser through the end of this call. The stream's own
   * `rawConsumed` can lag behind while it holds an unfinished start tag, so it
   * cannot be used as that bound. */
  parser->fedEnd = parser->fedEnd + length;
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
  /* The remaining raw-input budget is measured from the bytes handed to this
   * parser, not from the bytes the stream has consumed: an unfinished start tag
   * held over a feed boundary lags `rawConsumed`, and a reservation must not slip
   * past the budget through that gap. */
  if (len < 0 || (size_t)len > LEXPAT_MAX_INPUT - parser->fedEnd) {
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
