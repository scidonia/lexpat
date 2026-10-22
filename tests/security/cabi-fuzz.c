/*
 * libFuzzer target for the supported C ABI.
 *
 * One source serves two builds: the instrumented target links it with
 * `cabi/expat.c` and the generated Lean objects, and the artifact target links
 * it to the shipped `liblexpat.so.1` with only this file instrumented. It
 * calls public `XML_*` functions only and selects a deterministic combination
 * of handlers, feeding mode and lifecycle from the input's first byte:
 *
 *   0 whole-buffer XML_Parse            4 create and free inside a callback
 *   1 chunked XML_Parse                 5 free the parser inside a callback
 *   2 XML_GetBuffer/XML_ParseBuffer     6 no handlers
 *   3 two sequential parsers            7 all handlers, chunked
 *
 * No pointer is retained past the call that supplied it, and the fuzzer-owned
 * input is never dereferenced outside its allocation.
 */

#include <expat.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define LEXPAT_FUZZ_MAX_INPUT 8192

static XML_Parser active_parser;
static int free_in_callback;
static int create_in_callback;
static long starts;
static long ends;

static void XMLCALL on_start(void *userData, const XML_Char *name,
                             const XML_Char **atts) {
  (void)userData;
  starts++;
  if (name != NULL)
    (void)name[0];
  for (size_t i = 0; atts != NULL && atts[i] != NULL; i++)
    (void)atts[i][0];
  if (create_in_callback) {
    create_in_callback = 0;
    XML_Parser nested = XML_ParserCreate(NULL);
    if (nested != NULL)
      XML_ParserFree(nested);
  }
  if (free_in_callback) {
    free_in_callback = 0;
    XML_ParserFree(active_parser);
  }
}

static void XMLCALL on_end(void *userData, const XML_Char *name) {
  (void)userData;
  ends++;
  if (name != NULL)
    (void)name[0];
}

static void XMLCALL on_text(void *userData, const XML_Char *data, int length) {
  (void)userData;
  if (data != NULL && length > 0)
    (void)data[0];
}

static void XMLCALL on_comment(void *userData, const XML_Char *data) {
  (void)userData;
  if (data != NULL)
    (void)data[0];
}

static void XMLCALL on_pi(void *userData, const XML_Char *target,
                          const XML_Char *data) {
  (void)userData;
  if (target != NULL)
    (void)target[0];
  if (data != NULL)
    (void)data[0];
}

static void XMLCALL on_cdata_start(void *userData) { (void)userData; }
static void XMLCALL on_cdata_end(void *userData) { (void)userData; }

static void XMLCALL on_decl(void *userData, const XML_Char *version,
                            const XML_Char *encoding, int standalone) {
  (void)userData;
  (void)standalone;
  if (version != NULL)
    (void)version[0];
  if (encoding != NULL)
    (void)encoding[0];
}

static void install_all_handlers(XML_Parser parser) {
  XML_SetElementHandler(parser, on_start, on_end);
  XML_SetCharacterDataHandler(parser, on_text);
  XML_SetCommentHandler(parser, on_comment);
  XML_SetProcessingInstructionHandler(parser, on_pi);
  XML_SetCdataSectionHandler(parser, on_cdata_start, on_cdata_end);
  XML_SetXmlDeclHandler(parser, on_decl);
}

static int parse_whole(XML_Parser parser, const char *data, size_t size,
                       int is_final) {
  if (size > (size_t)INT32_MAX)
    return 0;
  return XML_Parse(parser, data, (int)size, is_final) == XML_STATUS_OK;
}

static void parse_chunked(XML_Parser parser, const uint8_t *data, size_t size,
                          size_t step) {
  size_t offset = 0;
  while (offset < size) {
    size_t chunk = step;
    if (chunk > size - offset)
      chunk = size - offset;
    if (XML_Parse(parser, (const char *)(data + offset), (int)chunk, 0)
        != XML_STATUS_OK)
      return;
    offset += chunk;
  }
  (void)XML_Parse(parser, "", 0, 1);
}

static void parse_buffered(XML_Parser parser, const uint8_t *data, size_t size) {
  void *buffer;
  if (size > (size_t)INT32_MAX)
    return;
  buffer = XML_GetBuffer(parser, (int)size);
  if (buffer == NULL)
    return;
  if (size > 0)
    memcpy(buffer, data, size);
  (void)XML_ParseBuffer(parser, (int)size, 1);
}

static void run_variant(XML_Parser parser, int variant, const uint8_t *data,
                        size_t size, size_t step) {
  active_parser = parser;
  switch (variant) {
  case 0:
    (void)parse_whole(parser, (const char *)data, size, 1);
    break;
  case 1:
    parse_chunked(parser, data, size, step);
    break;
  case 2:
    parse_buffered(parser, data, size);
    break;
  case 3: {
    XML_Parser second = XML_ParserCreate(NULL);
    (void)parse_whole(parser, (const char *)data, size, 1);
    if (second != NULL) {
      active_parser = second;
      (void)parse_whole(second, (const char *)data, size, 1);
      XML_ParserFree(second);
    }
    break;
  }
  case 4:
    create_in_callback = 1;
    (void)parse_whole(parser, (const char *)data, size, 1);
    create_in_callback = 0;
    break;
  case 5:
    free_in_callback = 1;
    (void)parse_whole(parser, (const char *)data, size, 1);
    free_in_callback = 0;
    break;
  case 6:
    (void)parse_whole(parser, (const char *)data, size, 1);
    break;
  default:
    parse_chunked(parser, data, size, step);
    break;
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int variant;
  size_t step;
  XML_Parser parser;

  if (size == 0 || size > LEXPAT_FUZZ_MAX_INPUT)
    return 0;
  variant = data[0] & 7;
  step = 1 + ((size > 1 ? data[1] : 0) % 97);
  data += 1;
  size -= 1;

  starts = 0;
  ends = 0;
  parser = XML_ParserCreate(NULL);
  if (parser == NULL)
    return 0;
  if (variant != 6)
    install_all_handlers(parser);
  run_variant(parser, variant, data, size, step);
  /* A parser freed from a callback was unregistered and released by the parse
   * call; the repeated free is a documented no-op. */
  XML_ParserFree(parser);
  active_parser = NULL;
  (void)starts;
  (void)ends;
  return 0;
}
