/*
 * In-process differential comparator for the pinned libexpat oracle.
 *
 * Two build shapes share this source, and both load *both* libraries with
 * `dlopen(..., RTLD_NOW | RTLD_LOCAL)` and call through separate `dlsym`
 * tables. Neither shape links a parser into the comparator:
 *
 *   differential-fuzz    `-DLEX_FUZZ_TARGET`. The fuzzer executable contains
 *                        only this harness and the libFuzzer runtime; the
 *                        coverage-instrumented candidate shared object and the
 *                        pinned, uninstrumented oracle are both loaded at
 *                        runtime. `LLVMFuzzerTestOneInput` generates a document
 *                        from the control bytes, parses it with both
 *                        libraries, and aborts on any unlisted mismatch.
 *
 *   differential-replay  No macro: the same two-library comparator runs as a
 *                        command-line driver. `--compare
 *                        <candidate|oracle|both> <file>` prints the normalized
 *                        events and result of the chosen side(s) from one
 *                        process, and `--version` prints the oracle identity
 *                        after the exact guard below has passed.
 *
 * Normalization keeps event order, start names and ordered attribute pairs,
 * PI target/data, declaration fields, comment and CDATA boundaries; adjacent
 * text is coalesced and never crosses a CDATA boundary. Byte/line/column and
 * error prose are dropped. Accepted documents compare their normalized event
 * stream; rejected documents compare accept/reject and the numeric public
 * error code. There is no heuristic exception: a mismatch is a failure.
 *
 * Oracle guard: before any comparison the comparator requires
 * `pkg-config --modversion expat` to be exactly `2.8.5` (that is the path the
 * oracle library is resolved from at build time), and the loaded oracle must
 * report exactly `XML_ExpatVersion() == "expat_2.8.5"` and
 * `XML_ExpatVersionInfo() == {2, 8, 5}`. The build and replay drivers repeat
 * the `pkg-config` check so a mismatch fails before the targets are produced
 * or replayed. A near match such as `2.8.50` is a prerequisite failure, never
 * an acceptable oracle.
 */

#define _POSIX_C_SOURCE 200809L

#include <expat.h>

#include <dlfcn.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LEXPAT_FUZZ_MAX_INPUT 8192

/* The build supplies absolute paths from the pinned pkg-config and artifact
 * location, because a `dlopen` of a soname does not consult a link-time rpath
 * for a library this binary never links. */
#ifndef LEX_DEFAULT_ORACLE
#define LEX_DEFAULT_ORACLE "libexpat.so.1"
#endif
#ifndef LEX_DEFAULT_CANDIDATE
#define LEX_DEFAULT_CANDIDATE ".lake/build/lib/liblexpat.so.1"
#endif

#define LEX_PINNED_VERSION_STRING "expat_2.8.5"
#define LEX_PINNED_VERSION_MAJOR 2
#define LEX_PINNED_VERSION_MINOR 8
#define LEX_PINNED_VERSION_MICRO 5
#define LEX_PINNED_PKG_CONFIG "2.8.5"

typedef struct {
  void *handle;
  XML_Parser (*ParserCreate)(const XML_Char *encoding);
  void (*ParserFree)(XML_Parser parser);
  void (*SetUserData)(XML_Parser parser, void *userData);
  void (*SetElementHandler)(XML_Parser parser, XML_StartElementHandler start,
                            XML_EndElementHandler end);
  void (*SetCharacterDataHandler)(XML_Parser parser,
                                  XML_CharacterDataHandler handler);
  void (*SetCommentHandler)(XML_Parser parser, XML_CommentHandler handler);
  void (*SetProcessingInstructionHandler)(XML_Parser parser,
                                          XML_ProcessingInstructionHandler handler);
  void (*SetCdataSectionHandler)(XML_Parser parser,
                                 XML_StartCdataSectionHandler start,
                                 XML_EndCdataSectionHandler end);
  void (*SetXmlDeclHandler)(XML_Parser parser, XML_XmlDeclHandler handler);
  int (*SetParamEntityParsing)(XML_Parser parser,
                               enum XML_ParamEntityParsing parsing);
  enum XML_Status (*Parse)(XML_Parser parser, const char *s, int len, int isFinal);
  enum XML_Error (*GetErrorCode)(XML_Parser parser);
  const XML_LChar *(*ExpatVersion)(void);
  XML_Expat_Version (*ExpatVersionInfo)(void);
} Api;

/* -------------------------------------------------------------------------
 * A growable output buffer.
 * ---------------------------------------------------------------------- */

typedef struct {
  char *data;
  size_t len;
  size_t cap;
  int open_text;
} Buf;

static void buf_init(Buf *buf) {
  buf->cap = 4096;
  buf->data = (char *)malloc(buf->cap);
  if (buf->data == NULL) {
    fputs("differential: out of memory for an output buffer\n", stderr);
    exit(3);
  }
  buf->data[0] = '\0';
  buf->len = 0;
  buf->open_text = 0;
}

static void buf_free(Buf *buf) {
  free(buf->data);
  buf->data = NULL;
  buf->len = 0;
  buf->cap = 0;
}

static void buf_need(Buf *buf, size_t extra) {
  if (buf->len + extra + 1 <= buf->cap)
    return;
  size_t cap = buf->cap;
  while (cap < buf->len + extra + 1)
    cap *= 2;
  char *grown = (char *)realloc(buf->data, cap);
  if (grown == NULL) {
    fputs("differential: out of memory growing an output buffer\n", stderr);
    exit(3);
  }
  buf->data = grown;
  buf->cap = cap;
}

static void buf_write(Buf *buf, const char *text, size_t length) {
  buf_need(buf, length);
  if (length > 0)
    memcpy(buf->data + buf->len, text, length);
  buf->len += length;
  buf->data[buf->len] = '\0';
}

static void buf_puts(Buf *buf, const char *text) {
  buf_write(buf, text, strlen(text));
}

static void buf_putc(Buf *buf, char byte) { buf_write(buf, &byte, 1); }

static void buf_int(Buf *buf, long value) {
  char digits[32];
  snprintf(digits, sizeof digits, "%ld", value);
  buf_puts(buf, digits);
}

static void buf_escape(Buf *buf, const char *text, size_t length) {
  for (size_t i = 0; i < length; i++) {
    unsigned char byte = (unsigned char)text[i];
    switch (byte) {
    case '"':
      buf_puts(buf, "\\\"");
      break;
    case '\\':
      buf_puts(buf, "\\\\");
      break;
    case '\n':
      buf_puts(buf, "\\n");
      break;
    case '\r':
      buf_puts(buf, "\\r");
      break;
    case '\t':
      buf_puts(buf, "\\t");
      break;
    default:
      if (byte < 0x20) {
        char escaped[8];
        snprintf(escaped, sizeof escaped, "\\u%04x", (unsigned)byte);
        buf_puts(buf, escaped);
      } else {
        buf_putc(buf, (char)byte);
      }
    }
  }
}

static void buf_json_bytes(Buf *buf, const char *text, size_t length) {
  buf_putc(buf, '"');
  buf_escape(buf, text, length);
  buf_putc(buf, '"');
}

/* Element names, PI targets/data and comment data are strings; a NULL from
 * either library means the empty string here, as in `tests/c-abi-client.c`. */
static void buf_json_cstr(Buf *buf, const char *text) {
  if (text == NULL) {
    buf_puts(buf, "\"\"");
    return;
  }
  buf_json_bytes(buf, text, strlen(text));
}

/* The declaration's encoding is genuinely optional. */
static void buf_json_optional(Buf *buf, const char *text) {
  if (text == NULL) {
    buf_puts(buf, "null");
    return;
  }
  buf_json_bytes(buf, text, strlen(text));
}

/* -------------------------------------------------------------------------
 * Normalized event recording.
 * ---------------------------------------------------------------------- */

typedef struct {
  Buf *out;
} Ctx;

static void close_text(Buf *buf) {
  if (buf->open_text) {
    buf_puts(buf, "\"}");
    buf->open_text = 0;
  }
}

static void begin_event(Buf *buf, const char *type) {
  close_text(buf);
  if (buf->len > 0)
    buf_putc(buf, '\n');
  buf_puts(buf, "{\"format\":1,\"type\":\"");
  buf_puts(buf, type);
  buf_putc(buf, '"');
}

static void end_event(Buf *buf) { buf_putc(buf, '}'); }

static void XMLCALL h_decl(void *userData, const XML_Char *version,
                           const XML_Char *encoding, int standalone) {
  Ctx *ctx = (Ctx *)userData;
  Buf *buf = ctx->out;
  begin_event(buf, "xmlDecl");
  buf_puts(buf, ",\"version\":");
  buf_json_cstr(buf, version);
  buf_puts(buf, ",\"encoding\":");
  buf_json_optional(buf, encoding);
  buf_puts(buf, ",\"standalone\":");
  if (standalone < 0)
    buf_puts(buf, "null");
  else
    buf_puts(buf, standalone == 0 ? "false" : "true");
  end_event(buf);
}

static void XMLCALL h_start(void *userData, const XML_Char *name,
                            const XML_Char **atts) {
  Ctx *ctx = (Ctx *)userData;
  Buf *buf = ctx->out;
  begin_event(buf, "start");
  buf_puts(buf, ",\"name\":");
  buf_json_cstr(buf, name);
  buf_puts(buf, ",\"attributes\":[");
  for (size_t i = 0; atts != NULL && atts[i] != NULL; i += 2) {
    if (i != 0)
      buf_putc(buf, ',');
    buf_putc(buf, '[');
    buf_json_cstr(buf, atts[i]);
    buf_putc(buf, ',');
    buf_json_cstr(buf, atts[i + 1]);
    buf_putc(buf, ']');
  }
  buf_puts(buf, "]");
  end_event(buf);
}

static void XMLCALL h_end(void *userData, const XML_Char *name) {
  Ctx *ctx = (Ctx *)userData;
  Buf *buf = ctx->out;
  begin_event(buf, "end");
  buf_puts(buf, ",\"name\":");
  buf_json_cstr(buf, name);
  end_event(buf);
}

static void XMLCALL h_text(void *userData, const XML_Char *data, int length) {
  Ctx *ctx = (Ctx *)userData;
  Buf *buf = ctx->out;
  if (length < 0)
    length = 0;
  if (buf->open_text) {
    buf_escape(buf, data == NULL ? "" : data, (size_t)length);
    return;
  }
  begin_event(buf, "text");
  buf_puts(buf, ",\"data\":\"");
  buf_escape(buf, data == NULL ? "" : data, (size_t)length);
  buf->open_text = 1;
}

static void XMLCALL h_cdata_start(void *userData) {
  Ctx *ctx = (Ctx *)userData;
  begin_event(ctx->out, "cdataStart");
  end_event(ctx->out);
}

static void XMLCALL h_cdata_end(void *userData) {
  Ctx *ctx = (Ctx *)userData;
  begin_event(ctx->out, "cdataEnd");
  end_event(ctx->out);
}

static void XMLCALL h_comment(void *userData, const XML_Char *data) {
  Ctx *ctx = (Ctx *)userData;
  begin_event(ctx->out, "comment");
  buf_puts(ctx->out, ",\"data\":");
  buf_json_cstr(ctx->out, data);
  end_event(ctx->out);
}

static void XMLCALL h_pi(void *userData, const XML_Char *target,
                         const XML_Char *data) {
  Ctx *ctx = (Ctx *)userData;
  begin_event(ctx->out, "pi");
  buf_puts(ctx->out, ",\"target\":");
  buf_json_cstr(ctx->out, target);
  buf_puts(ctx->out, ",\"data\":");
  buf_json_cstr(ctx->out, data);
  end_event(ctx->out);
}

static void record_parse(const Api *api, const unsigned char *data, size_t size,
                         Buf *out, int *ok, int *code) {
  Ctx ctx = {out};
  XML_Parser parser = api->ParserCreate(NULL);
  if (parser == NULL) {
    fputs("differential: XML_ParserCreate returned NULL\n", stderr);
    exit(3);
  }
  api->SetUserData(parser, &ctx);
  api->SetXmlDeclHandler(parser, h_decl);
  api->SetElementHandler(parser, h_start, h_end);
  api->SetCharacterDataHandler(parser, h_text);
  api->SetCdataSectionHandler(parser, h_cdata_start, h_cdata_end);
  api->SetCommentHandler(parser, h_comment);
  api->SetProcessingInstructionHandler(parser, h_pi);
  api->SetParamEntityParsing(parser, XML_PARAM_ENTITY_PARSING_NEVER);

  if (size > (size_t)INT32_MAX) {
    fputs("differential: input exceeds the public parser length field\n", stderr);
    exit(3);
  }
  enum XML_Status status = api->Parse(parser, (const char *)data, (int)size, 1);
  *code = (int)api->GetErrorCode(parser);
  *ok = status == XML_STATUS_OK;
  api->ParserFree(parser);

  close_text(out);
  if (out->len > 0)
    buf_putc(out, '\n');
  buf_puts(out, "{\"format\":1,\"type\":\"result\",\"ok\":");
  buf_puts(out, *ok ? "true" : "false");
  buf_puts(out, ",\"status\":");
  buf_int(out, (long)status);
  buf_puts(out, ",\"code\":");
  buf_int(out, (long)*code);
  buf_puts(out, "}");
}

/* -------------------------------------------------------------------------
 * Library loading.
 * ---------------------------------------------------------------------- */

static void *must_symbol(void *handle, const char *name) {
  dlerror();
  void *symbol = dlsym(handle, name);
  const char *error = dlerror();
  if (error != NULL) {
    fprintf(stderr, "differential: dlsym(%s) failed: %s\n", name, error);
    exit(3);
  }
  return symbol;
}

static void load_api(const char *path, Api *api) {
  memset(api, 0, sizeof *api);
  api->handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
  if (api->handle == NULL) {
    fprintf(stderr, "differential: dlopen(%s) failed: %s\n", path, dlerror());
    exit(3);
  }
#define BIND(field, symbol) \
  api->field = (__typeof__(api->field))must_symbol(api->handle, symbol)
  BIND(ParserCreate, "XML_ParserCreate");
  BIND(ParserFree, "XML_ParserFree");
  BIND(SetUserData, "XML_SetUserData");
  BIND(SetElementHandler, "XML_SetElementHandler");
  BIND(SetCharacterDataHandler, "XML_SetCharacterDataHandler");
  BIND(SetCommentHandler, "XML_SetCommentHandler");
  BIND(SetProcessingInstructionHandler, "XML_SetProcessingInstructionHandler");
  BIND(SetCdataSectionHandler, "XML_SetCdataSectionHandler");
  BIND(SetXmlDeclHandler, "XML_SetXmlDeclHandler");
  BIND(SetParamEntityParsing, "XML_SetParamEntityParsing");
  BIND(Parse, "XML_Parse");
  BIND(GetErrorCode, "XML_GetErrorCode");
  BIND(ExpatVersion, "XML_ExpatVersion");
  BIND(ExpatVersionInfo, "XML_ExpatVersionInfo");
#undef BIND
}

static const char *env_or(const char *name, const char *fallback) {
  const char *value = getenv(name);
  return value != NULL && value[0] != '\0' ? value : fallback;
}

static Api oracle_api;
static const char *oracle_path;
static char pkg_config_version[64];

/* The oracle path is chosen from `pkg-config` at build time, so the runtime
 * guard re-reads the same identity exactly. A near match such as 2.8.50 is a
 * prerequisite failure. */
static void require_pkg_config(void) {
  FILE *pipe = popen("pkg-config --modversion expat", "r");
  if (pipe == NULL) {
    fputs("differential: cannot run pkg-config --modversion expat\n", stderr);
    exit(3);
  }
  size_t got = fread(pkg_config_version, 1, sizeof pkg_config_version - 1, pipe);
  pkg_config_version[got] = '\0';
  int status = pclose(pipe);
  while (got > 0 && (pkg_config_version[got - 1] == '\n'
                     || pkg_config_version[got - 1] == '\r'
                     || pkg_config_version[got - 1] == ' '))
    pkg_config_version[--got] = '\0';
  if (status != 0 || strcmp(pkg_config_version, LEX_PINNED_PKG_CONFIG) != 0) {
    fprintf(stderr,
            "differential: pkg-config --modversion expat is \"%s\", not "
            "exactly \"%s\"\n",
            pkg_config_version, LEX_PINNED_PKG_CONFIG);
    exit(3);
  }
}

static void init_oracle(void) {
  require_pkg_config();
  oracle_path = env_or("LEXPAT_DIFF_ORACLE", LEX_DEFAULT_ORACLE);
  load_api(oracle_path, &oracle_api);

  const char *version = oracle_api.ExpatVersion();
  XML_Expat_Version info = oracle_api.ExpatVersionInfo();
  if (version == NULL || strcmp(version, LEX_PINNED_VERSION_STRING) != 0) {
    fprintf(stderr,
            "differential: the oracle version string is %s, not exactly "
            "\"%s\"\n",
            version == NULL ? "(null)" : version, LEX_PINNED_VERSION_STRING);
    exit(3);
  }
  if (info.major != LEX_PINNED_VERSION_MAJOR
      || info.minor != LEX_PINNED_VERSION_MINOR
      || info.micro != LEX_PINNED_VERSION_MICRO) {
    fprintf(stderr,
            "differential: the oracle version info is {%d,%d,%d}, not exactly "
            "{%d,%d,%d}\n",
            info.major, info.minor, info.micro, LEX_PINNED_VERSION_MAJOR,
            LEX_PINNED_VERSION_MINOR, LEX_PINNED_VERSION_MICRO);
    exit(3);
  }
}

static Api candidate_api;

static void init_candidate(void) {
  load_api(env_or("LEXPAT_DIFF_CANDIDATE", LEX_DEFAULT_CANDIDATE),
           &candidate_api);
}

/* -------------------------------------------------------------------------
 * Grammar generator.
 *
 * Only the documented supported intersection is generated: UTF-8, no DTD or
 * entity declarations, no external identifiers. Malformed cases are the
 * classes the corpus already compares exactly (mismatched tag, duplicate
 * attribute, junk after the root, a stray end tag, and the unclosed element,
 * comment, CDATA section and PI forms).
 * ---------------------------------------------------------------------- */

#ifdef LEX_FUZZ_TARGET

typedef struct {
  const uint8_t *data;
  size_t size;
  size_t at;
  char *out;
  size_t len;
  size_t cap;
} Gen;

static uint8_t take(Gen *gen) {
  return gen->at < gen->size ? gen->data[gen->at++] : 0;
}

static void emit(Gen *gen, char byte) {
  if (gen->len + 1 >= gen->cap)
    return;
  gen->out[gen->len++] = byte;
}

static void emit_str(Gen *gen, const char *text) {
  while (*text != '\0')
    emit(gen, *text++);
}

static void emit_value(Gen *gen) {
  int length = 1 + (int)(take(gen) % 8);
  for (int i = 0; i < length; i++) {
    uint8_t pick = take(gen) % 36;
    emit(gen, pick < 26 ? (char)('a' + pick) : (char)('0' + (pick - 26)));
  }
}

static void emit_text(Gen *gen, int length) {
  for (int i = 0; i < length; i++)
    emit(gen, (char)('a' + (take(gen) % 26)));
}

static size_t generate(const uint8_t *data, size_t size, char *out,
                       size_t capacity) {
  Gen gen = {data, size, 0, out, 0, capacity};
  static const char *const roots[] = {"r", "root", "a", "n1", "_x"};
  const char *root = roots[take(&gen) % 5];
  int corrupt = (int)(take(&gen) % 9);

  if ((take(&gen) & 1) != 0)
    emit_str(&gen, "<?xml version=\"1.0\"?>");

  emit(&gen, '<');
  emit_str(&gen, root);
  int attributes = (int)(take(&gen) % 4);
  for (int i = 0; i < attributes; i++) {
    emit(&gen, ' ');
    emit(&gen, 'a');
    emit(&gen, (char)('0' + i));
    emit_str(&gen, "=\"");
    emit_value(&gen);
    emit(&gen, '"');
    if (corrupt == 2 && i == 0) {
      emit_str(&gen, " a0=\"");
      emit_value(&gen);
      emit(&gen, '"');
    }
  }

  int empty = corrupt != 5 && (take(&gen) & 1) != 0;
  if (empty) {
    emit_str(&gen, "/>");
  } else {
    emit(&gen, '>');
    int pieces = (int)(take(&gen) % 6);
    for (int i = 0; i < pieces; i++) {
      switch (take(&gen) % 5) {
      case 0:
        emit_text(&gen, (int)(take(&gen) % 17));
        break;
      case 1:
        emit_str(&gen, "<!--");
        emit_text(&gen, (int)(take(&gen) % 9));
        emit_str(&gen, "-->");
        break;
      case 2:
        emit_str(&gen, "<?pi");
        if ((take(&gen) & 1) != 0) {
          emit(&gen, ' ');
          emit_text(&gen, (int)(take(&gen) % 9));
        }
        emit_str(&gen, "?>");
        break;
      case 3:
        emit_str(&gen, "<![CDATA[");
        emit_text(&gen, (int)(take(&gen) % 13));
        emit_str(&gen, "]]>");
        break;
      default:
        emit_str(&gen, "<c>");
        emit_text(&gen, (int)(take(&gen) % 9));
        emit_str(&gen, "</c>");
      }
    }
    if (corrupt != 5) {
      emit_str(&gen, "</");
      if (corrupt == 1)
        emit_str(&gen, "mismatch>");
      else {
        emit_str(&gen, root);
        emit(&gen, '>');
      }
    }
  }

  switch (corrupt) {
  case 3:
    emit_str(&gen, "<extra/>");
    break;
  case 4:
    emit_str(&gen, "</late>");
    break;
  case 6:
    emit_str(&gen, "<!--");
    break;
  case 7:
    emit_str(&gen, "<![CDATA[");
    break;
  case 8:
    emit_str(&gen, "<?p");
    break;
  default:
    break;
  }
  return gen.len;
}

/* -------------------------------------------------------------------------
 * Comparison.
 * ---------------------------------------------------------------------- */

static void report_mismatch(const unsigned char *document, size_t length,
                            const Buf *candidate, int candidate_ok,
                            int candidate_code, const Buf *oracle, int oracle_ok,
                            int oracle_code) {
  fprintf(stderr, "differential: MISMATCH input_len=%zu candidate_ok=%d code=%d "
                  "oracle_ok=%d code=%d\n",
          length, candidate_ok, candidate_code, oracle_ok, oracle_code);
  fprintf(stderr, "differential: candidate events: %.2000s\n",
          candidate->data == NULL ? "" : candidate->data);
  fprintf(stderr, "differential: oracle events: %.2000s\n",
          oracle->data == NULL ? "" : oracle->data);
  fputs("differential: input hex:", stderr);
  for (size_t i = 0; i < length && i < 512; i++)
    fprintf(stderr, "%02x", document[i]);
  fputc('\n', stderr);
}

static int documents_agree(const unsigned char *document, size_t length,
                           int report) {
  Buf candidate;
  Buf oracle;
  int candidate_ok;
  int candidate_code;
  int oracle_ok;
  int oracle_code;
  int agree;

  buf_init(&candidate);
  buf_init(&oracle);
  record_parse(&candidate_api, document, length, &candidate, &candidate_ok,
               &candidate_code);
  record_parse(&oracle_api, document, length, &oracle, &oracle_ok, &oracle_code);

  if (candidate_ok != oracle_ok)
    agree = 0;
  else if (!candidate_ok)
    agree = candidate_code == oracle_code;
  else
    agree = candidate.len == oracle.len
            && memcmp(candidate.data, oracle.data, candidate.len) == 0;
  if (!agree && report)
    report_mismatch(document, length, &candidate, candidate_ok, candidate_code,
                    &oracle, oracle_ok, oracle_code);
  buf_free(&candidate);
  buf_free(&oracle);
  return agree;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  init_oracle();
  init_candidate();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char document[LEXPAT_FUZZ_MAX_INPUT];
  size_t length = generate(data, size, document, sizeof document);
  if (length == 0) {
    memcpy(document, "<r/>", 4);
    length = 4;
  }
  if (!documents_agree((const unsigned char *)document, length, 1))
    abort();
  return 0;
}

#else

static int read_file(const char *path, unsigned char **data, size_t *size) {
  FILE *file = fopen(path, "rb");
  if (file == NULL)
    return 0;
  size_t capacity = 4096;
  size_t length = 0;
  unsigned char *buffer = (unsigned char *)malloc(capacity);
  if (buffer == NULL) {
    fclose(file);
    return 0;
  }
  for (;;) {
    if (length == capacity) {
      capacity *= 2;
      unsigned char *grown = (unsigned char *)realloc(buffer, capacity);
      if (grown == NULL) {
        free(buffer);
        fclose(file);
        return 0;
      }
      buffer = grown;
    }
    size_t got = fread(buffer + length, 1, capacity - length, file);
    length += got;
    if (got == 0)
      break;
  }
  int failed = ferror(file);
  fclose(file);
  if (failed) {
    free(buffer);
    return 0;
  }
  *data = buffer;
  *size = length;
  return 1;
}

/* The `both` mode emits one prefix per normalized line so a single process,
 * using the same two-library comparator as the fuzz target, produces both
 * sides of an exception side by side. */
static void print_prefixed(const char *prefix, const Buf *buf) {
  if (buf->data == NULL)
    return;
  const char *line = buf->data;
  while (*line != '\0') {
    const char *end = strchr(line, '\n');
    size_t length = end != NULL ? (size_t)(end - line) : strlen(line);
    if (length > 0)
      printf("%s %.*s\n", prefix, (int)length, line);
    if (end == NULL)
      break;
    line = end + 1;
  }
}

static int compare_one(const Api *api, const unsigned char *document,
                       size_t length, const char *prefix) {
  Buf out;
  int ok;
  int code;
  buf_init(&out);
  record_parse(api, document, length, &out, &ok, &code);
  if (prefix != NULL)
    print_prefixed(prefix, &out);
  else
    fputs(out.data, stdout);
  if (prefix == NULL) {
    fputc('\n', stdout);
  }
  buf_free(&out);
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "--version") == 0) {
    init_oracle();
    printf("oracle=%s\n", oracle_api.ExpatVersion());
    XML_Expat_Version info = oracle_api.ExpatVersionInfo();
    printf("oracle_info=%d.%d.%d\n", info.major, info.minor, info.micro);
    printf("oracle_path=%s\n", oracle_path);
    printf("pkg_config=%s\n", pkg_config_version);
    return 0;
  }
  if (argc == 4 && strcmp(argv[1], "--compare") == 0) {
    const char *side = argv[2];
    unsigned char *document = NULL;
    size_t length = 0;
    if (strcmp(side, "candidate") != 0 && strcmp(side, "oracle") != 0
        && strcmp(side, "both") != 0) {
      fprintf(stderr, "differential: unknown side %s\n", side);
      return 2;
    }
    init_oracle();
    if (strcmp(side, "oracle") != 0)
      init_candidate();
    if (!read_file(argv[3], &document, &length)) {
      fprintf(stderr, "differential: cannot read %s\n", argv[3]);
      return 2;
    }
    int status;
    if (strcmp(side, "candidate") == 0)
      status = compare_one(&candidate_api, document, length, NULL);
    else if (strcmp(side, "oracle") == 0)
      status = compare_one(&oracle_api, document, length, NULL);
    else {
      status = compare_one(&candidate_api, document, length, "candidate");
      if (status == 0)
        status = compare_one(&oracle_api, document, length, "oracle");
    }
    free(document);
    return status;
  }
  fprintf(stderr,
          "usage: %s --version | --compare <candidate|oracle|both> <file>\n",
          argv[0]);
  return 2;
}

#endif
