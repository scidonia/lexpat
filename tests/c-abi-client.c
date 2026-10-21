/*
 * Supported-subset C client for the C ABI differential.
 *
 * One source is compiled twice by `tests/c-abi-differential.py`: once against
 * `include/expat.h` and `liblexpat.so.1`, and once against the system Expat
 * header and library. It calls only the subset both provide, and every parser
 * behavior it prints comes from those calls; no `#ifdef` selects a different
 * parser.
 *
 * Output is JSON Lines with `"format":1` on every object. Events carry their
 * callback-time byte index, line and column, and start events carry their
 * attributes as ordered name/value pairs. The result object carries the final
 * status, the numeric error code and the number of callbacks observed outside
 * an active parse call. Exit status is 0 for an accepted document, 1 for a
 * rejected one and 2 for a usage or I/O error.
 *
 * Preconditions: every pointer passed to the library refers to accessible
 * memory for its declared length. The client never dereferences an invalid
 * pointer and never calls `XML_GetUserData` on a freed handle.
 */

#include <expat.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static XML_Parser parser;
static int parse_active;
static int callbacks_outside_parse;
static long callback_count;
static FILE *out;

/* -------------------------------------------------------------------------
 * JSON output.
 * ---------------------------------------------------------------------- */

static void json_bytes(const char *s, size_t n) {
  size_t i;
  putc('"', out);
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    switch (c) {
    case '"':
      fputs("\\\"", out);
      break;
    case '\\':
      fputs("\\\\", out);
      break;
    case '\n':
      fputs("\\n", out);
      break;
    case '\r':
      fputs("\\r", out);
      break;
    case '\t':
      fputs("\\t", out);
      break;
    default:
      if (c < 0x20)
        fprintf(out, "\\u%04x", (unsigned)c);
      else
        putc((int)c, out);
    }
  }
  putc('"', out);
}

static void json_cstr(const char *s) {
  if (s == NULL)
    json_bytes("", 0);
  else
    json_bytes(s, strlen(s));
}

static const char *code_name(long code) {
  switch (code) {
  case 0:
    return "NONE";
  case 1:
    return "NO_MEMORY";
  case 2:
    return "SYNTAX";
  case 3:
    return "NO_ELEMENTS";
  case 4:
    return "INVALID_TOKEN";
  case 5:
    return "UNCLOSED_TOKEN";
  case 6:
    return "PARTIAL_CHAR";
  case 7:
    return "TAG_MISMATCH";
  case 8:
    return "DUPLICATE_ATTRIBUTE";
  case 9:
    return "JUNK_AFTER_DOC_ELEMENT";
  case 10:
    return "PARAM_ENTITY_REF";
  case 11:
    return "UNDEFINED_ENTITY";
  case 12:
    return "RECURSIVE_ENTITY_REF";
  case 13:
    return "ASYNC_ENTITY";
  case 14:
    return "BAD_CHAR_REF";
  case 15:
    return "BINARY_ENTITY_REF";
  case 16:
    return "ATTRIBUTE_EXTERNAL_ENTITY_REF";
  case 17:
    return "MISPLACED_XML_PI";
  case 18:
    return "UNKNOWN_ENCODING";
  case 19:
    return "INCORRECT_ENCODING";
  case 20:
    return "UNCLOSED_CDATA_SECTION";
  case 21:
    return "EXTERNAL_ENTITY_HANDLING";
  case 22:
    return "NOT_STANDALONE";
  case 23:
    return "UNEXPECTED_STATE";
  case 24:
    return "ENTITY_DECLARED_IN_PE";
  case 25:
    return "FEATURE_REQUIRES_XML_DTD";
  case 26:
    return "CANT_CHANGE_FEATURE_ONCE_PARSING";
  case 27:
    return "UNBOUND_PREFIX";
  case 28:
    return "UNDECLARING_PREFIX";
  case 29:
    return "INCOMPLETE_PE";
  case 30:
    return "XML_DECL";
  case 31:
    return "TEXT_DECL";
  case 32:
    return "PUBLICID";
  case 33:
    return "SUSPENDED";
  case 34:
    return "NOT_SUSPENDED";
  case 35:
    return "ABORTED";
  case 36:
    return "FINISHED";
  case 37:
    return "SUSPEND_PE";
  case 38:
    return "RESERVED_PREFIX_XML";
  case 39:
    return "RESERVED_PREFIX_XMLNS";
  case 40:
    return "RESERVED_NAMESPACE_URI";
  case 41:
    return "INVALID_ARGUMENT";
  case 42:
    return "NO_BUFFER";
  case 43:
    return "AMPLIFICATION_LIMIT_BREACH";
  case 44:
    return "NOT_STARTED";
    /* Named lexpat extensions; the numeric values are part of the published
     * header, so this source notes them without naming the enum constants so
     * it also compiles against the system header. */
  case 45:
    return "UNSUPPORTED_DTD";
  case 46:
    return "LIMIT_INPUT";
  case 47:
    return "LIMIT_TOKEN";
  case 48:
    return "LIMIT_DEPTH";
  case 49:
    return "LIMIT_ENTITY_EXPANSION";
  case 50:
    return "UNSUPPORTED_FEATURE";
  case 51:
    return "MALFORMED_WIRE";
  case 52:
    return "REENTRANT_CALL";
  default:
    return "UNKNOWN_CODE";
  }
}

static void note_callback(void) {
  callback_count++;
  if (!parse_active)
    callbacks_outside_parse++;
}

static void emit_position(void) {
  long byte = (long)XML_GetCurrentByteIndex(parser);
  unsigned long line = (unsigned long)XML_GetCurrentLineNumber(parser);
  unsigned long column = (unsigned long)XML_GetCurrentColumnNumber(parser);
  fprintf(out, ",\"byte\":%ld,\"line\":%lu,\"column\":%lu", byte, line, column);
}

/* -------------------------------------------------------------------------
 * Handlers.
 * ---------------------------------------------------------------------- */

static void XMLCALL on_xml_decl(void *userData, const XML_Char *version,
                                const XML_Char *encoding, int standalone) {
  (void)userData;
  note_callback();
  fputs("{\"format\":1,\"type\":\"xmlDecl\",\"version\":", out);
  json_cstr(version);
  fputs(",\"encoding\":", out);
  if (encoding == NULL)
    fputs("null", out);
  else
    json_cstr(encoding);
  fputs(",\"standalone\":", out);
  if (standalone < 0)
    fputs("null", out);
  else if (standalone == 0)
    fputs("false", out);
  else
    fputs("true", out);
  emit_position();
  fputs("}\n", out);
}

static void XMLCALL on_start(void *userData, const XML_Char *name,
                             const XML_Char **atts) {
  const XML_Char **attr;
  int pairs = 0;
  (void)userData;
  note_callback();
  while (atts != NULL && atts[pairs * 2] != NULL)
    pairs++;
  fputs("{\"format\":1,\"type\":\"start\",\"name\":", out);
  json_cstr(name);
  fputs(",\"attributes\":[", out);
  for (attr = atts; attr != NULL && attr[0] != NULL; attr += 2) {
    if (attr != atts)
      putc(',', out);
    putc('[', out);
    json_cstr(attr[0]);
    putc(',', out);
    json_cstr(attr[1]);
    putc(']', out);
  }
  fputs("],\"specified\":", out);
  fprintf(out, "%d", XML_GetSpecifiedAttributeCount(parser));
  emit_position();
  fputs("}\n", out);
}

static void XMLCALL on_end(void *userData, const XML_Char *name) {
  (void)userData;
  note_callback();
  fputs("{\"format\":1,\"type\":\"end\",\"name\":", out);
  json_cstr(name);
  emit_position();
  fputs("}\n", out);
}

static void XMLCALL on_chars(void *userData, const XML_Char *s, int len) {
  (void)userData;
  note_callback();
  fputs("{\"format\":1,\"type\":\"text\",\"data\":", out);
  if (len < 0)
    len = 0;
  json_bytes(s == NULL ? "" : s, s == NULL ? 0 : (size_t)len);
  fprintf(out, ",\"length\":%d", len);
  emit_position();
  fputs("}\n", out);
}

static void XMLCALL on_cdata_start(void *userData) {
  (void)userData;
  note_callback();
  fputs("{\"format\":1,\"type\":\"cdataStart\"", out);
  emit_position();
  fputs("}\n", out);
}

static void XMLCALL on_cdata_end(void *userData) {
  (void)userData;
  note_callback();
  fputs("{\"format\":1,\"type\":\"cdataEnd\"", out);
  emit_position();
  fputs("}\n", out);
}

static void XMLCALL on_comment(void *userData, const XML_Char *data) {
  (void)userData;
  note_callback();
  fputs("{\"format\":1,\"type\":\"comment\",\"data\":", out);
  json_cstr(data);
  emit_position();
  fputs("}\n", out);
}

static void XMLCALL on_pi(void *userData, const XML_Char *target,
                          const XML_Char *data) {
  (void)userData;
  note_callback();
  fputs("{\"format\":1,\"type\":\"pi\",\"target\":", out);
  json_cstr(target);
  fputs(",\"data\":", out);
  json_cstr(data);
  emit_position();
  fputs("}\n", out);
}

static void install_handlers(void) {
  XML_SetXmlDeclHandler(parser, on_xml_decl);
  XML_SetElementHandler(parser, on_start, on_end);
  XML_SetCharacterDataHandler(parser, on_chars);
  XML_SetCdataSectionHandler(parser, on_cdata_start, on_cdata_end);
  XML_SetCommentHandler(parser, on_comment);
  XML_SetProcessingInstructionHandler(parser, on_pi);
  XML_SetParamEntityParsing(parser, XML_PARAM_ENTITY_PARSING_NEVER);
}

/* -------------------------------------------------------------------------
 * Partitioning.
 * ---------------------------------------------------------------------- */

enum partition_kind { PART_WHOLE, PART_BYTE, PART_FIXED, PART_SEEDED };

typedef struct {
  enum partition_kind kind;
  size_t fixed;
  uint32_t seed;
} Partition;

static uint32_t lcg_next(uint32_t state) {
  return (uint32_t)(1664525u * state + 1013904223u);
}

static size_t next_length(Partition partition, uint32_t *state, size_t remaining) {
  size_t take;
  switch (partition.kind) {
  case PART_BYTE:
    take = 1;
    break;
  case PART_FIXED:
    take = partition.fixed;
    break;
  case PART_SEEDED:
    *state = lcg_next(*state);
    take = 1 + (size_t)(*state % (uint32_t)partition.fixed);
    break;
  case PART_WHOLE:
  default:
    take = remaining;
    break;
  }
  if (take > remaining)
    take = remaining;
  if (take == 0 && remaining > 0)
    take = 1;
  return take;
}

static int parse_bytes(const unsigned char *data, size_t length,
                       Partition partition, int use_buffer) {
  size_t offset = 0;
  uint32_t state = partition.seed;
  long fed = 0;
  enum XML_Status status = XML_STATUS_OK;

  do {
    size_t take = next_length(partition, &state, length - offset);
    int final = offset + take == length;
    if (use_buffer) {
      char *buffer = (char *)XML_GetBuffer(parser, (int)take);
      if (buffer == NULL) {
        fprintf(stderr, "c-abi-client: XML_GetBuffer failed\n");
        status = XML_STATUS_ERROR;
        break;
      }
      if (take > 0)
        memcpy(buffer, data + offset, take);
      parse_active = 1;
      status = XML_ParseBuffer(parser, (int)take, final);
      parse_active = 0;
    } else {
      parse_active = 1;
      status = XML_Parse(parser, (const char *)(data + offset), (int)take, final);
      parse_active = 0;
    }
    offset += take;
    fed += (long)take;
    if (status != XML_STATUS_OK)
      break;
  } while (offset < length);

  if (status == XML_STATUS_OK && fed != (long)length)
    status = XML_STATUS_ERROR;
  return status == XML_STATUS_OK ? 0 : 1;
}

static void print_result(enum XML_Status status, long length) {
  long code = (long)XML_GetErrorCode(parser);
  fprintf(out,
          "{\"format\":1,\"type\":\"result\",\"ok\":%s,\"status\":%d,"
          "\"code\":%ld,\"codeName\":\"%s\",\"length\":%ld,"
          "\"callbacks\":%ld,\"outsideParse\":%d}\n",
          status == XML_STATUS_OK ? "true" : "false", (int)status, code,
          code_name(code), length, callback_count, callbacks_outside_parse);
}

/* -------------------------------------------------------------------------
 * Timing case: feed one document in prefix steps and report the callback
 * count each call produced. The per-token sink contract fixes these counts
 * for the candidate; the harness asserts them independently.
 * ---------------------------------------------------------------------- */

static int timing_starts;
static int timing_ends;
static int timing_texts;

static void XMLCALL timing_start(void *userData, const XML_Char *name,
                                 const XML_Char **atts) {
  (void)userData;
  (void)name;
  (void)atts;
  timing_starts++;
}

static void XMLCALL timing_end(void *userData, const XML_Char *name) {
  (void)userData;
  (void)name;
  timing_ends++;
}

static void XMLCALL timing_text(void *userData, const XML_Char *data, int len) {
  (void)userData;
  (void)data;
  (void)len;
  timing_texts++;
}

static int timing_mode(void) {
  static const char *steps[] = {"<r", ">", "<c/", ">", "</r>"};
  static const int final_flags[] = {0, 0, 0, 0, 1};
  XML_Parser p = XML_ParserCreate(NULL);
  int step;
  int ok = 1;

  if (p == NULL) {
    fprintf(stderr, "c-abi-client: cannot create parser\n");
    return 2;
  }
  parser = p;
  timing_starts = timing_ends = timing_texts = 0;
  XML_SetElementHandler(p, timing_start, timing_end);
  XML_SetCharacterDataHandler(p, timing_text);
  for (step = 0; step < (int)(sizeof(steps) / sizeof(steps[0])); step++) {
    size_t n = strlen(steps[step]);
    enum XML_Status status;
    parse_active = 1;
    status = XML_Parse(p, steps[step], (int)n, final_flags[step]);
    parse_active = 0;
    fprintf(stdout,
            "{\"format\":1,\"type\":\"timing\",\"step\":%d,\"fed\":%zu,"
            "\"status\":%d,\"starts\":%d,\"ends\":%d,\"texts\":%d}\n",
            step, n, (int)status, timing_starts, timing_ends, timing_texts);
    if (status != XML_STATUS_OK)
      ok = 0;
  }
  fprintf(stdout,
          "{\"format\":1,\"type\":\"result\",\"ok\":%s,\"status\":%d,"
          "\"code\":%d,\"codeName\":\"%s\",\"starts\":%d,\"ends\":%d,"
          "\"texts\":%d,\"outsideParse\":%d}\n",
          ok ? "true" : "false", ok ? 1 : 0, (int)XML_GetErrorCode(p),
          code_name((long)XML_GetErrorCode(p)), timing_starts, timing_ends,
          timing_texts, callbacks_outside_parse);
  XML_ParserFree(p);
  return ok ? 0 : 1;
}

/* -------------------------------------------------------------------------
 * Main.
 * ---------------------------------------------------------------------- */

static unsigned char *read_file(const char *path, size_t *out_len) {
  FILE *f = fopen(path, "rb");
  long size;
  unsigned char *buffer;
  size_t got;

  if (f == NULL) {
    perror("c-abi-client: open");
    return NULL;
  }
  if (fseek(f, 0, SEEK_END) != 0) {
    perror("c-abi-client: seek");
    fclose(f);
    return NULL;
  }
  size = ftell(f);
  if (size < 0) {
    perror("c-abi-client: tell");
    fclose(f);
    return NULL;
  }
  if (fseek(f, 0, SEEK_SET) != 0) {
    perror("c-abi-client: seek");
    fclose(f);
    return NULL;
  }
  buffer = (unsigned char *)malloc((size_t)size + 1);
  if (buffer == NULL) {
    fputs("c-abi-client: out of memory\n", stderr);
    fclose(f);
    return NULL;
  }
  got = fread(buffer, 1, (size_t)size, f);
  if (got != (size_t)size) {
    fputs("c-abi-client: short read\n", stderr);
    free(buffer);
    fclose(f);
    return NULL;
  }
  fclose(f);
  buffer[size] = 0;
  *out_len = (size_t)size;
  return buffer;
}

static int parse_mode(const char *path, Partition partition, int use_buffer) {
  size_t length = 0;
  unsigned char *data = read_file(path, &length);
  enum XML_Status status;

  if (data == NULL)
    return 2;
  parser = XML_ParserCreate(NULL);
  if (parser == NULL) {
    fputs("c-abi-client: cannot create parser\n", stderr);
    free(data);
    return 2;
  }
  install_handlers();

  status = XML_STATUS_OK;
  if (length == 0) {
    parse_active = 1;
    status = XML_Parse(parser, "", 0, 1);
    parse_active = 0;
  } else {
    int failed = parse_bytes(data, length, partition, use_buffer);
    status = failed ? XML_STATUS_ERROR : status;
  }

  print_result(status, (long)length);
  XML_ParserFree(parser);
  free(data);
  return status == XML_STATUS_OK ? 0 : 1;
}

static int parse_partition(const char *text, Partition *partition) {
  if (strcmp(text, "whole") == 0) {
    partition->kind = PART_WHOLE;
    return 1;
  }
  if (strcmp(text, "byte") == 0) {
    partition->kind = PART_BYTE;
    return 1;
  }
  if (strncmp(text, "fixed:", 6) == 0) {
    long n = strtol(text + 6, NULL, 10);
    if (n < 1 || n > 65536)
      return 0;
    partition->kind = PART_FIXED;
    partition->fixed = (size_t)n;
    return 1;
  }
  if (strncmp(text, "seeded:", 7) == 0) {
    const char *colon;
    long n;
    unsigned long seed;
    n = strtol(text + 7, (char **)&colon, 10);
    if (colon == NULL || *colon != ':' || n < 1 || n > 65536)
      return 0;
    seed = strtoul(colon + 1, NULL, 10);
    if (seed > 4294967295ul)
      return 0;
    partition->kind = PART_SEEDED;
    partition->fixed = (size_t)n;
    partition->seed = (uint32_t)seed;
    return 1;
  }
  return 0;
}

static void usage(const char *program) {
  fprintf(stderr,
          "usage: %s --parse FILE [--partition whole|byte|fixed:N|seeded:N:SEED]"
          " [--buffer]\n"
          "       %s --timing\n",
          program, program);
}

int main(int argc, char **argv) {
  const char *path = NULL;
  Partition partition = {PART_WHOLE, 0, 0};
  int use_buffer = 0;
  int use_timing = 0;
  int i;
  int code;

  out = stdout;
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--parse") == 0) {
      if (++i >= argc) {
        usage(argv[0]);
        return 2;
      }
      path = argv[i];
    } else if (strcmp(argv[i], "--partition") == 0) {
      if (++i >= argc || !parse_partition(argv[i], &partition)) {
        usage(argv[0]);
        return 2;
      }
    } else if (strcmp(argv[i], "--buffer") == 0) {
      use_buffer = 1;
    } else if (strcmp(argv[i], "--timing") == 0) {
      use_timing = 1;
    } else if (strcmp(argv[i], "--version") == 0) {
      printf("%s\n", XML_ExpatVersion());
      return 0;
    } else {
      usage(argv[0]);
      return 2;
    }
  }

  if (use_timing) {
    if (path != NULL || use_buffer) {
      usage(argv[0]);
      return 2;
    }
    return timing_mode();
  }
  if (path == NULL) {
    usage(argv[0]);
    return 2;
  }
  code = parse_mode(path, partition, use_buffer);
  return code;
}
