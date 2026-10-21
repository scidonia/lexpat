/*
 * reference.c — the libexpat side of the differential oracle.
 *
 * This program is a test oracle only. It links against the system libexpat,
 * emits the same JSON Lines schema as `lexpatTrace`, and is compiled by
 * `tests/differential.py` inside its temporary directory. No C code here is
 * part of the Lean library or the demonstrated executable.
 *
 * Registered handlers: XML declaration, start/end, character data, CDATA
 * sections, comments and processing instructions. No DTD handler, no external
 * entity resolver, and parameter-entity parsing is set to NEVER, so the oracle
 * never reads a system identifier or fetches a document.
 */

#include <expat.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void json_bytes(const char *s, size_t n) {
  size_t i;
  putchar('"');
  for (i = 0; i < n; i++) {
    unsigned char c = (unsigned char)s[i];
    switch (c) {
    case '"':
      fputs("\\\"", stdout);
      break;
    case '\\':
      fputs("\\\\", stdout);
      break;
    case '\n':
      fputs("\\n", stdout);
      break;
    case '\r':
      fputs("\\r", stdout);
      break;
    case '\t':
      fputs("\\t", stdout);
      break;
    default:
      if (c < 0x20) {
        printf("\\u%04x", (unsigned)c);
      } else {
        putchar((int)c);
      }
    }
  }
  putchar('"');
}

static void json_cstr(const char *s) {
  if (s == NULL) {
    s = "";
  }
  json_bytes(s, strlen(s));
}

static const char *error_name(enum XML_Error code) {
  switch (code) {
  case XML_ERROR_NONE:
    return "NONE";
  case XML_ERROR_NO_MEMORY:
    return "NO_MEMORY";
  case XML_ERROR_SYNTAX:
    return "SYNTAX";
  case XML_ERROR_NO_ELEMENTS:
    return "NO_ELEMENTS";
  case XML_ERROR_INVALID_TOKEN:
    return "INVALID_TOKEN";
  case XML_ERROR_UNCLOSED_TOKEN:
    return "UNCLOSED_TOKEN";
  case XML_ERROR_PARTIAL_CHAR:
    return "PARTIAL_CHAR";
  case XML_ERROR_TAG_MISMATCH:
    return "TAG_MISMATCH";
  case XML_ERROR_DUPLICATE_ATTRIBUTE:
    return "DUPLICATE_ATTRIBUTE";
  case XML_ERROR_JUNK_AFTER_DOC_ELEMENT:
    return "JUNK_AFTER_DOC_ELEMENT";
  case XML_ERROR_PARAM_ENTITY_REF:
    return "PARAM_ENTITY_REF";
  case XML_ERROR_UNDEFINED_ENTITY:
    return "UNDEFINED_ENTITY";
  case XML_ERROR_RECURSIVE_ENTITY_REF:
    return "RECURSIVE_ENTITY_REF";
  case XML_ERROR_ASYNC_ENTITY:
    return "ASYNC_ENTITY";
  case XML_ERROR_BAD_CHAR_REF:
    return "BAD_CHAR_REF";
  case XML_ERROR_BINARY_ENTITY_REF:
    return "BINARY_ENTITY_REF";
  case XML_ERROR_ATTRIBUTE_EXTERNAL_ENTITY_REF:
    return "ATTRIBUTE_EXTERNAL_ENTITY_REF";
  case XML_ERROR_MISPLACED_XML_PI:
    return "MISPLACED_XML_PI";
  case XML_ERROR_UNKNOWN_ENCODING:
    return "UNKNOWN_ENCODING";
  case XML_ERROR_INCORRECT_ENCODING:
    return "INCORRECT_ENCODING";
  case XML_ERROR_UNCLOSED_CDATA_SECTION:
    return "UNCLOSED_CDATA_SECTION";
  case XML_ERROR_EXTERNAL_ENTITY_HANDLING:
    return "EXTERNAL_ENTITY_HANDLING";
  case XML_ERROR_NOT_STANDALONE:
    return "NOT_STANDALONE";
  case XML_ERROR_UNEXPECTED_STATE:
    return "UNEXPECTED_STATE";
  case XML_ERROR_ENTITY_DECLARED_IN_PE:
    return "ENTITY_DECLARED_IN_PE";
  case XML_ERROR_FEATURE_REQUIRES_XML_DTD:
    return "FEATURE_REQUIRES_XML_DTD";
  case XML_ERROR_CANT_CHANGE_FEATURE_ONCE_PARSING:
    return "CANT_CHANGE_FEATURE_ONCE_PARSING";
  case XML_ERROR_UNBOUND_PREFIX:
    return "UNBOUND_PREFIX";
  case XML_ERROR_UNDECLARING_PREFIX:
    return "UNDECLARING_PREFIX";
  case XML_ERROR_INCOMPLETE_PE:
    return "INCOMPLETE_PE";
  case XML_ERROR_XML_DECL:
    return "XML_DECL";
  case XML_ERROR_TEXT_DECL:
    return "TEXT_DECL";
  case XML_ERROR_PUBLICID:
    return "PUBLICID";
  case XML_ERROR_SUSPENDED:
    return "SUSPENDED";
  case XML_ERROR_NOT_SUSPENDED:
    return "NOT_SUSPENDED";
  case XML_ERROR_ABORTED:
    return "ABORTED";
  case XML_ERROR_FINISHED:
    return "FINISHED";
  case XML_ERROR_SUSPEND_PE:
    return "SUSPEND_PE";
  case XML_ERROR_RESERVED_PREFIX_XML:
    return "RESERVED_PREFIX_XML";
  case XML_ERROR_RESERVED_PREFIX_XMLNS:
    return "RESERVED_PREFIX_XMLNS";
  case XML_ERROR_RESERVED_NAMESPACE_URI:
    return "RESERVED_NAMESPACE_URI";
#if XML_MAJOR_VERSION > 2 || (XML_MAJOR_VERSION == 2 && XML_MINOR_VERSION >= 4)
  case XML_ERROR_AMPLIFICATION_LIMIT_BREACH:
    return "AMPLIFICATION_LIMIT_BREACH";
#endif
  default:
    return "UNKNOWN_CODE";
  }
}

static void XMLCALL on_xml_decl(void *user, const XML_Char *version,
                                const XML_Char *encoding, int standalone) {
  (void)user;
  fputs("{\"format\":1,\"type\":\"xmlDecl\",\"version\":", stdout);
  json_cstr(version);
  fputs(",\"encoding\":", stdout);
  if (encoding == NULL) {
    fputs("null", stdout);
  } else {
    json_cstr(encoding);
  }
  fputs(",\"standalone\":", stdout);
  if (standalone < 0) {
    fputs("null", stdout);
  } else if (standalone == 0) {
    fputs("false", stdout);
  } else {
    fputs("true", stdout);
  }
  fputs("}\n", stdout);
}

typedef struct {
  const char *name;
  const char *value;
} attr_pair;

static int attr_cmp(const void *a, const void *b) {
  const attr_pair *x = (const attr_pair *)a;
  const attr_pair *y = (const attr_pair *)b;
  return strcmp(x->name, y->name);
}

static void XMLCALL on_start(void *user, const XML_Char *name,
                             const XML_Char **atts) {
  size_t count = 0;
  size_t i;
  attr_pair *pairs;
  (void)user;

  while (atts[count * 2] != NULL) {
    count++;
  }
  pairs = NULL;
  if (count > 0) {
    pairs = (attr_pair *)malloc(count * sizeof(attr_pair));
    if (pairs == NULL) {
      fputs("reference: out of memory\n", stderr);
      exit(2);
    }
  }
  for (i = 0; i < count; i++) {
    pairs[i].name = atts[i * 2];
    pairs[i].value = atts[i * 2 + 1];
  }
  qsort(pairs, count, sizeof(attr_pair), attr_cmp);

  fputs("{\"format\":1,\"type\":\"start\",\"name\":", stdout);
  json_cstr(name);
  fputs(",\"attributes\":{", stdout);
  for (i = 0; i < count; i++) {
    if (i > 0) {
      putchar(',');
    }
    json_cstr(pairs[i].name);
    putchar(':');
    json_cstr(pairs[i].value);
  }
  fputs("}}\n", stdout);
  free(pairs);
}

static void XMLCALL on_end(void *user, const XML_Char *name) {
  (void)user;
  fputs("{\"format\":1,\"type\":\"end\",\"name\":", stdout);
  json_cstr(name);
  fputs("}\n", stdout);
}

static void XMLCALL on_chars(void *user, const XML_Char *s, int len) {
  (void)user;
  if (len <= 0) {
    return;
  }
  fputs("{\"format\":1,\"type\":\"text\",\"data\":", stdout);
  json_bytes(s, (size_t)len);
  fputs("}\n", stdout);
}

static void XMLCALL on_cdata_start(void *user) {
  (void)user;
  fputs("{\"format\":1,\"type\":\"cdataStart\"}\n", stdout);
}

static void XMLCALL on_cdata_end(void *user) {
  (void)user;
  fputs("{\"format\":1,\"type\":\"cdataEnd\"}\n", stdout);
}

static void XMLCALL on_comment(void *user, const XML_Char *data) {
  (void)user;
  fputs("{\"format\":1,\"type\":\"comment\",\"data\":", stdout);
  json_cstr(data);
  fputs("}\n", stdout);
}

static void XMLCALL on_pi(void *user, const XML_Char *target,
                          const XML_Char *data) {
  (void)user;
  fputs("{\"format\":1,\"type\":\"pi\",\"target\":", stdout);
  json_cstr(target);
  fputs(",\"data\":", stdout);
  json_cstr(data);
  fputs("}\n", stdout);
}

static unsigned char *read_file(const char *path, size_t *out_len) {
  FILE *f;
  long size;
  unsigned char *buf;
  size_t got;

  f = fopen(path, "rb");
  if (f == NULL) {
    perror("reference: open");
    exit(2);
  }
  if (fseek(f, 0, SEEK_END) != 0) {
    perror("reference: seek");
    exit(2);
  }
  size = ftell(f);
  if (size < 0) {
    perror("reference: tell");
    exit(2);
  }
  if (fseek(f, 0, SEEK_SET) != 0) {
    perror("reference: seek");
    exit(2);
  }
  buf = (unsigned char *)malloc((size_t)size + 1);
  if (buf == NULL) {
    fputs("reference: out of memory\n", stderr);
    exit(2);
  }
  got = fread(buf, 1, (size_t)size, f);
  if (got != (size_t)size) {
    fputs("reference: short read\n", stderr);
    exit(2);
  }
  fclose(f);
  buf[size] = 0;
  *out_len = (size_t)size;
  return buf;
}

int main(int argc, char **argv) {
  unsigned char *buf;
  size_t len;
  XML_Parser parser;
  enum XML_Status status;
  enum XML_Error error;

  if (argc == 2 && strcmp(argv[1], "--version") == 0) {
    printf("%s\n", XML_ExpatVersion());
    return 0;
  }
  if (argc != 2) {
    fputs("usage: reference <file>\n", stderr);
    return 2;
  }

  buf = read_file(argv[1], &len);
  parser = XML_ParserCreate(NULL);
  if (parser == NULL) {
    fputs("reference: cannot create parser\n", stderr);
    return 2;
  }
  XML_SetXmlDeclHandler(parser, on_xml_decl);
  XML_SetElementHandler(parser, on_start, on_end);
  XML_SetCharacterDataHandler(parser, on_chars);
  XML_SetCdataSectionHandler(parser, on_cdata_start, on_cdata_end);
  XML_SetCommentHandler(parser, on_comment);
  XML_SetProcessingInstructionHandler(parser, on_pi);
  XML_SetParamEntityParsing(parser, XML_PARAM_ENTITY_PARSING_NEVER);

  status = XML_Parse(parser, (const char *)buf, (int)len, 1);
  if (status == XML_STATUS_OK) {
    fputs("{\"format\":1,\"type\":\"result\",\"ok\":true}\n", stdout);
  } else {
    error = XML_GetErrorCode(parser);
    fputs("{\"format\":1,\"type\":\"result\",\"ok\":false,\"code\":", stdout);
    json_cstr(error_name(error));
    fputs("}\n", stdout);
  }
  XML_ParserFree(parser);
  free(buf);
  fflush(stdout);
  return status == XML_STATUS_OK ? 0 : 1;
}
