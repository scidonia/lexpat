/*
 * Paired performance driver for the lexpat C ABI and libexpat.
 *
 * The driver loads exactly one measured library plus, when both are present in
 * the process, libexpat through a distinct `dlopen(RTLD_NOW | RTLD_LOCAL)`
 * handle and a separate `dlsym` table. Base and candidate lexpat artifacts are
 * measured in separate processes: two Lean runtimes never share a process.
 *
 * Modes
 *   observe    one parse, one JSON-lines record per callback in callback order
 *   calibrate  choose a bounded repetition count from a short untimed reading
 *   measure    warmups then one raw timing sample of `reps` whole documents
 *
 * Timed region is `XML_Parse` only: parser creation, handler registration and
 * `XML_ParserFree` happen outside the two clock reads, so the reading covers
 * the input copy and every callback the parse makes. `--include-create`
 * measures creation through free as a separate labelled diagnostic.
 *
 * Every measured trial re-checks its callback counters against the declared
 * expectations passed as flags; a mismatch, a failed parse or a wrong error
 * code exits 1 and invalidates the run.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* expat's enum XML_Status: XML_STATUS_ERROR = 0, XML_STATUS_OK = 1. */
#define XML_STATUS_OK_VALUE 1

typedef struct XML_ParserStruct *XML_Parser;
typedef char XML_Char;
typedef void (*StartElementHandler)(void *, const XML_Char *, const XML_Char **);
typedef void (*EndElementHandler)(void *, const XML_Char *);
typedef void (*CharacterDataHandler)(void *, const XML_Char *, int);
typedef void (*CommentHandler)(void *, const XML_Char *);
typedef void (*PiHandler)(void *, const XML_Char *, const XML_Char *);
typedef void (*StartCdataHandler)(void *);
typedef void (*EndCdataHandler)(void *);
typedef void (*XmlDeclHandler)(void *, const XML_Char *, const XML_Char *, int);

typedef struct {
  const char *name;
  void *handle;
  XML_Parser (*create)(const XML_Char *);
  void (*freeParser)(XML_Parser);
  void (*setElement)(XML_Parser, StartElementHandler, EndElementHandler);
  void (*setText)(XML_Parser, CharacterDataHandler);
  void (*setComment)(XML_Parser, CommentHandler);
  void (*setPi)(XML_Parser, PiHandler);
  void (*setCdata)(XML_Parser, StartCdataHandler, EndCdataHandler);
  void (*setXmlDecl)(XML_Parser, XmlDeclHandler);
  int (*parse)(XML_Parser, const char *, int, int);
  int (*getError)(XML_Parser);
  const XML_Char *(*errorString)(XML_Parser);
  int64_t (*getByteIndex)(XML_Parser);
  unsigned long (*getLine)(XML_Parser);
  unsigned long (*getColumn)(XML_Parser);
} Api;

static const char *g_side = "";
static int g_observe = 0;
static int g_includeCreate = 0;

static uint64_t g_starts, g_ends, g_textBytes, g_attrPairs, g_comments;
static uint64_t g_pis, g_cdataStarts, g_cdataEnds, g_xmlDecls;

static void resetCounters(void) {
  g_starts = g_ends = g_textBytes = g_attrPairs = g_comments = 0;
  g_pis = g_cdataStarts = g_cdataEnds = g_xmlDecls = 0;
}

/* ---------------------------------------------------------------- base64 -- */

static void putB64(FILE *out, const unsigned char *data, size_t length) {
  static const char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  size_t i = 0;
  fputc('"', out);
  while (i + 2 < length) {
    uint32_t v = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8) | data[i + 2];
    fputc(alphabet[(v >> 18) & 63], out);
    fputc(alphabet[(v >> 12) & 63], out);
    fputc(alphabet[(v >> 6) & 63], out);
    fputc(alphabet[v & 63], out);
    i += 3;
  }
  if (i + 1 == length) {
    uint32_t v = (uint32_t)data[i] << 16;
    fputc(alphabet[(v >> 18) & 63], out);
    fputc(alphabet[(v >> 12) & 63], out);
    fputs("==", out);
  } else if (i + 2 == length) {
    uint32_t v = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8);
    fputc(alphabet[(v >> 18) & 63], out);
    fputc(alphabet[(v >> 12) & 63], out);
    fputc(alphabet[(v >> 6) & 63], out);
    fputc('=', out);
  }
  fputc('"', out);
}

static void putCString(FILE *out, const XML_Char *s) {
  putB64(out, (const unsigned char *)s, s == NULL ? 0 : strlen(s));
}

/* --------------------------------------------------------------- handlers -- */

static void onStart(void *ud, const XML_Char *name, const XML_Char **atts) {
  (void)ud;
  g_starts++;
  if (atts != NULL)
    for (size_t i = 0; atts[i] != NULL; i += 2)
      g_attrPairs++;
  if (!g_observe)
    return;
  printf("{\"kind\":\"start\",\"name\":");
  putCString(stdout, name);
  fputs(",\"attrs\":[", stdout);
  if (atts != NULL) {
    for (size_t i = 0; atts[i] != NULL; i += 2) {
      if (i > 0)
        fputc(',', stdout);
      fputc('[', stdout);
      putCString(stdout, atts[i]);
      fputc(',', stdout);
      putCString(stdout, atts[i + 1]);
      fputc(']', stdout);
    }
  }
  fputs("]}\n", stdout);
}

static void onEnd(void *ud, const XML_Char *name) {
  (void)ud;
  g_ends++;
  if (!g_observe)
    return;
  fputs("{\"kind\":\"end\",\"name\":", stdout);
  putCString(stdout, name);
  fputs("}\n", stdout);
}

static void onText(void *ud, const XML_Char *data, int len) {
  (void)ud;
  if (len < 0)
    return;
  g_textBytes += (uint64_t)len;
  if (!g_observe)
    return;
  fputs("{\"kind\":\"text\",\"data\":", stdout);
  putB64(stdout, (const unsigned char *)data, (size_t)len);
  fputs("}\n", stdout);
}

static void onComment(void *ud, const XML_Char *data) {
  (void)ud;
  g_comments++;
  if (!g_observe)
    return;
  fputs("{\"kind\":\"comment\",\"data\":", stdout);
  putCString(stdout, data);
  fputs("}\n", stdout);
}

static void onPi(void *ud, const XML_Char *target, const XML_Char *data) {
  (void)ud;
  g_pis++;
  if (!g_observe)
    return;
  fputs("{\"kind\":\"pi\",\"target\":", stdout);
  putCString(stdout, target);
  fputs(",\"data\":", stdout);
  putCString(stdout, data);
  fputs("}\n", stdout);
}

static void onCdataStart(void *ud) {
  (void)ud;
  g_cdataStarts++;
  if (g_observe)
    fputs("{\"kind\":\"cdata_start\"}\n", stdout);
}

static void onCdataEnd(void *ud) {
  (void)ud;
  g_cdataEnds++;
  if (g_observe)
    fputs("{\"kind\":\"cdata_end\"}\n", stdout);
}

static void onXmlDecl(void *ud, const XML_Char *version, const XML_Char *encoding,
                      int standalone) {
  (void)ud;
  g_xmlDecls++;
  if (!g_observe)
    return;
  fputs("{\"kind\":\"xml_decl\",\"version\":", stdout);
  putCString(stdout, version);
  fputs(",\"encoding\":", stdout);
  if (encoding == NULL)
    fputs("null", stdout);
  else
    putCString(stdout, encoding);
  printf(",\"standalone\":%d}\n", standalone);
}

/* ------------------------------------------------------------------ api -- */

static void *need(void *handle, const char *symbol, const char *lib) {
  void *p = dlsym(handle, symbol);
  if (p == NULL) {
    fprintf(stderr, "performance-benchmark: %s: missing %s: %s\n", lib, symbol,
            dlerror());
    exit(2);
  }
  return p;
}

static Api loadApi(const char *name, const char *path) {
  Api a;
  memset(&a, 0, sizeof(a));
  a.name = name;
  a.handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
  if (a.handle == NULL) {
    fprintf(stderr, "performance-benchmark: dlopen %s (%s): %s\n", name, path,
            dlerror());
    exit(2);
  }
  a.create = (XML_Parser(*)(const XML_Char *))need(a.handle, "XML_ParserCreate", name);
  a.freeParser = (void (*)(XML_Parser))need(a.handle, "XML_ParserFree", name);
  a.setElement = (void (*)(XML_Parser, StartElementHandler, EndElementHandler))need(
      a.handle, "XML_SetElementHandler", name);
  a.setText = (void (*)(XML_Parser, CharacterDataHandler))need(
      a.handle, "XML_SetCharacterDataHandler", name);
  a.setComment = (void (*)(XML_Parser, CommentHandler))need(
      a.handle, "XML_SetCommentHandler", name);
  a.setPi = (void (*)(XML_Parser, PiHandler))need(a.handle,
                                                 "XML_SetProcessingInstructionHandler",
                                                 name);
  a.setCdata = (void (*)(XML_Parser, StartCdataHandler, EndCdataHandler))need(
      a.handle, "XML_SetCdataSectionHandler", name);
  a.setXmlDecl = (void (*)(XML_Parser, XmlDeclHandler))need(
      a.handle, "XML_SetXmlDeclHandler", name);
  a.parse = (int (*)(XML_Parser, const char *, int, int))need(a.handle, "XML_Parse",
                                                              name);
  a.getError = (int (*)(XML_Parser))need(a.handle, "XML_GetErrorCode", name);
  a.errorString = (const XML_Char *(*)(XML_Parser))need(a.handle, "XML_ErrorString",
                                                        name);
  a.getByteIndex = (int64_t (*)(XML_Parser))need(a.handle, "XML_GetCurrentByteIndex",
                                                 name);
  a.getLine = (unsigned long (*)(XML_Parser))need(
      a.handle, "XML_GetCurrentLineNumber", name);
  a.getColumn = (unsigned long (*)(XML_Parser))need(
      a.handle, "XML_GetCurrentColumnNumber", name);
  return a;
}

/* ---------------------------------------------------------------- parse -- */

static unsigned char *readFile(const char *path, size_t *length) {
  FILE *f = fopen(path, "rb");
  if (f == NULL) {
    fprintf(stderr, "performance-benchmark: open %s: %s\n", path, strerror(errno));
    exit(2);
  }
  if (fseek(f, 0, SEEK_END) != 0) {
    fprintf(stderr, "performance-benchmark: seek %s\n", path);
    exit(2);
  }
  long size = ftell(f);
  if (size < 0 || fseek(f, 0, SEEK_SET) != 0) {
    fprintf(stderr, "performance-benchmark: size %s\n", path);
    exit(2);
  }
  unsigned char *bytes = (unsigned char *)malloc((size_t)size == 0 ? 1 : (size_t)size);
  if (bytes == NULL) {
    fprintf(stderr, "performance-benchmark: out of memory for %s\n", path);
    exit(2);
  }
  if (size > 0 && fread(bytes, 1, (size_t)size, f) != (size_t)size) {
    fprintf(stderr, "performance-benchmark: short read on %s\n", path);
    exit(2);
  }
  fclose(f);
  *length = (size_t)size;
  return bytes;
}

static void installHandlers(const Api *api, XML_Parser parser) {
  api->setElement(parser, onStart, onEnd);
  api->setText(parser, onText);
  api->setComment(parser, onComment);
  api->setPi(parser, onPi);
  api->setCdata(parser, onCdataStart, onCdataEnd);
  api->setXmlDecl(parser, onXmlDecl);
}

/* One complete document through a fresh parser. Returns 1 on success. */
static int parseDocument(const Api *api, const unsigned char *data, size_t length,
                         size_t chunk, int chunked) {
  XML_Parser parser = api->create(NULL);
  if (parser == NULL) {
    fprintf(stderr, "performance-benchmark: %s: XML_ParserCreate failed\n", api->name);
    return 0;
  }
  installHandlers(api, parser);
  int status = 0;
  if (!chunked || chunk == 0 || chunk >= length) {
    status = api->parse(parser, (const char *)data, (int)length, 1);
  } else {
    size_t offset = 0;
    while (offset < length) {
      size_t take = length - offset < chunk ? length - offset : chunk;
      int final = offset + take == length;
      status = api->parse(parser, (const char *)data + offset, (int)take, final);
      if (status != XML_STATUS_OK_VALUE)
        break;
      offset += take;
    }
  }
  int error = api->getError(parser);
  if (status != XML_STATUS_OK_VALUE) {
    fprintf(stderr, "performance-benchmark: %s: parse failed: error=%d (%s) at byte %" PRId64
                    "\n",
            api->name, error, api->errorString(parser), api->getByteIndex(parser));
  } else if (error != 0) {
    fprintf(stderr, "performance-benchmark: %s: error code %d after success\n",
            api->name, error);
    status = 1;
  }
  api->freeParser(parser);
  return status == XML_STATUS_OK_VALUE && error == 0;
}

/* --------------------------------------------------------------- timing -- */

static uint64_t nowNs(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    perror("performance-benchmark: clock_gettime");
    exit(2);
  }
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* One repetition: creation outside the timed interval unless asked for. */
static int oneRepetition(const Api *api, const unsigned char *data, size_t length,
                         size_t chunk, int chunked, uint64_t *elapsed) {
  uint64_t start = 0;
  resetCounters();
  if (!g_includeCreate)
    start = nowNs();
  XML_Parser parser = api->create(NULL);
  if (parser == NULL)
    return 0;
  installHandlers(api, parser);
  uint64_t begin = g_includeCreate ? start : nowNs();
  int status;
  if (!chunked || chunk == 0 || chunk >= length) {
    status = api->parse(parser, (const char *)data, (int)length, 1);
  } else {
    status = 0;
    size_t offset = 0;
    while (offset < length) {
      size_t take = length - offset < chunk ? length - offset : chunk;
      int final = offset + take == length;
      status = api->parse(parser, (const char *)data + offset, (int)take, final);
      if (status != XML_STATUS_OK_VALUE)
        break;
      offset += take;
    }
  }
  uint64_t end = nowNs();
  int error = api->getError(parser);
  if (status != XML_STATUS_OK_VALUE || error != 0) {
    fprintf(stderr, "performance-benchmark: %s: parse failed: status=%d error=%d\n",
            api->name, status, error);
    api->freeParser(parser);
    return 0;
  }
  api->freeParser(parser);
  *elapsed += end - begin;
  return 1;
}

/* --------------------------------------------------------------- options -- */

typedef struct {
  const char *mode;
  const char *side;
  const char *lib;
  const char *expat;
  const char *file;
  const char *caseId;
  size_t chunk;
  int chunked;
  int warmups;
  int samples;
  int reps;
  uint64_t expectStarts, expectEnds, expectTextBytes, expectAttrPairs;
  uint64_t expectComments, expectPis, expectCdataStarts, expectCdataEnds;
  uint64_t expectXmlDecls;
  double targetMs;
  int capReps;
  int header;
  int sampleStart;
} Options;

static void usage(void) {
  fprintf(stderr,
          "usage: performance-benchmark <observe|calibrate|measure> --side NAME --lib PATH\n"
          "         --file PATH [--expat PATH] [--case ID] [--chunk N] [--mode whole|chunked]\n"
          "         [--warmups N] [--samples N] [--reps N] [--include-create]\n"
          "         [--expect-start N --expect-end N --expect-text-bytes N\n"
          "          --expect-attr-pairs N --expect-comment N --expect-pi N\n"
          "          --expect-cdata-start N --expect-cdata-end N --expect-xml-decl N]\n"
          "       performance-benchmark calibrate --target-ms F --cap N ...\n");
  exit(2);
}

static uint64_t parseU64(const char *name, const char *value) {
  errno = 0;
  char *end = NULL;
  unsigned long long v = strtoull(value, &end, 10);
  if (errno != 0 || end == value || *end != '\0') {
    fprintf(stderr, "performance-benchmark: %s needs a non-negative integer\n", name);
    exit(2);
  }
  return (uint64_t)v;
}

static void parseOptions(int argc, char **argv, Options *o) {
  memset(o, 0, sizeof(*o));
  o->chunk = 4096;
  o->warmups = 3;
  o->samples = 9;
  o->reps = 1;
  o->targetMs = 8.0;
  o->capReps = 128;
  o->sampleStart = 1;
  if (argc < 2)
    usage();
  o->mode = argv[1];
  for (int i = 2; i < argc; i++) {
    const char *flag = argv[i];
    if (strcmp(flag, "--include-create") == 0) {
      g_includeCreate = 1;
      continue;
    }
    if (strcmp(flag, "--header") == 0) {
      o->header = 1;
      continue;
    }
    if (i + 1 >= argc) {
      fprintf(stderr, "performance-benchmark: %s needs a value\n", flag);
      usage();
    }
    const char *value = argv[i + 1];
    i++;
    if (strcmp(flag, "--side") == 0)
      o->side = value;
    else if (strcmp(flag, "--lib") == 0)
      o->lib = value;
    else if (strcmp(flag, "--expat") == 0)
      o->expat = value;
    else if (strcmp(flag, "--file") == 0)
      o->file = value;
    else if (strcmp(flag, "--case") == 0)
      o->caseId = value;
    else if (strcmp(flag, "--chunk") == 0)
      o->chunk = (size_t)parseU64(flag, value);
    else if (strcmp(flag, "--mode") == 0) {
      if (strcmp(value, "whole") == 0)
        o->chunked = 0;
      else if (strcmp(value, "chunked") == 0)
        o->chunked = 1;
      else {
        fprintf(stderr, "performance-benchmark: --mode needs whole or chunked\n");
        usage();
      }
    } else if (strcmp(flag, "--warmups") == 0)
      o->warmups = (int)parseU64(flag, value);
    else if (strcmp(flag, "--samples") == 0)
      o->samples = (int)parseU64(flag, value);
    else if (strcmp(flag, "--reps") == 0)
      o->reps = (int)parseU64(flag, value);
    else if (strcmp(flag, "--expect-start") == 0)
      o->expectStarts = parseU64(flag, value);
    else if (strcmp(flag, "--expect-end") == 0)
      o->expectEnds = parseU64(flag, value);
    else if (strcmp(flag, "--expect-text-bytes") == 0)
      o->expectTextBytes = parseU64(flag, value);
    else if (strcmp(flag, "--expect-attr-pairs") == 0)
      o->expectAttrPairs = parseU64(flag, value);
    else if (strcmp(flag, "--expect-comment") == 0)
      o->expectComments = parseU64(flag, value);
    else if (strcmp(flag, "--expect-pi") == 0)
      o->expectPis = parseU64(flag, value);
    else if (strcmp(flag, "--expect-cdata-start") == 0)
      o->expectCdataStarts = parseU64(flag, value);
    else if (strcmp(flag, "--expect-cdata-end") == 0)
      o->expectCdataEnds = parseU64(flag, value);
    else if (strcmp(flag, "--expect-xml-decl") == 0)
      o->expectXmlDecls = parseU64(flag, value);
    else if (strcmp(flag, "--target-ms") == 0)
      o->targetMs = strtod(value, NULL);
    else if (strcmp(flag, "--cap") == 0)
      o->capReps = (int)parseU64(flag, value);
    else if (strcmp(flag, "--sample-start") == 0)
      o->sampleStart = (int)parseU64(flag, value);
    else
      usage();
  }
  if (o->side == NULL || o->lib == NULL || o->file == NULL)
    usage();
  if (o->warmups < 0 || o->samples < 1 || o->reps < 1)
    usage();
}

static int checkExpectations(const Options *o) {
  struct {
    const char *name;
    uint64_t seen;
    uint64_t want;
  } rows[] = {
      {"start", g_starts, o->expectStarts},
      {"end", g_ends, o->expectEnds},
      {"text-bytes", g_textBytes, o->expectTextBytes},
      {"attr-pairs", g_attrPairs, o->expectAttrPairs},
      {"comment", g_comments, o->expectComments},
      {"pi", g_pis, o->expectPis},
      {"cdata-start", g_cdataStarts, o->expectCdataStarts},
      {"cdata-end", g_cdataEnds, o->expectCdataEnds},
      {"xml-decl", g_xmlDecls, o->expectXmlDecls},
  };
  int ok = 1;
  for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
    if (rows[i].seen != rows[i].want) {
      fprintf(stderr,
              "performance-benchmark: %s: %s callback count %" PRIu64
              " does not match declared expectation %" PRIu64 "\n",
              o->side, rows[i].name, rows[i].seen, rows[i].want);
      ok = 0;
    }
  }
  return ok;
}

/* `version` needs a handle before the full API table is loaded, because the
 * oracle does not have to be a lexpat artifact. */
static void *apiHandleForVersion(const char *path) {
  void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
  if (handle == NULL) {
    fprintf(stderr, "performance-benchmark: dlopen %s: %s\n", path, dlerror());
    exit(2);
  }
  return handle;
}

int main(int argc, char **argv) {
  Options o;
  parseOptions(argc, argv, &o);
  g_side = o.side;

  if (o.expat != NULL || strcmp(o.side, "expat") == 0) {
    const char *expatPath = o.expat != NULL ? o.expat : o.lib;
    if (o.expat != NULL) {
      /* Distinct handle and symbol table: loading this library must not satisfy
       * the measured side's symbols through symbol interposition. */
      void *expatHandle = dlopen(expatPath, RTLD_NOW | RTLD_LOCAL);
      if (expatHandle == NULL) {
        fprintf(stderr, "performance-benchmark: dlopen expat (%s): %s\n", expatPath,
                dlerror());
        return 2;
      }
      if (dlsym(expatHandle, "XML_Parse") == NULL) {
        fprintf(stderr, "performance-benchmark: expat oracle has no XML_Parse\n");
        return 2;
      }
    }
  }

  if (strcmp(o.mode, "version") == 0) {
    typedef const char *(*VersionFn)(void);
    typedef struct {
      int major, minor, micro;
    } VersionInfo;
    typedef VersionInfo (*VersionInfoFn)(void);
    VersionFn versionFn = (VersionFn)need(apiHandleForVersion(o.lib), "XML_ExpatVersion", o.lib);
    VersionInfoFn infoFn =
        (VersionInfoFn)need(apiHandleForVersion(o.lib), "XML_ExpatVersionInfo", o.lib);
    VersionInfo info = infoFn();
    printf("XML_ExpatVersion=%s\n", versionFn());
    printf("XML_ExpatVersionInfo=%d.%d.%d\n", info.major, info.minor, info.micro);
    return 0;
  }

  Api api = loadApi(o.side, o.lib);
  size_t length = 0;
  unsigned char *data = readFile(o.file, &length);
  int ok = 1;

  if (strcmp(o.mode, "observe") == 0) {
    g_observe = 1;
    ok = parseDocument(&api, data, length, o.chunk, o.chunked);
    if (ok) {
      printf("{\"kind\":\"status\",\"side\":\"%s\",\"ok\":true}\n", o.side);
      if (o.caseId != NULL)
        fprintf(stderr, "performance-benchmark: observed %s/%s\n", o.side, o.caseId);
    } else {
      printf("{\"kind\":\"status\",\"side\":\"%s\",\"ok\":false}\n", o.side);
    }
    free(data);
    dlclose(api.handle);
    return ok ? 0 : 1;
  }

  if (strcmp(o.mode, "calibrate") == 0) {
    uint64_t readings[3];
    for (int w = 0; w < 1; w++) {
      uint64_t ignored = 0;
      if (!oneRepetition(&api, data, length, o.chunk, o.chunked, &ignored)) {
        free(data);
        return 1;
      }
    }
    for (int s = 0; s < 3; s++) {
      uint64_t elapsed = 0;
      if (!oneRepetition(&api, data, length, o.chunk, o.chunked, &elapsed)) {
        free(data);
        return 1;
      }
      readings[s] = elapsed;
    }
    uint64_t best = readings[0];
    for (int i = 1; i < 3; i++)
      best = readings[i] < best ? readings[i] : best;
    double target = o.targetMs * 1e6;
    int reps = best == 0 ? o.capReps : (int)(target / (double)best) + 1;
    if (reps < 1)
      reps = 1;
    if (reps > o.capReps)
      reps = o.capReps;
    printf("side=%s case=%s mode=%s chunk=%zu single_ns=%" PRIu64 " reps=%d\n", o.side,
           o.caseId == NULL ? "" : o.caseId, o.chunked ? "chunked" : "whole", o.chunk,
           best, reps);
    free(data);
    dlclose(api.handle);
    return 0;
  }

  if (strcmp(o.mode, "measure") != 0)
    usage();

  for (int w = 0; w < o.warmups; w++) {
    uint64_t ignored = 0;
    if (!oneRepetition(&api, data, length, o.chunk, o.chunked, &ignored)) {
      free(data);
      return 1;
    }
  }
  if (!checkExpectations(&o)) {
    free(data);
    return 1;
  }

  if (o.header)
    printf("sample,side,case,mode,chunk,reps,total_ns,per_doc_ns,include_create\n");
  for (int s = 1; s <= o.samples; s++) {
    uint64_t total = 0;
    for (int r = 0; r < o.reps; r++) {
      uint64_t elapsed = 0;
      if (!oneRepetition(&api, data, length, o.chunk, o.chunked, &elapsed)) {
        free(data);
        return 1;
      }
      total += elapsed;
    }
    if (!checkExpectations(&o)) {
      free(data);
      return 1;
    }
    printf("%d,%s,%s,%s,%zu,%d,%" PRIu64 ",%.3f,%d\n", s + o.sampleStart - 1, o.side,
           o.caseId == NULL ? "" : o.caseId, o.chunked ? "chunked" : "whole", o.chunk,
           o.reps, total, (double)total / (double)o.reps, g_includeCreate ? 1 : 0);
  }

  free(data);
  dlclose(api.handle);
  return 0;
}
