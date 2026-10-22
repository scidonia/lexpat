/*
 * Non-sanitized scaling benchmark for the bounded C ABI.
 *
 * Schedule and measurement:
 *
 *   - The driver generates each shape from a size parameter, checks the parse
 *     result and the exact callback payload before timing, and measures
 *     one-shot and fixed 64-byte-chunk parses with parser creation outside the
 *     timed region.
 *   - One-shot and chunked readings of a case are interleaved trial by trial:
 *     even trials measure one-shot first, odd trials measure chunked first.
 *   - Every entry (a case, a drift control or a limit-adjacent input) runs in
 *     its own forked child. The parent writes the row with the child's
 *     `wait4` resident peak (`ru_maxrss`, KiB), so `rss_kb` is attributable to
 *     that entry rather than being the process-lifetime high-water mark.
 *   - `--plan` prints the deterministic schedule, `--entry N` runs one entry
 *     and appends its rows, and `--suite` runs the whole schedule. The paired
 *     driver uses `--plan`/`--entry` so base and candidate readings for the
 *     same entry are adjacent in time and alternate which side runs first.
 *
 * Families: long name/value/text/comment/CDATA tokens, the colon-dense
 * CVE-2018-20843 name class, many short elements, many distinct attributes,
 * element depth (including the 257 rejection), raw whitespace up to the 8 MiB
 * input bound, and the 1 KiB drift control. `--suite full` adds the 1 MiB
 * token ceiling and the 4/8 MiB raw sizes; `--suite ci` is the bounded set.
 *
 * This file makes no network, file-system or clock-of-day request beyond
 * reading its arguments writing the requested CSV. Timing uses
 * CLOCK_MONOTONIC.
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <expat.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define DRIFT_BYTES 1024
#define SAMPLE_LIMIT 16

enum shape {
  SHAPE_NAME,
  SHAPE_VALUE,
  SHAPE_TEXT,
  SHAPE_COMMENT,
  SHAPE_CDATA,
  SHAPE_COLON,
  SHAPE_ELEMENTS,
  SHAPE_ATTRIBUTES,
  SHAPE_DEPTH,
  SHAPE_WHITESPACE
};

typedef struct {
  const char *family;
  const char *shape_name;
  const char *cve;
  enum shape shape;
  size_t size;
  int ci;
  int expect_code; /* 0 accepted; otherwise the exact XML_Error */
  const char *unit;
} Case;

typedef struct {
  enum shape shape;
  size_t size;
  long starts;
  long ends;
  long texts;
  long comments;
  long cdata_starts;
  long cdata_ends;
  long pairs;
  size_t text_bytes;
  size_t comment_bytes;
  size_t cdata_text_bytes;
  int bad;
} Check;

static Check g_check;

static int all_char(const char *text, size_t length, char byte) {
  for (size_t i = 0; i < length; i++)
    if (text[i] != byte)
      return 0;
  return 1;
}

static void XMLCALL check_start(void *userData, const XML_Char *name,
                                const XML_Char **atts) {
  (void)userData;
  g_check.starts++;
  if (g_check.shape == SHAPE_NAME) {
    size_t length = strlen(name);
    if (length != g_check.size || !all_char(name, length, 'a'))
      g_check.bad = 1;
  } else if (g_check.shape == SHAPE_COLON) {
    size_t length = strlen(name);
    if (length != g_check.size || name[0] != 'a'
        || name[length - 1] != 'b'
        || !all_char(name + 1, length - 2, ':'))
      g_check.bad = 1;
  } else if (g_check.shape == SHAPE_VALUE) {
    if (atts == NULL || atts[0] == NULL || strcmp(atts[0], "a") != 0
        || atts[1] == NULL || strlen(atts[1]) != g_check.size
        || !all_char(atts[1], g_check.size, 'x') || atts[2] != NULL)
      g_check.bad = 1;
    g_check.pairs++;
  } else if (g_check.shape == SHAPE_ATTRIBUTES) {
    long pairs = 0;
    while (atts != NULL && atts[pairs * 2] != NULL)
      pairs++;
    if ((size_t)pairs != g_check.size)
      g_check.bad = 1;
    for (long i = 0; i < pairs && !g_check.bad; i++) {
      char name[32];
      char value[32];
      snprintf(name, sizeof name, "a%ld", i);
      snprintf(value, sizeof value, "v%ld", i);
      if (strcmp(atts[i * 2], name) != 0 || strcmp(atts[i * 2 + 1], value) != 0)
        g_check.bad = 1;
    }
    g_check.pairs = pairs;
  }
}

static void XMLCALL check_end(void *userData, const XML_Char *name) {
  (void)userData;
  (void)name;
  g_check.ends++;
}

static void XMLCALL check_text(void *userData, const XML_Char *data, int length) {
  (void)userData;
  if (length < 0)
    length = 0;
  g_check.texts++;
  g_check.text_bytes += (size_t)length;
  if (g_check.shape == SHAPE_TEXT && !all_char(data, (size_t)length, 'x'))
    g_check.bad = 1;
  if (g_check.shape == SHAPE_CDATA) {
    g_check.cdata_text_bytes += (size_t)length;
    if (!all_char(data, (size_t)length, 'c'))
      g_check.bad = 1;
  }
}

static void XMLCALL check_comment(void *userData, const XML_Char *data) {
  (void)userData;
  g_check.comments++;
  g_check.comment_bytes = strlen(data);
  if (!all_char(data, g_check.comment_bytes, 'c'))
    g_check.bad = 1;
}

static void XMLCALL check_cdata_start(void *userData) {
  (void)userData;
  g_check.cdata_starts++;
}

static void XMLCALL check_cdata_end(void *userData) {
  (void)userData;
  g_check.cdata_ends++;
}

static void install_handlers(XML_Parser parser) {
  XML_SetElementHandler(parser, check_start, check_end);
  XML_SetCharacterDataHandler(parser, check_text);
  XML_SetCommentHandler(parser, check_comment);
  XML_SetCdataSectionHandler(parser, check_cdata_start, check_cdata_end);
}

/* -------------------------------------------------------------------------
 * Document construction.
 * ---------------------------------------------------------------------- */

static unsigned char *build(const Case *item, size_t *length) {
  size_t size = item->size;
  size_t capacity;
  switch (item->shape) {
  case SHAPE_NAME:
  case SHAPE_COLON:
    capacity = size + 8;
    break;
  case SHAPE_VALUE:
    capacity = size + 32;
    break;
  case SHAPE_TEXT:
    capacity = size + 16;
    break;
  case SHAPE_COMMENT:
    capacity = size + 32;
    break;
  case SHAPE_CDATA:
    capacity = size + 32;
    break;
  case SHAPE_ELEMENTS:
    capacity = size * 4 + 32;
    break;
  case SHAPE_ATTRIBUTES:
    capacity = size * 16 + 32;
    break;
  case SHAPE_DEPTH:
    capacity = size * 8 + 32;
    break;
  default:
    capacity = size + 8;
    break;
  }
  unsigned char *document = (unsigned char *)malloc(capacity);
  if (document == NULL) {
    fputs("benchmark: out of memory building a document\n", stderr);
    exit(3);
  }
  size_t at = 0;
  switch (item->shape) {
  case SHAPE_NAME:
    document[at++] = '<';
    memset(document + at, 'a', size);
    at += size;
    document[at++] = '/';
    document[at++] = '>';
    break;
  case SHAPE_COLON:
    document[at++] = '<';
    document[at++] = 'a';
    memset(document + at, ':', size - 2);
    at += size - 2;
    document[at++] = 'b';
    document[at++] = '/';
    document[at++] = '>';
    break;
  case SHAPE_VALUE:
    at += (size_t)snprintf((char *)document + at, capacity - at, "<r a=\"");
    memset(document + at, 'x', size);
    at += size;
    document[at++] = '"';
    document[at++] = '/';
    document[at++] = '>';
    break;
  case SHAPE_TEXT:
    at += (size_t)snprintf((char *)document + at, capacity - at, "<r>");
    memset(document + at, 'x', size);
    at += size;
    at += (size_t)snprintf((char *)document + at, capacity - at, "</r>");
    break;
  case SHAPE_COMMENT:
    at += (size_t)snprintf((char *)document + at, capacity - at, "<!--");
    memset(document + at, 'c', size);
    at += size;
    at += (size_t)snprintf((char *)document + at, capacity - at, "--><r/>");
    break;
  case SHAPE_CDATA:
    at += (size_t)snprintf((char *)document + at, capacity - at,
                           "<r><![CDATA[");
    memset(document + at, 'c', size);
    at += size;
    at += (size_t)snprintf((char *)document + at, capacity - at, "]]></r>");
    break;
  case SHAPE_ELEMENTS:
    at += (size_t)snprintf((char *)document + at, capacity - at, "<r>");
    for (size_t i = 0; i < size; i++) {
      document[at++] = '<';
      document[at++] = 'e';
      document[at++] = '/';
      document[at++] = '>';
    }
    at += (size_t)snprintf((char *)document + at, capacity - at, "</r>");
    break;
  case SHAPE_ATTRIBUTES:
    at += (size_t)snprintf((char *)document + at, capacity - at, "<r");
    for (size_t i = 0; i < size; i++)
      at += (size_t)snprintf((char *)document + at, capacity - at,
                             " a%zu=\"v%zu\"", i, i);
    document[at++] = '/';
    document[at++] = '>';
    break;
  case SHAPE_DEPTH:
    for (size_t i = 0; i < size; i++)
      at += (size_t)snprintf((char *)document + at, capacity - at, "<e>");
    for (size_t i = 0; i < size; i++)
      at += (size_t)snprintf((char *)document + at, capacity - at, "</e>");
    break;
  case SHAPE_WHITESPACE:
    at += (size_t)snprintf((char *)document + at, capacity - at, "<r/>");
    memset(document + at, ' ', size - at);
    at = size;
    break;
  }
  *length = at;
  return document;
}

static int check_result(const Case *item, const unsigned char *document,
                        size_t length) {
  memset(&g_check, 0, sizeof g_check);
  g_check.shape = item->shape;
  g_check.size = item->size;
  XML_Parser parser = XML_ParserCreate(NULL);
  if (parser == NULL) {
    fputs("benchmark: parser creation failed\n", stderr);
    return 0;
  }
  install_handlers(parser);
  enum XML_Status status =
      XML_Parse(parser, (const char *)document, (int)length, 1);
  enum XML_Error code = XML_GetErrorCode(parser);
  XML_ParserFree(parser);

  int failures = 0;
  if (item->expect_code != 0) {
    if (status != XML_STATUS_ERROR || code != (enum XML_Error)item->expect_code)
      failures++;
    return failures == 0;
  }
  if (status != XML_STATUS_OK || code != XML_ERROR_NONE)
    failures++;
  switch (item->shape) {
  case SHAPE_NAME:
  case SHAPE_COLON:
  case SHAPE_VALUE:
    if (g_check.starts != 1 || g_check.ends != 1)
      failures++;
    break;
  case SHAPE_TEXT:
    if (g_check.starts != 1 || g_check.ends != 1
        || g_check.text_bytes != item->size)
      failures++;
    break;
  case SHAPE_COMMENT:
    if (g_check.comments != 1)
      failures++;
    break;
  case SHAPE_CDATA:
    if (g_check.cdata_starts != 1 || g_check.cdata_ends != 1
        || g_check.cdata_text_bytes != item->size)
      failures++;
    break;
  case SHAPE_ELEMENTS:
    if ((size_t)g_check.starts != item->size + 1
        || (size_t)g_check.ends != item->size + 1)
      failures++;
    break;
  case SHAPE_ATTRIBUTES:
    if (g_check.starts != 1 || g_check.pairs != (long)item->size)
      failures++;
    break;
  case SHAPE_DEPTH:
    if ((size_t)g_check.starts != item->size
        || (size_t)g_check.ends != item->size)
      failures++;
    break;
  case SHAPE_WHITESPACE:
    if (g_check.starts != 1 || g_check.ends != 1)
      failures++;
    break;
  }
  if (g_check.bad)
    failures++;
  return failures == 0;
}

/* -------------------------------------------------------------------------
 * Timing.
 * ---------------------------------------------------------------------- */

static int64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static int64_t parse_timed(const unsigned char *document, size_t length,
                           int chunked) {
  XML_Parser parser = XML_ParserCreate(NULL);
  if (parser == NULL) {
    fputs("benchmark: parser creation failed\n", stderr);
    exit(3);
  }
  install_handlers(parser);
  int64_t start = now_ns();
  if (!chunked) {
    (void)XML_Parse(parser, (const char *)document, (int)length, 1);
  } else {
    size_t offset = 0;
    while (offset < length) {
      size_t chunk = 64;
      if (chunk > length - offset)
        chunk = length - offset;
      int final = offset + chunk == length;
      if (XML_Parse(parser, (const char *)document + offset, (int)chunk, final)
          != XML_STATUS_OK)
        break;
      offset += chunk;
    }
    if (offset == 0)
      (void)XML_Parse(parser, "", 0, 1);
  }
  int64_t elapsed = now_ns() - start;
  XML_ParserFree(parser);
  return elapsed;
}

static int compare_ll(const void *a, const void *b) {
  int64_t left = *(const int64_t *)a;
  int64_t right = *(const int64_t *)b;
  return left < right ? -1 : left > right ? 1 : 0;
}

static int64_t median(int64_t *samples, int count) {
  qsort(samples, (size_t)count, sizeof samples[0], compare_ll);
  return samples[count / 2];
}

/* -------------------------------------------------------------------------
 * Cases and schedule.
 * ---------------------------------------------------------------------- */

static const Case CI_CASES[] = {
    {"token", "name", "", SHAPE_NAME, 32768, 1, 0, "decoded-chars"},
    {"token", "name", "", SHAPE_NAME, 65536, 1, 0, "decoded-chars"},
    {"token", "name", "", SHAPE_NAME, 131072, 1, 0, "decoded-chars"},
    {"token", "name", "", SHAPE_NAME, 262144, 1, 0, "decoded-chars"},
    {"token", "value", "", SHAPE_VALUE, 32768, 1, 0, "decoded-chars"},
    {"token", "value", "", SHAPE_VALUE, 65536, 1, 0, "decoded-chars"},
    {"token", "value", "", SHAPE_VALUE, 131072, 1, 0, "decoded-chars"},
    {"token", "value", "", SHAPE_VALUE, 262144, 1, 0, "decoded-chars"},
    {"token", "text", "", SHAPE_TEXT, 32768, 1, 0, "decoded-chars"},
    {"token", "text", "", SHAPE_TEXT, 65536, 1, 0, "decoded-chars"},
    {"token", "text", "", SHAPE_TEXT, 131072, 1, 0, "decoded-chars"},
    {"token", "text", "", SHAPE_TEXT, 262144, 1, 0, "decoded-chars"},
    {"token", "comment", "", SHAPE_COMMENT, 32768, 1, 0, "decoded-chars"},
    {"token", "comment", "", SHAPE_COMMENT, 65536, 1, 0, "decoded-chars"},
    {"token", "comment", "", SHAPE_COMMENT, 131072, 1, 0, "decoded-chars"},
    {"token", "comment", "", SHAPE_COMMENT, 262144, 1, 0, "decoded-chars"},
    {"token", "cdata", "", SHAPE_CDATA, 32768, 1, 0, "decoded-chars"},
    {"token", "cdata", "", SHAPE_CDATA, 65536, 1, 0, "decoded-chars"},
    {"token", "cdata", "", SHAPE_CDATA, 131072, 1, 0, "decoded-chars"},
    {"token", "cdata", "", SHAPE_CDATA, 262144, 1, 0, "decoded-chars"},
    {"colon", "colon-name", "CVE-2018-20843", SHAPE_COLON, 32768, 1, 0,
     "name-chars"},
    {"colon", "colon-name", "CVE-2018-20843", SHAPE_COLON, 65536, 1, 0,
     "name-chars"},
    {"colon", "colon-name", "CVE-2018-20843", SHAPE_COLON, 131072, 1, 0,
     "name-chars"},
    {"colon", "colon-name", "CVE-2018-20843", SHAPE_COLON, 262144, 1, 0,
     "name-chars"},
    {"elements", "many-elements", "", SHAPE_ELEMENTS, 8192, 1, 0, "elements"},
    {"elements", "many-elements", "", SHAPE_ELEMENTS, 16384, 1, 0, "elements"},
    {"elements", "many-elements", "", SHAPE_ELEMENTS, 32768, 1, 0, "elements"},
    {"elements", "many-elements", "", SHAPE_ELEMENTS, 65536, 1, 0, "elements"},
    {"attributes", "count", "", SHAPE_ATTRIBUTES, 32, 1, 0, "attributes"},
    {"attributes", "count", "", SHAPE_ATTRIBUTES, 64, 1, 0, "attributes"},
    {"attributes", "count", "", SHAPE_ATTRIBUTES, 128, 1, 0, "attributes"},
    {"attributes", "count", "", SHAPE_ATTRIBUTES, 256, 1, 0, "attributes"},
    {"depth", "depth", "", SHAPE_DEPTH, 32, 1, 0, "elements"},
    {"depth", "depth", "", SHAPE_DEPTH, 64, 1, 0, "elements"},
    {"depth", "depth", "", SHAPE_DEPTH, 128, 1, 0, "elements"},
    {"depth", "depth", "", SHAPE_DEPTH, 256, 1, 0, "elements"},
    {"depth", "depth-over", "", SHAPE_DEPTH, 257, 1, XML_ERROR_LIMIT_DEPTH,
     "elements"},
};

static const Case FULL_CASES[] = {
    {"token", "name", "", SHAPE_NAME, 131072, 0, 0, "decoded-chars"},
    {"token", "name", "", SHAPE_NAME, 262144, 0, 0, "decoded-chars"},
    {"token", "name", "", SHAPE_NAME, 524288, 0, 0, "decoded-chars"},
    {"token", "name", "", SHAPE_NAME, 1048576, 0, 0, "decoded-chars"},
    {"token", "value", "", SHAPE_VALUE, 131072, 0, 0, "decoded-chars"},
    {"token", "value", "", SHAPE_VALUE, 262144, 0, 0, "decoded-chars"},
    {"token", "value", "", SHAPE_VALUE, 524288, 0, 0, "decoded-chars"},
    {"token", "value", "", SHAPE_VALUE, 1048576, 0, 0, "decoded-chars"},
    {"token", "text", "", SHAPE_TEXT, 131072, 0, 0, "decoded-chars"},
    {"token", "text", "", SHAPE_TEXT, 262144, 0, 0, "decoded-chars"},
    {"token", "text", "", SHAPE_TEXT, 524288, 0, 0, "decoded-chars"},
    {"token", "text", "", SHAPE_TEXT, 1048576, 0, 0, "decoded-chars"},
    {"token", "comment", "", SHAPE_COMMENT, 131072, 0, 0, "decoded-chars"},
    {"token", "comment", "", SHAPE_COMMENT, 262144, 0, 0, "decoded-chars"},
    {"token", "comment", "", SHAPE_COMMENT, 524288, 0, 0, "decoded-chars"},
    {"token", "comment", "", SHAPE_COMMENT, 1048576, 0, 0, "decoded-chars"},
    {"token", "cdata", "", SHAPE_CDATA, 131072, 0, 0, "decoded-chars"},
    {"token", "cdata", "", SHAPE_CDATA, 262144, 0, 0, "decoded-chars"},
    {"token", "cdata", "", SHAPE_CDATA, 524288, 0, 0, "decoded-chars"},
    {"token", "cdata", "", SHAPE_CDATA, 1048576, 0, 0, "decoded-chars"},
    {"colon", "colon-name", "CVE-2018-20843", SHAPE_COLON, 131072, 0, 0,
     "name-chars"},
    {"colon", "colon-name", "CVE-2018-20843", SHAPE_COLON, 262144, 0, 0,
     "name-chars"},
    {"colon", "colon-name", "CVE-2018-20843", SHAPE_COLON, 524288, 0, 0,
     "name-chars"},
    {"colon", "colon-name", "CVE-2018-20843", SHAPE_COLON, 1048576, 0, 0,
     "name-chars"},
    {"elements", "many-elements", "", SHAPE_ELEMENTS, 65536, 0, 0, "elements"},
    {"elements", "many-elements", "", SHAPE_ELEMENTS, 131072, 0, 0, "elements"},
    {"elements", "many-elements", "", SHAPE_ELEMENTS, 262144, 0, 0, "elements"},
    {"attributes", "count", "", SHAPE_ATTRIBUTES, 32, 0, 0, "attributes"},
    {"attributes", "count", "", SHAPE_ATTRIBUTES, 64, 0, 0, "attributes"},
    {"attributes", "count", "", SHAPE_ATTRIBUTES, 128, 0, 0, "attributes"},
    {"attributes", "count", "", SHAPE_ATTRIBUTES, 256, 0, 0, "attributes"},
    {"depth", "depth", "", SHAPE_DEPTH, 32, 0, 0, "elements"},
    {"depth", "depth", "", SHAPE_DEPTH, 64, 0, 0, "elements"},
    {"depth", "depth", "", SHAPE_DEPTH, 128, 0, 0, "elements"},
    {"depth", "depth", "", SHAPE_DEPTH, 256, 0, 0, "elements"},
    {"depth", "depth-over", "", SHAPE_DEPTH, 257, 0, XML_ERROR_LIMIT_DEPTH,
     "elements"},
    {"raw", "whitespace", "", SHAPE_WHITESPACE, 1048576, 0, 0, "input-bytes"},
    {"raw", "whitespace", "", SHAPE_WHITESPACE, 2097152, 0, 0, "input-bytes"},
    {"raw", "whitespace", "", SHAPE_WHITESPACE, 4194304, 0, 0, "input-bytes"},
    {"raw", "whitespace", "", SHAPE_WHITESPACE, 8388608, 0, 0, "input-bytes"},
};

static const Case LIMIT_CASES[] = {
    {"limit", "token-exact", "", SHAPE_TEXT, 1048576, 0, 0, "decoded-chars"},
    {"limit", "token-over", "", SHAPE_TEXT, 1048577, 0, XML_ERROR_LIMIT_TOKEN,
     "decoded-chars"},
    {"limit", "input-exact", "", SHAPE_WHITESPACE, 8388608, 0, 0,
     "input-bytes"},
    {"limit", "input-over", "", SHAPE_WHITESPACE, 8388609, 0,
     XML_ERROR_LIMIT_INPUT, "input-bytes"},
};

enum entry_kind { ENTRY_DRIFT, ENTRY_CASE, ENTRY_LIMIT };

typedef struct {
  enum entry_kind kind;
  const Case *item;
  char block[64];
} Entry;

#define SCHEDULE_LIMIT 4096

static uint32_t g_lcg;

static uint32_t lcg_next(void) {
  g_lcg = 1664525u * g_lcg + 1013904223u;
  return g_lcg;
}

static size_t build_schedule(const Case *cases, size_t count, Entry *schedule,
                             size_t capacity, uint32_t seed) {
  g_lcg = seed;
  size_t used = 0;
  size_t family_begin = 0;
  while (family_begin < count) {
    size_t family_end = family_begin;
    while (family_end < count
           && strcmp(cases[family_end].family, cases[family_begin].family) == 0)
      family_end++;
    const char *family = cases[family_begin].family;

    if (used + 2 + (family_end - family_begin) > capacity) {
      fputs("benchmark: schedule capacity exceeded\n", stderr);
      exit(3);
    }
    schedule[used].kind = ENTRY_DRIFT;
    schedule[used].item = NULL;
    snprintf(schedule[used].block, sizeof schedule[used].block, "%s-before",
             family);
    used++;

    size_t order[1024];
    size_t family_count = family_end - family_begin;
    if (family_count > sizeof order / sizeof order[0]) {
      fputs("benchmark: family too large for the order table\n", stderr);
      exit(3);
    }
    for (size_t i = 0; i < family_count; i++)
      order[i] = i;
    for (size_t i = family_count; i > 1; i--) {
      size_t j = lcg_next() % i;
      size_t swap = order[i - 1];
      order[i - 1] = order[j];
      order[j] = swap;
    }
    for (size_t i = 0; i < family_count; i++) {
      schedule[used].kind = ENTRY_CASE;
      schedule[used].item = &cases[family_begin + order[i]];
      schedule[used].block[0] = '\0';
      used++;
    }

    schedule[used].kind = ENTRY_DRIFT;
    schedule[used].item = NULL;
    snprintf(schedule[used].block, sizeof schedule[used].block, "%s-after",
             family);
    used++;
    family_begin = family_end;
  }

  size_t limit_count = sizeof LIMIT_CASES / sizeof LIMIT_CASES[0];
  if (used + limit_count > capacity) {
    fputs("benchmark: schedule capacity exceeded\n", stderr);
    exit(3);
  }
  for (size_t i = 0; i < limit_count; i++) {
    schedule[used].kind = ENTRY_LIMIT;
    schedule[used].item = &LIMIT_CASES[i];
    schedule[used].block[0] = '\0';
    used++;
  }
  return used;
}

/* -------------------------------------------------------------------------
 * Entry measurement.
 *
 * The child does all document construction and timing; the parent writes the
 * row with the child's `wait4` resident peak.
 * ---------------------------------------------------------------------- */

typedef struct {
  int64_t median_ns;
  int trials;
} Result;

static int write_full(int fd, const void *buffer, size_t length) {
  const char *at = (const char *)buffer;
  while (length > 0) {
    ssize_t wrote = write(fd, at, length);
    if (wrote <= 0)
      return 0;
    at += (size_t)wrote;
    length -= (size_t)wrote;
  }
  return 1;
}

static int read_full(int fd, void *buffer, size_t length) {
  char *at = (char *)buffer;
  while (length > 0) {
    ssize_t got = read(fd, at, length);
    if (got <= 0)
      return 0;
    at += (size_t)got;
    length -= (size_t)got;
  }
  return 1;
}

static int run_drift(const Entry *entry, int samples, Result *results,
                     int *count) {
  (void)entry;
  unsigned char document[DRIFT_BYTES];
  size_t length = (size_t)snprintf((char *)document, sizeof document, "<r>");
  memset(document + length, 'd', DRIFT_BYTES - length - 4);
  length = DRIFT_BYTES - 4;
  memcpy(document + length, "</r>", 4);
  length += 4;
  for (int warm = 0; warm < 2; warm++)
    (void)parse_timed(document, length, 0);
  /* The 1 KiB control is short enough that a handful of samples tracks host
   * scheduling noise rather than state. Use the median of a larger sample so
   * the same 15% rule detects a real shift instead of measurement jitter. */
  int64_t values[64];
  int drift_samples = samples * 7 + 2;
  if (drift_samples > (int)(sizeof values / sizeof values[0]))
    drift_samples = (int)(sizeof values / sizeof values[0]);
  for (int trial = 0; trial < drift_samples; trial++)
    values[trial] = parse_timed(document, length, 0);
  results[0].median_ns = median(values, drift_samples);
  results[0].trials = drift_samples;
  *count = 1;
  return 1;
}

static int run_case(const Entry *entry, int samples, Result *results,
                    int *count) {
  const Case *item = entry->item;
  size_t length = 0;
  unsigned char *document = build(item, &length);
  if (!check_result(item, document, length)) {
    fprintf(stderr, "benchmark: %s/%s size %zu did not produce its expected "
                    "result\n", item->family, item->shape_name, item->size);
    free(document);
    return 0;
  }
  for (int warm = 0; warm < 2; warm++) {
    (void)parse_timed(document, length, 0);
    (void)parse_timed(document, length, 1);
  }
  int64_t one_shot[SAMPLE_LIMIT];
  int64_t chunked[SAMPLE_LIMIT];
  /* Interleave the two feeding modes trial by trial rather than measuring all
   * one-shot samples before any chunked sample. */
  for (int trial = 0; trial < samples; trial++) {
    if (trial % 2 == 0) {
      one_shot[trial] = parse_timed(document, length, 0);
      chunked[trial] = parse_timed(document, length, 1);
    } else {
      chunked[trial] = parse_timed(document, length, 1);
      one_shot[trial] = parse_timed(document, length, 0);
    }
  }
  results[0].median_ns = median(one_shot, samples);
  results[0].trials = samples;
  results[1].median_ns = median(chunked, samples);
  results[1].trials = samples;
  *count = 2;
  free(document);
  return 1;
}

static int run_limit(const Entry *entry, Result *results, int *count) {
  const Case *item = entry->item;
  size_t length = 0;
  unsigned char *document = build(item, &length);
  if (!check_result(item, document, length)) {
    fprintf(stderr, "benchmark: limit case %s did not produce its expected "
                    "result\n", item->shape_name);
    free(document);
    return 0;
  }
  int64_t start = now_ns();
  int64_t elapsed = parse_timed(document, length, 0);
  int64_t total = now_ns() - start;
  free(document);
  if (total > 15000000000LL) {
    fprintf(stderr, "benchmark: limit case %s exceeded 15s\n",
            item->shape_name);
    return 0;
  }
  results[0].median_ns = elapsed;
  results[0].trials = 1;
  *count = 1;
  return 1;
}

static int run_entry_child(const Entry *entry, int samples, int fd) {
  Result results[2];
  int count = 0;
  int ok;
  if (entry->kind == ENTRY_DRIFT)
    ok = run_drift(entry, samples, results, &count);
  else if (entry->kind == ENTRY_CASE)
    ok = run_case(entry, samples, results, &count);
  else
    ok = run_limit(entry, results, &count);
  if (!ok)
    return 0;
  return write_full(fd, &count, sizeof count)
         && write_full(fd, results, sizeof results[0] * (size_t)count);
}

static void write_row(FILE *csv, const char *side, const char *family,
                      const char *shape, const char *cve, size_t size,
                      const char *unit, const char *mode, int trials,
                      int64_t median_ns, long rss_kb, const char *base_commit,
                      const char *candidate_tree, const char *manifest,
                      const char *toolchain, const char *flags) {
  fprintf(csv, "%s,%s,%s,%s,%zu,%s,%s,%d,%lld,%ld,%s,%s,%s,%s,%s\n", side,
          family, shape, cve, size, unit, mode, trials, (long long)median_ns,
          rss_kb, base_commit, candidate_tree, manifest, toolchain, flags);
}

static int measure_entry(FILE *csv, const Entry *entry, int samples,
                         const char *side, const char *base_commit,
                         const char *candidate_tree, const char *manifest,
                         const char *toolchain, const char *flags) {
  int fds[2];
  if (pipe(fds) != 0) {
    fputs("benchmark: pipe failed\n", stderr);
    return 0;
  }
  pid_t pid = fork();
  if (pid < 0) {
    fputs("benchmark: fork failed\n", stderr);
    close(fds[0]);
    close(fds[1]);
    return 0;
  }
  if (pid == 0) {
    close(fds[0]);
    int ok = run_entry_child(entry, samples, fds[1]);
    _exit(ok ? 0 : 1);
  }
  close(fds[1]);
  int count = 0;
  Result results[2];
  int read_ok = read_full(fds[0], &count, sizeof count)
                && count > 0 && count <= 2
                && read_full(fds[0], results,
                             sizeof results[0] * (size_t)count);
  close(fds[0]);
  int status = 0;
  struct rusage usage;
  memset(&usage, 0, sizeof usage);
  if (wait4(pid, &status, 0, &usage) < 0) {
    fputs("benchmark: wait4 failed\n", stderr);
    return 0;
  }
  if (!read_ok || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    fprintf(stderr, "benchmark: entry %s/%s failed\n",
            entry->kind == ENTRY_DRIFT ? "drift"
            : entry->kind == ENTRY_CASE ? entry->item->family
                                        : "limit",
            entry->kind == ENTRY_DRIFT ? entry->block
            : entry->item->shape_name);
    return 0;
  }
  long rss_kb = (long)usage.ru_maxrss;
  if (entry->kind == ENTRY_DRIFT) {
    write_row(csv, side, "drift", entry->block, "", DRIFT_BYTES, "input-bytes",
              "one-shot", results[0].trials, results[0].median_ns, rss_kb,
              base_commit, candidate_tree, manifest, toolchain, flags);
    return 1;
  }
  if (entry->kind == ENTRY_LIMIT) {
    write_row(csv, side, entry->item->family, entry->item->shape_name, "",
              entry->item->size, entry->item->unit, "one-shot",
              results[0].trials, results[0].median_ns, rss_kb, base_commit,
              candidate_tree, manifest, toolchain, flags);
    return 1;
  }
  write_row(csv, side, entry->item->family, entry->item->shape_name,
            entry->item->cve, entry->item->size, entry->item->unit, "one-shot",
            results[0].trials, results[0].median_ns, rss_kb, base_commit,
            candidate_tree, manifest, toolchain, flags);
  write_row(csv, side, entry->item->family, entry->item->shape_name,
            entry->item->cve, entry->item->size, entry->item->unit, "chunk-64",
            results[1].trials, results[1].median_ns, rss_kb, base_commit,
            candidate_tree, manifest, toolchain, flags);
  return 1;
}

static void print_plan(const Entry *schedule, size_t count) {
  for (size_t i = 0; i < count; i++) {
    const Entry *entry = &schedule[i];
    if (entry->kind == ENTRY_DRIFT)
      printf("%zu drift %s\n", i, entry->block);
    else if (entry->kind == ENTRY_LIMIT)
      printf("%zu limit %s %zu\n", i, entry->item->shape_name,
             entry->item->size);
    else
      printf("%zu case %s %s %zu\n", i, entry->item->family,
             entry->item->shape_name, entry->item->size);
  }
}

static FILE *open_csv(const char *path) {
  FILE *csv = fopen(path, "a");
  if (csv == NULL) {
    fprintf(stderr, "benchmark: cannot write %s\n", path);
    return NULL;
  }
  if (fseek(csv, 0, SEEK_END) != 0) {
    fprintf(stderr, "benchmark: cannot seek %s\n", path);
    fclose(csv);
    return NULL;
  }
  if (ftell(csv) == 0) {
    fprintf(csv, "side,family,shape,cve_id,size,unit,mode,trials,median_ns,"
                 "rss_kb,base_commit,candidate_tree,manifest_sha256,toolchain,"
                 "flags\n");
  }
  return csv;
}

int main(int argc, char **argv) {
  const char *suite = NULL;
  const char *csv_path = NULL;
  const char *side = "candidate";
  const char *base_commit = "unknown";
  const char *candidate_tree = "unknown";
  const char *manifest = "unknown";
  const char *toolchain = "unknown";
  const char *flags = "unknown";
  int samples = 7;
  uint32_t seed = 1;
  int plan = 0;
  long entry_index = -1;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--suite") == 0 && i + 1 < argc)
      suite = argv[++i];
    else if (strcmp(argv[i], "--csv") == 0 && i + 1 < argc)
      csv_path = argv[++i];
    else if (strcmp(argv[i], "--samples") == 0 && i + 1 < argc)
      samples = atoi(argv[++i]);
    else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc)
      seed = (uint32_t)strtoul(argv[++i], NULL, 10);
    else if (strcmp(argv[i], "--side") == 0 && i + 1 < argc)
      side = argv[++i];
    else if (strcmp(argv[i], "--base-commit") == 0 && i + 1 < argc)
      base_commit = argv[++i];
    else if (strcmp(argv[i], "--candidate-tree") == 0 && i + 1 < argc)
      candidate_tree = argv[++i];
    else if (strcmp(argv[i], "--manifest-sha256") == 0 && i + 1 < argc)
      manifest = argv[++i];
    else if (strcmp(argv[i], "--toolchain") == 0 && i + 1 < argc)
      toolchain = argv[++i];
    else if (strcmp(argv[i], "--flags") == 0 && i + 1 < argc)
      flags = argv[++i];
    else if (strcmp(argv[i], "--plan") == 0)
      plan = 1;
    else if (strcmp(argv[i], "--entry") == 0 && i + 1 < argc)
      entry_index = strtol(argv[++i], NULL, 10);
    else {
      fprintf(stderr,
              "usage: %s --suite ci|full [--csv PATH] [--samples N] "
              "[--seed S] [--side NAME] [--base-commit SHA] "
              "[--candidate-tree TREE] [--manifest-sha256 SHA] "
              "[--toolchain TEXT] [--flags TEXT] [--plan] [--entry INDEX]\n",
              argv[0]);
      return 2;
    }
  }
  if (suite == NULL) {
    fputs("benchmark: --suite is required\n", stderr);
    return 2;
  }
  if (samples < 1 || samples > SAMPLE_LIMIT) {
    fputs("benchmark: --samples must be between 1 and 16\n", stderr);
    return 2;
  }

  const Case *cases;
  size_t count;
  if (strcmp(suite, "ci") == 0) {
    cases = CI_CASES;
    count = sizeof CI_CASES / sizeof CI_CASES[0];
  } else if (strcmp(suite, "full") == 0) {
    cases = FULL_CASES;
    count = sizeof FULL_CASES / sizeof FULL_CASES[0];
  } else {
    fprintf(stderr, "benchmark: unknown suite %s\n", suite);
    return 2;
  }

  static Entry schedule[SCHEDULE_LIMIT];
  size_t entries = build_schedule(cases, count, schedule, SCHEDULE_LIMIT, seed);

  if (plan) {
    print_plan(schedule, entries);
    return 0;
  }

  if (csv_path == NULL) {
    fputs("benchmark: --csv is required unless --plan is used\n", stderr);
    return 2;
  }
  FILE *csv = open_csv(csv_path);
  if (csv == NULL)
    return 3;

  if (entry_index >= 0) {
    if ((size_t)entry_index >= entries) {
      fprintf(stderr, "benchmark: entry %ld is outside the %zu-entry plan\n",
              entry_index, entries);
      fclose(csv);
      return 2;
    }
    int ok = measure_entry(csv, &schedule[entry_index], samples, side,
                           base_commit, candidate_tree, manifest, toolchain,
                           flags);
    fclose(csv);
    if (!ok) {
      fputs("benchmark: entry measurement failed\n", stderr);
      return 1;
    }
    return 0;
  }

  int failures = 0;
  for (size_t i = 0; i < entries; i++) {
    if (!measure_entry(csv, &schedule[i], samples, side, base_commit,
                       candidate_tree, manifest, toolchain, flags))
      failures++;
  }
  fclose(csv);
  if (failures != 0) {
    fprintf(stderr, "benchmark: %d measurement or correctness failures\n",
            failures);
    return 1;
  }
  printf("benchmark: %zu entries measured into %s\n", entries, csv_path);
  return 0;
}
