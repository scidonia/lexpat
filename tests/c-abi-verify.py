#!/usr/bin/env python3
"""ABI, header, symbol, runtime and policy checks for the C ABI artifact.

The checks are grouped so each acceptance criterion has its own command:

  --header       source compatibility of `include/expat.h`, refused build modes,
                 opaque `XML_Parser`, and the pinned `XML_GetUserData` macro
                 used with the candidate library
  --abi          exact dynamic `XML_*` export allowlist against the header,
                 SONAME/NEEDED/RUNPATH, loader resolution, a real launch, the
                 `FLAGS_1` `NODELETE` entry that keeps the initialized runtime
                 mapped after `dlclose`, and 16 fresh-process load/parse/free/
                 close clients under one 60-second aggregate deadline
                 (`--base-lib <absolute .so>` applies the same detector to a
                 base artifact and requires it to lack `NODELETE`)
  --layout       public enumerator values and defined struct sizes, alignment
                 and offsets equal the pinned system Expat header
  --identity     truthful version, version info, compile-time macros and feature
                 list, with no unsupported feature advertised
  --lifecycle    independent parsers, user data, registry-checked stale
                 handles and immediate repeated free
  --buffers      `XML_GetBuffer`/`XML_ParseBuffer` reservation, invalidation,
                 exact consumption and refusal cases
  --errors       exact numeric error mapping, stable strings and terminal states
  --locations    callback-time byte index, line and column for UTF-8, UTF-16,
                 BOM, CRLF, reference, CDATA, empty-tag and chunked cases
  --unsupported  every declared unsupported family fails closed without a
                 resolver, including the parameter-entity timing rule
  --bridge       the callback-specific direct receivers refuse inverted, oversized
                 or out-of-bounds text spans, impossible positions, invalid UTF-8
                 and impossible declaration metadata before any callback, report
                 a shim allocation failure as `XML_ERROR_NO_MEMORY`, deliver every
                 handler family affirmatively, and allocate no payload copy for an
                 event with no handler
  --adversarial  NULL handles, invalid lengths, capacity arithmetic, re-entrant
                 parses, callback-time parser creation and free-in-callback
                 behavior
  --docs         documentation, test-policy and CI claims match the verified
                 surface and name their limitations

With no group the script runs every group. It never dereferences a fabricated
pointer, never calls `XML_GetUserData` on a freed handle, and never claims
protection from post-free address reuse.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HEADER = ROOT / "include" / "expat.h"
LIB_DIR = ROOT / ".lake" / "build" / "lib"
LIB = LIB_DIR / "liblexpat.so.1"
CLIENT_SRC = ROOT / "tests" / "c-abi-client.c"

GROUPS = ["header", "abi", "layout", "identity", "lifecycle", "buffers",
          "errors", "locations", "unsupported", "bridge", "adversarial", "docs"]


class VerifyError(Exception):
    pass


def run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def need(condition, message):
    if not condition:
        raise VerifyError(message)


def parse_enum(text, name):
    marker = "enum " + name + " {"
    start = text.index(marker) + len(marker)
    values = {}
    token = ""
    next_value = 0
    depth = 1
    index = start
    while index < len(text) and depth > 0:
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                break
        elif char == "," or char == "\n":
            entry = token.strip()
            if entry and not entry.startswith("/*") and not entry.startswith("//"):
                if "=" in entry:
                    label, raw = entry.split("=", 1)
                    label = label.strip()
                    value = int(raw.strip(), 0)
                else:
                    label = entry
                    value = next_value
                values[label] = value
                next_value = value + 1
            token = ""
            index += 1
            continue
        elif char == "/" and text[index:index + 2] == "/*":
            index = text.index("*/", index) + 2
            continue
        token += char
        index += 1
    need(values, f"no enumerators found in enum {name}")
    return values


HARNESS_SOURCE = r"""
/*
 * Runtime checks for the C ABI artifact. `tests/c-abi-verify.py` compiles this
 * source against `include/expat.h` and `liblexpat.so.1` and runs one group per
 * invocation. Every non-NULL pointer this file passes to the library refers to
 * accessible memory for its declared size; `XML_GetUserData` is used only on a
 * live handle returned by `XML_ParserCreate`.
 */

#include <expat.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;
static long checks;

#define CHECK(condition, message)                                              \
  do {                                                                         \
    checks++;                                                                  \
    if (!(condition)) {                                                        \
      fprintf(stderr, "verify: FAIL: %s\n", (message));                        \
      failures++;                                                              \
    }                                                                          \
  } while (0)

#define CHECK_EQ(actual, expected, message)                                    \
  do {                                                                         \
    long actualValue = (long)(actual);                                         \
    long expectedValue = (long)(expected);                                     \
    checks++;                                                                  \
    if (actualValue != expectedValue) {                                        \
      fprintf(stderr, "verify: FAIL: %s (got %ld, want %ld)\n", (message),     \
              actualValue, expectedValue);                                     \
      failures++;                                                              \
    }                                                                          \
  } while (0)

#define CHECK_STR(actual, expected, message)                                   \
  do {                                                                         \
    const char *actualValue = (actual);                                        \
    const char *expectedValue = (expected);                                    \
    checks++;                                                                  \
    if (actualValue == NULL || strcmp(actualValue, expectedValue) != 0) {      \
      fprintf(stderr, "verify: FAIL: %s (got %s, want %s)\n", (message),       \
              actualValue == NULL ? "(null)" : actualValue, expectedValue);    \
      failures++;                                                              \
    }                                                                          \
  } while (0)

static XML_Parser current;

static XML_Parser fresh(const char *message) {
  XML_Parser parser = XML_ParserCreate(NULL);
  CHECK(parser != NULL, message);
  if (parser == NULL) {
    fputs("verify: cannot create a parser\n", stderr);
    exit(2);
  }
  return parser;
}

static void report(const char *group) {
  if (failures != 0) {
    fprintf(stderr, "verify: %s: %d of %ld checks failed\n", group, failures, checks);
    exit(1);
  }
  printf("PASS %s (%ld checks)\n", group, checks);
}

/* ------------------------------------------------------------------ */
/* Counting handlers and a shared record.                              */

typedef struct {
  int starts;
  int ends;
  void *expected_user;
  int wrong_user;
  int outside;
  int parse_active;
} Counts;

static void note_user(Counts *counts, void *userData) {
  if (counts->expected_user != userData)
    counts->wrong_user = 1;
  if (!counts->parse_active)
    counts->outside = 1;
}

static void XMLCALL count_start(void *userData, const XML_Char *name,
                                const XML_Char **atts) {
  Counts *counts = (Counts *)userData;
  (void)name;
  (void)atts;
  note_user(counts, userData);
  counts->starts++;
}

static void XMLCALL count_end(void *userData, const XML_Char *name) {
  Counts *counts = (Counts *)userData;
  (void)name;
  note_user(counts, userData);
  counts->ends++;
}

/* ------------------------------------------------------------------ */
/* lifecycle                                                           */

static void group_lifecycle(void) {
  Counts first = {0, 0, NULL, 0, 0, 0};
  Counts second = {0, 0, NULL, 0, 0, 0};
  int token_a = 1;
  int token_b = 2;

  XML_Parser a = fresh("lifecycle: first parser created");
  XML_Parser b = fresh("lifecycle: second parser created");
  CHECK(a != b, "lifecycle: parsers are independent handles");
  XML_SetUserData(a, &token_a);
  XML_SetUserData(b, &token_b);
  XML_SetElementHandler(a, count_start, count_end);
  XML_SetElementHandler(b, count_start, count_end);
  XML_SetUserData(a, &first);
  XML_SetUserData(b, &second);
  first.expected_user = &first;
  second.expected_user = &second;
  CHECK(XML_GetUserData(a) == &first, "lifecycle: XML_GetUserData reads offset zero");
  CHECK(XML_GetUserData(b) == &second, "lifecycle: second user data is separate");

  first.parse_active = 1;
  second.parse_active = 1;
  CHECK_EQ(XML_Parse(a, "<alpha>", 7, 0), XML_STATUS_OK,
           "lifecycle: first parser accepts a prefix");
  CHECK_EQ(XML_Parse(b, "<beta>", 6, 0), XML_STATUS_OK,
           "lifecycle: second parser accepts a different prefix");
  CHECK_EQ(XML_Parse(a, "</alpha>", 8, 1), XML_STATUS_OK,
           "lifecycle: first parser finishes");
  CHECK_EQ(XML_Parse(b, "</beta>", 7, 1), XML_STATUS_OK,
           "lifecycle: second parser finishes");
  first.parse_active = 0;
  second.parse_active = 0;

  CHECK_EQ(first.starts, 1, "lifecycle: first parser saw one start");
  CHECK_EQ(first.ends, 1, "lifecycle: first parser saw one end");
  CHECK_EQ(second.starts, 1, "lifecycle: second parser saw one start");
  CHECK_EQ(second.ends, 1, "lifecycle: second parser saw one end");
  CHECK(!first.wrong_user && !second.wrong_user,
        "lifecycle: each callback received its own parser's user data");
  CHECK(!first.outside && !second.outside,
        "lifecycle: callbacks ran inside their parse calls");

  CHECK(XML_ParserCreate("UTF-8") == NULL,
        "lifecycle: a non-NULL encoding hint is refused");
  CHECK(XML_ParserCreate("") == NULL, "lifecycle: an empty encoding hint is refused");

  XML_ParserFree(a);
  XML_ParserFree(a); /* immediate repeat is ignored */
  CHECK_EQ(XML_Parse(a, "<x/>", 4, 1), XML_STATUS_ERROR,
           "lifecycle: a released handle is refused by the registry");
  CHECK_EQ(XML_GetErrorCode(a), XML_ERROR_INVALID_ARGUMENT,
           "lifecycle: a released handle reports an invalid argument without dereference");
  CHECK(XML_GetBuffer(a, 1) == NULL, "lifecycle: no reservation for a released handle");
  XML_SetUserData(a, &token_a); /* registry-checked no-op */
  {
    XML_ParsingStatus status;
    status.parsing = XML_SUSPENDED;
    status.finalBuffer = XML_TRUE;
    XML_GetParsingStatus(a, &status);
    CHECK_EQ(status.parsing, XML_SUSPENDED,
             "lifecycle: status of a released handle is not written");
    CHECK_EQ(status.finalBuffer, XML_TRUE,
             "lifecycle: final buffer of a released handle is not written");
  }
  XML_ParserFree(b);
  report("lifecycle");
}

/* ------------------------------------------------------------------ */
/* buffers                                                             */

static void group_buffers(void) {
  Counts counts = {0, 0, NULL, 0, 0, 0};
  XML_Parser parser;
  char *buffer;

  parser = fresh("buffers: parser created");
  counts.expected_user = &counts;
  XML_SetUserData(parser, &counts);
  XML_SetElementHandler(parser, count_start, count_end);
  CHECK_EQ(XML_ParseBuffer(parser, 0, 1), XML_STATUS_ERROR,
           "buffers: ParseBuffer without a reservation is refused");
  CHECK_EQ(XML_GetErrorCode(parser), XML_ERROR_NO_BUFFER,
           "buffers: no-buffer error is reported");
  XML_ParserFree(parser);

  parser = fresh("buffers: reservation parser created");
  counts.starts = counts.ends = 0;
  counts.parse_active = 1;
  XML_SetElementHandler(parser, count_start, count_end);
  XML_SetUserData(parser, &counts);
  buffer = (char *)XML_GetBuffer(parser, 4);
  CHECK(buffer != NULL, "buffers: a four-byte reservation is returned");
  if (buffer != NULL)
    memcpy(buffer, "<r/>", 4);
  CHECK_EQ(XML_ParseBuffer(parser, 4, 1), XML_STATUS_OK,
           "buffers: ParseBuffer consumes the reservation");
  CHECK_EQ(counts.starts, 1, "buffers: start callback from the reservation");
  CHECK_EQ(counts.ends, 1, "buffers: end callback from the reservation");
  counts.parse_active = 0;
  CHECK(XML_GetBuffer(parser, 1) == NULL,
        "buffers: GetBuffer after the final parse is refused");
  CHECK_EQ(XML_GetErrorCode(parser), XML_ERROR_FINISHED,
           "buffers: finality is terminal for GetBuffer");
  CHECK_EQ(XML_ParseBuffer(parser, 0, 1), XML_STATUS_ERROR,
           "buffers: ParseBuffer after the final parse is refused");
  XML_ParserFree(parser);

  parser = fresh("buffers: invalidation parser created");
  buffer = (char *)XML_GetBuffer(parser, 8);
  CHECK(buffer != NULL, "buffers: first reservation exists");
  if (buffer != NULL)
    memcpy(buffer, "<r", 2);
  buffer = (char *)XML_GetBuffer(parser, 8);
  CHECK(buffer != NULL, "buffers: second reservation exists");
  if (buffer != NULL)
    memcpy(buffer, "/>", 2);
  CHECK_EQ(XML_ParseBuffer(parser, 2, 1), XML_STATUS_ERROR,
           "buffers: the replaced reservation's bytes are not consumed");
  CHECK_EQ(XML_GetErrorCode(parser), XML_ERROR_INVALID_TOKEN,
           "buffers: the second reservation alone is invalid input");
  XML_ParserFree(parser);

  parser = fresh("buffers: capacity parser created");
  buffer = (char *)XML_GetBuffer(parser, 2);
  CHECK(buffer != NULL, "buffers: a two-byte reservation exists");
  if (buffer != NULL)
    memcpy(buffer, "<r", 2);
  CHECK_EQ(XML_ParseBuffer(parser, 3, 1), XML_STATUS_ERROR,
           "buffers: ParseBuffer beyond capacity is refused");
  CHECK_EQ(XML_GetErrorCode(parser), XML_ERROR_INVALID_ARGUMENT,
           "buffers: a capacity overrun is an invalid argument");
  CHECK_EQ(XML_ParseBuffer(parser, 0, 1), XML_STATUS_ERROR,
           "buffers: the overrun leaves the parser terminal");
  CHECK_EQ(XML_GetErrorCode(parser), XML_ERROR_INVALID_ARGUMENT,
           "buffers: the first refusal is retained after an overrun");
  XML_ParserFree(parser);

  parser = fresh("buffers: zero reservation parser created");
  buffer = (char *)XML_GetBuffer(parser, 0);
  CHECK(buffer != NULL, "buffers: a zero-byte reservation is returned");
  CHECK_EQ(XML_ParseBuffer(parser, 0, 0), XML_STATUS_OK,
           "buffers: a zero-byte non-final ParseBuffer succeeds");
  buffer = (char *)XML_GetBuffer(parser, 4);
  CHECK(buffer != NULL, "buffers: a later reservation exists");
  if (buffer != NULL)
    memcpy(buffer, "<r/>", 4);
  CHECK_EQ(XML_ParseBuffer(parser, 4, 1), XML_STATUS_OK,
           "buffers: the later reservation finishes the document");
  XML_ParserFree(parser);

  parser = fresh("buffers: negative parser created");
  CHECK(XML_GetBuffer(parser, -1) == NULL,
        "buffers: a negative reservation is refused");
  CHECK_EQ(XML_GetErrorCode(parser), XML_ERROR_INVALID_ARGUMENT,
           "buffers: a negative reservation is an invalid argument");
  XML_ParserFree(parser);

  parser = fresh("buffers: large parser created");
  CHECK(XML_GetBuffer(parser, INT_MAX) == NULL,
        "buffers: a reservation beyond the input budget is refused");
  CHECK_EQ(XML_GetErrorCode(parser), XML_ERROR_INVALID_ARGUMENT,
           "buffers: an over-budget reservation is an invalid argument");
  XML_ParserFree(parser);

  parser = fresh("buffers: exact parser created");
  counts.starts = counts.ends = 0;
  XML_SetElementHandler(parser, count_start, count_end);
  XML_SetUserData(parser, &counts);
  buffer = (char *)XML_GetBuffer(parser, 16);
  CHECK(buffer != NULL, "buffers: a larger-than-needed reservation exists");
  if (buffer != NULL)
    memcpy(buffer, "<r/>garbage", 11);
  counts.parse_active = 1;
  CHECK_EQ(XML_ParseBuffer(parser, 4, 1), XML_STATUS_OK,
           "buffers: exactly the declared prefix is parsed");
  counts.parse_active = 0;
  CHECK_EQ(counts.starts, 1, "buffers: one start from the four-byte prefix");
  CHECK_EQ(counts.ends, 1, "buffers: one end from the four-byte prefix");
  XML_ParserFree(parser);

  parser = fresh("buffers: empty input parser created");
  CHECK_EQ(XML_Parse(parser, NULL, 0, 1), XML_STATUS_ERROR,
           "buffers: an empty document is rejected");
  CHECK_EQ(XML_GetErrorCode(parser), XML_ERROR_NO_ELEMENTS,
           "buffers: an empty document reports no elements");
  XML_ParserFree(parser);

  report("buffers");
}

/* ------------------------------------------------------------------ */
/* errors                                                              */

typedef struct {
  const char *document;
  long code;
} ErrorCase;

static void group_errors(void) {
  static const ErrorCase cases[] = {
      {"<a><b></a>", 7},           /* TAG_MISMATCH */
      {"<a x=\"1\" x=\"2\"/>", 8},  /* DUPLICATE_ATTRIBUTE */
      {"<a/>x", 9},                 /* JUNK_AFTER_DOC_ELEMENT */
      {"<a>&foo;</a>", 11},         /* UNDEFINED_ENTITY */
      {"<a>&#0;</a>", 14},          /* BAD_CHAR_REF */
      {"<a><![CDATA[x", 20},        /* UNCLOSED_CDATA_SECTION */
      {"<?xml version=\"2.0\"?><a/>", 30}, /* XML_DECL */
      {"<!DOCTYPE a><a/>", 45},     /* UNSUPPORTED_DTD */
      {"<a>", 3},                   /* NO_ELEMENTS at finish */
      {"<a b=\"<\"/>", 4},          /* INVALID_TOKEN */
  };
  size_t index;
  long code;
  enum XML_Error mapped;

  for (index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
    XML_Parser parser = fresh("errors: parser created");
    enum XML_Status status =
        XML_Parse(parser, cases[index].document, (int)strlen(cases[index].document), 1);
    CHECK_EQ(status, XML_STATUS_ERROR, "errors: representative rejection");
    CHECK_EQ(XML_GetErrorCode(parser), cases[index].code,
             "errors: exact numeric code");
    CHECK(XML_ErrorString(XML_GetErrorCode(parser)) != NULL,
          "errors: rejected code has a string");
    XML_ParserFree(parser);
  }

  for (code = 0; code <= 52; code++) {
    const char *text = XML_ErrorString((enum XML_Error)code);
    CHECK(text != NULL && text[0] != '\0', "errors: every published code has a string");
    CHECK(text == XML_ErrorString((enum XML_Error)code),
          "errors: error strings are stable pointers");
  }
  CHECK(XML_ErrorString((enum XML_Error)999) == NULL,
        "errors: an unknown code has no string");
  CHECK_EQ(XML_GetErrorCode(NULL), XML_ERROR_INVALID_ARGUMENT,
           "errors: a NULL parser reports an invalid argument");
  CHECK_EQ(XML_ErrorString(XML_ERROR_UNSUPPORTED_DTD)[0], 'D',
           "errors: the DTD refusal string is present");

  {
    XML_Parser parser = fresh("errors: terminal parser created");
    CHECK_EQ(XML_Parse(parser, "<a><b></a>", 10, 1), XML_STATUS_ERROR,
             "errors: mismatch rejected");
    CHECK_EQ(XML_GetErrorCode(parser), XML_ERROR_TAG_MISMATCH,
             "errors: mismatch code retained");
    CHECK_EQ(XML_Parse(parser, "<a/>", 4, 1), XML_STATUS_ERROR,
             "errors: a terminal parse stays terminal");
    CHECK_EQ(XML_GetErrorCode(parser), XML_ERROR_TAG_MISMATCH,
             "errors: the first error is retained");
    XML_ParserFree(parser);
  }
  {
    XML_Parser parser = fresh("errors: finished parser created");
    CHECK_EQ(XML_Parse(parser, "<a/>", 4, 1), XML_STATUS_OK,
             "errors: accepted document");
    CHECK_EQ(XML_Parse(parser, "<b/>", 4, 1), XML_STATUS_ERROR,
             "errors: a finished parser refuses more input");
    CHECK_EQ(XML_GetErrorCode(parser), XML_ERROR_FINISHED,
             "errors: finished parses report XML_ERROR_FINISHED");
    XML_ParserFree(parser);
  }
  {
    /* LIMIT_INPUT is checked before any byte is read. */
    size_t budget = 8 * 1024 * 1024;
    char *text = (char *)malloc(budget + 1);
    CHECK(text != NULL, "errors: input budget buffer allocated");
    if (text != NULL) {
      XML_Parser parser = fresh("errors: limit parser created");
      memset(text, ' ', budget);
      text[budget] = '<';
      CHECK_EQ(XML_Parse(parser, text, (int)(budget + 1), 1), XML_STATUS_ERROR,
               "errors: over-budget input rejected");
      CHECK_EQ(XML_GetErrorCode(parser), 46, "errors: LIMIT_INPUT code");
      XML_ParserFree(parser);
      free(text);
    }
  }
  {
    size_t count = (size_t)(1024 * 1024) + 1;
    char *text = (char *)malloc(3 + count * 2 + 1 + 4 + 1);
    CHECK(text != NULL, "errors: token budget buffer allocated");
    if (text != NULL) {
      XML_Parser parser = fresh("errors: token limit parser created");
      char *at = text;
      memcpy(at, "<a>", 3);
      at += 3;
      {
        size_t i;
        for (i = 0; i < count; i++) {
          *at++ = 'x';
        }
      }
      memcpy(at, "</a>", 5);
      CHECK_EQ(XML_Parse(parser, text, (int)(3 + count + 5), 1), XML_STATUS_ERROR,
               "errors: over-budget token rejected");
      CHECK_EQ(XML_GetErrorCode(parser), 47, "errors: LIMIT_TOKEN code");
      XML_ParserFree(parser);
      free(text);
    }
  }
  {
    size_t depth = 257;
    size_t length = depth * 3 + depth * 4;
    char *text = (char *)malloc(length + 1);
    CHECK(text != NULL, "errors: depth budget buffer allocated");
    if (text != NULL) {
      XML_Parser parser = fresh("errors: depth limit parser created");
      size_t i;
      char *at = text;
      for (i = 0; i < depth; i++) {
        memcpy(at, "<e>", 3);
        at += 3;
      }
      for (i = 0; i < depth; i++) {
        memcpy(at, "</e>", 4);
        at += 4;
      }
      CHECK_EQ(XML_Parse(parser, text, (int)length, 1), XML_STATUS_ERROR,
               "errors: over-budget depth rejected");
      CHECK_EQ(XML_GetErrorCode(parser), 48, "errors: LIMIT_DEPTH code");
      XML_ParserFree(parser);
      free(text);
    }
  }
  {
    XML_Parser parser = fresh("errors: unsupported feature parser created");
    CHECK_EQ(XML_SetEncoding(parser, "UTF-8"), XML_STATUS_ERROR,
             "errors: SetEncoding is refused");
    CHECK_EQ(XML_GetErrorCode(parser), 50, "errors: refusal is UNSUPPORTED_FEATURE");
    CHECK_EQ(XML_Parse(parser, "<a/>", 4, 1), XML_STATUS_ERROR,
             "errors: a poisoned parser cannot parse");
    mapped = XML_GetErrorCode(parser);
    CHECK_EQ(mapped, 50, "errors: the refusal error is retained");
    XML_ParserFree(parser);
  }
  report("errors");
}

/* ------------------------------------------------------------------ */
/* locations                                                           */

typedef struct {
  int kind; /* 0 start, 1 end, 2 text */
  char name[32];
  char data[64];
  long byte;
  unsigned long line;
  unsigned long column;
  int parsing;
  int final_buffer;
} LocEvent;

typedef struct {
  LocEvent events[16];
  int count;
  int parse_active;
  int outside;
  int parsing_seen;
  int specified;
} LocLog;

static void XMLCALL loc_start(void *userData, const XML_Char *name,
                              const XML_Char **atts) {
  LocLog *log = (LocLog *)userData;
  (void)atts;
  if (!log->parse_active)
    log->outside = 1;
  if (log->count < 16) {
    LocEvent *event = &log->events[log->count];
    memset(event, 0, sizeof(*event));
    event->kind = 0;
    snprintf(event->name, sizeof(event->name), "%s", name);
    event->byte = (long)XML_GetCurrentByteIndex(current);
    event->line = (unsigned long)XML_GetCurrentLineNumber(current);
    event->column = (unsigned long)XML_GetCurrentColumnNumber(current);
    {
      XML_ParsingStatus status;
      XML_GetParsingStatus(current, &status);
      event->parsing = (int)status.parsing;
      event->final_buffer = (int)status.finalBuffer;
    }
  }
  log->specified = XML_GetSpecifiedAttributeCount(current);
  log->parsing_seen = 1;
  log->count++;
}

static void XMLCALL loc_end(void *userData, const XML_Char *name) {
  LocLog *log = (LocLog *)userData;
  if (!log->parse_active)
    log->outside = 1;
  if (log->count < 16) {
    LocEvent *event = &log->events[log->count];
    memset(event, 0, sizeof(*event));
    event->kind = 1;
    snprintf(event->name, sizeof(event->name), "%s", name);
    event->byte = (long)XML_GetCurrentByteIndex(current);
    event->line = (unsigned long)XML_GetCurrentLineNumber(current);
    event->column = (unsigned long)XML_GetCurrentColumnNumber(current);
    {
      XML_ParsingStatus status;
      XML_GetParsingStatus(current, &status);
      event->parsing = (int)status.parsing;
      event->final_buffer = (int)status.finalBuffer;
    }
  }
  log->count++;
}

static void XMLCALL loc_text(void *userData, const XML_Char *data, int len) {
  LocLog *log = (LocLog *)userData;
  if (!log->parse_active)
    log->outside = 1;
  if (log->count < 16) {
    LocEvent *event = &log->events[log->count];
    size_t copy = (size_t)(len < 0 ? 0 : len);
    memset(event, 0, sizeof(*event));
    event->kind = 2;
    if (copy > sizeof(event->data) - 1)
      copy = sizeof(event->data) - 1;
    memcpy(event->data, data, copy);
    event->byte = (long)XML_GetCurrentByteIndex(current);
    event->line = (unsigned long)XML_GetCurrentLineNumber(current);
    event->column = (unsigned long)XML_GetCurrentColumnNumber(current);
    {
      XML_ParsingStatus status;
      XML_GetParsingStatus(current, &status);
      event->parsing = (int)status.parsing;
      event->final_buffer = (int)status.finalBuffer;
    }
  }
  log->count++;
}

/* The final-buffer value the events being asserted were recorded with. */
static int expected_final_buffer = 1;

static void loc_init(LocLog *log) {
  memset(log, 0, sizeof(*log));
  log->specified = -99;
}

static XML_Parser loc_parser(LocLog *log) {
  XML_Parser parser = fresh("locations: parser created");
  expected_final_buffer = 1;
  current = parser;
  XML_SetUserData(parser, log);
  XML_SetElementHandler(parser, loc_start, loc_end);
  XML_SetCharacterDataHandler(parser, loc_text);
  log->parse_active = 1;
  return parser;
}

static void expect_event(const LocLog *log, int index, int kind,
                         const char *text, long byte, unsigned long line,
                         unsigned long column, const char *message) {
  const LocEvent *event;
  CHECK(log->count > index, message);
  if (log->count <= index)
    return;
  event = &log->events[index];
  CHECK_EQ(event->kind, kind, message);
  if (kind == 2)
    CHECK_STR(event->data, text, message);
  else
    CHECK_STR(event->name, text, message);
  CHECK_EQ(event->byte, byte, message);
  CHECK_EQ(event->line, line, message);
  CHECK_EQ(event->column, column, message);
  CHECK_EQ(event->parsing, XML_PARSING, message);
  CHECK_EQ(event->final_buffer, expected_final_buffer, message);
}

static void group_locations(void) {
  LocLog log;
  XML_Parser parser;
  enum XML_Status status;

  loc_init(&log);
  parser = loc_parser(&log);
  status = XML_Parse(parser, "<r><child/></r>", 15, 1);
  log.parse_active = 0;
  CHECK_EQ(status, XML_STATUS_OK, "locations: nested document accepted");
  CHECK_EQ(log.count, 4, "locations: four element events");
  expect_event(&log, 0, 0, "r", 0, 1, 0, "locations: start r at the document opener");
  expect_event(&log, 1, 0, "child", 3, 1, 3, "locations: start child at its opener");
  expect_event(&log, 2, 1, "child", 3, 1, 3,
               "locations: an empty-tag end is anchored at its opener");
  expect_event(&log, 3, 1, "r", 11, 1, 11, "locations: end r at its opener");
  {
    XML_ParsingStatus after;
    XML_GetParsingStatus(parser, &after);
    CHECK_EQ(after.parsing, XML_FINISHED, "locations: finished after the final parse");
    CHECK_EQ(after.finalBuffer, XML_TRUE, "locations: final buffer recorded");
  }
  XML_ParserFree(parser);

  loc_init(&log);
  parser = loc_parser(&log);
  status = XML_Parse(parser, "<r/>", 4, 1);
  log.parse_active = 0;
  CHECK_EQ(status, XML_STATUS_OK, "locations: empty element accepted");
  expect_event(&log, 0, 0, "r", 0, 1, 0, "locations: empty start at the opener");
  expect_event(&log, 1, 1, "r", 0, 1, 0, "locations: empty end at the opener");
  XML_ParserFree(parser);

  /* The final-buffer flag describes the call whose callbacks are running. */
  loc_init(&log);
  parser = loc_parser(&log);
  expected_final_buffer = 0;
  status = XML_Parse(parser, "<r><c/>", 7, 0);
  CHECK_EQ(status, XML_STATUS_OK, "locations: a non-final parse accepts a prefix");
  CHECK_EQ(log.count, 3, "locations: three events from the non-final prefix");
  expect_event(&log, 0, 0, "r", 0, 1, 0, "locations: non-final start r");
  expect_event(&log, 1, 0, "c", 3, 1, 3, "locations: non-final start c");
  expect_event(&log, 2, 1, "c", 3, 1, 3, "locations: non-final empty-tag end");
  CHECK_EQ(log.events[0].final_buffer, 0,
           "locations: a non-final callback sees XML_FALSE");
  expected_final_buffer = 1;
  status = XML_Parse(parser, "</r>", 4, 1);
  log.parse_active = 0;
  CHECK_EQ(status, XML_STATUS_OK, "locations: the final continuation is accepted");
  CHECK_EQ(log.count, 4, "locations: the final event is appended");
  expect_event(&log, 3, 1, "r", 7, 1, 7, "locations: final end r");
  CHECK_EQ(log.events[3].final_buffer, 1,
           "locations: a final callback sees XML_TRUE");
  XML_ParserFree(parser);

  loc_init(&log);
  parser = loc_parser(&log);
  status = XML_Parse(parser, "<r>\r\n\xc3\xa9</r>", 11, 1);
  log.parse_active = 0;
  CHECK_EQ(status, XML_STATUS_OK, "locations: CRLF document accepted");
  expect_event(&log, 0, 0, "r", 0, 1, 0, "locations: CRLF start");
  expect_event(&log, 1, 2, "\n\xc3\xa9", 3, 1, 3,
               "locations: text starts at the first body scalar with CRLF normalized");
  expect_event(&log, 2, 1, "r", 7, 2, 1, "locations: end after CRLF on line two");
  XML_ParserFree(parser);

  loc_init(&log);
  parser = loc_parser(&log);
  status = XML_Parse(parser, "\xef\xbb\xbf<r/>", 7, 1);
  log.parse_active = 0;
  CHECK_EQ(status, XML_STATUS_OK, "locations: UTF-8 BOM document accepted");
  expect_event(&log, 0, 0, "r", 3, 1, 0, "locations: BOM contributes no column");
  expect_event(&log, 1, 1, "r", 3, 1, 0, "locations: BOM end at the opener");
  XML_ParserFree(parser);

  {
    static const char utf16le[] = {(char)0xFF, (char)0xFE, '<', 0, 'a', 0, '/', 0, '>', 0};
    loc_init(&log);
    parser = loc_parser(&log);
    status = XML_Parse(parser, utf16le, (int)sizeof(utf16le), 1);
    log.parse_active = 0;
    CHECK_EQ(status, XML_STATUS_OK, "locations: UTF-16LE document accepted");
    expect_event(&log, 0, 0, "a", 2, 1, 0, "locations: UTF-16LE start after the BOM");
    expect_event(&log, 1, 1, "a", 2, 1, 0, "locations: UTF-16LE end at the opener");
    XML_ParserFree(parser);
  }
  {
    static const char utf16be[] = {(char)0xFE, (char)0xFF, 0, '<', 0, 'a', 0, '/', 0, '>'};
    loc_init(&log);
    parser = loc_parser(&log);
    status = XML_Parse(parser, utf16be, (int)sizeof(utf16be), 1);
    log.parse_active = 0;
    CHECK_EQ(status, XML_STATUS_OK, "locations: UTF-16BE document accepted");
    expect_event(&log, 0, 0, "a", 2, 1, 0, "locations: UTF-16BE start after the BOM");
    expect_event(&log, 1, 1, "a", 2, 1, 0, "locations: UTF-16BE end at the opener");
    XML_ParserFree(parser);
  }

  loc_init(&log);
  parser = loc_parser(&log);
  status = XML_Parse(parser, "<r>&#65;</r>", 12, 1);
  log.parse_active = 0;
  CHECK_EQ(status, XML_STATUS_OK, "locations: reference document accepted");
  expect_event(&log, 0, 0, "r", 0, 1, 0, "locations: reference start");
  expect_event(&log, 1, 2, "A", 3, 1, 3,
               "locations: text starts at the reference marker");
  expect_event(&log, 2, 1, "r", 8, 1, 8, "locations: reference end");
  XML_ParserFree(parser);

  loc_init(&log);
  parser = loc_parser(&log);
  status = XML_Parse(parser, "<r>\xc3\xa9</r>", 9, 1);
  log.parse_active = 0;
  CHECK_EQ(status, XML_STATUS_OK, "locations: UTF-8 document accepted");
  expect_event(&log, 1, 2, "\xc3\xa9", 3, 1, 3,
               "locations: multibyte text starts at its first scalar");
  expect_event(&log, 2, 1, "r", 5, 1, 4,
               "locations: multibyte text advances the scalar column by one");
  XML_ParserFree(parser);

  /* A failing document reports its failed token location. */
  loc_init(&log);
  parser = loc_parser(&log);
  status = XML_Parse(parser, "<a><b></a>", 10, 1);
  log.parse_active = 0;
  CHECK_EQ(status, XML_STATUS_ERROR, "locations: mismatch rejected");
  CHECK_EQ(XML_GetErrorCode(parser), XML_ERROR_TAG_MISMATCH,
           "locations: mismatch code");
  CHECK_EQ(XML_GetCurrentByteIndex(parser), 6, "locations: failure byte index");
  CHECK_EQ(XML_GetCurrentLineNumber(parser), 1, "locations: failure line");
  CHECK_EQ(XML_GetCurrentColumnNumber(parser), 6, "locations: failure column");
  XML_ParserFree(parser);

  /* A duplicate attribute is a fault of the whole start tag: the byte index,
   * line and column all name the opening `<`. */
  loc_init(&log);
  parser = loc_parser(&log);
  status = XML_Parse(parser, "<a x=\"1\" x=\"2\"/>", 16, 1);
  log.parse_active = 0;
  CHECK_EQ(status, XML_STATUS_ERROR, "locations: duplicate attribute rejected");
  CHECK_EQ(XML_GetErrorCode(parser), XML_ERROR_DUPLICATE_ATTRIBUTE,
           "locations: duplicate attribute code");
  CHECK_EQ(XML_GetCurrentByteIndex(parser), 0,
           "locations: duplicate attribute byte index is the opener");
  CHECK_EQ(XML_GetCurrentLineNumber(parser), 1,
           "locations: duplicate attribute line is the opener");
  CHECK_EQ(XML_GetCurrentColumnNumber(parser), 0,
           "locations: duplicate attribute column is the opener");
  CHECK_EQ(log.count, 0, "locations: no start callback for a rejected tag");
  XML_ParserFree(parser);

  /* Chunk cuts do not change the event records or positions. */
  {
    LocLog whole;
    LocLog chunked;
    int i;
    loc_init(&whole);
    parser = loc_parser(&whole);
    CHECK_EQ(XML_Parse(parser, "<r><c/></r>", 11, 1), XML_STATUS_OK,
             "locations: whole parse accepted");
    whole.parse_active = 0;
    XML_ParserFree(parser);

    loc_init(&chunked);
    parser = loc_parser(&chunked);
    for (i = 0; i < 11; i++) {
      CHECK_EQ(XML_Parse(parser, "<r><c/></r>" + i, 1, i == 10), XML_STATUS_OK,
               "locations: chunked parse accepted");
    }
    chunked.parse_active = 0;
    XML_ParserFree(parser);
    CHECK_EQ(chunked.count, whole.count, "locations: chunking preserves event count");
    for (i = 0; i < whole.count && i < 16; i++) {
      CHECK_EQ(chunked.events[i].kind, whole.events[i].kind,
               "locations: chunking preserves event kind");
      CHECK_EQ(chunked.events[i].byte, whole.events[i].byte,
               "locations: chunking preserves byte index");
      CHECK_EQ(chunked.events[i].line, whole.events[i].line,
               "locations: chunking preserves line");
      CHECK_EQ(chunked.events[i].column, whole.events[i].column,
               "locations: chunking preserves column");
    }
  }

  /* Specified attribute count and ID index inside and outside a start event. */
  {
    Counts counts = {0, 0, NULL, 0, 0, 0};
    XML_Parser control =
        fresh("locations: unrelated detector control parser created");
    XML_SetUserData(control, &counts);
    XML_SetElementHandler(control, count_start, count_end);
    counts.expected_user = &counts;
    counts.parse_active = 1;
    CHECK_EQ(XML_Parse(control, "<r/>", 4, 1), XML_STATUS_OK,
             "locations: the detector control parse is accepted");
    counts.parse_active = 0;
    CHECK_EQ(counts.starts, 1,
             "locations: the same detector observes a start in its control");
    CHECK_EQ(counts.ends, 1,
             "locations: the same detector observes an end in its control");
    counts.starts = counts.ends = 0;

    loc_init(&log);
    parser = loc_parser(&log);
    CHECK_EQ(XML_GetSpecifiedAttributeCount(parser), 0,
             "locations: no specified attributes outside a start callback");
    CHECK_EQ(XML_GetIdAttributeIndex(parser), -1,
             "locations: no ID attribute without a DTD");
    CHECK_EQ(XML_GetSpecifiedAttributeCount(NULL), -1,
             "locations: a NULL parser has no specified attribute count");
    CHECK_EQ(XML_GetIdAttributeIndex(NULL), -1,
             "locations: a NULL parser has no ID attribute");
    status = XML_Parse(parser, "<r a=\"1\" b=\"2\"/>", 16, 1);
    log.parse_active = 0;
    CHECK_EQ(status, XML_STATUS_OK, "locations: attribute document accepted");
    CHECK_EQ(log.specified, 4, "locations: two attribute pairs count as four");
    CHECK_EQ(XML_GetSpecifiedAttributeCount(parser), 0,
             "locations: the count resets after the callback");
    CHECK_EQ(counts.starts, 0, "locations: unrelated detector stayed silent");
    XML_ParserFree(parser);
    XML_ParserFree(control);
  }
  report("locations");
}

/* ------------------------------------------------------------------ */
/* unsupported                                                         */

static int XMLCALL stub_notstandalone(void *u) { (void)u; return 1; }
static int XMLCALL stub_external(XML_Parser p, const XML_Char *context,
                                 const XML_Char *base, const XML_Char *systemId,
                                 const XML_Char *publicId) {
  (void)p; (void)context; (void)base; (void)systemId; (void)publicId;
  return 0;
}
static void XMLCALL stub_skipped(void *u, const XML_Char *name, int pe) {
  (void)u; (void)name; (void)pe;
}
static void XMLCALL stub_default(void *u, const XML_Char *s, int l) {
  (void)u; (void)s; (void)l;
}
static void XMLCALL stub_doctype_start(void *u, const XML_Char *n,
                                       const XML_Char *sys, const XML_Char *pub,
                                       int has_internal) {
  (void)u; (void)n; (void)sys; (void)pub; (void)has_internal;
}
static void XMLCALL stub_doctype_end(void *u) { (void)u; }
static void XMLCALL stub_element_decl(void *u, const XML_Char *n, XML_Content *m) {
  (void)u; (void)n; (void)m;
}
static void XMLCALL stub_attlist(void *u, const XML_Char *el, const XML_Char *at,
                                 const XML_Char *type, const XML_Char *dflt,
                                 int required) {
  (void)u; (void)el; (void)at; (void)type; (void)dflt; (void)required;
}
static void XMLCALL stub_entity(void *u, const XML_Char *name, int pe,
                                const XML_Char *value, int value_length,
                                const XML_Char *base, const XML_Char *systemId,
                                const XML_Char *publicId, const XML_Char *notation) {
  (void)u; (void)name; (void)pe; (void)value; (void)value_length;
  (void)base; (void)systemId; (void)publicId; (void)notation;
}
static void XMLCALL stub_unparsed(void *u, const XML_Char *name,
                                  const XML_Char *base, const XML_Char *systemId,
                                  const XML_Char *publicId, const XML_Char *notation) {
  (void)u; (void)name; (void)base; (void)systemId; (void)publicId; (void)notation;
}
static void XMLCALL stub_notation(void *u, const XML_Char *name,
                                  const XML_Char *base, const XML_Char *systemId,
                                  const XML_Char *publicId) {
  (void)u; (void)name; (void)base; (void)systemId; (void)publicId;
}
static void XMLCALL stub_namespace_start(void *u, const XML_Char *prefix,
                                         const XML_Char *uri) {
  (void)u; (void)prefix; (void)uri;
}
static void XMLCALL stub_namespace_end(void *u, const XML_Char *prefix) {
  (void)u; (void)prefix;
}
static int XMLCALL stub_unknown_encoding(void *data, const XML_Char *name,
                                         XML_Encoding *info) {
  (void)data; (void)name; (void)info;
  return 0;
}

static void expect_unsupported(XML_Parser parser, const char *message) {
  CHECK_EQ(XML_GetErrorCode(parser), XML_ERROR_UNSUPPORTED_FEATURE, message);
  CHECK_EQ(XML_Parse(parser, "<r/>", 4, 1), XML_STATUS_ERROR, message);
}

static void group_unsupported(void) {
  XML_Parser parser;
  Counts control = {0, 0, NULL, 0, 0, 0};
  int offset = -1;
  int size = -1;

  /* Affirmative control: the detector used below observes a supported handler. */
  parser = fresh("unsupported: control parser created");
  control.expected_user = &control;
  control.parse_active = 1;
  XML_SetUserData(parser, &control);
  XML_SetElementHandler(parser, count_start, count_end);
  CHECK_EQ(XML_Parse(parser, "<r/>", 4, 1), XML_STATUS_OK,
           "unsupported: the supported control parses");
  control.parse_active = 0;
  CHECK_EQ(control.starts, 1, "unsupported: the control detector observes a start");
  XML_ParserFree(parser);

  CHECK(XML_ParserCreateNS(NULL, ':') == NULL,
        "unsupported: a namespace parser is refused");
  CHECK(XML_ParserCreate_MM(NULL, NULL, NULL) == NULL,
        "unsupported: a memory-suite parser is refused");
  CHECK(XML_ExternalEntityParserCreate(NULL, NULL, NULL) == NULL,
        "unsupported: an external-entity parser is refused");

  parser = fresh("unsupported: refusal parser created");
  CHECK_EQ(XML_ParserReset(parser, NULL), XML_FALSE,
           "unsupported: ParserReset returns false");
  CHECK_EQ(XML_SetEncoding(parser, "UTF-8"), XML_STATUS_ERROR,
           "unsupported: SetEncoding is refused");
  CHECK_EQ(XML_GetErrorCode(parser), 50, "unsupported: SetEncoding poisons");
  XML_ParserFree(parser);

  parser = fresh("unsupported: base parser created");
  CHECK_EQ(XML_SetBase(parser, "/tmp"), XML_STATUS_ERROR,
           "unsupported: SetBase is refused");
  CHECK_EQ(XML_GetErrorCode(parser), 50, "unsupported: SetBase poisons");
  XML_ParserFree(parser);

  parser = fresh("unsupported: GetBase parser created");
  CHECK(XML_GetBase(parser) == NULL, "unsupported: GetBase returns NULL");
  CHECK_EQ(XML_GetErrorCode(parser), 50, "unsupported: GetBase poisons");
  XML_ParserFree(parser);

  parser = fresh("unsupported: foreign DTD parser created");
  CHECK_EQ(XML_UseForeignDTD(parser, XML_TRUE), XML_ERROR_UNSUPPORTED_FEATURE,
           "unsupported: UseForeignDTD is refused");
  XML_ParserFree(parser);

  parser = fresh("unsupported: stop parser created");
  CHECK_EQ(XML_StopParser(parser, XML_TRUE), XML_STATUS_ERROR,
           "unsupported: StopParser returns ERROR, never SUSPENDED");
  CHECK_EQ(XML_GetErrorCode(parser), 50, "unsupported: StopParser poisons");
  CHECK_EQ(XML_ResumeParser(parser), XML_STATUS_ERROR,
           "unsupported: ResumeParser is refused");
  XML_ParserFree(parser);

  parser = fresh("unsupported: current parser created");
  XML_DefaultCurrent(parser);
  CHECK_EQ(XML_GetErrorCode(parser), 50, "unsupported: DefaultCurrent poisons");
  CHECK(XML_GetInputContext(parser, &offset, &size) == NULL,
        "unsupported: GetInputContext returns NULL");
  CHECK_EQ(offset, 0, "unsupported: GetInputContext zeroes the offset");
  CHECK_EQ(size, 0, "unsupported: GetInputContext zeroes the size");
  CHECK_EQ(XML_GetErrorCode(parser), 50, "unsupported: GetInputContext poisons");
  XML_ParserFree(parser);

  parser = fresh("unsupported: byte count parser created");
  CHECK_EQ(XML_GetCurrentByteCount(parser), -1,
           "unsupported: GetCurrentByteCount returns -1");
  CHECK_EQ(XML_GetErrorCode(parser), 50, "unsupported: GetCurrentByteCount poisons");
  XML_ParserFree(parser);

  parser = fresh("unsupported: salt parser created");
  CHECK_EQ(XML_SetHashSalt(parser, 7), 0, "unsupported: SetHashSalt is refused");
  CHECK_EQ(XML_GetErrorCode(parser), 50, "unsupported: SetHashSalt poisons");
  XML_ParserFree(parser);

  parser = fresh("unsupported: entropy parser created");
  {
    static const uint8_t entropy[16] = {0};
    CHECK_EQ(XML_SetHashSalt16Bytes(parser, entropy), XML_FALSE,
             "unsupported: SetHashSalt16Bytes is refused");
    CHECK_EQ(XML_GetErrorCode(parser), 50, "unsupported: SetHashSalt16Bytes poisons");
  }
  XML_ParserFree(parser);

  parser = fresh("unsupported: reparse parser created");
  CHECK_EQ(XML_SetReparseDeferralEnabled(parser, XML_TRUE), XML_FALSE,
           "unsupported: SetReparseDeferralEnabled is refused");
  CHECK_EQ(XML_GetErrorCode(parser), 50,
           "unsupported: SetReparseDeferralEnabled poisons");
  XML_ParserFree(parser);

  parser = fresh("unsupported: amplification parser created");
  CHECK_EQ(XML_SetBillionLaughsAttackProtectionMaximumAmplification(parser, 1.0f),
           XML_FALSE, "unsupported: amplification maximum is refused");
  CHECK_EQ(XML_GetErrorCode(parser), 50, "unsupported: amplification maximum poisons");
  XML_ParserFree(parser);

  parser = fresh("unsupported: threshold parser created");
  CHECK_EQ(XML_SetBillionLaughsAttackProtectionActivationThreshold(parser, 1ull),
           XML_FALSE, "unsupported: amplification threshold is refused");
  CHECK_EQ(XML_GetErrorCode(parser), 50, "unsupported: amplification threshold poisons");
  XML_ParserFree(parser);

  parser = fresh("unsupported: alloc tracker parser created");
  CHECK_EQ(XML_SetAllocTrackerMaximumAmplification(parser, 1.0f), XML_FALSE,
           "unsupported: alloc tracker maximum is refused");
  CHECK_EQ(XML_GetErrorCode(parser), 50, "unsupported: alloc tracker maximum poisons");
  XML_ParserFree(parser);

  parser = fresh("unsupported: alloc threshold parser created");
  CHECK_EQ(XML_SetAllocTrackerActivationThreshold(parser, 1ull), XML_FALSE,
           "unsupported: alloc tracker threshold is refused");
  CHECK_EQ(XML_GetErrorCode(parser), 50, "unsupported: alloc tracker threshold poisons");
  XML_ParserFree(parser);

  parser = fresh("unsupported: memory parser created");
  CHECK(XML_MemMalloc(parser, 4) == NULL, "unsupported: MemMalloc is refused");
  CHECK_EQ(XML_GetErrorCode(parser), 50, "unsupported: MemMalloc poisons");
  XML_ParserFree(parser);

  parser = fresh("unsupported: realloc parser created");
  CHECK(XML_MemRealloc(parser, NULL, 4) == NULL, "unsupported: MemRealloc is refused");
  CHECK_EQ(XML_GetErrorCode(parser), 50, "unsupported: MemRealloc poisons");
  XML_ParserFree(parser);

  parser = fresh("unsupported: memfree parser created");
  XML_MemFree(parser, NULL);
  CHECK_EQ(XML_GetErrorCode(parser), 50, "unsupported: MemFree poisons");
  XML_ParserFree(parser);

  parser = fresh("unsupported: content model parser created");
  XML_FreeContentModel(parser, NULL);
  CHECK_EQ(XML_GetErrorCode(parser), 50, "unsupported: FreeContentModel poisons");
  XML_ParserFree(parser);

  parser = fresh("unsupported: default handler parser created");
  XML_SetDefaultHandler(parser, stub_default);
  expect_unsupported(parser, "unsupported: a default handler is refused");
  XML_ParserFree(parser);

  parser = fresh("unsupported: default expand parser created");
  XML_SetDefaultHandlerExpand(parser, stub_default);
  expect_unsupported(parser, "unsupported: an expanding default handler is refused");
  XML_ParserFree(parser);

  parser = fresh("unsupported: doctype parser created");
  XML_SetDoctypeDeclHandler(parser, stub_doctype_start, stub_doctype_end);
  expect_unsupported(parser, "unsupported: a DOCTYPE handler is refused");
  XML_ParserFree(parser);

  parser = fresh("unsupported: start doctype parser created");
  XML_SetStartDoctypeDeclHandler(parser, stub_doctype_start);
  expect_unsupported(parser, "unsupported: a start-DOCTYPE handler is refused");
  XML_ParserFree(parser);

  parser = fresh("unsupported: end doctype parser created");
  XML_SetEndDoctypeDeclHandler(parser, stub_doctype_end);
  expect_unsupported(parser, "unsupported: an end-DOCTYPE handler is refused");
  XML_ParserFree(parser);

  parser = fresh("unsupported: element decl parser created");
  XML_SetElementDeclHandler(parser, stub_element_decl);
  expect_unsupported(parser, "unsupported: an element declaration handler is refused");
  XML_ParserFree(parser);

  parser = fresh("unsupported: attlist parser created");
  XML_SetAttlistDeclHandler(parser, stub_attlist);
  expect_unsupported(parser, "unsupported: an attribute-list handler is refused");
  XML_ParserFree(parser);

  parser = fresh("unsupported: entity decl parser created");
  XML_SetEntityDeclHandler(parser, stub_entity);
  expect_unsupported(parser, "unsupported: an entity declaration handler is refused");
  XML_ParserFree(parser);

  parser = fresh("unsupported: unparsed entity parser created");
  XML_SetUnparsedEntityDeclHandler(parser, stub_unparsed);
  expect_unsupported(parser, "unsupported: an unparsed entity handler is refused");
  XML_ParserFree(parser);

  parser = fresh("unsupported: notation parser created");
  XML_SetNotationDeclHandler(parser, stub_notation);
  expect_unsupported(parser, "unsupported: a notation handler is refused");
  XML_ParserFree(parser);

  parser = fresh("unsupported: namespace pair parser created");
  XML_SetNamespaceDeclHandler(parser, stub_namespace_start, stub_namespace_end);
  expect_unsupported(parser, "unsupported: namespace handlers are refused");
  XML_ParserFree(parser);

  parser = fresh("unsupported: start namespace parser created");
  XML_SetStartNamespaceDeclHandler(parser, stub_namespace_start);
  expect_unsupported(parser, "unsupported: a start-namespace handler is refused");
  XML_ParserFree(parser);

  parser = fresh("unsupported: end namespace parser created");
  XML_SetEndNamespaceDeclHandler(parser, stub_namespace_end);
  expect_unsupported(parser, "unsupported: an end-namespace handler is refused");
  XML_ParserFree(parser);

  parser = fresh("unsupported: not standalone parser created");
  XML_SetNotStandaloneHandler(parser, stub_notstandalone);
  expect_unsupported(parser, "unsupported: a not-standalone handler is refused");
  XML_ParserFree(parser);

  parser = fresh("unsupported: external entity parser created");
  XML_SetExternalEntityRefHandler(parser, stub_external);
  expect_unsupported(parser, "unsupported: an external entity handler is refused");
  XML_ParserFree(parser);

  parser = fresh("unsupported: entity arg parser created");
  XML_SetExternalEntityRefHandlerArg(parser, &offset);
  expect_unsupported(parser, "unsupported: an external entity argument is refused");
  XML_ParserFree(parser);

  parser = fresh("unsupported: skipped entity parser created");
  XML_SetSkippedEntityHandler(parser, stub_skipped);
  expect_unsupported(parser, "unsupported: a skipped entity handler is refused");
  XML_ParserFree(parser);

  parser = fresh("unsupported: unknown encoding parser created");
  XML_SetUnknownEncodingHandler(parser, stub_unknown_encoding, &offset);
  expect_unsupported(parser, "unsupported: an unknown encoding handler is refused");
  XML_ParserFree(parser);

  parser = fresh("unsupported: parser-as-arg parser created");
  XML_UseParserAsHandlerArg(parser);
  CHECK_EQ(XML_GetErrorCode(parser), 50, "unsupported: UseParserAsHandlerArg poisons");
  XML_ParserFree(parser);

  parser = fresh("unsupported: return triplet parser created");
  XML_SetReturnNSTriplet(parser, 0);
  CHECK_EQ(XML_GetErrorCode(parser), XML_ERROR_NONE,
           "unsupported: disabling namespace triplets is harmless");
  XML_SetReturnNSTriplet(parser, 1);
  CHECK_EQ(XML_GetErrorCode(parser), 50,
           "unsupported: enabling namespace triplets poisons");
  XML_ParserFree(parser);

  /* Clearing any registered handler with NULL stays harmless. */
  parser = fresh("unsupported: clearing parser created");
  XML_SetDefaultHandler(parser, NULL);
  XML_SetDefaultHandlerExpand(parser, NULL);
  XML_SetDoctypeDeclHandler(parser, NULL, NULL);
  XML_SetStartDoctypeDeclHandler(parser, NULL);
  XML_SetEndDoctypeDeclHandler(parser, NULL);
  XML_SetElementDeclHandler(parser, NULL);
  XML_SetAttlistDeclHandler(parser, NULL);
  XML_SetEntityDeclHandler(parser, NULL);
  XML_SetUnparsedEntityDeclHandler(parser, NULL);
  XML_SetNotationDeclHandler(parser, NULL);
  XML_SetNamespaceDeclHandler(parser, NULL, NULL);
  XML_SetStartNamespaceDeclHandler(parser, NULL);
  XML_SetEndNamespaceDeclHandler(parser, NULL);
  XML_SetNotStandaloneHandler(parser, NULL);
  XML_SetExternalEntityRefHandler(parser, NULL);
  XML_SetExternalEntityRefHandlerArg(parser, NULL);
  XML_SetSkippedEntityHandler(parser, NULL);
  XML_SetUnknownEncodingHandler(parser, NULL, NULL);
  CHECK_EQ(XML_GetErrorCode(parser), XML_ERROR_NONE,
           "unsupported: clearing handlers does not poison");
  CHECK_EQ(XML_Parse(parser, "<r/>", 4, 1), XML_STATUS_OK,
           "unsupported: a cleared parser still parses");
  XML_ParserFree(parser);

  /* Parameter-entity timing matches the pinned header's contract. */
  {
    const char *prefix = "<r>";
    parser = fresh("unsupported: param entity parser created");
    CHECK_EQ(XML_SetParamEntityParsing(parser, XML_PARAM_ENTITY_PARSING_NEVER), 1,
             "unsupported: NEVER before parsing is accepted");
    CHECK_EQ(XML_Parse(parser, prefix, (int)strlen(prefix), 0), XML_STATUS_OK,
             "unsupported: prefix accepted");
    CHECK_EQ(XML_SetParamEntityParsing(parser, XML_PARAM_ENTITY_PARSING_NEVER), 0,
             "unsupported: NEVER after parsing started returns 0");
    CHECK_EQ(XML_GetErrorCode(parser), XML_ERROR_NONE,
             "unsupported: the post-start NEVER call has no effect");
    CHECK_EQ(XML_SetParamEntityParsing(parser, XML_PARAM_ENTITY_PARSING_ALWAYS), 0,
             "unsupported: ALWAYS after parsing started returns 0");
    CHECK_EQ(XML_GetErrorCode(parser), XML_ERROR_NONE,
             "unsupported: a post-start mode change cannot poison live state");
    CHECK_EQ(XML_Parse(parser, "</r>", 4, 1), XML_STATUS_OK,
             "unsupported: the live parser completes");
    CHECK_EQ(XML_SetParamEntityParsing(parser, XML_PARAM_ENTITY_PARSING_NEVER), 0,
             "unsupported: the setter returns 0 after finality");
    CHECK_EQ(XML_GetErrorCode(parser), XML_ERROR_NONE,
             "unsupported: post-finality setter keeps the terminal result");
    XML_ParserFree(parser);

    parser = fresh("unsupported: param entity before parser created");
    CHECK_EQ(XML_SetParamEntityParsing(parser, XML_PARAM_ENTITY_PARSING_ALWAYS), 0,
             "unsupported: ALWAYS before parsing is refused");
    CHECK_EQ(XML_GetErrorCode(parser), 50, "unsupported: ALWAYS poisons");
    XML_ParserFree(parser);

    parser = fresh("unsupported: param entity unless parser created");
    CHECK_EQ(XML_SetParamEntityParsing(parser, XML_PARAM_ENTITY_PARSING_UNLESS_STANDALONE),
             0, "unsupported: UNLESS_STANDALONE is refused");
    CHECK_EQ(XML_GetErrorCode(parser), 50, "unsupported: UNLESS_STANDALONE poisons");
    XML_ParserFree(parser);

    CHECK_EQ(XML_SetParamEntityParsing(NULL, XML_PARAM_ENTITY_PARSING_NEVER), 0,
             "unsupported: a NULL parser returns 0");
  }

  /* DTD input is refused before any identifier is read; raw namespace names
   * are accepted as ordinary qualified names and the namespace-aware parser is
   * still refused. No resolver exists, so no system identifier is loaded. */
  parser = fresh("unsupported: DTD input parser created");
  CHECK_EQ(XML_Parse(parser, "<!DOCTYPE r [<!ENTITY e \"x\">]><r>&e;</r>", 40, 1),
           XML_STATUS_ERROR, "unsupported: DTD input is rejected");
  CHECK_EQ(XML_GetErrorCode(parser), 45, "unsupported: DTD input reports UNSUPPORTED_DTD");
  XML_ParserFree(parser);

  parser = fresh("unsupported: unknown encoding input parser created");
  CHECK_EQ(XML_Parse(parser,
                     "<?xml version=\"1.0\" encoding=\"KLINGON\"?><a/>", 44, 1),
           XML_STATUS_ERROR, "unsupported: an unknown encoding label is rejected");
  CHECK_EQ(XML_GetErrorCode(parser), XML_ERROR_UNKNOWN_ENCODING,
           "unsupported: unknown encoding is a standard error code");
  XML_ParserFree(parser);

  parser = fresh("unsupported: raw namespace parser created");
  CHECK_EQ(XML_Parse(parser, "<p:a xmlns:p=\"u\" p:b=\"v\"/>", 26, 1), XML_STATUS_OK,
           "unsupported: qualified names parse as raw names");
  XML_ParserFree(parser);

  /* Printed so a caller that reuses this group as a verification command can
   * read the numeric refusal code it observed, not only the assertions. */
  printf("unsupported: refusals report code %d (XML_ERROR_UNSUPPORTED_FEATURE); "
         "ExternalEntityParserCreate returns NULL\n",
         (int)XML_ERROR_UNSUPPORTED_FEATURE);
  report("unsupported");
}

/* ------------------------------------------------------------------ */
/* adversarial                                                         */

typedef struct {
  XML_Parser parser;
  XML_Parser other;
  int mode;
  int same_status;
  int other_status;
  int same_code;
  int other_code;
  int ends;
} Threat;

static void XMLCALL threat_start(void *userData, const XML_Char *name,
                                 const XML_Char **atts) {
  Threat *threat = (Threat *)userData;
  (void)name;
  (void)atts;
  if (threat->mode == 1) {
    threat->same_status = (int)XML_Parse(threat->parser, "<x/>", 4, 0);
    threat->same_code = (int)XML_GetErrorCode(threat->parser);
  } else if (threat->mode == 2) {
    threat->other_status = (int)XML_Parse(threat->other, "<x/>", 4, 0);
    threat->other_code = (int)XML_GetErrorCode(threat->other);
  } else if (threat->mode == 3) {
    XML_ParserFree(threat->parser);
  }
}

static void XMLCALL threat_end(void *userData, const XML_Char *name) {
  Threat *threat = (Threat *)userData;
  (void)name;
  threat->ends++;
}

typedef struct {
  XML_Parser created;
  int create_calls;
} CreateProbe;

static void XMLCALL create_probe_start(void *userData, const XML_Char *name,
                                       const XML_Char **atts) {
  CreateProbe *probe = (CreateProbe *)userData;
  (void)name;
  (void)atts;
  probe->create_calls++;
  if (probe->created == NULL)
    probe->created = XML_ParserCreate(NULL);
}

static void group_adversarial(void) {
  XML_Parser parser;
  int sentinel = 7;

  CHECK_EQ(XML_GetCurrentByteIndex(NULL), -1, "adversarial: NULL byte index");
  CHECK_EQ(XML_GetCurrentLineNumber(NULL), 0, "adversarial: NULL line");
  CHECK_EQ(XML_GetCurrentColumnNumber(NULL), 0, "adversarial: NULL column");
  CHECK_EQ(XML_GetSpecifiedAttributeCount(NULL), -1, "adversarial: NULL attribute count");
  CHECK_EQ(XML_GetIdAttributeIndex(NULL), -1, "adversarial: NULL ID index");
  CHECK_EQ(XML_Parse(NULL, "<r/>", 4, 1), XML_STATUS_ERROR,
           "adversarial: NULL parser parse is refused");
  CHECK(XML_GetBuffer(NULL, 1) == NULL, "adversarial: NULL parser GetBuffer");
  CHECK_EQ(XML_ParseBuffer(NULL, 0, 1), XML_STATUS_ERROR,
           "adversarial: NULL parser ParseBuffer");
  CHECK_EQ(XML_SetEncoding(NULL, "UTF-8"), XML_STATUS_ERROR,
           "adversarial: NULL parser SetEncoding");
  CHECK_EQ(XML_SetBase(NULL, "/"), XML_STATUS_ERROR, "adversarial: NULL parser SetBase");
  CHECK(XML_GetBase(NULL) == NULL, "adversarial: NULL parser GetBase");
  CHECK_EQ(XML_UseForeignDTD(NULL, XML_TRUE), XML_ERROR_INVALID_ARGUMENT,
           "adversarial: NULL parser UseForeignDTD");
  CHECK_EQ(XML_StopParser(NULL, XML_TRUE), XML_STATUS_ERROR,
           "adversarial: NULL parser StopParser");
  CHECK_EQ(XML_ResumeParser(NULL), XML_STATUS_ERROR,
           "adversarial: NULL parser ResumeParser");
  XML_DefaultCurrent(NULL);
  CHECK(XML_GetInputContext(NULL, NULL, NULL) == NULL,
        "adversarial: NULL parser GetInputContext");
  CHECK_EQ(XML_GetCurrentByteCount(NULL), -1, "adversarial: NULL parser byte count");
  CHECK_EQ(XML_SetHashSalt(NULL, 1), 0, "adversarial: NULL parser SetHashSalt");
  CHECK(XML_MemMalloc(NULL, 1) == NULL, "adversarial: NULL parser MemMalloc");
  CHECK(XML_MemRealloc(NULL, NULL, 1) == NULL, "adversarial: NULL parser MemRealloc");
  XML_MemFree(NULL, NULL);
  XML_FreeContentModel(NULL, NULL);
  CHECK_EQ(XML_ParserReset(NULL, NULL), XML_FALSE, "adversarial: NULL parser reset");
  XML_SetUserData(NULL, &sentinel);
  XML_SetElementHandler(NULL, NULL, NULL);
  XML_SetCharacterDataHandler(NULL, NULL);
  XML_ParserFree(NULL);

  /* Invalid lengths on a live parser. */
  parser = fresh("adversarial: length parser created");
  CHECK_EQ(XML_Parse(parser, NULL, 1, 1), XML_STATUS_ERROR,
           "adversarial: NULL bytes with a positive length are refused");
  CHECK_EQ(XML_GetErrorCode(parser), XML_ERROR_INVALID_ARGUMENT,
           "adversarial: NULL bytes with a length is an invalid argument");
  XML_ParserFree(parser);

  parser = fresh("adversarial: negative parser created");
  CHECK_EQ(XML_Parse(parser, "", -1, 1), XML_STATUS_ERROR,
           "adversarial: a negative length is refused");
  CHECK_EQ(XML_GetErrorCode(parser), XML_ERROR_INVALID_ARGUMENT,
           "adversarial: a negative length is an invalid argument");
  XML_ParserFree(parser);

  parser = fresh("adversarial: huge length parser created");
  CHECK_EQ(XML_Parse(parser, "", INT_MAX, 1), XML_STATUS_ERROR,
           "adversarial: an INT_MAX length is refused before reading");
  CHECK_EQ(XML_GetErrorCode(parser), 46,
           "adversarial: an INT_MAX length reports the input budget");
  XML_ParserFree(parser);

  parser = fresh("adversarial: status pointer parser created");
  XML_GetParsingStatus(parser, NULL);
  CHECK_EQ(XML_GetErrorCode(parser), XML_ERROR_INVALID_ARGUMENT,
           "adversarial: a NULL status pointer is refused");
  XML_ParserFree(parser);

  /* Re-entrant parse attempts during a callback. */
  {
    Threat threat;
    memset(&threat, 0, sizeof(threat));
    parser = fresh("adversarial: same-parser threat created");
    threat.parser = parser;
    threat.mode = 1;
    XML_SetUserData(parser, &threat);
    XML_SetElementHandler(parser, threat_start, threat_end);
    CHECK_EQ(XML_Parse(parser, "<r/>", 4, 1), XML_STATUS_ERROR,
             "adversarial: a same-parser re-entrant parse fails the outer call");
    CHECK_EQ(XML_GetErrorCode(parser), 52,
             "adversarial: a same-parser re-entrant parse reports REENTRANT_CALL");
    CHECK_EQ(threat.same_status, XML_STATUS_ERROR,
             "adversarial: the inner same-parser call is refused");
    CHECK_EQ(threat.same_code, 52,
             "adversarial: the inner same-parser call reports REENTRANT_CALL");
    XML_ParserFree(parser);

    memset(&threat, 0, sizeof(threat));
    parser = fresh("adversarial: cross-parser threat created");
    threat.parser = parser;
    threat.other = fresh("adversarial: other parser created");
    threat.mode = 2;
    XML_SetUserData(parser, &threat);
    XML_SetElementHandler(parser, threat_start, threat_end);
    CHECK_EQ(XML_Parse(parser, "<r/>", 4, 1), XML_STATUS_OK,
             "adversarial: the outer parse is unaffected");
    CHECK_EQ(threat.other_status, XML_STATUS_ERROR,
             "adversarial: the cross-parser call is refused");
    CHECK_EQ(threat.other_code, 52,
             "adversarial: the cross-parser call reports REENTRANT_CALL");
    XML_ParserFree(threat.other);
    XML_ParserFree(parser);
  }

  /* The same end detector records ends in a control parse. */
  {
    Threat control;
    memset(&control, 0, sizeof(control));
    parser = fresh("adversarial: end detector control parser created");
    control.parser = parser;
    XML_SetUserData(parser, &control);
    XML_SetElementHandler(parser, threat_start, threat_end);
    CHECK_EQ(XML_Parse(parser, "<r><c/></r>", 11, 1), XML_STATUS_OK,
             "adversarial: the end detector control parse succeeds");
    CHECK_EQ(control.ends, 2,
             "adversarial: the same end detector records both ends in its control");
    XML_ParserFree(parser);
  }

  /* Freeing the parser from its own callback defers the release. */
  {
    Threat threat;
    memset(&threat, 0, sizeof(threat));
    parser = fresh("adversarial: free-in-callback parser created");
    threat.parser = parser;
    threat.mode = 3;
    XML_SetUserData(parser, &threat);
    XML_SetElementHandler(parser, threat_start, threat_end);
    CHECK_EQ(XML_Parse(parser, "<r><c/></r>", 11, 1), XML_STATUS_ERROR,
             "adversarial: a parse whose callback frees the parser fails");
    CHECK_EQ(threat.ends, 0,
             "adversarial: no callback follows a free inside a callback");
    CHECK_EQ(XML_GetErrorCode(parser), XML_ERROR_INVALID_ARGUMENT,
             "adversarial: the released handle is registry-checked");
    XML_ParserFree(parser);
  }

  /* XML_ParserCreate is supported inside a callback. It creates an independent
   * parser, usable once the outer call has returned. */
  {
    CreateProbe probe;
    memset(&probe, 0, sizeof(probe));
    parser = fresh("adversarial: callback-create parser created");
    XML_SetUserData(parser, &probe);
    XML_SetStartElementHandler(parser, create_probe_start);
    CHECK_EQ(XML_Parse(parser, "<r/>", 4, 1), XML_STATUS_OK,
             "adversarial: the outer parse completes after callback creation");
    CHECK_EQ(probe.create_calls, 1, "adversarial: the creating callback ran once");
    CHECK(probe.created != NULL,
          "adversarial: XML_ParserCreate succeeds inside a callback");
    XML_ParserFree(parser);
    if (probe.created != NULL) {
      Counts counts = {0, 0, NULL, 0, 0, 0};
      counts.expected_user = &counts;
      XML_SetUserData(probe.created, &counts);
      XML_SetElementHandler(probe.created, count_start, count_end);
      counts.parse_active = 1;
      CHECK_EQ(XML_Parse(probe.created, "<x/>", 4, 1), XML_STATUS_OK,
               "adversarial: the callback-created parser parses after the outer call");
      counts.parse_active = 0;
      CHECK_EQ(counts.starts, 1,
               "adversarial: the callback-created parser delivers a start");
      CHECK_EQ(counts.ends, 1,
               "adversarial: the callback-created parser delivers an end");
      XML_ParserFree(probe.created);
    }
  }

  /* Clearing a supported handler with NULL disables it. */
  {
    Counts counts = {0, 0, NULL, 0, 0, 0};
    parser = fresh("adversarial: clearing parser created");
    XML_SetElementHandler(parser, count_start, count_end);
    XML_SetUserData(parser, &counts);
    counts.parse_active = 1;
    CHECK_EQ(XML_Parse(parser, "<r/>", 4, 1), XML_STATUS_OK,
             "adversarial: registered handler parses");
    counts.parse_active = 0;
    CHECK_EQ(counts.starts, 1, "adversarial: registered start observed");
    XML_ParserFree(parser);

    counts.starts = counts.ends = 0;
    parser = fresh("adversarial: cleared parser created");
    XML_SetElementHandler(parser, NULL, NULL);
    XML_SetCharacterDataHandler(parser, NULL);
    XML_SetUserData(parser, &counts);
    counts.parse_active = 1;
    CHECK_EQ(XML_Parse(parser, "<r/>", 4, 1), XML_STATUS_OK,
             "adversarial: a cleared parser parses");
    counts.parse_active = 0;
    CHECK_EQ(counts.starts + counts.ends, 0,
             "adversarial: a cleared handler receives no callbacks");
    XML_ParserFree(parser);
  }

  report("adversarial");
}

/* ------------------------------------------------------------------ */
/* identity                                                            */

static void group_identity(void) {
  const XML_Feature *features;
  int saw_char = 0;
  int saw_lchar = 0;
  int terminated = 0;
  int forbidden = 0;

  CHECK_STR(XML_ExpatVersion(), "lexpat_0.1.0-cabi1",
            "identity: the version string names lexpat truthfully");
  {
    XML_Expat_Version version = XML_ExpatVersionInfo();
    CHECK_EQ(version.major, 0, "identity: version major");
    CHECK_EQ(version.minor, 1, "identity: version minor");
    CHECK_EQ(version.micro, 0, "identity: version micro");
    CHECK_EQ(XML_MAJOR_VERSION, version.major, "identity: compile-time major");
    CHECK_EQ(XML_MINOR_VERSION, version.minor, "identity: compile-time minor");
    CHECK_EQ(XML_MICRO_VERSION, version.micro, "identity: compile-time micro");
  }
  features = XML_GetFeatureList();
  CHECK(features != NULL, "identity: a feature list exists");
  if (features != NULL) {
    const XML_Feature *feature;
    for (feature = features; feature->feature != XML_FEATURE_END; feature++) {
      if (feature->feature == XML_FEATURE_SIZEOF_XML_CHAR) {
        saw_char = 1;
        CHECK_EQ(feature->value, 1, "identity: XML_Char is one byte");
      } else if (feature->feature == XML_FEATURE_SIZEOF_XML_LCHAR) {
        saw_lchar = 1;
        CHECK_EQ(feature->value, 1, "identity: XML_LChar is one byte");
      } else if (feature->feature == XML_FEATURE_DTD
                 || feature->feature == XML_FEATURE_NS
                 || feature->feature == XML_FEATURE_GE
                 || feature->feature == XML_FEATURE_CONTEXT_BYTES
                 || feature->feature == XML_FEATURE_UNICODE
                 || feature->feature == XML_FEATURE_LARGE_SIZE
                 || feature->feature == XML_FEATURE_ATTR_INFO) {
        forbidden = 1;
      }
      CHECK(feature->name != NULL, "identity: feature entries are named");
    }
    terminated = features[0].feature != XML_FEATURE_END;
  }
  CHECK(saw_char && saw_lchar, "identity: size features are reported");
  CHECK(terminated, "identity: the feature list is not empty");
  CHECK(!forbidden, "identity: no unsupported feature is advertised");
  report("identity");
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <lifecycle|buffers|errors|locations|unsupported|adversarial|identity>\n",
            argv[0]);
    return 2;
  }
  if (strcmp(argv[1], "lifecycle") == 0)
    group_lifecycle();
  else if (strcmp(argv[1], "buffers") == 0)
    group_buffers();
  else if (strcmp(argv[1], "errors") == 0)
    group_errors();
  else if (strcmp(argv[1], "locations") == 0)
    group_locations();
  else if (strcmp(argv[1], "unsupported") == 0)
    group_unsupported();
  else if (strcmp(argv[1], "adversarial") == 0)
    group_adversarial();
  else if (strcmp(argv[1], "identity") == 0)
    group_identity();
  else {
    fprintf(stderr, "%s: unknown group %s\n", argv[0], argv[1]);
    return 2;
  }
  return 0;
}
"""

BRIDGE_SOURCE = r"""/*
 * Direct-bridge checks. This program links the C shim and the Lean module
 * objects directly into a test executable; it is a test target, not a shared
 * object and not an exported bypass. From inside a registered callback it
 * calls the same callback-specific receivers the Lean producer calls, with
 * fabricated Lean objects, and asserts the parser's error state and handler
 * calls.
 *
 * The control set covers: a well-formed text span, start, end, comment,
 * processing instruction, CDATA and declaration delivered to real handlers; a
 * span whose bounds are inverted, past the owner, past the bytes already fed,
 * or whose position is impossible; payloads that are not legal UTF-8; a NUL in
 * a text payload; an impossible standalone value; an allocation failure; and
 * the absence of any payload allocation when no handler is installed.
 */

#include "expat.h"
#include <lean/lean.h>

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern uint64_t lexpat_cabi_emit_xml_decl(lean_object *version, lean_object *encoding,
                                          uint8_t has_encoding, int64_t standalone,
                                          uint64_t offset, uint64_t line,
                                          uint64_t column);
extern uint64_t lexpat_cabi_emit_start(lean_object *name, lean_object *attrs,
                                       uint64_t offset, uint64_t line,
                                       uint64_t column);
extern uint64_t lexpat_cabi_emit_end(lean_object *name, uint64_t offset, uint64_t line,
                                     uint64_t column);
extern uint64_t lexpat_cabi_emit_text(lean_object *owner, uint64_t start, uint64_t stop,
                                      uint64_t base, uint64_t offset, uint64_t line,
                                      uint64_t column);
extern uint64_t lexpat_cabi_emit_text_string(lean_object *data, uint64_t offset,
                                             uint64_t line, uint64_t column);
extern uint64_t lexpat_cabi_emit_text_bytes(lean_object *data, uint64_t offset,
                                            uint64_t line, uint64_t column);
extern uint64_t lexpat_cabi_emit_cdata_start(uint64_t offset, uint64_t line,
                                             uint64_t column);
extern uint64_t lexpat_cabi_emit_cdata_end(uint64_t offset, uint64_t line,
                                           uint64_t column);
extern uint64_t lexpat_cabi_emit_comment(lean_object *data, uint64_t offset,
                                         uint64_t line, uint64_t column);
extern uint64_t lexpat_cabi_emit_pi(lean_object *target, lean_object *data,
                                    uint64_t offset, uint64_t line, uint64_t column);

/* The shim copies callback payloads with malloc/calloc. Wrapping those two
 * symbols counts the linked shim's allocations only. A countdown armed before
 * an injection makes that one allocation fail. */
static int counting;
static long allocations;
static int fail_malloc_countdown = -1;

void *__real_malloc(size_t size);
void *__real_calloc(size_t count, size_t size);

void *__wrap_malloc(size_t size) {
  if (counting)
    allocations++;
  if (fail_malloc_countdown == 0) {
    fail_malloc_countdown = -1;
    return NULL;
  }
  if (fail_malloc_countdown > 0)
    fail_malloc_countdown--;
  return __real_malloc(size);
}

void *__wrap_calloc(size_t count, size_t size) {
  if (counting)
    allocations++;
  if (fail_malloc_countdown == 0) {
    fail_malloc_countdown = -1;
    return NULL;
  }
  if (fail_malloc_countdown > 0)
    fail_malloc_countdown--;
  return __real_calloc(count, size);
}

static XML_Parser P;
static int injecting;
static int triggered;
static long calls;
static long pairs;
static long chars;
static uint64_t last_emit;
static int last_code;
static int pending_case;

static void XMLCALL on_start(void *userData, const XML_Char *name,
                             const XML_Char **atts);
static uint64_t inject_case(int which);

static void trigger(void) {
  triggered = 1;
  calls = 0;
  pairs = 0;
  chars = 0;
  injecting = 1;
  last_emit = inject_case(pending_case);
  injecting = 0;
  last_code = (int)XML_GetErrorCode(P);
}

static void XMLCALL on_start(void *userData, const XML_Char *name,
                             const XML_Char **atts) {
  (void)userData;
  (void)name;
  if (!injecting) {
    if (!triggered)
      trigger();
    return;
  }
  calls++;
  if (atts != NULL) {
    long entries = 0;
    while (atts[entries] != NULL)
      entries++;
    pairs = entries / 2;
  }
}

static void XMLCALL on_end(void *userData, const XML_Char *name) {
  (void)userData;
  (void)name;
  if (injecting)
    calls++;
}

static void XMLCALL on_text(void *userData, const XML_Char *data, int length) {
  (void)userData;
  (void)data;
  if (injecting) {
    calls++;
    chars += length;
  }
}

static void XMLCALL on_comment(void *userData, const XML_Char *data) {
  (void)userData;
  (void)data;
  if (injecting)
    calls++;
}

static void XMLCALL on_pi(void *userData, const XML_Char *target,
                          const XML_Char *data) {
  (void)userData;
  (void)target;
  (void)data;
  if (injecting)
    calls++;
}

static void XMLCALL on_decl(void *userData, const XML_Char *version,
                            const XML_Char *encoding, int standalone) {
  (void)userData;
  (void)version;
  (void)encoding;
  (void)standalone;
  if (injecting)
    calls++;
}

static void XMLCALL on_cdata_start(void *userData) {
  (void)userData;
  if (injecting)
    calls++;
}

static void XMLCALL on_cdata_end(void *userData) {
  (void)userData;
  if (injecting)
    calls++;
}

/* Fabricated Lean objects: the receivers own whatever they are handed. */
static lean_object *mk_bytes(const unsigned char *data, size_t size) {
  lean_object *array = lean_alloc_sarray(1, size, size);
  if (size > 0)
    memcpy(lean_sarray_cptr(array), data, size);
  return array;
}

static lean_object *mk_string(const unsigned char *data, size_t size) {
  return lean_mk_string_from_bytes_unchecked((const char *)data, size);
}

static lean_object *mk_attrs(lean_object *name, lean_object *value) {
  lean_object *array = lean_alloc_array(1, 1);
  lean_object *pair = lean_alloc_ctor(0, 2, 0);
  lean_ctor_set(pair, 0, name);
  lean_ctor_set(pair, 1, value);
  lean_array_set_core(array, 0, pair);
  return array;
}

static const unsigned char GOOD[] = "hi";
static const unsigned char BAD_UTF8[] = {0xC0, 0x80};
static const unsigned char WITH_NUL[] = {'a', 0x00, 'b'};

static uint64_t inject_case(int which) {
  switch (which) {
  case 0: /* affirmative: a well-formed text span reaches the text handler */
    return lexpat_cabi_emit_text(mk_bytes(GOOD, 2), 0, 2, 0, 0, 1, 0);
  case 1: /* affirmative: a start tag with one ordered attribute pair */
    return lexpat_cabi_emit_start(mk_string((const unsigned char *)"x", 1),
                                  mk_attrs(mk_string((const unsigned char *)"a", 1),
                                           mk_string((const unsigned char *)"1", 1)),
                                  0, 1, 0);
  case 2: /* affirmative: an end tag */
    return lexpat_cabi_emit_end(mk_string((const unsigned char *)"x", 1), 0, 1, 0);
  case 3: /* affirmative: a comment */
    return lexpat_cabi_emit_comment(mk_string((const unsigned char *)"c", 1), 1, 1, 0);
  case 4: /* affirmative: a processing instruction */
    return lexpat_cabi_emit_pi(mk_string((const unsigned char *)"p", 1),
                               mk_string((const unsigned char *)"d", 1), 1, 1, 0);
  case 5: /* affirmative: CDATA start and end */
    if (lexpat_cabi_emit_cdata_start(0, 1, 0) != 0)
      return 1;
    return lexpat_cabi_emit_cdata_end(2, 1, 0);
  case 6: /* affirmative: a declaration */
    return lexpat_cabi_emit_xml_decl(mk_string((const unsigned char *)"1.0", 3),
                                     mk_string((const unsigned char *)"UTF-8", 5), 1,
                                     0, 0, 1, 0);
  case 7: /* affirmative: materialized character data */
    return lexpat_cabi_emit_text_string(mk_string(GOOD, 2), 1, 1, 0);
  case 8: /* inverted span */
    return lexpat_cabi_emit_text(mk_bytes(GOOD, 2), 2, 1, 0, 0, 1, 0);
  case 9: /* span past the owner */
    return lexpat_cabi_emit_text(mk_bytes(GOOD, 2), 0, 3, 0, 0, 1, 0);
  case 10: /* span whose absolute end is past the bytes fed */
    return lexpat_cabi_emit_text(mk_bytes(GOOD, 2), 0, 2, 3, 0, 1, 0);
  case 11: /* offset at the fed boundary */
    return lexpat_cabi_emit_text(mk_bytes(GOOD, 2), 0, 2, 0, 4, 1, 0);
  case 12: /* line numbers are 1-based */
    return lexpat_cabi_emit_text(mk_bytes(GOOD, 2), 0, 2, 0, 0, 0, 0);
  case 13: /* a column cannot pass the fed byte count */
    return lexpat_cabi_emit_text(mk_bytes(GOOD, 2), 0, 2, 0, 0, 1, 5);
  case 14: /* a base that would overflow the absolute offset */
    return lexpat_cabi_emit_text(mk_bytes(GOOD, 2), 1, 2, UINT64_MAX, 0, 1, 0);
  case 15: /* invalid UTF-8 in a borrowed span */
    return lexpat_cabi_emit_text(mk_bytes(BAD_UTF8, 2), 0, 2, 0, 0, 1, 0);
  case 16: /* a NUL inside a borrowed span */
    return lexpat_cabi_emit_text(mk_bytes(WITH_NUL, 3), 0, 3, 0, 0, 1, 0);
  case 17: /* invalid UTF-8 in a materialized payload */
    return lexpat_cabi_emit_text_string(mk_string(BAD_UTF8, 2), 1, 1, 0);
  case 18: /* invalid UTF-8 in an element name */
    return lexpat_cabi_emit_start(mk_string(BAD_UTF8, 2), lean_alloc_array(0, 0), 0, 1,
                                  0);
  case 19: /* invalid UTF-8 in an attribute value */
    return lexpat_cabi_emit_start(mk_string((const unsigned char *)"x", 1),
                                  mk_attrs(mk_string((const unsigned char *)"a", 1),
                                           mk_string(BAD_UTF8, 2)),
                                  0, 1, 0);
  case 20: /* a payload allocation failure */
    fail_malloc_countdown = 0;
    return lexpat_cabi_emit_start(mk_string((const unsigned char *)"x", 1),
                                  lean_alloc_array(0, 0), 0, 1, 0);
  case 21: /* CDATA start at the fed boundary */
    return lexpat_cabi_emit_cdata_start(4, 1, 0);
  case 22: /* an impossible standalone value */
    return lexpat_cabi_emit_xml_decl(mk_string((const unsigned char *)"1.0", 3),
                                     lean_mk_string(""), 0, 2, 0, 1, 0);
  case 23: /* invalid UTF-8 in a declaration encoding */
    return lexpat_cabi_emit_xml_decl(mk_string((const unsigned char *)"1.0", 3),
                                     mk_string(BAD_UTF8, 2), 1, -1, 0, 1, 0);
  case 24: /* affirmative: materialized character data held as owned bytes */
    return lexpat_cabi_emit_text_bytes(mk_bytes(GOOD, 2), 1, 1, 0);
  case 25: /* invalid UTF-8 in an owned byte payload */
    return lexpat_cabi_emit_text_bytes(mk_bytes(BAD_UTF8, 2), 1, 1, 0);
  case 26: /* a NUL inside an owned byte payload */
    return lexpat_cabi_emit_text_bytes(mk_bytes(WITH_NUL, 3), 1, 1, 0);
  default:
    return 0xFFFFFFFFu;
  }
}

/* Expectations per case. `code` is the parser error after the injection. */
typedef struct {
  int emit;
  int code;
  long calls;
  long pairs;
  long chars;
} Expect;

static const Expect EXPECTATIONS[] = {
    [0] = {0, XML_ERROR_NONE, 1, 0, 2},
    [1] = {0, XML_ERROR_NONE, 1, 1, 0},
    [2] = {0, XML_ERROR_NONE, 1, 0, 0},
    [3] = {0, XML_ERROR_NONE, 1, 0, 0},
    [4] = {0, XML_ERROR_NONE, 1, 0, 0},
    [5] = {0, XML_ERROR_NONE, 2, 0, 0},
    [6] = {0, XML_ERROR_NONE, 1, 0, 0},
    [7] = {0, XML_ERROR_NONE, 1, 0, 2},
    [8] = {1, XML_ERROR_MALFORMED_WIRE, 0, 0, 0},
    [9] = {1, XML_ERROR_MALFORMED_WIRE, 0, 0, 0},
    [10] = {1, XML_ERROR_MALFORMED_WIRE, 0, 0, 0},
    [11] = {1, XML_ERROR_MALFORMED_WIRE, 0, 0, 0},
    [12] = {1, XML_ERROR_MALFORMED_WIRE, 0, 0, 0},
    [13] = {1, XML_ERROR_MALFORMED_WIRE, 0, 0, 0},
    [14] = {1, XML_ERROR_MALFORMED_WIRE, 0, 0, 0},
    [15] = {1, XML_ERROR_MALFORMED_WIRE, 0, 0, 0},
    [16] = {1, XML_ERROR_MALFORMED_WIRE, 0, 0, 0},
    [17] = {1, XML_ERROR_MALFORMED_WIRE, 0, 0, 0},
    [18] = {1, XML_ERROR_MALFORMED_WIRE, 0, 0, 0},
    [19] = {1, XML_ERROR_MALFORMED_WIRE, 0, 0, 0},
    [20] = {1, XML_ERROR_NO_MEMORY, 0, 0, 0},
    [21] = {1, XML_ERROR_MALFORMED_WIRE, 0, 0, 0},
    [22] = {1, XML_ERROR_MALFORMED_WIRE, 0, 0, 0},
    [23] = {1, XML_ERROR_MALFORMED_WIRE, 0, 0, 0},
    [24] = {0, XML_ERROR_NONE, 1, 0, 2},
    [25] = {1, XML_ERROR_MALFORMED_WIRE, 0, 0, 0},
    [26] = {1, XML_ERROR_MALFORMED_WIRE, 0, 0, 0},
};

/* Every event kind with no handler first, then with all handlers: the first
 * parse must not allocate any payload copy, the second is the affirmative
 * control that the counter sees the receiver's copies at all. */
static int check_unhandled_allocations(void) {
  static const char document[] =
      "<?xml version=\"1.0\"?><!--c--><?pi d?><r a=\"1\"><s><![CDATA[x]]></s></r>";
  int failures = 0;
  XML_Parser parser = XML_ParserCreate(NULL);
  if (parser == NULL) {
    fputs("bridge: cannot create a parser\n", stderr);
    return 1;
  }
  counting = 1;
  allocations = 0;
  enum XML_Status status = XML_Parse(parser, document, (int)strlen(document), 1);
  counting = 0;
  long unhandled = allocations;
  if (status != XML_STATUS_OK || unhandled != 0) {
    fprintf(stderr, "bridge: unhandled events allocated %ld payload copies (status %d)\n",
            unhandled, (int)status);
    failures++;
  }
  XML_ParserFree(parser);

  parser = XML_ParserCreate(NULL);
  if (parser == NULL) {
    fputs("bridge: cannot create a parser\n", stderr);
    return failures + 1;
  }
  triggered = 1; /* do not inject during this control */
  injecting = 1; /* count every callback the control document produces */
  XML_SetElementHandler(parser, on_start, on_end);
  XML_SetCharacterDataHandler(parser, on_text);
  XML_SetCommentHandler(parser, on_comment);
  XML_SetProcessingInstructionHandler(parser, on_pi);
  XML_SetXmlDeclHandler(parser, on_decl);
  XML_SetCdataSectionHandler(parser, on_cdata_start, on_cdata_end);
  calls = 0;
  counting = 1;
  allocations = 0;
  status = XML_Parse(parser, document, (int)strlen(document), 1);
  counting = 0;
  injecting = 0;
  if (status != XML_STATUS_OK || allocations == 0 || calls == 0) {
    fprintf(stderr,
            "bridge: handler control saw %ld allocations and %ld callbacks (status %d)\n",
            allocations, calls, (int)status);
    failures++;
  }
  printf("bridge: unhandled events allocated %ld payload copies; handler control "
         "allocated %ld\n", unhandled, allocations);
  XML_ParserFree(parser);
  return failures;
}

int main(void) {
  int failures = 0;
  size_t count = sizeof(EXPECTATIONS) / sizeof(EXPECTATIONS[0]);
  for (pending_case = 0; (size_t)pending_case < count; pending_case++) {
    const Expect *want = &EXPECTATIONS[pending_case];
    enum XML_Status want_status =
        want->code == XML_ERROR_NONE ? XML_STATUS_OK : XML_STATUS_ERROR;
    P = XML_ParserCreate(NULL);
    if (P == NULL) {
      fputs("bridge: cannot create a parser\n", stderr);
      return 2;
    }
    triggered = 0;
    injecting = 0;
    calls = 0;
    pairs = 0;
    chars = 0;
    last_emit = 0xFFFFFFFFu;
    last_code = -1;
    XML_SetElementHandler(P, on_start, on_end);
    XML_SetCharacterDataHandler(P, on_text);
    XML_SetCommentHandler(P, on_comment);
    XML_SetProcessingInstructionHandler(P, on_pi);
    XML_SetXmlDeclHandler(P, on_decl);
    XML_SetCdataSectionHandler(P, on_cdata_start, on_cdata_end);
    enum XML_Status status = XML_Parse(P, "<r/>", 4, 1);
    if (status != want_status || last_code != want->code ||
        last_emit != (uint64_t)want->emit || calls != want->calls ||
        pairs != want->pairs || chars != want->chars) {
      fprintf(stderr,
              "bridge: case %d failed (status %d/%d code %d/%d emit %" PRIu64
              "/%d calls %ld/%ld pairs %ld/%ld chars %ld/%ld)\n",
              pending_case, (int)status, (int)want_status, last_code, want->code,
              last_emit, want->emit, calls, want->calls, pairs, want->pairs, chars,
              want->chars);
      failures++;
    }
    XML_ParserFree(P);
  }

  /* Outside a parse there is no current parser: a receiver must refuse without
   * touching one. */
  if (lexpat_cabi_emit_text(mk_bytes(GOOD, 2), 0, 2, 0, 0, 1, 0) != 1) {
    fputs("bridge: a receiver without a current parser did not refuse\n", stderr);
    failures++;
  }

  failures += check_unhandled_allocations();
  if (failures != 0) {
    fprintf(stderr, "verify: bridge: %d checks failed\n", failures);
    return 1;
  }
  printf("PASS bridge (%zu direct receiver controls; malformed spans and payloads "
         "refuse before any callback, shim allocation failures report NO_MEMORY, "
         "a receiver without a parser does nothing, unhandled events allocate no "
         "payload copy)\n", count);
  return 0;
}
"""


# ---------------------------------------------------------------------------
# C probes compiled by the header, layout and ABI groups.


LAYOUT_SOURCE = r"""
#include <expat.h>
#include <stdio.h>
#include <stddef.h>

#define SHOW(expression) printf("%s %ld\n", #expression, (long)(expression))

/* Stub functions written with the pinned Expat callback signatures. Both
 * headers compile this file, so a typedef that differs from the pinned header
 * fails the assignment instead of silently agreeing with itself. */
static void XMLCALL sig_start(void *u, const XML_Char *name, const XML_Char **atts) {
  (void)u; (void)name; (void)atts;
}
static void XMLCALL sig_end(void *u, const XML_Char *name) { (void)u; (void)name; }
static void XMLCALL sig_text(void *u, const XML_Char *s, int len) {
  (void)u; (void)s; (void)len;
}
static void XMLCALL sig_pi(void *u, const XML_Char *target, const XML_Char *data) {
  (void)u; (void)target; (void)data;
}
static void XMLCALL sig_comment(void *u, const XML_Char *data) { (void)u; (void)data; }
static void XMLCALL sig_cdata_start(void *u) { (void)u; }
static void XMLCALL sig_cdata_end(void *u) { (void)u; }
static void XMLCALL sig_decl(void *u, const XML_Char *version,
                             const XML_Char *encoding, int standalone) {
  (void)u; (void)version; (void)encoding; (void)standalone;
}
static void XMLCALL sig_element_decl(void *u, const XML_Char *name, XML_Content *model) {
  (void)u; (void)name; (void)model;
}
static void XMLCALL sig_attlist(void *u, const XML_Char *el, const XML_Char *at,
                                const XML_Char *type, const XML_Char *dflt,
                                int required) {
  (void)u; (void)el; (void)at; (void)type; (void)dflt; (void)required;
}
static void XMLCALL sig_entity(void *u, const XML_Char *name, int pe,
                               const XML_Char *value, int value_length,
                               const XML_Char *base, const XML_Char *systemId,
                               const XML_Char *publicId, const XML_Char *notation) {
  (void)u; (void)name; (void)pe; (void)value; (void)value_length;
  (void)base; (void)systemId; (void)publicId; (void)notation;
}
static void XMLCALL sig_unparsed(void *u, const XML_Char *name,
                                 const XML_Char *base, const XML_Char *systemId,
                                 const XML_Char *publicId, const XML_Char *notation) {
  (void)u; (void)name; (void)base; (void)systemId; (void)publicId; (void)notation;
}
static void XMLCALL sig_notation(void *u, const XML_Char *name,
                                 const XML_Char *base, const XML_Char *systemId,
                                 const XML_Char *publicId) {
  (void)u; (void)name; (void)base; (void)systemId; (void)publicId;
}
static void XMLCALL sig_ns_start(void *u, const XML_Char *prefix,
                                 const XML_Char *uri) {
  (void)u; (void)prefix; (void)uri;
}
static void XMLCALL sig_ns_end(void *u, const XML_Char *prefix) {
  (void)u; (void)prefix;
}
static int XMLCALL sig_notstandalone(void *u) { (void)u; return 1; }
static int XMLCALL sig_external(XML_Parser p, const XML_Char *context,
                                const XML_Char *base, const XML_Char *systemId,
                                const XML_Char *publicId) {
  (void)p; (void)context; (void)base; (void)systemId; (void)publicId;
  return 0;
}
static void XMLCALL sig_skipped(void *u, const XML_Char *name, int pe) {
  (void)u; (void)name; (void)pe;
}
static void XMLCALL sig_default(void *u, const XML_Char *s, int len) {
  (void)u; (void)s; (void)len;
}
static void XMLCALL sig_doctype_start(void *u, const XML_Char *name,
                                      const XML_Char *sysid, const XML_Char *pubid,
                                      int internal) {
  (void)u; (void)name; (void)sysid; (void)pubid; (void)internal;
}
static void XMLCALL sig_doctype_end(void *u) { (void)u; }
static int XMLCALL sig_unknown_encoding(void *data, const XML_Char *name,
                                        XML_Encoding *info) {
  (void)data; (void)name; (void)info;
  return 0;
}

int main(void) {
  XML_StartElementHandler start = sig_start;
  XML_EndElementHandler end = sig_end;
  XML_CharacterDataHandler text = sig_text;
  XML_ProcessingInstructionHandler pi = sig_pi;
  XML_CommentHandler comment = sig_comment;
  XML_StartCdataSectionHandler cdata_start = sig_cdata_start;
  XML_EndCdataSectionHandler cdata_end = sig_cdata_end;
  XML_XmlDeclHandler decl = sig_decl;
  XML_ElementDeclHandler element_decl = sig_element_decl;
  XML_AttlistDeclHandler attlist = sig_attlist;
  XML_EntityDeclHandler entity = sig_entity;
  XML_UnparsedEntityDeclHandler unparsed = sig_unparsed;
  XML_NotationDeclHandler notation = sig_notation;
  XML_StartNamespaceDeclHandler ns_start = sig_ns_start;
  XML_EndNamespaceDeclHandler ns_end = sig_ns_end;
  XML_NotStandaloneHandler notstandalone = sig_notstandalone;
  XML_ExternalEntityRefHandler external = sig_external;
  XML_SkippedEntityHandler skipped = sig_skipped;
  XML_DefaultHandler deflt = sig_default;
  XML_StartDoctypeDeclHandler doctype_start = sig_doctype_start;
  XML_EndDoctypeDeclHandler doctype_end = sig_doctype_end;
  XML_UnknownEncodingHandler unknown_encoding = sig_unknown_encoding;
  (void)start; (void)end; (void)text; (void)pi; (void)comment;
  (void)cdata_start; (void)cdata_end; (void)decl; (void)element_decl;
  (void)attlist; (void)entity; (void)unparsed; (void)notation;
  (void)ns_start; (void)ns_end; (void)notstandalone; (void)external;
  (void)skipped; (void)deflt; (void)doctype_start; (void)doctype_end;
  (void)unknown_encoding;

  SHOW(sizeof(XML_Char));
  SHOW(sizeof(XML_LChar));
  SHOW(sizeof(XML_Bool));
  SHOW(sizeof(XML_Index));
  SHOW(sizeof(XML_Size));
  SHOW(sizeof(XML_Parser));
  SHOW(sizeof(XML_Content));
  SHOW(_Alignof(XML_Content));
  SHOW(offsetof(XML_Content, type));
  SHOW(offsetof(XML_Content, quant));
  SHOW(offsetof(XML_Content, name));
  SHOW(offsetof(XML_Content, numchildren));
  SHOW(offsetof(XML_Content, children));
  SHOW(sizeof(XML_Memory_Handling_Suite));
  SHOW(_Alignof(XML_Memory_Handling_Suite));
  SHOW(offsetof(XML_Memory_Handling_Suite, malloc_fcn));
  SHOW(offsetof(XML_Memory_Handling_Suite, realloc_fcn));
  SHOW(offsetof(XML_Memory_Handling_Suite, free_fcn));
  SHOW(sizeof(XML_Encoding));
  SHOW(_Alignof(XML_Encoding));
  SHOW(offsetof(XML_Encoding, map));
  SHOW(offsetof(XML_Encoding, data));
  SHOW(offsetof(XML_Encoding, convert));
  SHOW(offsetof(XML_Encoding, release));
  SHOW(sizeof(XML_ParsingStatus));
  SHOW(_Alignof(XML_ParsingStatus));
  SHOW(offsetof(XML_ParsingStatus, parsing));
  SHOW(offsetof(XML_ParsingStatus, finalBuffer));
  SHOW(sizeof(XML_Expat_Version));
  SHOW(_Alignof(XML_Expat_Version));
  SHOW(offsetof(XML_Expat_Version, major));
  SHOW(offsetof(XML_Expat_Version, minor));
  SHOW(offsetof(XML_Expat_Version, micro));
  SHOW(sizeof(XML_Feature));
  SHOW(_Alignof(XML_Feature));
  SHOW(offsetof(XML_Feature, feature));
  SHOW(offsetof(XML_Feature, name));
  SHOW(offsetof(XML_Feature, value));
  SHOW(XML_STATUS_ERROR);
  SHOW(XML_STATUS_OK);
  SHOW(XML_STATUS_SUSPENDED);
  SHOW(XML_ERROR_NONE);
  SHOW(XML_ERROR_NO_MEMORY);
  SHOW(XML_ERROR_SYNTAX);
  SHOW(XML_ERROR_NO_ELEMENTS);
  SHOW(XML_ERROR_INVALID_TOKEN);
  SHOW(XML_ERROR_UNCLOSED_TOKEN);
  SHOW(XML_ERROR_PARTIAL_CHAR);
  SHOW(XML_ERROR_TAG_MISMATCH);
  SHOW(XML_ERROR_DUPLICATE_ATTRIBUTE);
  SHOW(XML_ERROR_JUNK_AFTER_DOC_ELEMENT);
  SHOW(XML_ERROR_PARAM_ENTITY_REF);
  SHOW(XML_ERROR_UNDEFINED_ENTITY);
  SHOW(XML_ERROR_RECURSIVE_ENTITY_REF);
  SHOW(XML_ERROR_ASYNC_ENTITY);
  SHOW(XML_ERROR_BAD_CHAR_REF);
  SHOW(XML_ERROR_BINARY_ENTITY_REF);
  SHOW(XML_ERROR_ATTRIBUTE_EXTERNAL_ENTITY_REF);
  SHOW(XML_ERROR_MISPLACED_XML_PI);
  SHOW(XML_ERROR_UNKNOWN_ENCODING);
  SHOW(XML_ERROR_INCORRECT_ENCODING);
  SHOW(XML_ERROR_UNCLOSED_CDATA_SECTION);
  SHOW(XML_ERROR_EXTERNAL_ENTITY_HANDLING);
  SHOW(XML_ERROR_NOT_STANDALONE);
  SHOW(XML_ERROR_UNEXPECTED_STATE);
  SHOW(XML_ERROR_ENTITY_DECLARED_IN_PE);
  SHOW(XML_ERROR_FEATURE_REQUIRES_XML_DTD);
  SHOW(XML_ERROR_CANT_CHANGE_FEATURE_ONCE_PARSING);
  SHOW(XML_ERROR_UNBOUND_PREFIX);
  SHOW(XML_ERROR_UNDECLARING_PREFIX);
  SHOW(XML_ERROR_INCOMPLETE_PE);
  SHOW(XML_ERROR_XML_DECL);
  SHOW(XML_ERROR_TEXT_DECL);
  SHOW(XML_ERROR_PUBLICID);
  SHOW(XML_ERROR_SUSPENDED);
  SHOW(XML_ERROR_NOT_SUSPENDED);
  SHOW(XML_ERROR_ABORTED);
  SHOW(XML_ERROR_FINISHED);
  SHOW(XML_ERROR_SUSPEND_PE);
  SHOW(XML_ERROR_RESERVED_PREFIX_XML);
  SHOW(XML_ERROR_RESERVED_PREFIX_XMLNS);
  SHOW(XML_ERROR_RESERVED_NAMESPACE_URI);
  SHOW(XML_ERROR_INVALID_ARGUMENT);
  SHOW(XML_ERROR_NO_BUFFER);
  SHOW(XML_ERROR_AMPLIFICATION_LIMIT_BREACH);
  SHOW(XML_ERROR_NOT_STARTED);
  SHOW(XML_CTYPE_EMPTY);
  SHOW(XML_CTYPE_ANY);
  SHOW(XML_CTYPE_MIXED);
  SHOW(XML_CTYPE_NAME);
  SHOW(XML_CTYPE_CHOICE);
  SHOW(XML_CTYPE_SEQ);
  SHOW(XML_CQUANT_NONE);
  SHOW(XML_CQUANT_OPT);
  SHOW(XML_CQUANT_REP);
  SHOW(XML_CQUANT_PLUS);
  SHOW(XML_PARAM_ENTITY_PARSING_NEVER);
  SHOW(XML_PARAM_ENTITY_PARSING_UNLESS_STANDALONE);
  SHOW(XML_PARAM_ENTITY_PARSING_ALWAYS);
  SHOW(XML_INITIALIZED);
  SHOW(XML_PARSING);
  SHOW(XML_FINISHED);
  SHOW(XML_SUSPENDED);
  SHOW(XML_FEATURE_END);
  SHOW(XML_FEATURE_UNICODE);
  SHOW(XML_FEATURE_UNICODE_WCHAR_T);
  SHOW(XML_FEATURE_DTD);
  SHOW(XML_FEATURE_CONTEXT_BYTES);
  SHOW(XML_FEATURE_MIN_SIZE);
  SHOW(XML_FEATURE_SIZEOF_XML_CHAR);
  SHOW(XML_FEATURE_SIZEOF_XML_LCHAR);
  SHOW(XML_FEATURE_NS);
  SHOW(XML_FEATURE_LARGE_SIZE);
  SHOW(XML_FEATURE_ATTR_INFO);
  SHOW(XML_TRUE);
  SHOW(XML_FALSE);
  return 0;
}
"""

USERDATA_SOURCE = r"""
#include <expat.h>
#include <stdio.h>

int main(void) {
  int token = 0;
  XML_Parser parser = XML_ParserCreate(NULL);
  if (parser == NULL)
    return 2;
  XML_SetUserData(parser, &token);
  printf("getuserdata %d\n", XML_GetUserData(parser) == &token);
  printf("status %d\n", (int)XML_Parse(parser, "<r/>", 4, 1));
  XML_ParserFree(parser);
  return 0;
}
"""

WRONG_SIGNATURE_SOURCE = r"""
#include <expat.h>
static void XMLCALL wrong_signature(void *userData, const XML_Char *data) {
  (void)userData;
  (void)data;
}
int main(void) {
  XML_CharacterDataHandler handler = wrong_signature;
  (void)handler;
  return 0;
}
"""

OPAQUE_SOURCE = r"""
#include <expat.h>
int main(void) {
  struct XML_ParserStruct value;
  (void)value;
  return 0;
}
"""

POINTER_SIZE_SOURCE = r"""
#include <expat.h>
int main(void) {
  return sizeof(XML_Parser) == sizeof(void *) ? 0 : 1;
}
"""

INCLUDE_SOURCE = r"""
#include <expat.h>
int main(void) {
  XML_Char c = 'x';
  return c == 'x' ? 0 : 1;
}
"""

LOADER_SOURCE = r"""
/*
 * One fresh-process loader client for `tests/c-abi-verify.py --abi`. It resolves
 * the shipped artifact through the real dynamic loader, parses one known
 * document with registered element and character-data handlers, frees the
 * parser, closes the handle and exits. Each failing step returns its own status.
 * An optional delay in milliseconds keeps the process alive after the handle is
 * closed, so the deadline control can observe an active child.
 */
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <expat.h>

static int elements;
static int text_bytes;

static void XMLCALL on_start_element(void *userData, const XML_Char *name,
                                     const XML_Char **atts) {
  (void)userData;
  (void)atts;
  if (strcmp(name, "root") == 0)
    elements++;
}

static void XMLCALL on_character_data(void *userData, const XML_Char *text,
                                      int len) {
  (void)userData;
  (void)text;
  if (len > 0)
    text_bytes += len;
}

static void delay_milliseconds(int milliseconds) {
  struct timespec span;
  span.tv_sec = milliseconds / 1000;
  span.tv_nsec = (long)(milliseconds % 1000) * 1000000L;
  while (nanosleep(&span, &span) != 0)
    ;
}

int main(int argc, char **argv) {
  static const char document[] = "<root>hello</root>";
  int delay_ms = 0;
  void *handle;
  XML_Parser parser;
  int status;
  typedef XML_Parser (*create_fn)(const XML_Char *);
  typedef void (*set_element_fn)(XML_Parser, XML_StartElementHandler,
                                 XML_EndElementHandler);
  typedef void (*set_text_fn)(XML_Parser, XML_CharacterDataHandler);
  typedef int (*parse_fn)(XML_Parser, const char *, int, int);
  typedef void (*free_fn)(XML_Parser);
  create_fn create;
  set_element_fn set_element;
  set_text_fn set_text;
  parse_fn parse;
  free_fn destroy;

  if (argc < 2 || argc > 3) {
    fprintf(stderr, "usage: %s <library> [delay-ms]\n", argv[0]);
    return 2;
  }
  if (argc == 3)
    delay_ms = atoi(argv[2]);

  handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (handle == NULL) {
    fprintf(stderr, "dlopen: %s\n", dlerror());
    return 10;
  }
  create = (create_fn)dlsym(handle, "XML_ParserCreate");
  set_element = (set_element_fn)dlsym(handle, "XML_SetElementHandler");
  set_text = (set_text_fn)dlsym(handle, "XML_SetCharacterDataHandler");
  parse = (parse_fn)dlsym(handle, "XML_Parse");
  destroy = (free_fn)dlsym(handle, "XML_ParserFree");
  if (create == NULL || set_element == NULL || set_text == NULL ||
      parse == NULL || destroy == NULL) {
    fprintf(stderr, "dlsym: %s\n", dlerror());
    return 11;
  }

  parser = create(NULL);
  if (parser == NULL) {
    fprintf(stderr, "XML_ParserCreate returned NULL\n");
    return 12;
  }
  set_element(parser, on_start_element, NULL);
  set_text(parser, on_character_data);
  status = parse(parser, document, (int)(sizeof document - 1), 1);
  destroy(parser);
  if (status != XML_STATUS_OK) {
    fprintf(stderr, "XML_Parse status %d\n", status);
    return 13;
  }
  if (elements != 1 || text_bytes != 5) {
    fprintf(stderr, "callbacks: elements=%d text_bytes=%d\n", elements,
            text_bytes);
    return 14;
  }
  if (dlclose(handle) != 0) {
    fprintf(stderr, "dlclose: %s\n", dlerror());
    return 15;
  }
  if (delay_ms > 0)
    delay_milliseconds(delay_ms);
  printf("parse ok elements=%d text_bytes=%d\n", elements, text_bytes);
  return 0;
}
"""

LOADER_CHILDREN = 16
LOADER_CHILD_SECONDS = 15.0
LOADER_DEADLINE_SECONDS = 60.0


def dynamic_entries(path, tag):
    """Every value `readelf -d` prints for one dynamic `tag`, in file order."""
    result = run(["readelf", "-d", str(path)])
    need(result.returncode == 0, f"readelf -d failed for {path}:\n{result.stderr}")
    marker = f"({tag})"
    values = []
    for line in result.stdout.splitlines():
        if marker in line:
            values.append(line.split(marker, 1)[1].strip())
    return values


def flags1_words(path):
    """The `FLAGS_1` flag words of `path`; the detector for `DF_1_NODELETE`.

    `NODELETE` is a word of that entry, not a substring of the whole dynamic
    section, so an unrelated text occurrence cannot satisfy the check.
    """
    entries = dynamic_entries(path, "FLAGS_1")
    need(len(entries) == 1,
         f"{path} has {len(entries)} FLAGS_1 dynamic entries, expected exactly one")
    entry = entries[0]
    if entry.startswith("Flags:"):
        entry = entry[len("Flags:"):]
    return set(entry.split())


class LoaderTimeout(VerifyError):
    """A loader run that exceeded its aggregate deadline or a child bound."""

    def __init__(self, message, launches, reaped, deadline_seconds):
        super().__init__(message)
        self.launches = launches
        self.reaped = reaped
        self.deadline_seconds = deadline_seconds


class LoaderSmoke:
    """Fresh-process loader runs bounded by one monotonic aggregate deadline.

    The deadline starts immediately before the client is compiled and covers
    every child, so the measurement includes compilation. Each child is also
    bounded on its own. Before each step the runner uses the remaining aggregate
    time, and for a child the smaller of that time and the child bound; a step
    that passes its bound is terminated, reaped and reported, and no child is
    ever launched once the deadline has passed.
    """

    def __init__(self, tmp, library, children, deadline_seconds):
        self.tmp = tmp
        self.library = library
        self.children = children
        self.deadline_seconds = deadline_seconds
        self.deadline = time.monotonic() + deadline_seconds
        self.launches = 0
        self.executable = None

    def remaining(self):
        return self.deadline - time.monotonic()

    def deadline_note(self, launched):
        return (f"the {self.deadline_seconds:g}s aggregate loader deadline passed after "
                f"{launched} of {self.children} children")

    def compile_client(self):
        remaining = self.remaining()
        if remaining <= 0:
            raise LoaderTimeout(self.deadline_note(self.launches), self.launches,
                                True, self.deadline_seconds)
        source = self.tmp / "c-abi-loader.c"
        source.write_text(LOADER_SOURCE, encoding="utf-8")
        executable = self.tmp / "c-abi-loader"
        args = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                f"-I{ROOT / 'include'}", str(source), "-ldl", "-o", str(executable)]
        try:
            result = run(args, timeout=remaining)
        except subprocess.TimeoutExpired:
            raise LoaderTimeout(
                self.deadline_note(self.launches) + " while compiling the loader client",
                self.launches, True, self.deadline_seconds)
        need(result.returncode == 0,
             "the loader client does not build:\n" + result.stderr)
        self.executable = executable
        return executable

    def run(self, delay_ms=0):
        need(self.executable is not None, "the loader client was not compiled")
        for index in range(1, self.children + 1):
            remaining = self.remaining()
            if remaining <= 0:
                raise LoaderTimeout(self.deadline_note(self.launches),
                                    self.launches, True, self.deadline_seconds)
            bound = min(remaining, LOADER_CHILD_SECONDS)
            args = [str(self.executable), str(self.library)]
            if delay_ms:
                args.append(str(delay_ms))
            started = time.monotonic()
            process = subprocess.Popen(args, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True)
            self.launches += 1
            try:
                out, err = process.communicate(timeout=bound)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                reaped = process.poll() is not None
                which = ("aggregate loader deadline"
                         if remaining < LOADER_CHILD_SECONDS
                         else f"{LOADER_CHILD_SECONDS:g}s child bound")
                raise LoaderTimeout(
                    f"loader child {index}/{self.children} (pid {process.pid}) passed "
                    f"the {which} {bound:.3f}s after launch; it was terminated "
                    f"({'reaped' if reaped else 'not reaped'}), and no further child was "
                    f"launched ({self.launches} of {self.children} started)",
                    self.launches, reaped, self.deadline_seconds)
            elapsed = time.monotonic() - started
            need(process.returncode == 0,
                 f"loader child {index}/{self.children} exited {process.returncode}: "
                 + (err.strip() or "(no stderr)"))
            need("parse ok" in out,
                 f"loader child {index}/{self.children} reported no affirmative parse: "
                 + (out.strip() or "(no stdout)"))
            print(f"  loader child {index}/{self.children} pid {process.pid} exit 0 "
                  f"in {elapsed:.3f}s: {out.strip()}")


def build_artifact(no_build):
    if no_build:
        need(LIB.exists(), f"{LIB} is missing; run without --no-build")
        return
    result = run(["lake", "build", "lexpatCAbi"], cwd=ROOT)
    if result.returncode != 0:
        raise VerifyError("lake build lexpatCAbi failed:\n" + result.stdout + result.stderr)
    need(LIB.exists(), f"{LIB} was not produced")


def compile_source(source, name, tmp, link_flags=(), cflags=None):
    path = tmp / f"{name}.c"
    path.write_text(source, encoding="utf-8")
    args = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror"]
    args += list(cflags if cflags is not None else [])
    args += [str(path)] + list(link_flags)
    args += ["-o", str(tmp / name)]
    return run(args)


def system_cflags():
    pkg = run(["pkg-config", "--cflags", "expat"])
    need(pkg.returncode == 0, "pkg-config found no expat headers")
    return pkg.stdout.split()


def system_libs():
    pkg = run(["pkg-config", "--libs", "expat"])
    need(pkg.returncode == 0, "pkg-config found no expat library")
    return pkg.stdout.split()


def candidate_cflags():
    return [f"-I{ROOT / 'include'}"]


def candidate_link_flags():
    return [f"-L{LIB_DIR}", "-llexpat", f"-Wl,-rpath,{LIB_DIR}"]


class Checks:
    def __init__(self, tmp, base_lib=None):
        self.tmp = tmp
        self.base_lib = base_lib
        self.group = None

    def pass_group(self, message):
        print(f"PASS {self.group}: {message}")

    # -- header ------------------------------------------------------------

    def header(self):
        self.group = "header"
        candidate = compile_source(INCLUDE_SOURCE, "include-candidate", self.tmp,
                                   (), cflags=candidate_cflags())
        need(candidate.returncode == 0,
             "the header does not compile as C11:\n" + candidate.stderr)
        reference = compile_source(INCLUDE_SOURCE, "include-reference", self.tmp,
                                   (), cflags=system_cflags())
        need(reference.returncode == 0,
             "the system header does not compile as a control:\n" + reference.stderr)
        client_candidate = run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                                "-c", str(CLIENT_SRC), "-o", str(self.tmp / "client.o"),
                                *candidate_cflags()])
        need(client_candidate.returncode == 0,
             "tests/c-abi-client.c does not compile against the candidate header:\n"
             + client_candidate.stderr)
        client_reference = run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                                "-c", str(CLIENT_SRC), "-o", str(self.tmp / "client-ref.o"),
                                *system_cflags()])
        need(client_reference.returncode == 0,
             "tests/c-abi-client.c does not compile against the system header:\n"
             + client_reference.stderr)

        for define in ("XML_UNICODE", "XML_UNICODE_WCHAR_T", "XML_LARGE_SIZE",
                       "XML_ATTR_INFO"):
            refusal = compile_source(INCLUDE_SOURCE, f"refuse-{define}", self.tmp,
                                     (), cflags=[f"-D{define}"] + candidate_cflags())
            need(refusal.returncode != 0,
                 f"the header silently accepted -D{define}")
            need("not supported" in refusal.stderr,
                 f"-D{define} failed without the documented diagnostic:\n"
                 + refusal.stderr)

        opaque = compile_source(OPAQUE_SOURCE, "opaque", self.tmp, (),
                                cflags=candidate_cflags())
        need(opaque.returncode != 0,
             "struct XML_ParserStruct is not opaque to clients")
        pointer = compile_source(POINTER_SIZE_SOURCE, "pointer-size", self.tmp, (),
                                 cflags=candidate_cflags())
        need(pointer.returncode == 0, "XML_Parser is not a pointer-sized handle")
        header_text = HEADER.read_text(encoding="utf-8")
        need("struct XML_ParserStruct {" not in header_text,
             "the header defines the private parser struct")

        for label, flags in (("candidate", candidate_cflags()),
                             ("system", system_cflags())):
            probe = compile_source(USERDATA_SOURCE, f"userdata-{label}", self.tmp,
                                   candidate_link_flags(), cflags=flags)
            need(probe.returncode == 0,
                 f"the user-data probe does not build with the {label} header:\n"
                 + probe.stderr)
            output = run([str(self.tmp / f"userdata-{label}")])
            need(output.returncode == 0,
                 f"the user-data probe failed at runtime:\n" + output.stderr)
            need("getuserdata 1" in output.stdout,
                 f"XML_GetUserData does not read offset zero with the {label} header: "
                 + output.stdout)
            need("status 1" in output.stdout,
                 f"the user-data probe did not parse with the {label} header")
        self.pass_group("C11 source compatibility, refused build modes, opaque parser, "
                        "pinned XML_GetUserData offset")

    # -- layout ------------------------------------------------------------

    def layout(self):
        self.group = "layout"
        candidate = compile_source(LAYOUT_SOURCE, "layout-candidate", self.tmp, (),
                                   cflags=candidate_cflags())
        reference = compile_source(LAYOUT_SOURCE, "layout-reference", self.tmp, (),
                                   cflags=system_cflags())
        need(candidate.returncode == 0, "the layout probe does not compile:\n"
             + candidate.stderr)
        wrong = compile_source(WRONG_SIGNATURE_SOURCE, "wrong-signature", self.tmp, (),
                               cflags=candidate_cflags())
        need(wrong.returncode != 0,
             "control: an incompatible callback signature was accepted")
        need(reference.returncode == 0, "the reference layout probe does not compile:\n"
             + reference.stderr)
        candidate_values = self.read_pairs(self.tmp / "layout-candidate")
        reference_values = self.read_pairs(self.tmp / "layout-reference")

        def compare(left, right):
            if left != right:
                keys = sorted(set(left) | set(right))
                for key in keys:
                    if left.get(key) != right.get(key):
                        raise VerifyError(
                            f"public layout differs for {key}: "
                            f"candidate {left.get(key)} != system {right.get(key)}")
            return True

        compare(candidate_values, reference_values)
        mutated = dict(candidate_values)
        mutated["sizeof(XML_Content)"] = mutated["sizeof(XML_Content)"] + 1
        try:
            compare(mutated, reference_values)
        except VerifyError:
            pass
        else:
            raise VerifyError("control: a changed layout value was not detected")
        import ctypes
        need(candidate_values.get("sizeof(XML_Parser)") == ctypes.sizeof(ctypes.c_void_p),
             "XML_Parser is not pointer sized")
        need(candidate_values.get("XML_ERROR_NOT_STARTED") == 44,
             "XML_ERROR_NOT_STARTED is not 44")
        extensions = {
            "XML_ERROR_UNSUPPORTED_DTD": 45,
            "XML_ERROR_LIMIT_INPUT": 46,
            "XML_ERROR_LIMIT_TOKEN": 47,
            "XML_ERROR_LIMIT_DEPTH": 48,
            "XML_ERROR_LIMIT_ENTITY_EXPANSION": 49,
            "XML_ERROR_UNSUPPORTED_FEATURE": 50,
            "XML_ERROR_MALFORMED_WIRE": 51,
            "XML_ERROR_REENTRANT_CALL": 52,
        }
        header_text = HEADER.read_text(encoding="utf-8")
        enums = parse_enum(header_text, "XML_Error")
        for name, value in extensions.items():
            need(enums.get(name) == value, f"{name} is not {value}")
        need("XML_ERROR_AMPLIFICATION_LIMIT_BREACH" in enums,
             "the pinned amplification code is missing")
        self.pass_group("public enums, sizes, alignment, offsets and callback typedef "
                        "signatures equal pinned Expat, with mutation controls")

    def read_pairs(self, executable):
        output = run([str(executable)])
        need(output.returncode == 0, f"{executable} failed: {output.stderr}")
        values = {}
        for line in output.stdout.splitlines():
            name, _, value = line.rpartition(" ")
            values[name] = int(value)
        need(values, f"{executable} produced no values")
        return values

    # -- abi ---------------------------------------------------------------

    def abi(self):
        self.group = "abi"
        header_text = HEADER.read_text(encoding="utf-8")
        declared = set(re.findall(
            r"XMLPARSEAPI\s*\([^)]*\)\s+(XML_[A-Za-z0-9_]+)\s*\(", header_text))
        need(len(declared) >= 60,
             f"only {len(declared)} XML_* functions were found in the header")
        need("XML_Parse" in declared and "XML_GetSpecifiedAttributeCount" in declared,
             "the header extractor missed known declarations")

        nm = run(["nm", "-D", "--defined-only", str(LIB)])
        need(nm.returncode == 0, "nm failed:\n" + nm.stderr)
        exported = set()
        for line in nm.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                exported.add(parts[2])
        need("XML_Parse" in exported, "the symbol extractor missed XML_Parse")
        need(exported == declared,
             "exported symbols differ from the header: "
             f"missing {sorted(declared - exported)}, extra {sorted(exported - declared)}")
        forbidden = sorted(name for name in exported
                           if not name.startswith("XML_"))
        need(not forbidden, "non-XML symbols are exported: " + ", ".join(forbidden))
        control_declared = set(declared)
        control_declared.remove("XML_Parse")
        need(control_declared != exported,
             "control: removing a declared symbol was not detected")

        reference_header = run(["pkg-config", "--variable=includedir", "expat"])
        need(reference_header.returncode == 0, "pkg-config has no expat includedir")
        reference_text = Path(reference_header.stdout.strip()) / "expat.h"
        reference_text = reference_text.read_text(encoding="utf-8")
        need("XML_GetAttributeInfo" in reference_text,
             "the pinned header has no XML_GetAttributeInfo control symbol")
        need("XML_GetAttributeInfo" not in declared,
             "the candidate header declares XML_GetAttributeInfo")
        need("XML_GetAttributeInfo" not in exported,
             "the candidate exports XML_GetAttributeInfo")
        need("XML_GetSpecifiedAttributeCount" in exported,
             "the affirmative symbol control is missing")

        readelf = run(["readelf", "-d", str(LIB)])
        need(readelf.returncode == 0, "readelf failed:\n" + readelf.stderr)
        need("Library soname: [liblexpat.so.1]" in readelf.stdout,
             "wrong or missing SONAME")
        need("Shared library: [libleanshared.so]" in readelf.stdout,
             "libleanshared.so is not a NEEDED entry")
        need("libexpat.so" not in readelf.stdout,
             "the artifact depends on system libexpat")
        lean_libdir = run(["lean", "--print-libdir"]).stdout.strip()
        need(lean_libdir, "lean --print-libdir produced no path")
        need(lean_libdir in readelf.stdout, "the Lean runtime directory is not in RUNPATH")

        # The initialized Lean runtime starts threads whose code lives in the
        # runtime libraries and that have no stop or join path. `DF_1_NODELETE`
        # is what keeps those libraries mapped after the caller's `dlclose`,
        # so the flag is part of the supported lifetime, not an incidental one.
        candidate_flags = flags1_words(LIB)
        need("NODELETE" in candidate_flags,
             "the shipped artifact's FLAGS_1 entry is "
             f"{' '.join(sorted(candidate_flags)) or '(empty)'}, not NODELETE: "
             "dlclose would unload the initialized Lean runtime")

        base_note = ""
        if self.base_lib is not None:
            base_flags = flags1_words(self.base_lib)
            need("NODELETE" not in base_flags,
                 f"the base artifact already carries NODELETE "
                 f"({' '.join(sorted(base_flags)) or '(empty)'}), so the detector "
                 "cannot show that the shipped flag is the change")
            for tag in ("SONAME", "NEEDED", "RUNPATH"):
                base_values = dynamic_entries(self.base_lib, tag)
                candidate_values = dynamic_entries(LIB, tag)
                need(base_values == candidate_values,
                     f"{tag} differs between the base artifact {base_values} and the "
                     f"candidate {candidate_values}")
            base_note = (f"; the same FLAGS_1 detector found NODELETE absent on "
                         f"{self.base_lib} and present here, with unchanged "
                         "SONAME/NEEDED/RUNPATH")
            print(f"  FLAGS_1 detector: base {' '.join(sorted(base_flags)) or '(empty)'} "
                  f"-> candidate {' '.join(sorted(candidate_flags))}")

        ldd = run(["ldd", str(LIB)])
        need(ldd.returncode == 0, "ldd failed:\n" + ldd.stderr)
        need("not found" not in ldd.stdout, "an unresolved dependency is reported:\n"
             + ldd.stdout)
        need("libexpat.so" not in ldd.stdout, "ldd resolves system libexpat")

        probe = compile_source(USERDATA_SOURCE, "loader", self.tmp,
                               candidate_link_flags(), cflags=candidate_cflags())
        need(probe.returncode == 0, "the loader probe does not build:\n" + probe.stderr)
        env = dict(os.environ, LD_DEBUG="libs")
        debug = run([str(self.tmp / "loader")], env=env)
        need(debug.returncode == 0, "the loader probe failed to run:\n" + debug.stderr)
        need("liblexpat.so.1" in debug.stderr, "the loader did not load liblexpat.so.1")
        need("libleanshared.so" in debug.stderr,
             "the loader did not load libleanshared.so")
        need("error:" not in debug.stderr.lower(),
             "the dynamic loader reported an error:\n" + debug.stderr[-2000:])

        smoke = LoaderSmoke(self.tmp, LIB, LOADER_CHILDREN, LOADER_DEADLINE_SECONDS)
        smoke.compile_client()
        print(f"  loader smoke: {LOADER_CHILDREN} fresh processes, "
              f"{LOADER_CHILD_SECONDS:g}s each, {LOADER_DEADLINE_SECONDS:g}s aggregate "
              "including client compilation")
        try:
            smoke.run()
        except LoaderTimeout as exc:
            raise VerifyError(str(exc)) from exc
        elapsed = LOADER_DEADLINE_SECONDS - smoke.remaining()
        need(elapsed < LOADER_DEADLINE_SECONDS,
             f"the loader smoke finished at {elapsed:.3f}s, not inside its "
             f"{LOADER_DEADLINE_SECONDS:g}s aggregate deadline")
        print(f"  loader smoke: {smoke.launches} children passed in {elapsed:.3f}s")
        self.loader_control()
        self.pass_group("exact XML_* export allowlist, absent Expat extension symbol, "
                        "SONAME/NEEDED/RUNPATH, a real loader launch, the FLAGS_1 "
                        "NODELETE runtime retention and 16 bounded fresh-process "
                        "load/parse/free/close clients" + base_note)

    def loader_control(self):
        """Prove the aggregate-deadline branch fails, reaps and stops launching.

        The client is already built, so this control spends no time on
        compilation: a child that stays alive past a deliberately short deadline
        must produce a nonzero outcome, the active child must be terminated and
        reaped, and no second child may be started.
        """
        control = LoaderSmoke(self.tmp, LIB, 3, 0.5)
        control.executable = self.tmp / "c-abi-loader"
        try:
            control.run(delay_ms=3000)
        except LoaderTimeout as exc:
            need(exc.launches == 1,
                 f"control: {exc.launches} children were launched after the aggregate "
                 "deadline, expected only the one already running")
            need(exc.reaped, "control: the active child was not terminated and reaped")
            need("aggregate loader deadline" in str(exc),
                 f"control: the failure was not the aggregate deadline: {exc}")
            print("  loader control: a 3s child under a 0.5s aggregate deadline failed "
                  f"as expected after {exc.launches} launch with the child reaped")
            return
        raise VerifyError(
            "control: a child that outlives the aggregate deadline did not fail the "
            "loader run")

    # -- runtime groups ----------------------------------------------------

    def runtime(self, group):
        self.group = group
        harness = self.tmp / "verify-harness"
        if not harness.exists():
            result = compile_source(HARNESS_SOURCE, "verify-harness", self.tmp,
                                    candidate_link_flags(), cflags=candidate_cflags())
            need(result.returncode == 0,
                 "the runtime harness does not compile:\n" + result.stderr)
        try:
            output = run([str(harness), group], timeout=120)
        except subprocess.TimeoutExpired:
            raise VerifyError(
                f"runtime group {group} did not finish within 120 seconds")
        sys.stdout.write(output.stdout)
        sys.stderr.write(output.stderr)
        need(output.returncode == 0,
             f"runtime group {group} failed with status {output.returncode}")

    def bridge(self):
        self.group = "bridge"
        build_artifact(False)
        lean_libdir = run(["lean", "--print-libdir"]).stdout.strip()
        need(lean_libdir, "lean --print-libdir produced no path")
        objects = sorted(
            path for path in (ROOT / ".lake" / "build" / "ir" / "LexPat").rglob("*.c.o.export")
            if "Exe" not in path.parts)
        need(objects, "no Lean module objects were found; run lake build lexpatCAbi")
        source = self.tmp / "c-abi-bridge.c"
        source.write_text(BRIDGE_SOURCE, encoding="utf-8")
        executable = self.tmp / "c-abi-bridge"
        args = ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                f"-I{ROOT / 'include'}",
                f"-I{Path(lean_libdir).parent.parent / 'include'}",
                str(source), str(ROOT / "cabi" / "expat.c")]
        args += [str(obj) for obj in objects]
        args += [f"-L{lean_libdir}", "-lleanshared", "-pthread",
                 "-Wl,--wrap=malloc", "-Wl,--wrap=calloc",
                 f"-Wl,-rpath,{lean_libdir}", "-o", str(executable)]
        result = run(args)
        need(result.returncode == 0,
             "the bridge test target does not link:\n" + result.stderr)
        output = run([str(executable)])
        sys.stdout.write(output.stdout)
        sys.stderr.write(output.stderr)
        need(output.returncode == 0, "the bridge checks failed")

    # -- docs --------------------------------------------------------------

    def docs(self):
        self.group = "docs"
        def normalize(text):
            return " ".join(text.split())

        readme = normalize((ROOT / "README.md").read_text(encoding="utf-8"))
        compatibility = normalize((ROOT / "docs" / "compatibility.md").read_text(encoding="utf-8"))
        agents = normalize((ROOT / "AGENTS.md").read_text(encoding="utf-8"))
        trace = normalize((ROOT / "LexPat" / "Exe" / "Trace.lean").read_text(encoding="utf-8"))
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

        need("verified C integration route" in readme,
             "README does not name the verified C integration route")
        need("This is not a drop-in replacement for libexpat outside that subset."
             in readme, "README lacks the bounded-compatibility disclaimer")
        need("nix develop -c python3 tests/c-abi-differential.py" in readme,
             "README lacks the tested compile recipe command")

        for phrase in ("not a drop-in replacement", "fails closed",
                       "XML_GetUserData", "post-free"):
            need(phrase in compatibility,
                 f"docs/compatibility.md lacks the limitation: {phrase}")

        header_text = HEADER.read_text(encoding="utf-8")
        declared = set(re.findall(
            r"XMLPARSEAPI\s*\([^)]*\)\s+(XML_[A-Za-z0-9_]+)\s*\(", header_text))
        missing = sorted(name for name in declared if name not in compatibility)
        need(not missing,
             "docs/compatibility.md does not document these header functions: "
             + ", ".join(missing))
        for code in ("UNSUPPORTED_DTD", "LIMIT_INPUT", "LIMIT_TOKEN", "LIMIT_DEPTH",
                     "LIMIT_ENTITY_EXPANSION", "UNSUPPORTED_FEATURE", "MALFORMED_WIRE",
                     "REENTRANT_CALL"):
            need(code in compatibility, f"docs/compatibility.md omits the {code} mapping")

        for sentence in self.sentences(readme) + self.sentences(compatibility):
            if "drop-in" in sentence:
                need(any(negation in sentence.lower()
                         for negation in ("not", "never", "no ")),
                     "a drop-in claim is not negated: " + sentence)

        need("not a supported integration route" in readme,
             "README no longer states the Lean library is not a supported route")
        need("inspection and differential" in compatibility,
             "docs/compatibility.md no longer limits the M1/M2 surfaces")

        security_path = ROOT / "docs" / "security.md"
        need(security_path.exists(),
             "docs/security.md is missing")
        security = normalize(security_path.read_text(encoding="utf-8"))
        for phrase in ("not a drop-in replacement", "not free of bugs",
                       "Lean runtime", "LSan", "Valgrind",
                       "library coverage is absent", "XML_ERROR_NO_MEMORY",
                       "stochastic", "post-free"):
            need(phrase in security,
                 f"docs/security.md lacks the limitation: {phrase}")
        for command in ("tests/security-cve.py",
                        "tests/security-differential-fixed.sh",
                        "tests/security-oom-sanitized.sh",
                        "tests/security-benchmark.sh",
                        "tests/security-fuzz-smoke.sh",
                        "tests/security-ci.sh"):
            need(command in security,
                 f"docs/security.md omits the command: {command}")
        need("docs/security.md" in readme,
             "README does not link the security threat model")
        need("XML_ERROR_NO_MEMORY" in readme,
             "README does not explain the corrected allocation error")
        need("tests/c-abi-oom-contract.sh A3" in readme,
             "README does not name the public allocation contract")
        need("limit-decl-name-exact" in compatibility
             and "twelve actual exception rows" in compatibility,
             "docs/compatibility.md does not state the corrected exception and "
             "budget facts")

        for name in ("cve-cases.json", "SOURCES.md",
                     "differential-exceptions.json"):
            need((ROOT / "tests" / "security" / name).exists(),
                 f"tests/security/{name} is missing")

        for command in ("nix develop -c bash tests/c-abi-contract.sh",
                        "nix develop -c python3 tests/c-abi-differential.py",
                        "nix develop -c python3 tests/c-abi-verify.py",
                        "nix develop -c bash tests/c-abi-memory.sh",
                        "nix develop -c bash tests/c-abi-oom-contract.sh A3",
                        "nix develop -c python3 tests/security-cve.py",
                        "nix develop -c bash tests/security-differential-fixed.sh",
                        "nix develop -c bash tests/security-oom-sanitized.sh",
                        "nix develop -c bash tests/security-benchmark.sh",
                        "nix develop -c bash tests/security-fuzz-smoke.sh",
                        "nix develop -c bash tests/security-ci.sh"):
            need(command in agents, f"AGENTS.md omits the test command: {command}")
        need("ASan" in agents and "Valgrind" in agents,
             "AGENTS.md does not record the memory detectors and their limits")
        need("# library, proofs and the C ABI artifact" in agents,
             "AGENTS.md understates what the default lake build produces")
        need("lake build FuzzParser" in agents,
             "AGENTS.md omits the test-only fuzz parser target")
        need("library coverage is absent" in agents,
             "AGENTS.md does not record the artifact target's coverage limit")
        need("2.8.5" in agents,
             "AGENTS.md does not record the pinned oracle assertion")

        need("include/expat.h" in trace,
             "the trace documentation does not point at the separate C header")
        need("does not use it" in trace,
             "the trace documentation does not state that the trace does not use the C ABI")

        for snippet in ("nix develop -c bash tests/clean-build.sh",
                        "nix develop -c bash tests/c-abi-contract.sh A1",
                        "nix develop -c bash tests/c-abi-contract.sh A2",
                        "nix develop -c bash tests/c-abi-oom-contract.sh A3",
                        "nix develop -c bash tests/security-ci.sh",
                        "nix develop -c python3 tests/c-abi-differential.py",
                        "nix develop -c python3 tests/c-abi-verify.py",
                        "nix develop -c bash tests/c-abi-memory.sh",
                        "nix develop -c lake env lean --run tests/OneShotPrecedence.lean",
                        "nix develop -c python3 tests/streaming.py",
                        "nix develop -c python3 tests/differential.py",
                        "nix develop -c python3 tests/differential.py --group limits",
                        "nix develop -c bash tests/no-admits.sh",
                        "nix develop -c lake env lean LexPat/Encoding/Proofs.lean"):
            need(snippet in workflow, f"CI omits the step: {snippet}")
        need("fetch-depth: 0" in workflow,
             "CI does not fetch the base revision for the corpus comparison")
        # The security step is bounded by the process-group wrapper, which is
        # invoked outside `nix develop` so its 300-second deadline includes Nix
        # startup, and a failed preparation or security step uploads its logs.
        need("          python3 scripts/run-bounded-security.py" in workflow,
             "CI does not run the security step through the process-group wrapper")
        need("--seconds 300" in workflow,
             "CI does not apply the 300-second outer cap to the security step")
        need("prepare the fuzz build" in workflow,
             "CI does not prepare the fuzz build in its own capped step")
        need("if: failure()" in workflow and "lexpat-security-diagnostics" in workflow,
             "CI does not retain security diagnostics on failure")
        need("if-no-files-found: error" in workflow,
             "CI does not require the security diagnostics artifact to be non-empty")
        need("--phase smoke" in workflow,
             "CI does not run the correctness-only performance smoke")
        order = [
            "run: nix develop -c lake build",
            "run: nix develop -c bash tests/clean-build.sh",
            "run: nix develop -c bash tests/c-abi-contract.sh A1",
            "run: nix develop -c bash tests/c-abi-contract.sh A2",
            "run: nix develop -c bash tests/c-abi-oom-contract.sh A3",
            "tests/security-ci.sh",
            "run: nix develop -c python3 tests/c-abi-differential.py",
            "run: nix develop -c python3 tests/c-abi-verify.py",
            "run: nix develop -c bash tests/c-abi-memory.sh",
            "run: nix develop -c lake env lean --run tests/OneShotPrecedence.lean",
            "run: nix develop -c python3 tests/streaming.py",
            "run: nix develop -c python3 tests/differential.py",
            "run: nix develop -c python3 tests/differential.py --group limits",
            "run: nix develop -c bash tests/no-admits.sh",
            "run: nix develop -c lake env lean LexPat/Encoding/Proofs.lean",
        ]
        positions = [workflow.index(marker) for marker in order]
        need(positions == sorted(positions), "CI steps are out of order")

        need((ROOT / "tests" / "c-abi-client.c").exists()
             and (ROOT / "tests" / "c-abi-differential.py").exists(),
             "the advertised recipe's inputs are absent")
        for document in (readme, compatibility):
            need("<absolute-repo>" not in document,
                 "a documentation command contains a placeholder path")
        self.pass_group("README, compatibility, test policy, trace wording and CI "
                        "match the verified surface and its limitations")

    def sentences(self, text):
        return [sentence.strip() + "." for sentence in text.replace("\n", " ").split(".")]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-build", action="store_true",
                        help="use the existing .lake/build/lib/liblexpat.so.1")
    parser.add_argument("--base-lib", type=Path, default=None,
                        help="absolute path to a pre-change liblexpat.so.1 whose "
                             "FLAGS_1 entry must lack NODELETE; meaningful only "
                             "with --abi")
    for group in GROUPS:
        parser.add_argument(f"--{group}", action="store_true",
                            help=f"run only the {group} checks")
    args = parser.parse_args()

    selected = [group for group in GROUPS if getattr(args, group)]
    if not selected:
        selected = GROUPS

    base_lib = args.base_lib
    if base_lib is not None:
        need(args.abi, "--base-lib is meaningful only with --abi")
        need(base_lib.is_absolute(), f"--base-lib must be an absolute path: {base_lib}")
        need(base_lib.is_file(), f"--base-lib does not exist: {base_lib}")
        need(os.access(base_lib, os.R_OK), f"--base-lib is not readable: {base_lib}")
        need(base_lib.resolve() != LIB.resolve(),
             "--base-lib names the candidate artifact itself; a base comparison needs "
             "the artifact from before the change")

    build_artifact(args.no_build)
    runtime_groups = {"identity", "lifecycle", "buffers", "errors", "locations",
                      "unsupported", "adversarial"}
    with tempfile.TemporaryDirectory(prefix="lexpat-cabi-verify-", dir="/tmp") as tmp_name:
        checks = Checks(Path(tmp_name), base_lib)
        try:
            for group in selected:
                if group == "header":
                    checks.header()
                elif group == "abi":
                    checks.abi()
                elif group == "layout":
                    checks.layout()
                elif group in runtime_groups:
                    checks.runtime(group)
                elif group == "bridge":
                    checks.bridge()
                elif group == "docs":
                    checks.docs()
            print(f"OK: {len(selected)} C ABI check groups passed")
            return 0
        except VerifyError as exc:
            print(f"FAIL: {exc}", file=sys.stderr)
            return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except VerifyError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
