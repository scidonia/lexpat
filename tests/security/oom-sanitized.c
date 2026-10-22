/*
 * Deterministic C-shim allocation failures under ASan/UBSan.
 *
 * This is a test-only executable. It links `cabi/expat.c` and the Lean module
 * objects directly, so the `--wrap` allocator hooks reach the shim's own
 * malloc/calloc/free calls; the Lean runtime keeps its own allocator and is
 * never faulted. `tests/security-oom-sanitized.sh` builds it with the
 * sanitizers and runs the capability control before the matrix.
 *
 * Each scenario runs in one process on a fresh parser. A scenario records
 * every shim allocation and free while it runs, arms exactly one allocation
 * index to fail, and asserts the public result, the error code of the same
 * parser, the callback counts, and that every recorded allocation was freed
 * again. No fabricated pointer is passed to the library.
 */

#include "expat.h"

#include <lean/lean.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *__real_malloc(size_t size);
void *__real_calloc(size_t count, size_t size);
void __real_free(void *ptr);

#define MAX_RECORDS 512

typedef struct {
  void *ptr;
  size_t size;
  int kind; /* 1 malloc, 2 calloc */
  int freed;
} Record;

static Record records[MAX_RECORDS];
static int record_count;
static int counting;

/* 0 disarmed, 1 malloc, 2 calloc. The occurrence is counted from the last
 * `arm` call, so allocations made while the parser was being created do not
 * shift the target. */
static int failure_kind;
static int failure_occurrence;
static int malloc_seen;
static int calloc_seen;
static int injected_failures;
static int failed_kind;
static size_t failed_size;

static void record_alloc(void *ptr, size_t size, int kind) {
  if (!counting || ptr == NULL)
    return;
  if (record_count >= MAX_RECORDS) {
    fputs("oom: allocation record table exhausted\n", stderr);
    exit(2);
  }
  records[record_count].ptr = ptr;
  records[record_count].size = size;
  records[record_count].kind = kind;
  records[record_count].freed = 0;
  record_count++;
}

void *__wrap_malloc(size_t size) {
  if (counting) {
    int index = malloc_seen++;
    if (failure_kind == 1 && index == failure_occurrence) {
      failure_kind = 0;
      injected_failures++;
      failed_kind = 1;
      failed_size = size;
      return NULL;
    }
  }
  void *ptr = __real_malloc(size);
  record_alloc(ptr, size, 1);
  return ptr;
}

void *__wrap_calloc(size_t count, size_t size) {
  size_t total = (count != 0 && size > SIZE_MAX / count) ? SIZE_MAX : count * size;
  if (counting) {
    int index = calloc_seen++;
    if (failure_kind == 2 && index == failure_occurrence) {
      failure_kind = 0;
      injected_failures++;
      failed_kind = 2;
      failed_size = total;
      return NULL;
    }
  }
  void *ptr = __real_calloc(count, size);
  record_alloc(ptr, total, 2);
  return ptr;
}

void __wrap_free(void *ptr) {
  if (counting && ptr != NULL) {
    for (int i = record_count - 1; i >= 0; i--) {
      if (records[i].ptr == ptr) {
        records[i].freed = 1;
        break;
      }
    }
  }
  __real_free(ptr);
}

/* -------------------------------------------------------------------------
 * Scenario state.
 * ---------------------------------------------------------------------- */

static XML_Parser current;
static int starts;
static int ends;
static int decls;
static int comments;
static int pis;
static int free_in_start;
static int failures;

static void check(const char *scenario, int condition, const char *message) {
  if (!condition) {
    fprintf(stderr, "oom: FAIL %s: %s\n", scenario, message);
    failures++;
  }
}

static void begin_scenario(void) {
  record_count = 0;
  counting = 1;
  malloc_seen = 0;
  calloc_seen = 0;
  injected_failures = 0;
  failed_kind = 0;
  failed_size = 0;
  failure_kind = 0;
  failure_occurrence = 0;
  starts = 0;
  ends = 0;
  decls = 0;
  comments = 0;
  pis = 0;
  free_in_start = 0;
  current = NULL;
}

static void arm(int kind, int occurrence) {
  failure_kind = kind;
  failure_occurrence = occurrence;
  malloc_seen = 0;
  calloc_seen = 0;
}

/* Every shim allocation this scenario made must have been released by the
 * library before the scenario ends. A partial copy that the shim forgot to
 * free is reported here even though the C-shim free is not fault-injected. */
static void check_all_freed(const char *scenario) {
  int leaked = 0;
  for (int i = 0; i < record_count; i++) {
    if (!records[i].freed) {
      fprintf(stderr, "oom: FAIL %s: %zu-byte %s allocation not freed\n",
              scenario, records[i].size,
              records[i].kind == 1 ? "malloc" : "calloc");
      leaked = 1;
    }
  }
  if (leaked)
    failures++;
}

static void XMLCALL cb_start(void *userData, const XML_Char *name,
                             const XML_Char **atts) {
  (void)userData;
  (void)name;
  (void)atts;
  starts++;
  if (free_in_start && current != NULL) {
    free_in_start = 0;
    XML_ParserFree(current);
  }
}

static void XMLCALL cb_end(void *userData, const XML_Char *name) {
  (void)userData;
  (void)name;
  ends++;
}

static void XMLCALL cb_decl(void *userData, const XML_Char *version,
                            const XML_Char *encoding, int standalone) {
  (void)userData;
  (void)version;
  (void)encoding;
  (void)standalone;
  decls++;
}

static void XMLCALL cb_comment(void *userData, const XML_Char *data) {
  (void)userData;
  (void)data;
  comments++;
}

static void XMLCALL cb_pi(void *userData, const XML_Char *target,
                          const XML_Char *data) {
  (void)userData;
  (void)target;
  (void)data;
  pis++;
}

static XML_Parser new_parser(void) {
  XML_Parser parser = XML_ParserCreate(NULL);
  if (parser != NULL) {
    XML_SetElementHandler(parser, cb_start, cb_end);
    XML_SetXmlDeclHandler(parser, cb_decl);
    XML_SetCommentHandler(parser, cb_comment);
    XML_SetProcessingInstructionHandler(parser, cb_pi);
    current = parser;
  }
  return parser;
}

static enum XML_Status parse(XML_Parser parser, const char *document) {
  return XML_Parse(parser, document, (int)strlen(document), 1);
}

/* A parse that must fail at the named shim allocation with NO_MEMORY. */
static void parse_oom_case(const char *scenario, const char *document, int kind,
                           int occurrence, size_t want_size, int want_starts) {
  begin_scenario();
  XML_Parser parser = new_parser();
  check(scenario, parser != NULL, "parser creation failed before arming");
  if (parser == NULL) {
    counting = 0;
    return;
  }
  arm(kind, occurrence);
  enum XML_Status status = parse(parser, document);
  enum XML_Error code = XML_GetErrorCode(parser);
  check(scenario, status == XML_STATUS_ERROR, "parse did not fail");
  check(scenario, code == XML_ERROR_NO_MEMORY,
        "parse error is not XML_ERROR_NO_MEMORY");
  check(scenario, injected_failures == 1, "exactly one fault was not consumed");
  check(scenario, failed_kind == kind && failed_size == want_size,
        "the selected allocation kind/size is not the expected callsite");
  check(scenario, starts == want_starts, "unexpected start callback count");
  check(scenario, ends == 0, "an end callback was delivered after the failure");
  check(scenario, decls == 0 && comments == 0 && pis == 0,
        "an event callback was delivered after the failure");
  if (status == XML_STATUS_ERROR && code == XML_ERROR_NO_MEMORY) {
    /* The first error is terminal: a later call cannot replace it. */
    check(scenario, parse(parser, "<q/>") == XML_STATUS_ERROR,
          "a later parse call did not fail");
    check(scenario, XML_GetErrorCode(parser) == XML_ERROR_NO_MEMORY,
          "a later call replaced the first error");
  }
  XML_ParserFree(parser);
  counting = 0;
  check_all_freed(scenario);
}

/* -------------------------------------------------------------------------
 * Scenarios.
 * ---------------------------------------------------------------------- */

static void scenario_control(void) {
  const char *scenario = "control";
  begin_scenario();
  XML_Parser parser = new_parser();
  check(scenario, parser != NULL, "parser creation failed");
  if (parser == NULL) {
    counting = 0;
    return;
  }
  enum XML_Status status = parse(parser, "<r a=\"1\" b=\"2\"/>");
  check(scenario, status == XML_STATUS_OK, "the control parse was rejected");
  check(scenario, starts == 1 && ends == 1,
        "the control did not deliver one start and one end");
  check(scenario, malloc_seen >= 6 && calloc_seen >= 1,
        "the wrapper did not observe the shim's known allocations");
  check(scenario, injected_failures == 0, "the control injected a fault");
  XML_ParserFree(parser);
  counting = 0;
  check_all_freed(scenario);
}

static void scenario_create_calloc(void) {
  const char *scenario = "create-calloc";
  begin_scenario();
  arm(2, 0);
  XML_Parser parser = XML_ParserCreate(NULL);
  check(scenario, parser == NULL, "parser creation did not fail");
  check(scenario, injected_failures == 1, "exactly one fault was not consumed");
  check(scenario, failed_kind == 2 && failed_size > 0,
        "the failed allocation was not the parser-struct calloc");
  if (parser != NULL)
    XML_ParserFree(parser);
  counting = 0;
  check_all_freed(scenario);
}

static void scenario_create_registry(void) {
  const char *scenario = "create-registry";
  begin_scenario();
  arm(1, 0);
  XML_Parser parser = XML_ParserCreate(NULL);
  check(scenario, parser == NULL, "parser creation did not fail");
  check(scenario, injected_failures == 1, "exactly one fault was not consumed");
  check(scenario, failed_kind == 1 && failed_size > 0,
        "the failed allocation was not the registry node");
  if (parser != NULL)
    XML_ParserFree(parser);
  counting = 0;
  check_all_freed(scenario);
}

static void scenario_reservation(void) {
  const char *scenario = "reservation";
  begin_scenario();
  XML_Parser parser = new_parser();
  check(scenario, parser != NULL, "parser creation failed");
  if (parser == NULL) {
    counting = 0;
    return;
  }
  arm(1, 0);
  void *buffer = XML_GetBuffer(parser, 64);
  check(scenario, buffer == NULL, "XML_GetBuffer did not fail");
  check(scenario, XML_GetErrorCode(parser) == XML_ERROR_NO_MEMORY,
        "XML_GetBuffer did not report XML_ERROR_NO_MEMORY");
  check(scenario, injected_failures == 1, "exactly one fault was not consumed");
  check(scenario, failed_kind == 1 && failed_size == 64,
        "the failed allocation was not the 64-byte reservation");
  check(scenario, XML_Parse(parser, "x", 1, 1) == XML_STATUS_ERROR,
        "a parse after a failed reservation did not fail");
  XML_ParserFree(parser);
  counting = 0;
  check_all_freed(scenario);
}

static void scenario_reservation_replace(void) {
  const char *scenario = "reservation-replace";
  begin_scenario();
  XML_Parser parser = new_parser();
  check(scenario, parser != NULL, "parser creation failed");
  if (parser == NULL) {
    counting = 0;
    return;
  }
  void *first = XML_GetBuffer(parser, 16);
  check(scenario, first != NULL, "the first reservation failed");
  int first_record = -1;
  for (int i = 0; i < record_count; i++)
    if (records[i].ptr == first)
      first_record = i;
  check(scenario, first_record >= 0, "the first reservation was not recorded");
  arm(1, 0);
  void *second = XML_GetBuffer(parser, 32);
  check(scenario, second == NULL, "the replacement reservation did not fail");
  check(scenario, XML_GetErrorCode(parser) == XML_ERROR_NO_MEMORY,
        "the replacement did not report XML_ERROR_NO_MEMORY");
  check(scenario, failed_kind == 1 && failed_size == 32,
        "the failed allocation was not the 32-byte replacement");
  check(scenario, first_record >= 0 && records[first_record].freed,
        "the replaced reservation was not released before the new request");
  XML_ParserFree(parser);
  counting = 0;
  check_all_freed(scenario);
}

static void scenario_free_paths(void) {
  const char *scenario = "free-paths";
  begin_scenario();
  XML_Parser with_reservation = new_parser();
  check(scenario, with_reservation != NULL, "parser creation failed");
  if (with_reservation != NULL) {
    check(scenario, XML_GetBuffer(with_reservation, 8) != NULL,
          "the reservation failed");
    XML_ParserFree(with_reservation);
    check(scenario,
          XML_GetErrorCode(with_reservation) == XML_ERROR_INVALID_ARGUMENT,
          "the freed handle was still accepted");
  }
  XML_Parser plain = new_parser();
  check(scenario, plain != NULL, "second parser creation failed");
  if (plain != NULL) {
    XML_ParserFree(plain);
    check(scenario, XML_GetErrorCode(plain) == XML_ERROR_INVALID_ARGUMENT,
          "the freed handle was still accepted");
  }
  counting = 0;
  check_all_freed(scenario);
}

static void scenario_deferred_free(void) {
  const char *scenario = "deferred-free";
  begin_scenario();
  XML_Parser parser = new_parser();
  check(scenario, parser != NULL, "parser creation failed");
  if (parser == NULL) {
    counting = 0;
    return;
  }
  free_in_start = 1;
  enum XML_Status status = parse(parser, "<r/>");
  check(scenario, status == XML_STATUS_ERROR,
        "free inside a callback did not end the parse with an error");
  check(scenario, starts == 1, "the start callback did not run");
  check(scenario, XML_GetErrorCode(parser) == XML_ERROR_INVALID_ARGUMENT,
        "the deferred free left an accepted handle");
  counting = 0;
  check_all_freed(scenario);
}

static void scenario_parse_cases(void) {
  parse_oom_case("start-name", "<r/>", 1, 0, 2, 0);
  parse_oom_case("start-vector", "<r a=\"1\"/>", 2, 0, 24, 0);
  parse_oom_case("attr-name", "<r a=\"1\"/>", 1, 1, 2, 0);
  parse_oom_case("attr-value", "<r a=\"1\"/>", 1, 2, 2, 0);
  parse_oom_case("second-attr-name", "<r a=\"1\" b=\"2\"/>", 1, 3, 2, 0);
  parse_oom_case("second-attr-value", "<r a=\"1\" b=\"2\"/>", 1, 4, 2, 0);
  parse_oom_case("decl-version", "<?xml version=\"1.0\"?><r/>", 1, 0, 4, 0);
  parse_oom_case("decl-encoding", "<?xml version=\"1.0\" encoding=\"UTF-8\"?><r/>",
                 1, 1, 6, 0);
  parse_oom_case("end-name", "<r></r>", 1, 1, 2, 1);
  parse_oom_case("comment", "<!--c--><r/>", 1, 0, 2, 0);
  parse_oom_case("pi-target", "<?pi data?><r/>", 1, 0, 3, 0);
  parse_oom_case("pi-data", "<?pi data?><r/>", 1, 1, 5, 0);
}

int main(int argc, char **argv) {
  if (argc != 2 || (strcmp(argv[1], "--control") != 0
                    && strcmp(argv[1], "--matrix") != 0)) {
    fprintf(stderr, "usage: %s --control|--matrix\n", argv[0]);
    return 2;
  }
  scenario_control();
  if (strcmp(argv[1], "--control") == 0) {
    if (failures != 0) {
      fprintf(stderr, "oom: control: FAIL (%d checks)\n", failures);
      return 1;
    }
    printf("oom: control: PASS\n");
    return 0;
  }
  scenario_create_calloc();
  scenario_create_registry();
  scenario_reservation();
  scenario_reservation_replace();
  scenario_free_paths();
  scenario_deferred_free();
  scenario_parse_cases();
  if (failures != 0) {
    fprintf(stderr, "oom: matrix: FAIL (%d checks)\n", failures);
    return 1;
  }
  printf("oom: matrix: PASS (12 parse callsites, create, reservation, free paths)\n");
  return 0;
}
