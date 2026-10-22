/*
 * Behavior contract for an allocation failure in the C ABI parse path.
 *
 * The executable is a test-only build that links the C shim and the Lean module
 * objects directly, so `-Wl,--wrap=malloc` and `-Wl,--wrap=calloc` cover the
 * shim's own allocations. The pinned Lean runtime keeps its allocator inside
 * libleanshared.so, where the wrapper does not reach. The `control` mode proves
 * that the wrapper observes the shim allocation made while a start callback is
 * delivered; the `A3` mode arms a one-shot failure for the first shim malloc
 * of the candidate parse. Every assertion reads the status, error code and
 * callback counts of the same parser the parse was driven on.
 */

#include <expat.h>

#include <stddef.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(condition, message)                                              \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "c-abi-oom-contract: FAIL: %s\n", (message));            \
      failures++;                                                              \
    }                                                                          \
  } while (0)

#define CHECK_EQ_INT(actual, expected, message)                                \
  do {                                                                         \
    long actualValue = (long)(actual);                                         \
    long expectedValue = (long)(expected);                                     \
    if (actualValue != expectedValue) {                                        \
      fprintf(stderr,                                                          \
              "c-abi-oom-contract: FAIL: %s (got %ld, want %ld)\n",            \
              (message), actualValue, expectedValue);                          \
      failures++;                                                              \
    }                                                                          \
  } while (0)

/* Allocator wrapper. -Wl,--wrap maps the shim's malloc and calloc references
 * to these two functions; calls made inside the prebuilt Lean runtime keep
 * their own allocator. The failure is one-shot and is armed only for the
 * candidate parse, so the control parse and parser creation allocate
 * normally. */
static int counting;
static int fail_next_malloc;
static long shim_mallocs;
static long shim_callocs;
static int injected_failures;

void *__real_malloc(size_t size);
void *__real_calloc(size_t count, size_t size);

void *__wrap_malloc(size_t size) {
  if (counting)
    shim_mallocs++;
  if (fail_next_malloc) {
    fail_next_malloc = 0;
    injected_failures++;
    return NULL;
  }
  return __real_malloc(size);
}

void *__wrap_calloc(size_t count, size_t size) {
  if (counting)
    shim_callocs++;
  return __real_calloc(count, size);
}

typedef struct Detector {
  void *user_data;
  int parse_active;
  int wrong_user_data;
  int callback_outside_parse;
  int start_count;
  int end_count;
} Detector;

static void detector_init(Detector *detector, void *user_data) {
  memset(detector, 0, sizeof(*detector));
  detector->user_data = user_data;
}

static void detector_note(Detector *detector, void *userData) {
  if (userData != detector->user_data)
    detector->wrong_user_data = 1;
  if (!detector->parse_active)
    detector->callback_outside_parse = 1;
}

static void XMLCALL detector_start(void *userData, const XML_Char *name,
                                   const XML_Char **atts) {
  Detector *detector = (Detector *)userData;
  (void)name;
  (void)atts;
  detector->start_count++;
  detector_note(detector, userData);
}

static void XMLCALL detector_end(void *userData, const XML_Char *name) {
  Detector *detector = (Detector *)userData;
  (void)name;
  detector->end_count++;
  detector_note(detector, userData);
}

static void arm_counting(void) {
  shim_mallocs = 0;
  shim_callocs = 0;
  counting = 1;
}

static void disarm_counting(void) { counting = 0; }

/*
 * No-fault capability check: the same detector and the same direct-linked
 * wrappers parse the same document with the allocator intact, and the wrapper
 * reports the shim allocation the callback path makes.
 */
static int run_control(void) {
  Detector detector;
  const char document[] = "<r/>";
  const int length = (int)(sizeof(document) - 1);
  detector_init(&detector, &detector);

  XML_Parser parser = XML_ParserCreate(NULL);
  CHECK(parser != NULL, "control: XML_ParserCreate returns a parser");
  if (parser == NULL)
    return failures;

  XML_SetUserData(parser, &detector);
  XML_SetElementHandler(parser, detector_start, detector_end);

  arm_counting();
  detector.parse_active = 1;
  enum XML_Status status = XML_Parse(parser, document, length, 1);
  detector.parse_active = 0;
  disarm_counting();

  CHECK_EQ_INT(status, XML_STATUS_OK,
               "control: XML_Parse returns XML_STATUS_OK");
  CHECK(!detector.wrong_user_data,
        "control: callback userData is the pointer registered for the parser");
  CHECK(!detector.callback_outside_parse,
        "control: callbacks are delivered while XML_Parse is active");
  CHECK_EQ_INT(detector.start_count, 1,
               "control: the detector records one start callback");
  CHECK_EQ_INT(detector.end_count, 1,
               "control: the detector records one end callback");
  CHECK(shim_mallocs >= 1,
        "control: the wrapper observes a shim malloc during XML_Parse");
  CHECK_EQ_INT(injected_failures, 0,
               "control: no allocation was faulted");

  fprintf(stdout,
          "c-abi-oom-contract: control: shim malloc calls %ld, "
          "shim calloc calls %ld\n",
          shim_mallocs, shim_callocs);

  XML_ParserFree(parser);

  if (failures == 0)
    fprintf(stdout, "c-abi-oom-contract: control: PASS\n");
  return failures;
}

/*
 * A3: the first shim allocation of the candidate parse fails, and the
 * application observes that failure through the candidate parser's status,
 * error code and callback detector.
 */
static int run_a3(void) {
  Detector control;
  Detector candidate;
  const char document[] = "<r/>";
  const int length = (int)(sizeof(document) - 1);
  detector_init(&control, &control);
  detector_init(&candidate, &candidate);

  XML_Parser control_parser = XML_ParserCreate(NULL);
  CHECK(control_parser != NULL,
        "A3: the affirmative-control XML_ParserCreate returns a parser");
  if (control_parser == NULL)
    return failures;
  XML_SetUserData(control_parser, &control);
  XML_SetElementHandler(control_parser, detector_start, detector_end);

  control.parse_active = 1;
  enum XML_Status control_status =
      XML_Parse(control_parser, document, length, 1);
  control.parse_active = 0;

  CHECK_EQ_INT(control_status, XML_STATUS_OK,
               "A3: the affirmative-control XML_Parse returns XML_STATUS_OK");
  CHECK_EQ_INT(control.start_count, 1,
               "A3: the affirmative control records one start callback");

  /* The candidate parser is created after the Lean runtime has parsed the
   * control document, and the one-shot failure is armed only once the parser
   * and its handlers exist, so it reaches the parse path rather than parser
   * construction. */
  XML_Parser candidate_parser = XML_ParserCreate(NULL);
  CHECK(candidate_parser != NULL,
        "A3: the candidate XML_ParserCreate returns a parser");
  if (candidate_parser == NULL) {
    XML_ParserFree(control_parser);
    return failures;
  }
  XML_SetUserData(candidate_parser, &candidate);
  XML_SetElementHandler(candidate_parser, detector_start, detector_end);

  arm_counting();
  fail_next_malloc = 1;
  candidate.parse_active = 1;
  enum XML_Status status = XML_Parse(candidate_parser, document, length, 1);
  candidate.parse_active = 0;
  fail_next_malloc = 0;
  disarm_counting();

  CHECK_EQ_INT(status, XML_STATUS_ERROR,
               "A3: the candidate XML_Parse returns XML_STATUS_ERROR");
  CHECK_EQ_INT(XML_GetErrorCode(candidate_parser), XML_ERROR_NO_MEMORY,
               "A3: the candidate error code is XML_ERROR_NO_MEMORY");
  CHECK_EQ_INT(candidate.start_count, 0,
               "A3: the candidate records no start callback");
  CHECK_EQ_INT(control.start_count, 1,
               "A3: the control start count is one");

  fprintf(stdout,
          "c-abi-oom-contract: A3: error code %d, candidate starts %d, "
          "control starts %d, injected failures %d, shim malloc calls %ld\n",
          (int)XML_GetErrorCode(candidate_parser), candidate.start_count,
          control.start_count, injected_failures, shim_mallocs);

  XML_ParserFree(candidate_parser);
  XML_ParserFree(control_parser);

  if (failures == 0)
    fprintf(stdout, "c-abi-oom-contract: A3: PASS\n");
  return failures;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s control|A3\n", argv[0]);
    return 2;
  }
  if (strcmp(argv[1], "control") == 0)
    return run_control() == 0 ? 0 : 1;
  if (strcmp(argv[1], "A3") == 0)
    return run_a3() == 0 ? 0 : 1;
  fprintf(stderr, "%s: unknown mode %s\n", argv[0], argv[1]);
  return 2;
}
