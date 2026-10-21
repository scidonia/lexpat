/*
 * Behavior contracts for the C ABI artifact.
 *
 * Each scenario builds a fresh parser through the checked-in header and drives
 * it with literal XML bytes. The assertions bind the XML_Parse result and the
 * callback records produced by that same call; nothing is read from stdout.
 */

#include <expat.h>

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(condition, message)                                              \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "c-abi-contract: FAIL: %s\n", (message));                \
      failures++;                                                              \
    }                                                                          \
  } while (0)

#define CHECK_EQ_INT(actual, expected, message)                                \
  do {                                                                         \
    long actualValue = (long)(actual);                                         \
    long expectedValue = (long)(expected);                                     \
    if (actualValue != expectedValue) {                                        \
      fprintf(stderr, "c-abi-contract: FAIL: %s (got %ld, want %ld)\n",        \
              (message), actualValue, expectedValue);                          \
      failures++;                                                              \
    }                                                                          \
  } while (0)

#define CHECK_STR_EQ(actual, expected, message)                                \
  do {                                                                         \
    const char *actualValue = (actual);                                        \
    const char *expectedValue = (expected);                                    \
    if (strcmp(actualValue, expectedValue) != 0) {                             \
      fprintf(stderr, "c-abi-contract: FAIL: %s (got \"%s\", want \"%s\")\n",  \
              (message), actualValue, expectedValue);                          \
      failures++;                                                              \
    }                                                                          \
  } while (0)

#define MAX_RECORDS 8

typedef struct Detector {
  const char *scenario;
  void *user_data;
  int parse_active;
  int wrong_user_data;
  int callback_outside_parse;
  int start_count;
  int end_count;
  int record_count;
  char records[MAX_RECORDS][24];
} Detector;

static void detector_init(Detector *detector, const char *scenario,
                          void *user_data) {
  memset(detector, 0, sizeof(*detector));
  detector->scenario = scenario;
  detector->user_data = user_data;
}

static void detector_note(Detector *detector, void *userData, const char *kind,
                          const XML_Char *name) {
  if (userData != detector->user_data)
    detector->wrong_user_data = 1;
  if (!detector->parse_active)
    detector->callback_outside_parse = 1;
  if (detector->record_count < MAX_RECORDS)
    snprintf(detector->records[detector->record_count],
             sizeof(detector->records[0]), "%s:%s", kind, name);
  detector->record_count++;
}

static void XMLCALL detector_start(void *userData, const XML_Char *name,
                                   const XML_Char **atts) {
  Detector *detector = (Detector *)userData;
  (void)atts;
  detector_note(detector, userData, "start", name);
  detector->start_count++;
}

static void XMLCALL detector_end(void *userData, const XML_Char *name) {
  Detector *detector = (Detector *)userData;
  detector_note(detector, userData, "end", name);
  detector->end_count++;
}

/* The pinned external-entity signature. It is never expected to run: <r/> has
 * no entity reference, and the handler's registration is the behavior under
 * contract. Returning 0 performs no filesystem or network work. */
static int XMLCALL refusing_external_entity(XML_Parser parser,
                                            const XML_Char *context,
                                            const XML_Char *base,
                                            const XML_Char *systemId,
                                            const XML_Char *publicId) {
  (void)parser;
  (void)context;
  (void)base;
  (void)systemId;
  (void)publicId;
  return 0;
}

static int check_detector(Detector *detector) {
  int before = failures;
  CHECK(!detector->wrong_user_data,
        "callback userData is the pointer registered for its parser");
  CHECK(!detector->callback_outside_parse,
        "callbacks are delivered while XML_Parse is active");
  return failures == before;
}

static int run_a1(void) {
  Detector detector;
  const char document[] = "<r><child/></r>";
  detector_init(&detector, "A1", &detector);

  XML_Parser parser = XML_ParserCreate(NULL);
  CHECK(parser != NULL, "A1: XML_ParserCreate returns a parser");
  if (parser == NULL)
    return failures;

  XML_SetUserData(parser, &detector);
  XML_SetStartElementHandler(parser, detector_start);
  XML_SetEndElementHandler(parser, detector_end);

  detector.parse_active = 1;
  enum XML_Status status =
      XML_Parse(parser, document, (int)strlen(document), 1);
  detector.parse_active = 0;

  CHECK_EQ_INT(status, XML_STATUS_OK, "A1: XML_Parse returns XML_STATUS_OK");
  check_detector(&detector);
  CHECK_EQ_INT(detector.record_count, 4,
               "A1: exactly four element callbacks are delivered");
  if (detector.record_count == 4) {
    CHECK_STR_EQ(detector.records[0], "start:r",
                 "A1: first callback is start r");
    CHECK_STR_EQ(detector.records[1], "start:child",
                 "A1: second callback is start child");
    CHECK_STR_EQ(detector.records[2], "end:child",
                 "A1: third callback is end child");
    CHECK_STR_EQ(detector.records[3], "end:r",
                 "A1: fourth callback is end r");
  }

  XML_ParserFree(parser);

  if (failures == 0)
    fprintf(stdout, "c-abi-contract: A1: PASS\n");
  return failures;
}

static int run_a2(void) {
  Detector control;
  Detector candidate;
  const char document[] = "<r/>";
  detector_init(&control, "A2-control", &control);
  detector_init(&candidate, "A2-candidate", &candidate);

  XML_Parser control_parser = XML_ParserCreate(NULL);
  XML_Parser candidate_parser = XML_ParserCreate(NULL);
  CHECK(control_parser != NULL,
        "A2: the affirmative-control XML_ParserCreate returns a parser");
  CHECK(candidate_parser != NULL,
        "A2: the candidate XML_ParserCreate returns a parser");
  if (control_parser == NULL || candidate_parser == NULL) {
    if (control_parser != NULL)
      XML_ParserFree(control_parser);
    if (candidate_parser != NULL)
      XML_ParserFree(candidate_parser);
    return failures;
  }

  XML_SetUserData(control_parser, &control);
  XML_SetUserData(candidate_parser, &candidate);
  XML_SetElementHandler(control_parser, detector_start, detector_end);
  XML_SetElementHandler(candidate_parser, detector_start, detector_end);

  control.parse_active = 1;
  enum XML_Status control_status =
      XML_Parse(control_parser, document, (int)strlen(document), 1);
  control.parse_active = 0;

  CHECK_EQ_INT(control_status, XML_STATUS_OK,
               "A2: the affirmative-control XML_Parse returns XML_STATUS_OK");
  check_detector(&control);
  CHECK_EQ_INT(control.start_count, 1,
               "A2: the affirmative control records one start callback");
  CHECK_EQ_INT(control.end_count, 1,
               "A2: the affirmative control records one end callback");

  XML_SetExternalEntityRefHandler(candidate_parser,
                                  refusing_external_entity);

  candidate.parse_active = 1;
  enum XML_Status status =
      XML_Parse(candidate_parser, document, (int)strlen(document), 1);
  candidate.parse_active = 0;

  CHECK_EQ_INT(status, XML_STATUS_ERROR,
               "A2: the candidate XML_Parse returns XML_STATUS_ERROR");
  CHECK_EQ_INT(XML_GetErrorCode(candidate_parser),
               XML_ERROR_UNSUPPORTED_FEATURE,
               "A2: the candidate error code is XML_ERROR_UNSUPPORTED_FEATURE");
  check_detector(&candidate);
  CHECK_EQ_INT(candidate.start_count, 0,
               "A2: the candidate records no start callback");
  CHECK_EQ_INT(candidate.end_count, 0,
               "A2: the candidate records no end callback");
  CHECK_EQ_INT(control.start_count, 1,
               "A2: the control start count is unchanged");
  CHECK_EQ_INT(control.end_count, 1,
               "A2: the control end count is unchanged");

  XML_ParserFree(candidate_parser);
  XML_ParserFree(control_parser);

  if (failures == 0)
    fprintf(stdout, "c-abi-contract: A2: PASS\n");
  return failures;
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s A1|A2\n", argv[0]);
    return 2;
  }
  if (strcmp(argv[1], "A1") == 0)
    return run_a1() == 0 ? 0 : 1;
  if (strcmp(argv[1], "A2") == 0)
    return run_a2() == 0 ? 0 : 1;
  fprintf(stderr, "%s: unknown scenario %s\n", argv[0], argv[1]);
  return 2;
}
