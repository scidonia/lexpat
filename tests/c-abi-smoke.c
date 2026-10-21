/*
 * Direct smoke client for the C ABI artifact.
 *
 * It exercises the capability boundary only: parser creation and free, user
 * data, start/end callbacks delivered while XML_Parse is active, error and
 * version queries, and one deterministic refusal. It is not the behavioral
 * contract; `tests/c-abi-contract.sh`, the differential and the artifact
 * verification are the evidence for the supported subset.
 */

#include "expat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(condition, message)                                              \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "c-abi-smoke: FAIL: %s\n", (message));                   \
      failures++;                                                              \
    }                                                                          \
  } while (0)

#define CHECK_EQ_INT(actual, expected, message)                                \
  do {                                                                         \
    long actualValue = (long)(actual);                                         \
    long expectedValue = (long)(expected);                                     \
    if (actualValue != expectedValue) {                                        \
      fprintf(stderr, "c-abi-smoke: FAIL: %s (got %ld, want %ld)\n",           \
              (message), actualValue, expectedValue);                          \
      failures++;                                                              \
    }                                                                          \
  } while (0)

static int parse_active = 0;
static int callback_outside_parse = 0;
static int callback_count = 0;
static char callback_order[16];
static void *expected_user_data = NULL;
static XML_Parser current_parser = NULL;

static void record(char kind) {
  if (!parse_active)
    callback_outside_parse = 1;
  if (callback_count < (int)sizeof(callback_order) - 1)
    callback_order[callback_count] = kind;
  callback_count++;
}

static void XMLCALL on_start(void *userData, const XML_Char *name,
                             const XML_Char **atts) {
  (void)atts;
  if (userData != expected_user_data)
    callback_outside_parse = 1;
  if (XML_GetSpecifiedAttributeCount(current_parser) != 0)
    callback_outside_parse = 1;
  if (strcmp(name, "r") == 0)
    record('S');
  else if (strcmp(name, "child") == 0)
    record('s');
  else
    record('?');
}

static void XMLCALL on_end(void *userData, const XML_Char *name) {
  if (userData != expected_user_data)
    callback_outside_parse = 1;
  if (strcmp(name, "r") == 0)
    record('E');
  else if (strcmp(name, "child") == 0)
    record('e');
  else
    record('?');
}

typedef struct Rich {
  int starts;
  int ends;
  int texts;
  int comments;
  int pis;
  int cdata_starts;
  int cdata_ends;
  int decls;
  int saw_attr;
  int saw_text_hi;
  int saw_text_cd;
  int saw_comment;
  int saw_pi;
  int saw_decl;
} Rich;

static Rich rich;

static void XMLCALL rich_start(void *userData, const XML_Char *name,
                               const XML_Char **atts) {
  (void)userData;
  rich.starts++;
  if (strcmp(name, "r") == 0 && atts != NULL && atts[0] != NULL &&
      strcmp(atts[0], "a") == 0 && atts[1] != NULL &&
      strcmp(atts[1], "b") == 0 && atts[2] == NULL &&
      XML_GetSpecifiedAttributeCount(current_parser) == 2)
    rich.saw_attr = 1;
}

static void XMLCALL rich_end(void *userData, const XML_Char *name) {
  (void)userData;
  (void)name;
  rich.ends++;
}

static void XMLCALL rich_text(void *userData, const XML_Char *data, int len) {
  (void)userData;
  rich.texts++;
  if (len == 2 && memcmp(data, "hi", 2) == 0)
    rich.saw_text_hi = 1;
  if (len == 2 && memcmp(data, "cd", 2) == 0)
    rich.saw_text_cd = 1;
}

static void XMLCALL rich_cdata_start(void *userData) {
  (void)userData;
  rich.cdata_starts++;
}

static void XMLCALL rich_cdata_end(void *userData) {
  (void)userData;
  rich.cdata_ends++;
}

static void XMLCALL rich_comment(void *userData, const XML_Char *data) {
  (void)userData;
  rich.comments++;
  if (strcmp(data, "c") == 0)
    rich.saw_comment = 1;
}

static void XMLCALL rich_pi(void *userData, const XML_Char *target,
                            const XML_Char *data) {
  (void)userData;
  rich.pis++;
  if (strcmp(target, "pi") == 0 && strcmp(data, "d") == 0)
    rich.saw_pi = 1;
}

static void XMLCALL rich_decl(void *userData, const XML_Char *version,
                              const XML_Char *encoding, int standalone) {
  (void)userData;
  rich.decls++;
  if (version != NULL && strcmp(version, "1.0") == 0 && encoding == NULL &&
      standalone == -1)
    rich.saw_decl = 1;
}

typedef struct Detector {
  int starts;
  int ends;
  void *expected;
} Detector;

static void XMLCALL detect_start(void *userData, const XML_Char *name,
                                 const XML_Char **atts) {
  (void)name;
  (void)atts;
  Detector *detector = (Detector *)userData;
  if (detector == NULL || detector->expected != userData) {
    callback_outside_parse = 1;
    return;
  }
  detector->starts++;
}

static void XMLCALL detect_end(void *userData, const XML_Char *name) {
  (void)name;
  Detector *detector = (Detector *)userData;
  if (detector == NULL || detector->expected != userData) {
    callback_outside_parse = 1;
    return;
  }
  detector->ends++;
}

static int XMLCALL entity_stub(XML_Parser parser, const XML_Char *context,
                               const XML_Char *base, const XML_Char *systemId,
                               const XML_Char *publicId) {
  (void)parser;
  (void)context;
  (void)base;
  (void)systemId;
  (void)publicId;
  return 0;
}

int main(void) {
  const char *document = "<r><child/></r>";
  int sentinel = 0x5A5A;

  CHECK(strcmp(XML_ExpatVersion(), "lexpat_0.1.0-cabi1") == 0,
        "truthful version string");
  XML_Expat_Version version = XML_ExpatVersionInfo();
  CHECK_EQ_INT(version.major, 0, "version major");
  CHECK_EQ_INT(version.minor, 1, "version minor");
  CHECK_EQ_INT(version.micro, 0, "version micro");

  const XML_Feature *features = XML_GetFeatureList();
  CHECK(features != NULL, "feature list exists");
  int saw_char_size = 0;
  int terminated = 0;
  if (features != NULL) {
    for (const XML_Feature *feature = features; feature->feature != XML_FEATURE_END;
         feature++) {
      if (feature->feature == XML_FEATURE_SIZEOF_XML_CHAR && feature->value == 1)
        saw_char_size = 1;
    }
    terminated = features[0].feature != XML_FEATURE_END;
  }
  CHECK(saw_char_size, "size-of XML_Char feature");
  CHECK(terminated, "feature list has entries");

  CHECK(XML_ParserCreate("UTF-8") == NULL, "encoding hint refused");
  CHECK(XML_ParserCreateNS(NULL, ':') == NULL, "namespace parser refused");

  XML_Parser parser = XML_ParserCreate(NULL);
  CHECK(parser != NULL, "parser created");
  if (parser != NULL) {
    XML_SetUserData(parser, &sentinel);
    expected_user_data = &sentinel;
    CHECK(XML_GetUserData(parser) == &sentinel, "XML_GetUserData offset zero");
    XML_SetElementHandler(parser, on_start, on_end);
    current_parser = parser;
    CHECK_EQ_INT(XML_GetSpecifiedAttributeCount(parser), 0,
                 "no specified attributes outside a start callback");
    CHECK(XML_SetParamEntityParsing(parser, XML_PARAM_ENTITY_PARSING_NEVER) == 1,
          "safe parameter-entity setting accepted");

    parse_active = 1;
    enum XML_Status status =
        XML_Parse(parser, document, (int)strlen(document), 1);
    parse_active = 0;

    CHECK_EQ_INT(status, XML_STATUS_OK, "one-chunk parse status");
    CHECK_EQ_INT(XML_GetErrorCode(parser), XML_ERROR_NONE, "no error");
    CHECK_EQ_INT(callback_count, 4, "four element callbacks");
    CHECK(callback_order[0] == 'S' && callback_order[1] == 's' &&
              callback_order[2] == 'e' && callback_order[3] == 'E',
          "document-order start/end callbacks");
    CHECK_EQ_INT(callback_outside_parse, 0, "callbacks ran inside XML_Parse");
    CHECK(XML_GetCurrentByteIndex(parser) >= 0, "byte index recorded");
    CHECK(XML_GetCurrentLineNumber(parser) >= 1, "line recorded");

    XML_ParsingStatus parsing;
    XML_GetParsingStatus(parser, &parsing);
    CHECK_EQ_INT(parsing.parsing, XML_FINISHED, "parser finished");
    CHECK(parsing.finalBuffer == XML_TRUE, "final buffer recorded");

    XML_ParserFree(parser);
    XML_ParserFree(parser); /* immediate repeat is ignored */
  }

  parser = XML_ParserCreate(NULL);
  CHECK(parser != NULL, "buffer parser created");
  if (parser != NULL) {
    CHECK_EQ_INT(XML_ParseBuffer(parser, 0, 1), XML_STATUS_ERROR,
                 "ParseBuffer without a reservation refused");
    CHECK_EQ_INT(XML_GetErrorCode(parser), XML_ERROR_NO_BUFFER,
                 "no-buffer error reported");
    XML_ParserFree(parser);
  }

  parser = XML_ParserCreate(NULL);
  CHECK(parser != NULL, "buffer parser created with reservation");
  if (parser != NULL) {
    char *buffer = (char *)XML_GetBuffer(parser, 4);
    CHECK(buffer != NULL, "GetBuffer returned a reservation");
    if (buffer != NULL) {
      memcpy(buffer, "<r/>", 4);
      CHECK_EQ_INT(XML_ParseBuffer(parser, 4, 1), XML_STATUS_OK,
                   "ParseBuffer consumed the reservation");
    }
    XML_ParserFree(parser);
  }

  parser = XML_ParserCreate(NULL);
  CHECK(parser != NULL, "error-path parser created");
  if (parser != NULL) {
    enum XML_Status status = XML_Parse(parser, "<a>", 3, 1);
    CHECK_EQ_INT(status, XML_STATUS_ERROR, "unclosed document rejected");
    CHECK(XML_GetErrorCode(parser) != XML_ERROR_NONE, "error code set");
    CHECK(XML_ErrorString(XML_GetErrorCode(parser)) != NULL,
          "known error has a string");
    CHECK(XML_ErrorString((enum XML_Error)999) == NULL,
          "unknown error has no string");
    CHECK_EQ_INT(XML_Parse(parser, "<a/>", 4, 1), XML_STATUS_ERROR,
                 "terminal parse stays terminal");
    XML_ParserFree(parser);
  }

  parser = XML_ParserCreate(NULL);
  CHECK(parser != NULL, "rich parser created");
  if (parser != NULL) {
    const char *rich_document =
        "<?xml version=\"1.0\"?><r a=\"b\">hi<![CDATA[cd]]><!--c--><?pi d?><e/></r>";
    memset(&rich, 0, sizeof(rich));
    current_parser = parser;
    XML_SetUserData(parser, &rich);
    XML_SetElementHandler(parser, rich_start, rich_end);
    XML_SetCharacterDataHandler(parser, rich_text);
    XML_SetCdataSectionHandler(parser, rich_cdata_start, rich_cdata_end);
    XML_SetCommentHandler(parser, rich_comment);
    XML_SetProcessingInstructionHandler(parser, rich_pi);
    XML_SetXmlDeclHandler(parser, rich_decl);
    parse_active = 1;
    enum XML_Status status =
        XML_Parse(parser, rich_document, (int)strlen(rich_document), 1);
    parse_active = 0;
    CHECK_EQ_INT(status, XML_STATUS_OK, "rich document accepted");
    CHECK_EQ_INT(rich.starts, 2, "rich start callbacks");
    CHECK_EQ_INT(rich.ends, 2, "rich end callbacks");
    CHECK_EQ_INT(rich.texts, 2, "rich text callbacks");
    CHECK_EQ_INT(rich.cdata_starts, 1, "rich CDATA start");
    CHECK_EQ_INT(rich.cdata_ends, 1, "rich CDATA end");
    CHECK_EQ_INT(rich.comments, 1, "rich comment");
    CHECK_EQ_INT(rich.pis, 1, "rich PI");
    CHECK_EQ_INT(rich.decls, 1, "rich declaration");
    CHECK(rich.saw_attr && rich.saw_text_hi && rich.saw_text_cd &&
              rich.saw_comment && rich.saw_pi && rich.saw_decl,
          "rich handler payloads");
    XML_ParserFree(parser);
  }

  Detector control = {0, 0, NULL};
  Detector poisoned = {0, 0, NULL};
  control.expected = &control;
  poisoned.expected = &poisoned;

  XML_Parser control_parser = XML_ParserCreate(NULL);
  CHECK(control_parser != NULL, "control parser created");
  if (control_parser != NULL) {
    XML_SetUserData(control_parser, &control);
    XML_SetElementHandler(control_parser, detect_start, detect_end);
    CHECK_EQ_INT(XML_Parse(control_parser, "<r/>", 4, 1), XML_STATUS_OK,
                 "control parse accepted");
    CHECK_EQ_INT(control.starts, 1, "control saw one start");
    CHECK_EQ_INT(control.ends, 1, "control saw one end");
  }

  XML_Parser poisoned_parser = XML_ParserCreate(NULL);
  CHECK(poisoned_parser != NULL, "poisoned parser created");
  if (poisoned_parser != NULL) {
    XML_SetUserData(poisoned_parser, &poisoned);
    XML_SetElementHandler(poisoned_parser, detect_start, detect_end);
    XML_SetExternalEntityRefHandler(poisoned_parser, entity_stub);
    CHECK_EQ_INT(XML_Parse(poisoned_parser, "<r/>", 4, 1), XML_STATUS_ERROR,
                 "unsupported handler poisons the parse");
    CHECK_EQ_INT(XML_GetErrorCode(poisoned_parser), XML_ERROR_UNSUPPORTED_FEATURE,
                 "unsupported feature error");
    CHECK_EQ_INT(poisoned.starts, 0, "poisoned parser delivered no start");
    CHECK_EQ_INT(poisoned.ends, 0, "poisoned parser delivered no end");
    CHECK_EQ_INT(control.starts, 1, "control detector still observed its parser");
    CHECK_EQ_INT(control.ends, 1, "control detector still observed its parser");
  }
  if (control_parser != NULL)
    XML_ParserFree(control_parser);
  if (poisoned_parser != NULL)
    XML_ParserFree(poisoned_parser);

  if (failures != 0) {
    fprintf(stderr, "c-abi-smoke: %d failure(s)\n", failures);
    return 1;
  }
  printf("c-abi-smoke: OK\n");
  return 0;
}
