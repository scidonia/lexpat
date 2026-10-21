#!/usr/bin/env bash
# Memory checks for the C ABI artifact.
#
# Two detector paths over the same client cases: callbacks, supported handler
# registration, buffer reservations, multiple parsers, error exits,
# free-in-callback, re-entrant parse attempts and a released handle.
#
#   ASan/UBSan path: the C shim and the client are instrumented and linked with
#   the prebuilt Lean module objects. The pinned Lean runtime is not
#   instrumented, and leak detection is disabled on this path because the
#   artifact has no runtime-finalize step; the Valgrind path covers process
#   allocations.
#
#   Valgrind path: the unsanitized client is linked against the shipped
#   `.lake/build/lib/liblexpat.so.1` and run with definite-leak checking over
#   the whole process, including the pinned Lean runtime.
#
# Neither detector proves memory safety for every input: ASan sees only
# instrumented C code and its interceptors, Valgrind sees only reachable
# execution with its own roots, and no resident-memory claim is made from
# address-space readings.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lib="$repo/.lake/build/lib"

if command -v lake >/dev/null 2>&1; then
  (cd "$repo" && lake build lexpatCAbi)
else
  (cd "$repo" && nix develop -c lake build lexpatCAbi)
fi

for artifact in "$lib/liblexpat.so.1" "$repo/include/expat.h"; do
  if [ ! -e "$artifact" ]; then
    echo "c-abi-memory: missing $artifact" >&2
    exit 1
  fi
done

lean_libdir="$(lean --print-libdir)"
lean_include="$(dirname "$(dirname "$lean_libdir")")/include"
if [ ! -f "$lean_include/lean/lean.h" ]; then
  echo "c-abi-memory: lean.h not found under $lean_include" >&2
  exit 1
fi
objs=()
while IFS= read -r obj; do
  objs+=("$obj")
done < <(find "$repo/.lake/build/ir/LexPat" -name '*.c.o.export' -not -path '*/Exe/*' | sort)
if [ "${#objs[@]}" -eq 0 ]; then
  echo "c-abi-memory: no Lean module objects were found" >&2
  exit 1
fi

tmp="$(mktemp -d /tmp/lexpat-cabi-memory.XXXXXX)"
if [ -z "$tmp" ] || [ ! -d "$tmp" ]; then
  echo "c-abi-memory: mktemp did not produce a directory" >&2
  exit 1
fi
trap 'rm -rf -- "$tmp"' EXIT

cat >"$tmp/memory-client.c" <<'CLIENT'
/*
 * Memory-check client for the C ABI artifact. Every case keeps its pointers
 * inside their allocations; the released-handle cases rely only on the
 * registry check, never on dereferencing a freed pointer.
 */

#include <expat.h>

#include <stdio.h>
#include <string.h>

static int failures;
static int starts;
static int ends;
static int texts;
static int comments;
static int pis;
static int cdata_starts;
static int cdata_ends;
static int decls;
static XML_Parser reentrant_parser;

#define CHECK(condition, message)                                              \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, "memory-client: FAIL: %s\n", (message));                 \
      failures++;                                                              \
    }                                                                          \
  } while (0)

static void XMLCALL on_start(void *userData, const XML_Char *name,
                             const XML_Char **atts) {
  (void)userData;
  (void)name;
  (void)atts;
  starts++;
}

static void XMLCALL on_end(void *userData, const XML_Char *name) {
  (void)userData;
  (void)name;
  ends++;
}

static void XMLCALL on_chars(void *userData, const XML_Char *data, int len) {
  (void)userData;
  (void)data;
  (void)len;
  texts++;
}

static void XMLCALL on_comment(void *userData, const XML_Char *data) {
  (void)userData;
  (void)data;
  comments++;
}

static void XMLCALL on_pi(void *userData, const XML_Char *target,
                          const XML_Char *data) {
  (void)userData;
  (void)target;
  (void)data;
  pis++;
}

static void XMLCALL on_cdata_start(void *userData) {
  (void)userData;
  cdata_starts++;
}

static void XMLCALL on_cdata_end(void *userData) {
  (void)userData;
  cdata_ends++;
}

static void XMLCALL on_decl(void *userData, const XML_Char *version,
                            const XML_Char *encoding, int standalone) {
  (void)userData;
  (void)version;
  (void)encoding;
  (void)standalone;
  decls++;
}

static int XMLCALL refusing_entity(XML_Parser parser, const XML_Char *context,
                                   const XML_Char *base, const XML_Char *systemId,
                                   const XML_Char *publicId) {
  (void)parser;
  (void)context;
  (void)base;
  (void)systemId;
  (void)publicId;
  return 0;
}

static void install(XML_Parser parser) {
  XML_SetElementHandler(parser, on_start, on_end);
  XML_SetCharacterDataHandler(parser, on_chars);
  XML_SetCommentHandler(parser, on_comment);
  XML_SetProcessingInstructionHandler(parser, on_pi);
  XML_SetCdataSectionHandler(parser, on_cdata_start, on_cdata_end);
  XML_SetXmlDeclHandler(parser, on_decl);
  XML_SetParamEntityParsing(parser, XML_PARAM_ENTITY_PARSING_NEVER);
}

static void reset_counts(void) {
  starts = ends = texts = comments = pis = cdata_starts = cdata_ends = decls = 0;
}

static void exercise_success(void) {
  const char *document =
      "<?xml version=\"1.0\"?><!--lead--><?target data?><r a=\"1\">"
      "text<![CDATA[raw]]><c/><!--inner--><?q?></r>";
  XML_Parser parser = XML_ParserCreate(NULL);
  int sentinel = 0;
  reset_counts();
  CHECK(parser != NULL, "success parser created");
  if (parser == NULL)
    return;
  XML_SetUserData(parser, &sentinel);
  install(parser);
  CHECK(XML_Parse(parser, document, (int)strlen(document), 1) == XML_STATUS_OK,
        "supported document accepted");
  CHECK(starts == 2 && ends == 2, "element callbacks balanced");
  CHECK(texts >= 1 && comments == 2 && pis == 2, "rich callbacks delivered");
  CHECK(cdata_starts == 1 && cdata_ends == 1, "CDATA callbacks delivered");
  CHECK(decls == 1, "declaration callback delivered");
  XML_ParserFree(parser);
}

static void exercise_errors(void) {
  XML_Parser parser = XML_ParserCreate(NULL);
  CHECK(parser != NULL, "error parser created");
  if (parser == NULL)
    return;
  install(parser);
  CHECK(XML_Parse(parser, "<a><b></a>", 10, 1) == XML_STATUS_ERROR,
        "mismatched document rejected");
  CHECK(XML_ErrorString(XML_GetErrorCode(parser)) != NULL, "error string present");
  CHECK(XML_Parse(parser, "<a/>", 4, 1) == XML_STATUS_ERROR,
        "terminal parser stays terminal");
  XML_ParserFree(parser);

  parser = XML_ParserCreate(NULL);
  CHECK(parser != NULL, "buffer parser created");
  if (parser == NULL)
    return;
  CHECK(XML_ParseBuffer(parser, 4, 1) == XML_STATUS_ERROR,
        "ParseBuffer without reservation refused");
  XML_ParserFree(parser);

  parser = XML_ParserCreate(NULL);
  CHECK(parser != NULL, "oversize parser created");
  if (parser == NULL)
    return;
  CHECK(XML_GetBuffer(parser, -1) == NULL, "negative reservation refused");
  XML_ParserFree(parser);
  XML_ParserFree(parser); /* immediate repeat */
}

static void exercise_buffers(void) {
  XML_Parser parser = XML_ParserCreate(NULL);
  char *buffer;
  reset_counts();
  CHECK(parser != NULL, "buffer path parser created");
  if (parser == NULL)
    return;
  XML_SetElementHandler(parser, on_start, on_end);
  buffer = (char *)XML_GetBuffer(parser, 4);
  CHECK(buffer != NULL, "reservation returned");
  if (buffer != NULL)
    memcpy(buffer, "<r/>", 4);
  CHECK(XML_ParseBuffer(parser, 4, 1) == XML_STATUS_OK, "reservation parsed");
  CHECK(starts == 1 && ends == 1, "reservation callbacks");
  XML_ParserFree(parser);

  parser = XML_ParserCreate(NULL);
  CHECK(parser != NULL, "outstanding reservation parser created");
  if (parser == NULL)
    return;
  buffer = (char *)XML_GetBuffer(parser, 64);
  CHECK(buffer != NULL, "large reservation returned");
  if (buffer != NULL)
    memset(buffer, 'x', 64);
  XML_ParserFree(parser); /* reservation must be released with the parser */

  parser = XML_ParserCreate(NULL);
  CHECK(parser != NULL, "replaced reservation parser created");
  if (parser == NULL)
    return;
  buffer = (char *)XML_GetBuffer(parser, 8);
  if (buffer != NULL)
    memcpy(buffer, "<r", 2);
  buffer = (char *)XML_GetBuffer(parser, 8);
  if (buffer != NULL)
    memcpy(buffer, "/>", 2);
  CHECK(XML_ParseBuffer(parser, 2, 1) == XML_STATUS_ERROR,
        "replaced reservation alone is invalid");
  XML_ParserFree(parser);
}

static void exercise_unsupported(void) {
  XML_Parser parser = XML_ParserCreate(NULL);
  CHECK(parser != NULL, "unsupported parser created");
  if (parser == NULL)
    return;
  install(parser);
  XML_SetExternalEntityRefHandler(parser, refusing_entity);
  CHECK(XML_GetErrorCode(parser) == XML_ERROR_UNSUPPORTED_FEATURE,
        "unsupported registration poisons");
  CHECK(XML_Parse(parser, "<r/>", 4, 1) == XML_STATUS_ERROR,
        "poisoned parser refuses input");
  XML_ParserFree(parser);
}

static void exercise_many(void) {
  int index;
  for (index = 0; index < 64; index++) {
    XML_Parser parser = XML_ParserCreate(NULL);
    CHECK(parser != NULL, "bulk parser created");
    if (parser == NULL)
      return;
    install(parser);
    CHECK(XML_Parse(parser, "<r><c/></r>", 11, 1) == XML_STATUS_OK,
          "bulk document accepted");
    XML_ParserFree(parser);
  }

  {
    XML_Parser first = XML_ParserCreate(NULL);
    XML_Parser second = XML_ParserCreate(NULL);
    int one = 1;
    int two = 2;
    CHECK(first != NULL && second != NULL, "interleaved parsers created");
    if (first != NULL && second != NULL) {
      XML_SetUserData(first, &one);
      XML_SetUserData(second, &two);
      install(first);
      install(second);
      CHECK(XML_Parse(first, "<a>", 3, 0) == XML_STATUS_OK, "first prefix");
      CHECK(XML_Parse(second, "<b>", 3, 0) == XML_STATUS_OK, "second prefix");
      CHECK(XML_Parse(first, "</a>", 4, 1) == XML_STATUS_OK, "first finish");
      CHECK(XML_Parse(second, "</b>", 4, 1) == XML_STATUS_OK, "second finish");
    }
    if (first != NULL)
      XML_ParserFree(first);
    if (second != NULL)
      XML_ParserFree(second);
  }
}

static void XMLCALL freeing_start(void *userData, const XML_Char *name,
                                  const XML_Char **atts) {
  (void)name;
  (void)atts;
  XML_ParserFree((XML_Parser)userData);
}

static void exercise_free_in_callback(void) {
  XML_Parser parser = XML_ParserCreate(NULL);
  CHECK(parser != NULL, "free-in-callback parser created");
  if (parser == NULL)
    return;
  XML_SetUserData(parser, parser);
  XML_SetStartElementHandler(parser, freeing_start);
  CHECK(XML_Parse(parser, "<r/>", 4, 1) == XML_STATUS_ERROR,
        "free in callback aborts the parse");
}

static void XMLCALL reentrant_start(void *userData, const XML_Char *name,
                                    const XML_Char **atts) {
  (void)name;
  (void)atts;
  (void)userData;
  CHECK(XML_Parse(reentrant_parser, "<x/>", 4, 0) == XML_STATUS_ERROR,
        "re-entrant parse refused");
  CHECK(XML_GetErrorCode(reentrant_parser) == XML_ERROR_REENTRANT_CALL,
        "re-entrant parse reports REENTRANT_CALL");
}

static void exercise_reentrant(void) {
  XML_Parser parser = XML_ParserCreate(NULL);
  CHECK(parser != NULL, "re-entrant parser created");
  if (parser == NULL)
    return;
  reentrant_parser = parser;
  XML_SetStartElementHandler(parser, reentrant_start);
  CHECK(XML_Parse(parser, "<r/>", 4, 1) == XML_STATUS_ERROR,
        "re-entrant callback fails the outer parse");
  XML_ParserFree(parser);
}

static void exercise_released_handle(void) {
  XML_Parser parser = XML_ParserCreate(NULL);
  CHECK(parser != NULL, "released handle parser created");
  if (parser == NULL)
    return;
  XML_ParserFree(parser);
  CHECK(XML_Parse(parser, "<r/>", 4, 1) == XML_STATUS_ERROR,
        "released handle refuses parsing");
  CHECK(XML_GetBuffer(parser, 1) == NULL, "released handle has no reservation");
  CHECK(XML_GetErrorCode(parser) == XML_ERROR_INVALID_ARGUMENT,
        "released handle is registry-checked");
  XML_ParserFree(parser);
}

int main(void) {
  exercise_success();
  exercise_errors();
  exercise_buffers();
  exercise_unsupported();
  exercise_many();
  exercise_free_in_callback();
  exercise_reentrant();
  exercise_released_handle();
  if (failures != 0) {
    fprintf(stderr, "memory-client: %d failures\n", failures);
    return 1;
  }
  printf("memory-client: OK\n");
  return 0;
}
CLIENT

echo "c-abi-memory: building the sanitizer path"
cc -std=c11 -Wall -Wextra -Werror -g -fsanitize=address,undefined \
  -fno-omit-frame-pointer -I"$repo/include" -I"$lean_include" \
  "$tmp/memory-client.c" "$repo/cabi/expat.c" "${objs[@]}" \
  -L"$lean_libdir" -lleanshared -pthread -Wl,-rpath,"$lean_libdir" \
  -o "$tmp/memory-asan"

echo "c-abi-memory: running under ASan/UBSan (leak detection off; no runtime finalize)"
ASAN_OPTIONS="detect_leaks=0:abort_on_error=1" \
UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1" \
  "$tmp/memory-asan"

echo "c-abi-memory: building the release client against the shared object"
cc -std=c11 -Wall -Wextra -Werror -I"$repo/include" \
  "$tmp/memory-client.c" -L"$lib" -llexpat -Wl,-rpath,"$lib" \
  -o "$tmp/memory-release"

if ! command -v valgrind >/dev/null 2>&1; then
  echo "c-abi-memory: valgrind is not available in this shell" >&2
  exit 1
fi

echo "c-abi-memory: running under Valgrind (definite leaks are errors)"
set +e
valgrind --error-exitcode=1 --leak-check=full --show-leak-kinds=definite \
  --errors-for-leak-kinds=definite --log-file="$tmp/valgrind.log" \
  "$tmp/memory-release"
valgrind_status=$?
set -e
cat "$tmp/valgrind.log"
if [ "$valgrind_status" -ne 0 ]; then
  echo "c-abi-memory: Valgrind reported an error (status $valgrind_status)" >&2
  exit 1
fi
if ! grep -q 'ERROR SUMMARY: 0 errors' "$tmp/valgrind.log"; then
  echo "c-abi-memory: Valgrind error summary is not zero" >&2
  exit 1
fi
if ! grep -q 'definitely lost: 0 bytes' "$tmp/valgrind.log"; then
  echo "c-abi-memory: definite leaks remain" >&2
  exit 1
fi

echo "c-abi-memory: OK (ASan/UBSan instrumented shim and client; Valgrind release client)"
echo "c-abi-memory: detector limits: ASan sees instrumented C and its interceptors," \
  "not the prebuilt Lean runtime; ASan leak detection is off because this artifact" \
  "has no runtime-finalize step; Valgrind covers process allocations including the" \
  "pinned Lean runtime but only for the executed paths; neither proves memory safety" \
  "for every input and neither measures resident memory."
