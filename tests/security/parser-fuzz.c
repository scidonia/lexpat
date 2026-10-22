/*
 * libFuzzer target for the pure Lean one-shot parser.
 *
 * The fuzzer input becomes a `ByteArray` and `lexpat_fuzz_parse` calls
 * `LexPat.parseDocument` under the default budgets. The result is consumed so
 * the parse cannot be optimized away. No C ABI, file, network or clock is
 * involved; the target only observes parser return values and sanitizer
 * termination.
 */

#include <lean/lean.h>

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define LEXPAT_FUZZ_MAX_INPUT 8192

extern lean_object *initialize_lexpat_tests_FuzzParser(uint8_t builtin);
extern uint32_t lexpat_fuzz_parse(lean_object *bytes);

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  lean_object *result = initialize_lexpat_tests_FuzzParser(1);
  if (!lean_io_result_is_ok(result)) {
    lean_io_result_show_error(result);
    lean_dec_ref(result);
    abort();
  }
  lean_dec_ref(result);
  lean_io_mark_end_initialization();
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > LEXPAT_FUZZ_MAX_INPUT)
    return 0;
  lean_object *input = lean_alloc_sarray(1, size, size);
  if (input == NULL)
    return 0;
  if (size > 0)
    memcpy(lean_sarray_cptr(input), data, size);
  uint32_t events = lexpat_fuzz_parse(input);
  (void)events;
  return 0;
}
