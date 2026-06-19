/*
 * JSON parser fuzzer for simdjson
 *
 * OSV-2020-2108: Stack-buffer-overflow in simdjson::internal::decimal_right_shift
 * The bug was in parse_decimal() in from_chars.cpp. The condition
 * answer.num_digits + 1 < max_digits allowed one extra digit to be written,
 * causing a stack buffer overflow when the digit array was at capacity.
 * OSS-Fuzz issue: 26773
 * Fix commit: a8bf10ea
 */
#include "simdjson.h"
#include <cstddef>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    simdjson::dom::parser parser;
    simdjson_unused simdjson::dom::element elem;
    simdjson_unused auto error = parser.parse(Data, Size).get(elem);
    return 0;
}
