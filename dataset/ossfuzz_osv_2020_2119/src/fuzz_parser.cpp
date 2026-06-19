/*
 * JSON parser fuzzer for simdjson
 *
 * OSV-2020-2119: UNKNOWN READ in numberparsing.h
 * The bug was in compute_float_64() which could be called with
 * out-of-bounds exponent values, causing a read overflow in the
 * power-of-ten lookup table.
 * OSS-Fuzz issue: 26858
 * Fix commit: 0b82f071
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
