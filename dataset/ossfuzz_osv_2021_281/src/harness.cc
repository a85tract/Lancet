/*
 * Flatbuffers verifier fuzzer harness for OSV-2021-281.
 *
 * Bug: Heap-buffer-overflow READ in flatbuffers tokenizer / GetMutableRoot
 * Crash stack: GetMutableRoot<Table> -> GetRoot<Table> -> JsonPrinter::GenFieldOffset
 * Fix: 0e453ac3524100e7d78481d75e44ad3515dde0c1 - Add kTokenNumericConstant token for correct parsing of signed numeric constants
 *
 * This harness feeds raw binary data to the flatbuffers Verifier via
 * VerifyMonsterBuffer(), exercising the verifier's bounds-checking code
 * paths that are vulnerable at this commit.
 */
#include <stddef.h>
#include <stdint.h>
#include <string>

#include "monster_test_generated.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    flatbuffers::Verifier verifier(data, size);
    MyGame::Example::VerifyMonsterBuffer(verifier);
    return 0;
}
