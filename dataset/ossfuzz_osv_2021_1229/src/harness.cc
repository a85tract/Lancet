/*
 * Flatbuffers verifier fuzzer harness for OSV-2021-1229.
 *
 * Bug: Heap-buffer-overflow READ in JsonPrinter::GenFieldOffset (nested FB)
 * Crash stack: JsonPrinter::GenFieldOffset -> GenStruct -> GenerateText
 * Fix: 0fadaf391d55aac675e6cff122c83bf52eeabc2a - Enable verifier on nested_flatbuffers
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
