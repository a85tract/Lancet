/*
 * Flatbuffers verifier fuzzer harness for OSV-2021-308.
 *
 * Bug: Heap-buffer-overflow READ in JsonPrinter::GenFieldOffset
 * Crash stack: JsonPrinter::GenFieldOffset -> GenStruct -> GenerateText
 * Fix: 6f3e45eca1fde7a68cb72fd4499a3647f719c9db - Implement Rust object API defaults, fixing GenFieldOffset OOB
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
