/*
 * Flatbuffers verifier fuzzer harness for OSV-2021-1695.
 *
 * Bug: Heap-buffer-overflow READ in flexbuffers::Verifier::VerifyRef
 * Crash stack: flexbuffers::Verifier::VerifyRef -> VerifyVector -> VerifyRef
 * Fix: 5b0d4911278eec507fe5e621bd81fd7db42aa4db - Updated FlexBuffers fuzzer - change vector<bool> to vector<uint8_t>
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
