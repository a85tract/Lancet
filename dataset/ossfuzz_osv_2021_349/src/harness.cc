/*
 * Flatbuffers verifier fuzzer harness for OSV-2021-349.
 *
 * Bug: Heap-buffer-overflow WRITE in FlatBufferBuilder::ForceVectorAlignment
 * Crash stack: vector_downward::fill -> FlatBufferBuilder::PreAlign -> ForceVectorAlignment
 * Fix: fee095410b0969765b5c2545c10e585f69e961b0 - Validate force_align attribute on all possible paths
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
