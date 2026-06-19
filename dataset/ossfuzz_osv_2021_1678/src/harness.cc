/*
 * Flatbuffers verifier fuzzer harness for OSV-2021-1678.
 *
 * Bug: Heap-buffer-overflow READ in EscapeString via flexbuffers ToString
 * Crash stack: EscapeString -> flexbuffers::Reference::ToString -> AppendToString<Vector>
 * Fix: 4264daadd2487cd3e63cf83f5dca3f0ccc53af64 - FlexBuffers fuzzer fixes - fix verifier and string comparator
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
