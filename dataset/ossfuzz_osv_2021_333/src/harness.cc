/*
 * Flatbuffers verifier fuzzer harness for OSV-2021-333.
 *
 * Bug: Heap-buffer-overflow READ in Table::GetVTable / ReadScalar<int>
 * Crash stack: ReadScalar<int> -> Table::GetVTable -> Table::GetOptionalFieldOffset
 * Fix: 8fb8c2ce1dff00bc1455aba0770eb7eae9a06ece - Fix keyword escaping in C# codegen, correcting generated verifier code
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
