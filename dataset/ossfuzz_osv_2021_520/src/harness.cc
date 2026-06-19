/*
 * Flatbuffers verifier fuzzer harness for OSV-2021-520.
 *
 * Bug: Heap-buffer-overflow READ in flatbuffers::EscapeString via flexbuffers
 * Crash stack: EscapeString -> flexbuffers::Reference::ToString -> AppendToString<Vector>
 * Fix: 4d0e9a870610fb3d50d03b110dcd18388ed30bdd - Turn off nested FlatBuffers/FlexBuffers for the fuzzer
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
