/*
 * OSV-2022-1098 standalone harness
 * Heap-buffer-overflow READ in fasthuf_initialize (internal_huf.c)
 *
 * Based on openexr's oss-fuzz target: openexr_exrcorecheck_fuzzer.cc
 * The fuzzer calls checkOpenEXRFile() with useCore=true to exercise
 * the C Core API path (Huffman decoding -> fasthuf_initialize).
 *
 * Root cause: Missing bounds check in fasthuf_initialize() when
 * processing LONG_ZEROCODE_RUN entries. The code reads 8 bits via
 * fasthuf_read_bits without first verifying that currByte < topByte,
 * allowing an out-of-bounds read on truncated Huffman table data.
 *
 * Fix: Added guard check (currByte >= topByte) before the
 * fasthuf_read_bits call in the LONG_ZEROCODE_RUN branch.
 * Commit: 063a881e7a5cd57156dbd0c9b6ad4d30f7023e55
 *
 * Build:
 *   g++ -g -O0 -fsanitize=address -fno-omit-frame-pointer \
 *       -I openexr/install/include/OpenEXR \
 *       -I openexr/install/include/Imath \
 *       -o harness_asan harness.cpp \
 *       openexr/build/lib/libOpenEXR.a \
 *       openexr/build/lib/libOpenEXRUtil.a \
 *       openexr/build/lib/libOpenEXRCore.a \
 *       openexr/build/lib/libIlmThread.a \
 *       openexr/build/lib/libIex.a \
 *       openexr/build/lib/libImath.a \
 *       -lz -lpthread -ldl
 *
 * Usage:
 *   ./harness_asan poc.exr
 */

#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>

#include "ImfCheckFile.h"
#include "ImfNamespace.h"

using OPENEXR_IMF_NAMESPACE::checkOpenEXRFile;

static int fuzz_one(const uint8_t *data, size_t size)
{
    /* checkOpenEXRFile(data, size, reduceMemory, reduceTime, useCore)
     * useCore=true exercises the C Core API path where fasthuf_initialize lives */
    checkOpenEXRFile((const char *)data, size, true, true, true);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input-file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (len <= 0) {
        fprintf(stderr, "Empty or invalid file\n");
        fclose(f);
        return 1;
    }

    uint8_t *buf = (uint8_t *)malloc(len);
    if (!buf) {
        perror("malloc");
        fclose(f);
        return 1;
    }

    if ((long)fread(buf, 1, len, f) != len) {
        perror("fread");
        free(buf);
        fclose(f);
        return 1;
    }
    fclose(f);

    fprintf(stderr, "[harness] Running checkOpenEXRFile (core) with %ld bytes\n", len);
    fuzz_one(buf, (size_t)len);
    fprintf(stderr, "[harness] Done\n");

    free(buf);
    return 0;
}
