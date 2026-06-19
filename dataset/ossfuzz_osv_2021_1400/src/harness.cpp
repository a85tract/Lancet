/*
 * OSV-2021-1400 standalone harness
 * Heap-buffer-overflow WRITE in unpack_16bit
 *
 * Based on openexr's oss-fuzz target: openexr_exrcorecheck_fuzzer.cc
 * The fuzzer calls checkOpenEXRFile() with useCore=true to exercise
 * the C Core API path (exr_decoding_run -> unpack_16bit).
 *
 * Root cause: Insufficient validation of tile chunk metadata. A packed
 * size of zero or integer overflow in 32-bit arithmetic allowed malformed
 * EXR files to reach unpack_16bit with an incorrectly sized buffer.
 *
 * Fix: Changed unpacksize to uint64_t, rejected packed size <= 0,
 * added overflow checks for deep tile data.
 * Commit: 481bde4b2584ef018cca4a6538062efd0d5d0b88
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
     * useCore=true exercises the C Core API path where unpack_16bit lives */
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
