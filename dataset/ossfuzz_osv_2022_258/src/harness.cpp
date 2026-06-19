/*
 * OSV-2022-258 standalone harness
 * Heap-double-free in Imf_3_1::RgbaInputFile::~RgbaInputFile
 *
 * Based on openexr's oss-fuzz target: openexr_exrcheck_fuzzer.cc
 * The fuzzer calls checkOpenEXRFile() which exercises the C++ API
 * (InputFile, RgbaInputFile, DeepScanLineInputFile, etc.).
 *
 * Root cause: In RgbaInputFile::setPartAndLayer(), _inputPart was
 * deleted and immediately re-assigned via new. If the new allocation
 * threw an exception, the destructor would delete _inputPart again
 * (double-free on the dangling pointer).
 *
 * Fix: Set _inputPart = nullptr after delete.
 * Commit: 0b27d291b04924d5228b020247dbd02031d2aa51
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
    /* checkOpenEXRFile(data, size, reduceMemory, reduceTime, useCore) */
    checkOpenEXRFile((const char *)data, size, true, true, false);
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

    fprintf(stderr, "[harness] Running checkOpenEXRFile with %ld bytes\n", len);
    fuzz_one(buf, (size_t)len);
    fprintf(stderr, "[harness] Done\n");

    free(buf);
    return 0;
}
