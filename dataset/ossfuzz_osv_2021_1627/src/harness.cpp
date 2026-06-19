/*
 * OSV-2021-1627 standalone harness (CVE-2021-45942)
 * Heap-buffer-overflow WRITE 2 in LineCompositeTask::execute
 *
 * Based on openexr's oss-fuzz target: openexr_exrcheck_fuzzer.cc
 * The fuzzer calls checkOpenEXRFile() which opens DeepScanLineInputFile
 * and triggers LineCompositeTask::execute via ThreadPool::addGlobalTask.
 *
 * Root cause: In readSampleCountForLineBlock, only sampleCountTableDataSize
 * was validated against compressorMaxDataSize. packedDataSize and
 * unpackedDataSize were not checked, allowing crafted EXR files to bypass
 * validation and cause an OOB write in the decompression pipeline.
 *
 * Fix: Added bounds checks for packedDataSize and unpackedDataSize.
 * Changed compressorMaxDataSize from int to uint64_t.
 * Commit: db217f29dfb24f6b4b5100c24ac5e7490e1c57d0
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
