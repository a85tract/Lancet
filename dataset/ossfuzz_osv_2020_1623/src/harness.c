/*
 * harness.c: Standalone wrapper for the libxml2 xml fuzzer.
 *
 * Reads a file from disk and passes it to LLVMFuzzerTestOneInput.
 * This allows running the fuzzer reproducer without a fuzzing engine.
 *
 * OSV-2020-1623: heap-use-after-free in xmlXIncludeIncludeNode
 * OSS-Fuzz bug ID: 24925
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Forward declarations from fuzz harness */
int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const char *data, size_t size);

int main(int argc, char **argv) {
    FILE *f;
    char *buf;
    long len;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input-file>\n", argv[0]);
        return 1;
    }

    LLVMFuzzerInitialize(&argc, &argv);

    f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);

    buf = (char *)malloc(len);
    if (!buf) {
        perror("malloc");
        fclose(f);
        return 1;
    }

    if (fread(buf, 1, len, f) != (size_t)len) {
        perror("fread");
        free(buf);
        fclose(f);
        return 1;
    }
    fclose(f);

    fprintf(stderr, "[harness] Running with %ld bytes of input\n", len);
    LLVMFuzzerTestOneInput(buf, len);
    fprintf(stderr, "[harness] Done\n");

    free(buf);
    return 0;
}
