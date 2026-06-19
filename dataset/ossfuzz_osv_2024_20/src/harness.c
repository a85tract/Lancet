/*
 * harness.c: Standalone wrapper for the htslib hts_open fuzzer.
 *
 * Reads a file from disk and passes it to LLVMFuzzerTestOneInput.
 * This allows running the fuzzer reproducer without a fuzzing engine.
 *
 * OSV-2024-20: heap-buffer-overflow READ in bam_aux_get -> process_one_read -> cram_encode_container
 * OSS-Fuzz bug ID: 65820
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* Forward declaration from fuzz harness */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
    FILE *f;
    uint8_t *buf;
    long len;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input-file>\n", argv[0]);
        return 1;
    }

    f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    len = ftell(f);
    fseek(f, 0, SEEK_SET);

    buf = (uint8_t *)malloc(len);
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
