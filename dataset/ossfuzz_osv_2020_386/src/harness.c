/*
 * OSV-2020-386: Heap-buffer-overflow WRITE in OPENSSL_strlcpy (OpenSSL)
 *
 * Bug: In ERR_add_error_vdata() in crypto/err/err.c, multiple error data
 * strings are concatenated into a heap-allocated err_data buffer. The
 * reallocation logic has a size miscalculation: len tracks accumulated
 * string lengths, but the check if(len > size) fires too late --
 * OPENSSL_strlcat can be called with a buffer that is already too small.
 * This leads to OPENSSL_strlcat -> OPENSSL_strlcpy writing 1 byte past
 * the heap buffer.
 *
 * Trigger: A malformed OpenSSL config file that generates error messages
 * with long section/key names, causing ERR_add_error_data() to be called
 * with strings that overflow the initial 81-byte error buffer.
 *
 * Fix commit: 036913b1076da41f257c640a5e6230476c647eff
 * Parent (vulnerable): 49c6434673ca5e9413062851979cf6ed126c9f1c
 *
 * This file provides a main() driver for OpenSSL's fuzz/conf.c target.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* Prototypes for the fuzz target (OpenSSL uses FuzzerTestOneInput) */
int FuzzerInitialize(int *argc, char ***argv);
int FuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz <= 0) {
        fprintf(stderr, "Empty or invalid file\n");
        fclose(f);
        return 1;
    }

    uint8_t *data = (uint8_t *)malloc(sz);
    if (!data) {
        perror("malloc");
        fclose(f);
        return 1;
    }

    size_t nread = fread(data, 1, sz, f);
    fclose(f);

    if ((long)nread != sz) {
        fprintf(stderr, "Short read\n");
        free(data);
        return 1;
    }

    fprintf(stderr, "[harness] Initializing fuzzer...\n");
    FuzzerInitialize(&argc, &argv);

    fprintf(stderr, "[harness] Processing %ld bytes from %s\n", sz, argv[1]);
    FuzzerTestOneInput(data, (size_t)sz);
    fprintf(stderr, "[harness] Done\n");

    free(data);
    return 0;
}
