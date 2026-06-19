/*
 * OSV-2018-109: Heap use-after-free in ssl_get_prev_session (OpenSSL)
 *
 * Bug: In tls_decrypt_ticket() in ssl/t1_lib.c, when a decrypted session
 * ticket fails the consistency check (slen != 0 after d2i_SSL_SESSION),
 * the code calls SSL_SESSION_free(sess) but does NOT set sess = NULL.
 * Control falls through to the end label where *psess = sess assigns
 * the dangling pointer. The caller ssl_get_prev_session() then
 * dereferences it, triggering a heap-use-after-free READ of 4 bytes.
 *
 * Fix: Added sess = NULL; after SSL_SESSION_free(sess); in the
 * consistency check failure path.
 *
 * Fix commit: 5f96a95e2562f026557f625e50c052e77c7bc2e8
 * Parent (vulnerable): a925e7dbf4c3bb01365c961df86da3ebfa1a6c27
 *
 * This file provides a main() driver for OpenSSL's fuzz/server.c target,
 * which defines LLVMFuzzerTestOneInput(). We read the input file and
 * pass it to the fuzzer entry point.
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
