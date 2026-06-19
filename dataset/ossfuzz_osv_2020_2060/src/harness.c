/*
 * harness.c: Standalone wrapper for wolfSSL DH key generation fuzzer.
 *
 * Reads a file from disk and passes it to LLVMFuzzerTestOneInput.
 * This allows running the fuzzer reproducer without a fuzzing engine.
 *
 * OSV-2020-2060: heap-buffer-overflow WRITE 1 in fp_to_unsigned_bin_at_pos
 * OSS-Fuzz bug ID: 26295
 *
 * The bug is in GeneratePublicDh() which did not check if the DH result
 * fits in the output buffer before calling mp_to_unsigned_bin().
 * We trigger via DH key generation with crafted parameters that produce
 * an oversized result.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/tfm.h>

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
    DhKey key;
    WC_RNG rng;
    int ret;
    byte pub[64];   /* Intentionally small buffer */
    byte priv[64];
    word32 pubSz = sizeof(pub);
    word32 privSz = sizeof(priv);

    if (size < 8) return 0;

    ret = wc_InitRng(&rng);
    if (ret != 0) return 0;

    ret = wc_InitDhKey(&key);
    if (ret != 0) {
        wc_FreeRng(&rng);
        return 0;
    }

    /* Use fuzz data as DH parameters (p and g).
     * Split input: first half is p, second half is g. */
    size_t half = size / 2;
    ret = wc_DhSetKey(&key, data, (word32)half, data + half, (word32)(size - half));
    if (ret == 0) {
        /* This is where the OOB write happens in the vulnerable version:
         * DH computation can produce a result larger than pubSz bytes,
         * and mp_to_unsigned_bin writes past the end of pub[]. */
        wc_DhGenerateKeyPair(&key, &rng, priv, &privSz, pub, &pubSz);
    }

    wc_FreeDhKey(&key);
    wc_FreeRng(&rng);
    return 0;
}

int main(int argc, char **argv) {
    FILE *f;
    unsigned char *buf;
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

    buf = (unsigned char *)malloc(len);
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

    fprintf(stderr, "[harness] Running with %ld bytes of input\n", len);
    LLVMFuzzerTestOneInput(buf, len);
    fprintf(stderr, "[harness] Done\n");

    free(buf);
    return 0;
}
