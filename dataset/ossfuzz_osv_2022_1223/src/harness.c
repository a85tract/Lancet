/*
 * OSV-2022-1223: Heap-use-after-free in mbedtls_pkcs7_free
 *
 * The bug: In pkcs7_get_signed_data(), local variables like
 * end_content_info (a pointer) and content_type (an mbedtls_asn1_buf)
 * are not initialized. When parsing encounters malformed DER input
 * and fails partway through, the error path calls mbedtls_pkcs7_free()
 * on the partially-initialized pkcs7 structure. Since fields contain
 * uninitialized/garbage pointer values, mbedtls_pkcs7_free() follows
 * dangling pointers, causing a heap-use-after-free.
 *
 * Fixed in commit fd6cca444892 by initializing end_content_info = NULL
 * and zeroing content_type with memset before use.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/pkcs7.h"

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <der_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "Cannot open %s\n", argv[1]);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *buf = (unsigned char *)malloc(len);
    if (!buf) { fclose(f); return 1; }
    fread(buf, 1, len, f);
    fclose(f);

    fprintf(stderr, "[harness] Processing %ld bytes from %s\n", len, argv[1]);

    mbedtls_pkcs7 pkcs7;
    mbedtls_pkcs7_init(&pkcs7);

    int ret = mbedtls_pkcs7_parse_der(&pkcs7, buf, (size_t)len);
    fprintf(stderr, "[harness] mbedtls_pkcs7_parse_der returned %d\n", ret);

    mbedtls_pkcs7_free(&pkcs7);

    free(buf);
    fprintf(stderr, "[harness] Done\n");
    return 0;
}
