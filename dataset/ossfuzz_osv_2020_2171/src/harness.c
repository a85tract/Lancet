/*
 * harness.c: Standalone wrapper for wolfSSL x509 certificate parser.
 *
 * OSV-2020-2171: stack-buffer-overflow READ 8 in fp_read_unsigned_bin
 * OSS-Fuzz bug ID: 27666
 *
 * The bug is triggered when parsing a DER certificate with a DSA public key
 * and the library is built with --disable-ecc --enable-dsa. The struct
 * SignatureCtx layout is wrong (missing 'verify' field), causing stack
 * corruption that manifests as a stack-buffer-overflow in fp_read_unsigned_bin
 * when wc_RsaPublicKeyDecodeRaw reads from corrupted memory.
 *
 * This harness mimics fuzzer-wolfssl-x509: it parses fuzz input as a
 * DER-encoded certificate via InitDecodedCert + ParseCert, and also
 * calls DecodeToKey for additional coverage.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
    /* Parse as DER certificate */
    {
        DecodedCert cert;
        InitDecodedCert(&cert, data, (word32)size, NULL);
        ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL);
        FreeDecodedCert(&cert);
    }

    /* Also try DecodeToKey path */
    {
        DecodedCert cert;
        InitDecodedCert(&cert, data, (word32)size, NULL);
        DecodeToKey(&cert, 0);
        FreeDecodedCert(&cert);
    }

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
