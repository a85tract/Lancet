/*
 * harness.c: Standalone wrapper for wolfSSL x509/OCSP fuzzer.
 *
 * OSV-2023-358: heap-double-free via FreeOcspRequest after
 *   InitOcspRequest fails on URL allocation
 * OSS-Fuzz bug ID: 58484
 *
 * The bug is in InitOcspRequest(): when XMALLOC for req->url fails,
 * req->serial is freed but not set to NULL. The caller then calls
 * FreeOcspRequest() which frees req->serial again -> double-free.
 *
 * This harness mimics fuzzer-wolfssl-x509: parses fuzz input as a
 * DER certificate and then attempts InitOcspRequest + FreeOcspRequest,
 * directly exercising the vulnerable error path.
 *
 * To trigger the double-free reliably, we use a custom allocator
 * that fails on the second allocation (the URL alloc) while succeeding
 * on the first (the serial alloc).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/memory.h>

/* Allocation counter for controlled failure injection */
static int alloc_count = 0;
static int fail_at = -1;  /* Which allocation should fail (-1 = none) */

static void *custom_malloc(size_t sz) {
    alloc_count++;
    if (fail_at >= 0 && alloc_count == fail_at) {
        return NULL;  /* Simulate allocation failure */
    }
    return malloc(sz);
}

static void custom_free(void *ptr) {
    free(ptr);
}

static void *custom_realloc(void *ptr, size_t sz) {
    return realloc(ptr, sz);
}

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
    DecodedCert cert;

    InitDecodedCert(&cert, data, (word32)size, NULL);
    if (ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL) == 0) {
        OcspRequest req;

        /* Try with normal allocations first */
        alloc_count = 0;
        fail_at = -1;
        if (InitOcspRequest(&req, &cert, 0, NULL) == 0) {
            FreeOcspRequest(&req);
        }

        /* Now try with allocation failure to trigger the double-free.
         * The vulnerable path: serial alloc succeeds (alloc N),
         * URL alloc fails (alloc N+1) -> serial freed but not NULL'd
         * -> FreeOcspRequest frees serial again.
         *
         * We try failing at different allocation points to find the
         * URL allocation. */
        for (int i = 1; i <= 20; i++) {
            alloc_count = 0;
            fail_at = i;
            memset(&req, 0, sizeof(req));
            if (InitOcspRequest(&req, &cert, 0, NULL) != 0) {
                /* InitOcspRequest failed. Call FreeOcspRequest anyway
                 * (this is what the x509 fuzzer does when the caller
                 * checks the return but still needs to clean up the
                 * partially-initialized request). In the vulnerable
                 * version, this triggers the double-free. */
                FreeOcspRequest(&req);
            } else {
                FreeOcspRequest(&req);
            }
        }
    }
    FreeDecodedCert(&cert);

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

    /* Install custom allocator for controlled failure injection */
    wolfSSL_SetAllocators(custom_malloc, custom_free, custom_realloc);

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
