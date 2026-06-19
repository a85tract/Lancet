/*
 * harness.c: Standalone wrapper for wolfSSL TLS client fuzzer.
 *
 * OSV-2020-2299: heap-buffer-overflow READ in ato16
 * OSS-Fuzz bug ID: 29103
 *
 * The bug is in TLSX_CSR_Parse() where unsigned subtraction (length - offset)
 * wraps around when offset > length, bypassing the bounds check before ato16().
 *
 * This harness mimics fuzzer-wolfssl-client: creates a TLS client context with
 * OCSP stapling enabled, installs a custom recv callback that feeds fuzz data
 * as server responses, and calls wolfSSL_connect() to trigger TLS handshake
 * processing including extension parsing.
 *
 * The last byte of input selects the TLS method (0 = TLS 1.2, etc).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

/* Global fuzz data pointers for the I/O callbacks */
static const unsigned char *g_data = NULL;
static size_t g_data_size = 0;

/* Custom recv callback: feeds fuzz data as server responses */
static int fuzzer_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    (void)ssl;
    (void)ctx;

    if (sz <= 0) return WOLFSSL_CBIO_ERR_CONN_RST;
    if (g_data_size == 0) return WOLFSSL_CBIO_ERR_CONN_RST;

    int numRead = (size_t)sz <= g_data_size ? sz : (int)g_data_size;
    memcpy(buf, g_data, numRead);
    g_data += numRead;
    g_data_size -= numRead;

    return numRead;
}

/* Custom send callback: discard all output */
static int fuzzer_send(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    (void)ssl;
    (void)buf;
    (void)ctx;
    return sz;
}

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;
    WOLFSSL_METHOD *method;

    if (size < 2) return 0;

    /* Last byte selects TLS method */
    unsigned char methodIdx = data[size - 1] % 2;
    size--;

    if (methodIdx == 0) {
        method = wolfTLSv1_2_client_method();
    } else {
        method = wolfTLSv1_1_client_method();
    }

    ctx = wolfSSL_CTX_new(method);
    if (!ctx) return 0;

    wolfSSL_CTX_SetIORecv(ctx, fuzzer_recv);
    wolfSSL_CTX_SetIOSend(ctx, fuzzer_send);
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);

    /* Enable OCSP stapling -- this activates TLSX_CSR_Parse */
    wolfSSL_CTX_EnableOCSPStapling(ctx);

    ssl = wolfSSL_new(ctx);
    if (!ssl) {
        wolfSSL_CTX_free(ctx);
        return 0;
    }

    wolfSSL_UseOCSPStapling(ssl, WOLFSSL_CSR_OCSP,
                            WOLFSSL_CSR_OCSP_USE_NONCE);

    /* Set fuzz data for the recv callback */
    g_data = data;
    g_data_size = size;

    /* Attempt TLS handshake -- this triggers extension parsing
     * which reaches TLSX_CSR_Parse -> ato16 */
    wolfSSL_connect(ssl);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);

    g_data = NULL;
    g_data_size = 0;

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

    wolfSSL_Init();

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
    wolfSSL_Cleanup();
    return 0;
}
