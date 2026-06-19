/*
 * harness.c: Standalone wrapper for wolfSSH server fuzzer.
 *
 * OSV-2023-451: heap-buffer-overflow WRITE 9 in BundlePacket
 * OSS-Fuzz bug ID: 59498
 *
 * The bug is in GrowBuffer() which takes a caller-supplied usedSz parameter.
 * When callers miscalculate usedSz, BundlePacket() writes past the end of
 * the undersized output buffer during padding/MAC/ciphertext operations.
 *
 * This harness mimics fuzzer-wolfssh-server: creates a wolfSSH server,
 * accepts a connection using fuzz data as the client's SSH protocol data,
 * then calls wolfSSH_shutdown() which triggers SendChannelExit ->
 * BundlePacket -> heap-buffer-overflow.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wolfssh/ssh.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>

/* Global fuzz data pointers for the I/O callbacks */
static const unsigned char *g_data = NULL;
static size_t g_data_size = 0;

/* Custom recv callback: feeds fuzz data as client input */
static int fuzzer_recv(WOLFSSH *ssh, void *buf, word32 sz, void *ctx) {
    (void)ssh;
    (void)ctx;

    if (sz == 0) return WS_CBIO_ERR_CONN_RST;
    if (g_data_size == 0) return WS_CBIO_ERR_CONN_RST;

    word32 numRead = (word32)(sz <= g_data_size ? sz : g_data_size);
    memcpy(buf, g_data, numRead);
    g_data += numRead;
    g_data_size -= numRead;

    return (int)numRead;
}

/* Custom send callback: discard all output */
static int fuzzer_send(WOLFSSH *ssh, void *buf, word32 sz, void *ctx) {
    (void)ssh;
    (void)buf;
    (void)ctx;
    return (int)sz;
}

/* Minimal RSA host key for the SSH server */
static byte hostKeyBuf[4096];
static word32 hostKeySz = 0;

static int generate_host_key(void) {
    RsaKey key;
    WC_RNG rng;
    int ret;

    ret = wc_InitRng(&rng);
    if (ret != 0) return ret;

    ret = wc_InitRsaKey(&key, NULL);
    if (ret != 0) { wc_FreeRng(&rng); return ret; }

    ret = wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng);
    if (ret != 0) { wc_FreeRsaKey(&key); wc_FreeRng(&rng); return ret; }

    hostKeySz = sizeof(hostKeyBuf);
    ret = wc_RsaKeyToDer(&key, hostKeyBuf, hostKeySz);
    if (ret > 0) {
        hostKeySz = (word32)ret;
        ret = 0;
    }

    wc_FreeRsaKey(&key);
    wc_FreeRng(&rng);
    return ret;
}

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
    WOLFSSH_CTX *ctx = NULL;
    WOLFSSH *ssh = NULL;

    if (size < 10) return 0;

    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    if (!ctx) return 0;

    wolfSSH_SetIORecv(ctx, fuzzer_recv);
    wolfSSH_SetIOSend(ctx, fuzzer_send);

    /* Load host key */
    if (hostKeySz > 0) {
        wolfSSH_CTX_UsePrivateKey_buffer(ctx, hostKeyBuf, hostKeySz,
                                          WOLFSSH_FORMAT_ASN1);
    }

    ssh = wolfSSH_new(ctx);
    if (!ssh) {
        wolfSSH_CTX_free(ctx);
        return 0;
    }

    /* Set fuzz data for recv callback */
    g_data = data;
    g_data_size = size;

    /* Attempt SSH accept -- processes fuzz data as SSH client messages */
    wolfSSH_accept(ssh);

    /* Shutdown triggers SendChannelExit -> BundlePacket -> OOB write */
    wolfSSH_shutdown(ssh);

    wolfSSH_free(ssh);
    wolfSSH_CTX_free(ctx);

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

    wolfSSH_Init();

    /* Generate a host key for the server */
    if (generate_host_key() != 0) {
        fprintf(stderr, "[harness] Warning: could not generate host key\n");
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
    wolfSSH_Cleanup();
    return 0;
}
