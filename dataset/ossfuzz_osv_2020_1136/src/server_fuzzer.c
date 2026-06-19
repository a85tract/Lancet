/*
 * Server fuzzer for LibreSSL - based on libressl/fuzz/server.c
 * Tests the TLS server handshake by feeding fuzzed ClientHello data.
 *
 * OSV-2020-1136: Global-buffer-overflow READ in ssl_sigalg
 * The vulnerability occurs when parsing the signature_algorithms extension
 * in a TLS ClientHello. A malformed extension triggers an OOB read on a
 * global sigalg table.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

/* Minimal self-signed RSA cert + key for the server */
static SSL_CTX *ctx = NULL;

static void init_ctx(void)
{
    if (ctx != NULL)
        return;

    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL)
        abort();

    /* Generate an ephemeral RSA key and self-signed cert */
    EVP_PKEY *pkey = EVP_PKEY_new();
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    EVP_PKEY_assign_RSA(pkey, rsa);

    X509 *x509 = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
    X509_set_pubkey(x509, pkey);

    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (unsigned char *)"test", -1, -1, 0);
    X509_set_issuer_name(x509, name);
    X509_sign(x509, pkey, EVP_sha256());

    SSL_CTX_use_certificate(ctx, x509);
    SSL_CTX_use_PrivateKey(ctx, pkey);

    X509_free(x509);
    EVP_PKEY_free(pkey);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    SSL *ssl;
    BIO *rbio, *wbio;

    if (size == 0)
        return 0;

    init_ctx();

    ssl = SSL_new(ctx);
    if (ssl == NULL)
        return 0;

    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());
    BIO_write(rbio, data, size);
    SSL_set_bio(ssl, rbio, wbio);

    SSL_accept(ssl);

    SSL_free(ssl);
    ERR_clear_error();

    return 0;
}
