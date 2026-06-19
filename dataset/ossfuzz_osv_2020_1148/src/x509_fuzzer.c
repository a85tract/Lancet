/*
 * X.509/ASN.1 fuzzer for LibreSSL - based on libressl/fuzz/x509.c
 * Tests X.509 certificate parsing via d2i_X509.
 *
 * OSV-2020-1148: Heap-buffer-overflow in asn1_item_ex_d2i
 * The vulnerability occurs during ASN.1 deserialization of malformed
 * X.509/private key data, causing a heap OOB read.
 * OSS-Fuzz issue: 14217
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/asn1.h>

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    const unsigned char *p = buf;
    unsigned char *der = NULL;

    /* Try X509 parsing */
    X509 *x509 = d2i_X509(NULL, &p, len);
    if (x509 != NULL) {
        BIO *bio = BIO_new(BIO_s_null());
        X509_print(bio, x509);
        BIO_free(bio);
        i2d_X509(x509, &der);
        OPENSSL_free(der);
        der = NULL;
        X509_free(x509);
    }

    /* Try private key parsing (triggers asn1_item_ex_d2i path) */
    p = buf;
    EVP_PKEY *pkey = d2i_AutoPrivateKey(NULL, &p, len);
    if (pkey != NULL) {
        BIO *bio = BIO_new(BIO_s_null());
        EVP_PKEY_print_private(bio, pkey, 0, NULL);
        BIO_free(bio);
        i2d_PrivateKey(pkey, &der);
        OPENSSL_free(der);
        EVP_PKEY_free(pkey);
    }

    ERR_clear_error();
    return 0;
}
