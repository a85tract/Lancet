/*
 * X.509/ASN.1 fuzzer for LibreSSL - based on libressl/fuzz/x509.c
 *
 * OSV-2020-1245: Heap-buffer-overflow in c2i_ASN1_INTEGER
 * The vulnerability occurs in c2i_ASN1_INTEGER when parsing malformed
 * ASN.1 INTEGER values during X.509 certificate deserialization.
 * OSS-Fuzz issue: 14142
 * Fix commit: 2f782734 (same fix as OSV-2020-1148)
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    const unsigned char *p = buf;
    unsigned char *der = NULL;

    /* Try X509 parsing - exercises c2i_ASN1_INTEGER */
    X509 *x509 = d2i_X509(NULL, &p, len);
    if (x509 != NULL) {
        BIO *bio = BIO_new(BIO_s_null());
        X509_print(bio, x509);
        BIO_free(bio);
        i2d_X509(x509, &der);
        OPENSSL_free(der);
        X509_free(x509);
    }

    ERR_clear_error();
    return 0;
}
