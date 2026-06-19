/*
 * X.509/ASN.1 fuzzer for LibreSSL - based on libressl/fuzz/x509.c
 *
 * OSV-2022-698: Heap-buffer-overflow READ 1 in i2c_ASN1_INTEGER
 * The vulnerability occurs in i2c_ASN1_INTEGER during ASN.1 INTEGER
 * serialization (i2d path) after parsing a malformed certificate.
 * OSS-Fuzz issue: 49963
 * Fix commit: d46266c2 (portable bisection marker)
 * Vulnerable version: libressl 3.5.3
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/asn1.h>

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len)
{
    const unsigned char *p = buf;
    unsigned char *der = NULL;

    X509 *x509 = d2i_X509(NULL, &p, len);
    if (x509 != NULL) {
        BIO *bio = BIO_new(BIO_s_null());
        X509_print(bio, x509);
        BIO_free(bio);

        /* i2d triggers i2c_ASN1_INTEGER for serialization */
        int outlen = i2d_X509(x509, &der);
        if (outlen > 0)
            OPENSSL_free(der);

        X509_free(x509);
    }

    ERR_clear_error();
    return 0;
}
