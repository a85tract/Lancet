/*
 * X.509/ASN.1 fuzzer for LibreSSL - based on libressl/fuzz/x509.c
 *
 * OSV-2020-1923: Heap-buffer-overflow in do_print_ex
 * The vulnerability occurs in do_print_ex (called from X509_print) when
 * printing ASN.1 items from a malformed X.509 certificate. A 1-byte
 * heap OOB read occurs during ASN.1 name printing.
 * OSS-Fuzz issue: 13914
 * Fix commit: 17c88164 (portable bisection marker)
 * Vulnerable version: libressl 2.9.1
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

    /* Parse and print X.509 cert - triggers do_print_ex */
    X509 *x509 = d2i_X509(NULL, &p, len);
    if (x509 != NULL) {
        BIO *bio = BIO_new(BIO_s_null());
        /* X509_print calls do_print_ex internally */
        X509_print(bio, x509);
        BIO_free(bio);

        i2d_X509(x509, &der);
        OPENSSL_free(der);
        X509_free(x509);
    }

    ERR_clear_error();
    return 0;
}
