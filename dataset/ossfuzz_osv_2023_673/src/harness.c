/*
 * OSS-Fuzz harness for OSV-2023-673: Heap-buffer-overflow READ in pcre2_match
 *
 * Vulnerability: In pcre2_match.c line 5795, the OP_VREVERSE handler
 * (variable-length lookbehind) has a forward retry loop that calls
 * FORWARDCHAR(Feptr) without checking if Feptr exceeds end_subject.
 * This causes a 1-byte heap OOB read.
 *
 * The bug is triggered by a variable-length lookbehind with Lmin=0
 * (from alternation like \w?|literal), where the forward retry loop
 * gets Lmax advances instead of Lmax-1, pushing Feptr past end_subject.
 *
 * Fix commit: 5f77d022733a (replaced FORWARDCHAR with FORWARDCHARTEST)
 *
 * Input format: The file is used as BOTH the regex pattern and the match
 * subject (same as the PCRE2 OSS-Fuzz harness pcre2_fuzzsupport.c).
 * Compile options are derived from the input data using rand() seeded
 * from the middle byte, matching the original fuzzer behavior.
 */

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_MATCH_SIZE 1000

#define ALLOWED_COMPILE_OPTIONS \
  (PCRE2_ANCHORED|PCRE2_ALLOW_EMPTY_CLASS|PCRE2_ALT_BSUX|PCRE2_ALT_CIRCUMFLEX| \
   PCRE2_ALT_VERBNAMES|PCRE2_AUTO_CALLOUT|PCRE2_CASELESS|PCRE2_DOLLAR_ENDONLY| \
   PCRE2_DOTALL|PCRE2_DUPNAMES|PCRE2_ENDANCHORED|PCRE2_EXTENDED|PCRE2_FIRSTLINE| \
   PCRE2_MATCH_UNSET_BACKREF|PCRE2_MULTILINE|PCRE2_NEVER_BACKSLASH_C| \
   PCRE2_NO_AUTO_CAPTURE| \
   PCRE2_NO_AUTO_POSSESS|PCRE2_NO_DOTSTAR_ANCHOR|PCRE2_NO_START_OPTIMIZE| \
   PCRE2_UCP|PCRE2_UNGREEDY|PCRE2_USE_OFFSET_LIMIT| \
   PCRE2_UTF)

#define ALLOWED_MATCH_OPTIONS \
  (PCRE2_ANCHORED|PCRE2_ENDANCHORED|PCRE2_NOTBOL|PCRE2_NOTEOL|PCRE2_NOTEMPTY| \
   PCRE2_NOTEMPTY_ATSTART|PCRE2_PARTIAL_HARD| \
   PCRE2_PARTIAL_SOFT|PCRE2_NO_JIT)

static int callout_function(pcre2_callout_block *cb, void *callout_data) {
    (void)cb;
    *((uint32_t *)callout_data) += 1;
    return (*((uint32_t *)callout_data) > 100) ? PCRE2_ERROR_CALLOUT : 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <poc_file>\n", argv[0]);
        return 1;
    }

    /* Read the PoC file */
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize < 1) {
        fprintf(stderr, "Input too small\n");
        fclose(fp);
        return 1;
    }

    unsigned char *data = (unsigned char *)malloc(fsize);
    if (!data) {
        perror("malloc");
        fclose(fp);
        return 1;
    }
    fread(data, 1, fsize, fp);
    fclose(fp);

    size_t size = (size_t)fsize;
    size_t match_size = (size > MAX_MATCH_SIZE) ? MAX_MATCH_SIZE : size;

    printf("[*] OSV-2023-673: Heap-OOB READ in pcre2_match (OP_VREVERSE)\n");
    printf("[*] Input size: %zu bytes\n", size);
    printf("[*] Input: ");
    for (size_t i = 0; i < size && i < 64; i++) {
        if (data[i] >= 0x20 && data[i] < 0x7f)
            printf("%c", data[i]);
        else
            printf("\\x%02x", data[i]);
    }
    printf("\n");

    /* Derive compile/match options from input (matching pcre2_fuzzsupport.c) */
    srand((unsigned int)(data[size / 2]));
    int r1 = rand();
    int r2 = rand();

    uint32_t compile_options =
        ((((uint32_t)r1 << 16) | ((uint32_t)r2 & 0xffff)) & ALLOWED_COMPILE_OPTIONS) |
        PCRE2_NEVER_BACKSLASH_C;
    uint32_t match_options =
        ((((uint32_t)r1 << 16) | ((uint32_t)r2 & 0xffff)) & ALLOWED_MATCH_OPTIONS);

    if (((compile_options | match_options) & PCRE2_ENDANCHORED) != 0)
        match_options &= ~(PCRE2_PARTIAL_HARD | PCRE2_PARTIAL_SOFT);

    printf("[*] Compile options: 0x%08x\n", compile_options);
    printf("[*] Match options:   0x%08x\n", match_options);
    printf("[*] UTF: %s, DOTALL: %s, UCP: %s\n",
           (compile_options & PCRE2_UTF) ? "yes" : "no",
           (compile_options & PCRE2_DOTALL) ? "yes" : "no",
           (compile_options & PCRE2_UCP) ? "yes" : "no");

    /* Two iterations: first with derived options, second with options=0
       (matching the fuzzer behavior) */
    for (int iter = 0; iter < 2; iter++) {
        printf("\n[*] --- Iteration %d (options: compile=0x%08x match=0x%08x) ---\n",
               iter, compile_options, match_options);

        /* Compile the pattern (data is both pattern and subject) */
        int errnum;
        PCRE2_SIZE erroff;

        pcre2_code *re = pcre2_compile(
            (PCRE2_SPTR)data, (PCRE2_SIZE)size,
            compile_options, &errnum, &erroff, NULL);

        if (!re) {
            PCRE2_UCHAR errbuf[256];
            pcre2_get_error_message(errnum, errbuf, sizeof(errbuf));
            printf("[*] Compile error at offset %zu: %s\n", erroff, (char *)errbuf);
            compile_options = 0;
            match_options = 0;
            continue;
        }

        printf("[*] Pattern compiled successfully\n");

        /* Create match data and context */
        pcre2_match_data *match_data = pcre2_match_data_create(32, NULL);
        pcre2_match_context *match_context = pcre2_match_context_create(NULL);
        uint32_t callout_count = 0;
        pcre2_set_callout(match_context, callout_function, &callout_count);
        pcre2_set_match_limit(match_context, 100);
        pcre2_set_depth_limit(match_context, 100);

        /* Copy subject to its own heap allocation for ASan detection.
         * The OOB read is 1 byte past the subject buffer, and ASan
         * detects this only if the redzone is immediately after. */
        unsigned char *subject = (unsigned char *)malloc(match_size);
        if (!subject) {
            perror("malloc subject");
            pcre2_match_data_free(match_data);
            pcre2_match_context_free(match_context);
            pcre2_code_free(re);
            compile_options = 0;
            match_options = 0;
            continue;
        }
        memcpy(subject, data, match_size);

        printf("[*] Running pcre2_match (subject = %zu bytes in separate allocation)...\n",
               match_size);

        int rc = pcre2_match(
            re,
            (PCRE2_SPTR)subject,
            (PCRE2_SIZE)match_size,
            0,
            match_options,
            match_data,
            match_context);

        if (rc >= 0) {
            printf("[*] Match succeeded with %d capture groups\n", rc);
        } else if (rc == PCRE2_ERROR_NOMATCH) {
            printf("[*] No match\n");
        } else {
            PCRE2_UCHAR errbuf[256];
            pcre2_get_error_message(rc, errbuf, sizeof(errbuf));
            printf("[*] Match error: %s (code %d)\n", (char *)errbuf, rc);
        }

        /* Cleanup */
        free(subject);
        pcre2_match_data_free(match_data);
        pcre2_match_context_free(match_context);
        pcre2_code_free(re);

        /* Second iteration: no options */
        compile_options = 0;
        match_options = 0;
    }

    printf("\n[*] Done. If built with ASan against vulnerable PCRE2,\n");
    printf("[*] a heap-buffer-overflow READ should be reported above.\n");

    free(data);
    return 0;
}
