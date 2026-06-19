/*
 * OSV-2020-1113 standalone harness
 * heap-use-after-free in node_min_byte_len during regex compilation
 *
 * Based on oniguruma's harnesses/libfuzzer-onig.cpp (CC0/public domain)
 * Converted to C with stdin/file input for standalone execution.
 *
 * Build:
 *   gcc -g -O0 -fno-stack-protector -o harness harness.c \
 *       -I oniguruma/src oniguruma/src/.libs/libonig.a
 *
 * Usage:
 *   ./harness poc.bin
 *   # or: ./harness < poc.bin
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oniguruma.h>

int main(int argc, char *argv[])
{
    FILE *fp = NULL;
    unsigned char *buf = NULL;
    size_t len = 0;

    if (argc > 1) {
        fp = fopen(argv[1], "rb");
        if (!fp) {
            perror("fopen");
            return 1;
        }
    } else {
        fp = stdin;
    }

    /* Read entire input */
    size_t cap = 4096;
    buf = (unsigned char *)malloc(cap);
    if (!buf) {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }

    while (!feof(fp)) {
        size_t n = fread(buf + len, 1, cap - len, fp);
        len += n;
        if (len == cap) {
            cap *= 2;
            buf = (unsigned char *)realloc(buf, cap);
            if (!buf) {
                fprintf(stderr, "realloc failed\n");
                return 1;
            }
        }
    }
    if (argc > 1)
        fclose(fp);

    printf("[harness] Input size: %zu bytes\n", len);
    printf("[harness] Input (hex):");
    for (size_t i = 0; i < len && i < 128; i++)
        printf(" %02x", buf[i]);
    printf("\n");

    /* Compile the regex pattern (this is where the UAF occurs) */
    regex_t *reg;
    OnigEncoding enc = ONIG_ENCODING_UTF8;
    OnigErrorInfo einfo;

    onig_initialize(&enc, 1);
    onig_set_retry_limit_in_match(120);
    onig_set_parse_depth_limit(120);

    int r = onig_new(&reg, buf, buf + len,
                     ONIG_OPTION_DEFAULT, enc,
                     ONIG_SYNTAX_DEFAULT, &einfo);

    if (r == ONIG_NORMAL) {
        printf("[harness] Regex compiled successfully\n");
        onig_free(reg);
    } else {
        char errbuf[ONIG_MAX_ERROR_MESSAGE_LEN];
        onig_error_code_to_str((OnigUChar *)errbuf, r, &einfo);
        printf("[harness] Regex compile error: %s (code %d)\n", errbuf, r);
    }

    onig_end();
    free(buf);

    printf("[harness] Done\n");
    return 0;
}
