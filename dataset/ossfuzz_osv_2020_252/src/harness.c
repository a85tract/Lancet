/*
 * OSV-2020-252: global-buffer-overflow in json_tokener_parse_ex (json-c)
 *
 * Bug: When parsing unicode escape sequences (\uNNNN), if the input runs out
 * in the middle of a unicode escape while processing a high surrogate (e.g.
 * \uD800\u followed by truncation), the code at the end of the while(1) loop
 * in json_tokener_state_escape_unicode does:
 *
 *   if (tok->got_hi_surrogate &&
 *       strcmp(tok->pb->buf, (char *)utf8_replacement_char))
 *       printbuf_memappend_fast(tok->pb, (char *)utf8_replacement_char, 3);
 *
 * The utf8_replacement_char is a 3-byte static array {0xEF, 0xBF, 0xBD}
 * without a null terminator. strcmp() reads past the end of this array
 * looking for a null byte, causing a global-buffer-overflow read.
 *
 * Additionally, the unnecessary appending of utf8_replacement_char when
 * running out of input mid-escape corrupts the parse state, since parsing
 * may resume with additional data in a subsequent call.
 *
 * Fix commit: 36118b681ea3b8e99735beee73cbd25a63e942cd
 * The fix restructures the unicode escape handling to avoid the strcmp
 * against the non-null-terminated utf8_replacement_char and removes the
 * unnecessary appending of replacement chars on partial input.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "json.h"

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "rb");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fsize <= 0) {
        fprintf(stderr, "Empty or invalid file\n");
        fclose(fp);
        return 1;
    }

    char *data = (char *)malloc(fsize);
    if (!data) {
        perror("malloc");
        fclose(fp);
        return 1;
    }

    size_t nread = fread(data, 1, fsize, fp);
    fclose(fp);

    if ((long)nread != fsize) {
        fprintf(stderr, "Short read\n");
        free(data);
        return 1;
    }

    /*
     * Use json_tokener_parse_ex with explicit length to trigger the bug.
     * The bug occurs when the tokener runs out of input mid-unicode-escape.
     * We simulate incremental parsing by feeding the data in small chunks,
     * which increases the chance of hitting the vulnerable code path where
     * PEEK_CHAR returns 0 (end of current input) while inside the
     * json_tokener_state_escape_unicode state.
     */
    struct json_tokener *tok = json_tokener_new();
    if (!tok) {
        fprintf(stderr, "json_tokener_new failed\n");
        free(data);
        return 1;
    }

    struct json_object *jobj = NULL;
    enum json_tokener_error jerr;

    /*
     * Feed the input one byte at a time. This forces the tokener to
     * run out of input at every possible position, maximizing the chance
     * of triggering the bug when we're inside a unicode escape sequence
     * with a high surrogate pending (got_hi_surrogate != 0).
     */
    size_t pos = 0;
    while (pos < (size_t)fsize) {
        jobj = json_tokener_parse_ex(tok, data + pos, 1);
        jerr = json_tokener_get_error(tok);
        if (jerr == json_tokener_success) {
            /* Successfully parsed an object */
            if (jobj) {
                json_object_put(jobj);
                jobj = NULL;
            }
            break;
        } else if (jerr != json_tokener_continue) {
            /* Parse error (not just "need more data") */
            break;
        }
        pos++;
    }

    /* Also try parsing the entire input at once for completeness */
    json_tokener_reset(tok);
    jobj = json_tokener_parse_ex(tok, data, (int)fsize);
    jerr = json_tokener_get_error(tok);
    if (jobj) {
        json_object_put(jobj);
    }

    json_tokener_free(tok);
    free(data);

    printf("Parsing completed (error code: %d)\n", (int)jerr);
    return 0;
}
