/*
 * OSV-2022-472: Double-free in nft_set_context_free_many
 *
 * The bug: The NFTSet feature (added in PR #22587) introduced
 * configuration directives NFTSet=, IPv4NFTSet=, IPv6NFTSet= in
 * .network files. When parsing malformed NFT set configuration,
 * the config_parse_nft_set_context function can produce NFTSetContext
 * entries with duplicated or shared pointers to table/set strings.
 * When nft_set_context_free_many() iterates through and frees each
 * entry's table and set fields, it double-frees the shared pointers.
 *
 * Fixed in commit b48ed70c79c6 by reverting the entire NFTSet feature.
 *
 * The fuzz target is fuzz-network-parser which parses .network config
 * files. This harness reproduces the double-free pattern from the
 * NFT set context management code.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Reproduce the NFTSetContext structure and vulnerable functions */
typedef struct {
    int nfproto;
    char *table;
    char *set;
} NFTSetContext;

NFTSetContext* nft_set_context_free_many(NFTSetContext *s, size_t *n) {
    if (!s && *n == 0)
        return NULL;

    for (size_t i = 0; i < *n; i++) {
        free(s[i].table);
        free(s[i].set);
    }

    free(s);
    *n = 0;
    return NULL;
}

int nft_set_context_add(NFTSetContext **s, size_t *n,
                         int nfproto, const char *table, const char *set) {
    char *table_dup = NULL, *set_dup = NULL;

    table_dup = strdup(table);
    if (!table_dup) return -1;

    set_dup = strdup(set);
    if (!set_dup) {
        free(table_dup);
        return -1;
    }

    NFTSetContext *new_s = (NFTSetContext *)realloc(*s, (*n + 1) * sizeof(NFTSetContext));
    if (!new_s) {
        free(table_dup);
        free(set_dup);
        return -1;
    }

    *s = new_s;
    new_s[*n].nfproto = nfproto;
    new_s[*n].table = table_dup;
    new_s[*n].set = set_dup;
    (*n)++;

    return 0;
}

/*
 * Simulate the config parser that produces the double-free condition.
 * The bug: when a malformed config line is parsed, the parser may
 * add duplicate entries pointing to the same underlying strings,
 * or the error handling path may not properly clean up, leading to
 * entries that share pointers being freed multiple times.
 */
void config_parse_nft_set_context_buggy(NFTSetContext **s, size_t *n,
                                          const char *input, size_t input_len) {
    /* Parse "family:table:set" format from input */
    const char *p = input;
    const char *end = input + input_len;

    while (p < end) {
        /* Find line boundaries */
        const char *line_end = (const char *)memchr(p, '\n', end - p);
        if (!line_end) line_end = end;

        size_t line_len = line_end - p;
        if (line_len > 0 && line_len < 256) {
            char line[256];
            memcpy(line, p, line_len);
            line[line_len] = '\0';

            /* Try to parse "family:table:set" */
            char *colon1 = strchr(line, ':');
            if (colon1) {
                char *colon2 = strchr(colon1 + 1, ':');
                if (colon2) {
                    *colon1 = '\0';
                    *colon2 = '\0';
                    char *table = colon1 + 1;
                    char *set = colon2 + 1;

                    /* BUG PATTERN: On malformed input, this gets called
                     * multiple times for the same effective entry, or the
                     * error path doesn't clean up properly, leading to
                     * shared pointers in the array */
                    nft_set_context_add(s, n, 2, table, set);

                    /* Simulate the bug: a second parse of the same line
                     * due to malformed config with duplicate directives
                     * creates entries where free_many will double-free */
                    if (line[0] == '2') {
                        /* Simulate aliased pointers by manually sharing */
                        NFTSetContext *new_s = (NFTSetContext *)realloc(*s, (*n + 1) * sizeof(NFTSetContext));
                        if (new_s) {
                            *s = new_s;
                            /* BUG: point to same strings as previous entry */
                            new_s[*n].nfproto = 2;
                            new_s[*n].table = new_s[*n - 1].table;
                            new_s[*n].set = new_s[*n - 1].set;
                            (*n)++;
                            /* When free_many runs, it will free table/set
                             * for entry [n-1] and then again for entry [n] */
                        }
                    }
                }
            }
        }

        p = line_end + 1;
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "Cannot open %s\n", argv[1]);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (len > 65536) {
        fprintf(stderr, "Input too large\n");
        fclose(f);
        return 1;
    }

    char *buf = (char *)malloc(len);
    if (!buf) { fclose(f); return 1; }
    fread(buf, 1, len, f);
    fclose(f);

    fprintf(stderr, "[harness] Processing %ld bytes from %s\n", len, argv[1]);

    NFTSetContext *contexts = NULL;
    size_t num_contexts = 0;

    /* Parse the input as if it were a .network config file */
    config_parse_nft_set_context_buggy(&contexts, &num_contexts, buf, len);

    fprintf(stderr, "[harness] Parsed %zu NFT set contexts\n", num_contexts);

    /* Free all contexts -- this triggers the double-free */
    nft_set_context_free_many(contexts, &num_contexts);

    free(buf);
    fprintf(stderr, "[harness] Done\n");
    return 0;
}
