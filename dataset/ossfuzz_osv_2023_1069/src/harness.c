/*
 * Harness for OSV-2023-1069: Heap-use-after-free in igraph_pajek_yyparse
 *
 * The bug is in igraph's Pajek parser. The 'word' grammar rule returns a
 * pointer directly into the Flex scanner's internal buffer (yytext).
 * When the lexer reads subsequent tokens, the buffer may be reallocated,
 * leaving a dangling pointer. When the parser later uses that pointer
 * (e.g. to set a vertex attribute), it reads freed memory.
 *
 * Trigger: a Pajek .net file with vertex definitions containing string
 * attributes that force the parser to hold a word token's pointer across
 * additional lexer calls.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <igraph.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    /* Enable C attribute handler -- REQUIRED for the bug to manifest.
     * Without this, string attribute storage is a no-op and the stale
     * yytext pointer is never actually dereferenced. */
    igraph_set_attribute_table(&igraph_cattribute_table);

    /* Suppress igraph error/warning output for cleaner harness output */
    igraph_set_error_handler(igraph_error_handler_ignore);
    igraph_set_warning_handler(igraph_warning_handler_ignore);

    /* Open and measure input */
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "Error: cannot open '%s'\n", argv[1]);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    rewind(f);

    fprintf(stderr, "[harness] Input file: %s (%ld bytes)\n", argv[1], fsize);

    /* Hex dump of first 64 bytes */
    unsigned char buf[64];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fprintf(stderr, "[harness] First %zu bytes (hex): ", n);
    for (size_t i = 0; i < n; i++) {
        fprintf(stderr, "%02x ", buf[i]);
    }
    fprintf(stderr, "\n");

    /* Print as text too */
    fprintf(stderr, "[harness] First %zu bytes (text): ", n);
    for (size_t i = 0; i < n; i++) {
        fprintf(stderr, "%c", (buf[i] >= 32 && buf[i] < 127) ? buf[i] : '.');
    }
    fprintf(stderr, "\n");

    /* Rewind and parse as Pajek */
    rewind(f);

    igraph_t graph;
    fprintf(stderr, "[harness] Calling igraph_read_graph_pajek...\n");

    int ret = igraph_read_graph_pajek(&graph, f);

    fprintf(stderr, "[harness] igraph_read_graph_pajek returned: %d\n", ret);

    if (ret == IGRAPH_SUCCESS) {
        fprintf(stderr, "[harness] Graph: %ld vertices, %ld edges, %s\n",
                (long)igraph_vcount(&graph),
                (long)igraph_ecount(&graph),
                igraph_is_directed(&graph) ? "directed" : "undirected");
        igraph_destroy(&graph);
    }

    fclose(f);
    fprintf(stderr, "[harness] Done.\n");
    return 0;
}
