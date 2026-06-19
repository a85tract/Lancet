#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <igraph.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "[!] Cannot open file: %s\n", argv[1]);
        return 1;
    }

    /* Print input size */
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    rewind(f);
    fprintf(stderr, "[*] Input file: %s (%ld bytes)\n", argv[1], fsize);

    /* Read and hex dump first 64 bytes */
    unsigned char buf[64];
    size_t nread = fread(buf, 1, sizeof(buf), f);
    fprintf(stderr, "[*] First %zu bytes (hex): ", nread);
    for (size_t i = 0; i < nread; i++) {
        fprintf(stderr, "%02x ", buf[i]);
    }
    fprintf(stderr, "\n");
    rewind(f);

    /* Set a non-aborting error handler so the UAF can manifest */
    igraph_set_error_handler(igraph_error_handler_printignore);

    /* Attempt to read the GML graph */
    igraph_t graph;
    int ret = igraph_read_graph_gml(&graph, f);
    fprintf(stderr, "[*] igraph_read_graph_gml returned: %d\n", ret);

    if (ret == 0) {
        fprintf(stderr, "[*] Graph: %ld vertices, %ld edges\n",
                (long)igraph_vcount(&graph), (long)igraph_ecount(&graph));
        igraph_destroy(&graph);
    }

    fclose(f);
    fprintf(stderr, "[*] Done\n");
    return 0;
}
