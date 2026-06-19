#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "ucl.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* If size is 0 we need a null-terminated string.
     * We dont null-terminate the string and by the design
     * of the API passing 0 as size with non null-terminated string
     * gives undefined behavior. */
    if (size == 0) {
        return 0;
    }

    struct ucl_parser *parser;
    parser = ucl_parser_new(0);

    ucl_parser_add_string(parser, (char *)data, size);

    if (ucl_parser_get_error(parser) != NULL) {
        /* BUG: missing ucl_parser_free(parser) on the error path.
         * This is the original fuzzer behavior that contributes to
         * the use-after-free / memory corruption scenario. */
        return 0;
    }

    ucl_parser_free(parser);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
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
        fclose(fp);
        fprintf(stderr, "Empty or unreadable file\n");
        return 1;
    }

    uint8_t *buf = (uint8_t *)malloc(fsize);
    if (!buf) {
        fclose(fp);
        fprintf(stderr, "malloc failed\n");
        return 1;
    }

    size_t nread = fread(buf, 1, fsize, fp);
    fclose(fp);

    if (nread != (size_t)fsize) {
        fprintf(stderr, "Short read\n");
        free(buf);
        return 1;
    }

    LLVMFuzzerTestOneInput(buf, nread);

    free(buf);
    return 0;
}
