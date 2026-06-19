/*
 * Standalone harness for file/libmagic fuzz target.
 * Reads a file and calls LLVMFuzzerTestOneInput(data, size).
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = (uint8_t *)malloc(len);
    if (!buf) {
        fclose(f);
        return 1;
    }
    fread(buf, 1, len, f);
    fclose(f);
    int ret = LLVMFuzzerTestOneInput(buf, len);
    free(buf);
    return ret;
}
