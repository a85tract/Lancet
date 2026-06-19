/*
 * Standalone main for openh264 decoder fuzzer.
 * Reads a file and calls LLVMFuzzerTestOneInput(data, size).
 */
#include <cstdio>
#include <cstdlib>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

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
    fprintf(stderr, "[harness] Processing %zu bytes from %s\n", len, argv[1]);
    int ret = LLVMFuzzerTestOneInput(buf, len);
    fprintf(stderr, "[harness] Done\n");
    free(buf);
    return ret;
}
