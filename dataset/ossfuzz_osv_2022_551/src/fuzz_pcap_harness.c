/*
 * Standalone harness for fuzz_pcap (libpcap pcap file parser fuzzer).
 * Reads a file and calls LLVMFuzzerTestOneInput() with its contents.
 *
 * Build:
 *   gcc -g -O0 -fsanitize=address \
 *       fuzz_pcap_harness.c fuzz_pcap.o \
 *       -I<libpcap_src> -L<libpcap_build> -lpcap \
 *       -o fuzz_pcap_standalone
 *
 * Usage:
 *   ./fuzz_pcap_standalone <input_pcap_file>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

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
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0) {
        fprintf(stderr, "Empty or invalid file\n");
        fclose(f);
        return 1;
    }

    uint8_t *buf = (uint8_t *)malloc(size);
    if (!buf) {
        perror("malloc");
        fclose(f);
        return 1;
    }

    if (fread(buf, 1, size, f) != (size_t)size) {
        perror("fread");
        free(buf);
        fclose(f);
        return 1;
    }
    fclose(f);

    fprintf(stderr, "[harness] Running fuzz_pcap with %ld bytes\n", size);
    LLVMFuzzerTestOneInput(buf, (size_t)size);
    fprintf(stderr, "[harness] Done\n");

    free(buf);
    return 0;
}
