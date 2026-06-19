/*
 * Harness for OSV-2020-68: double-free in ares_parse_soa_reply
 *
 * Reads a file from disk and passes it to LLVMFuzzerTestOneInput
 * which exercises all ares_parse_*_reply functions, including the
 * vulnerable ares_parse_soa_reply.
 *
 * Build:
 *   gcc -g -O0 -fno-stack-protector -fno-omit-frame-pointer \
 *       -I c-ares -o ares_fuzz harness.c \
 *       c-ares/test/ares-test-fuzz.c \
 *       c-ares/.libs/libcares.a -lpthread
 *
 * Run:
 *   ./ares_fuzz poc.bin
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Declared in ares-test-fuzz.c */
int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size);

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return 1;
    }

    unsigned char *data = (unsigned char *)malloc(st.st_size);
    if (!data) {
        perror("malloc");
        close(fd);
        return 1;
    }

    ssize_t nread = read(fd, data, st.st_size);
    close(fd);

    if (nread != st.st_size) {
        fprintf(stderr, "Short read: got %zd of %ld bytes\n", nread, (long)st.st_size);
        free(data);
        return 1;
    }

    fprintf(stderr, "[harness] Processing %zd bytes from %s\n", nread, argv[1]);
    LLVMFuzzerTestOneInput(data, (unsigned long)nread);
    fprintf(stderr, "[harness] Done\n");

    free(data);
    return 0;
}
