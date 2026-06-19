/*
 * Harness for OSV-2022-147: heap-OOB read in parse_primitive (jplist.c)
 *
 * The bug is in the JSON parser's parse_primitive function.  When a
 * single '-' character appears as a primitive token the condition
 *   (str_val[0] == '-' && str_end > str_val && isdigit(str_val[1]))
 * passes the second check (str_end > str_val is trivially true when
 * there is at least one character) and reads str_val[1] which is one
 * byte past the token boundary, causing a heap out-of-bounds read.
 *
 * Fixed in commit 7d2cdc6 by changing the check to str_val+1 < str_end.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <plist/plist.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }
    struct stat st;
    if (fstat(fd, &st) < 0) { perror("fstat"); close(fd); return 1; }
    unsigned char *data = (unsigned char *)malloc(st.st_size);
    if (!data) { perror("malloc"); close(fd); return 1; }
    ssize_t nread = read(fd, data, st.st_size);
    close(fd);
    if (nread != st.st_size) {
        fprintf(stderr, "Short read\n"); free(data); return 1;
    }
    fprintf(stderr, "[harness] Processing %zd bytes from %s\n", nread, argv[1]);

    plist_t root_node = NULL;
    plist_err_t err = plist_from_json((const char *)data, (uint32_t)nread, &root_node);
    fprintf(stderr, "[harness] plist_from_json returned %d\n", err);
    if (root_node) {
        plist_free(root_node);
    }

    fprintf(stderr, "[harness] Done\n");
    free(data);
    return 0;
}
