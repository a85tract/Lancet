/*
 * Harness for OSV-2023-11: heap-OOB read in node_from_openstep (oplist.c)
 *
 * The bug is a missing bounds check after parsing hex data in an OpenStep
 * plist data literal (<...>). After consuming hex digits, the code accesses
 * *ctx->pos to check for the closing '>' without first verifying that
 * ctx->pos < ctx->end, causing a heap out-of-bounds read.
 *
 * Fix commit: 85f5cbd3705b2b4f0e6fc9ca89bd2c58bfe8beee
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <plist/plist.h>

int main(int argc, char *argv[])
{
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
        fprintf(stderr, "Short read\n");
        free(data);
        return 1;
    }

    fprintf(stderr, "[harness] Processing %zd bytes from %s\n", nread, argv[1]);

    plist_t root_node = NULL;
    plist_err_t err = plist_from_openstep((const char *)data, (uint32_t)nread, &root_node);
    fprintf(stderr, "[harness] plist_from_openstep returned %d\n", (int)err);

    if (root_node) {
        plist_free(root_node);
        fprintf(stderr, "[harness] Freed plist node\n");
    }

    fprintf(stderr, "[harness] Done\n");
    free(data);
    return 0;
}
