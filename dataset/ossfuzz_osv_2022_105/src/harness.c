/*
 * Harness for OSV-2022-105: heap-OOB read in parse_object (jplist.c)
 *
 * The bug is in libplist's JSON parser (jplist.c). The functions parse_object()
 * and parse_array() iterate through JSMN tokens using index j, but never check
 * whether j exceeds the valid token count (parser.toknext). A malformed JSON
 * input whose token "size" field claims more children than tokens that actually
 * exist causes a heap out-of-bounds read when accessing tokens[j].
 *
 * Fixed in commit 924ba961d68f by introducing jsmntok_info_t which carries
 * both the token array and its count, and adding bounds checks before access.
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
    plist_from_json((const char *)data, (uint32_t)nread, &root_node);
    if (root_node) {
        fprintf(stderr, "[harness] Parsed plist node successfully\n");
        plist_free(root_node);
    } else {
        fprintf(stderr, "[harness] Parsing returned NULL\n");
    }

    fprintf(stderr, "[harness] Done\n");
    free(data);
    return 0;
}
