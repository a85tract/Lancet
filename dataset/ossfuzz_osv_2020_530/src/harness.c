/*
 * Standalone harness for OSV-2020-530: stack-buffer-overflow in ares_parse_aaaa_reply
 *
 * The vulnerability: ares_parse_aaaa_reply() writes to a caller-supplied
 * addrttls[] array without checking the array bounds. If a DNS response
 * contains more AAAA records than the array can hold, it overflows the
 * stack-allocated buffer.
 *
 * This harness mirrors the fuzz target (ares-test-fuzz.c): it allocates
 * a stack buffer of 5 ares_addr6ttl entries, then passes a crafted DNS
 * response containing more than 5 AAAA records.
 */

#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>

#include "ares.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <poc_file>\n", argv[0]);
        return 1;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    /* Read the PoC file */
    unsigned char buf[65536];
    int len = read(fd, buf, sizeof(buf));
    close(fd);

    if (len <= 0) {
        fprintf(stderr, "Failed to read input or empty file\n");
        return 1;
    }

    /* Make a tight copy so overflows are more apparent */
    unsigned char *data = (unsigned char *)malloc(len);
    if (!data) {
        perror("malloc");
        return 1;
    }
    memcpy(data, buf, len);

    printf("[*] Loaded %d bytes from %s\n", len, argv[1]);
    printf("[*] Calling ares_parse_aaaa_reply with stack buffer of 5 entries...\n");

    /*
     * This is the vulnerable pattern from ares-test-fuzz.c:
     * A stack-allocated array of only 5 ares_addr6ttl entries.
     * If the DNS response has >5 AAAA records, the function writes
     * past the end of info6[], corrupting the stack.
     */
    struct hostent *host = NULL;
    struct ares_addr6ttl info6[5];
    int count = 5;

    int status = ares_parse_aaaa_reply(data, len, &host, info6, &count);

    printf("[*] ares_parse_aaaa_reply returned: %d\n", status);
    printf("[*] count after call: %d\n", count);

    if (host) {
        printf("[*] hostname: %s\n", host->h_name ? host->h_name : "(null)");
        ares_free_hostent(host);
    }

    free(data);
    printf("[*] Done.\n");
    return 0;
}
