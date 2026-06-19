/*
 * Harness for OSV-2020-280: Null pointer dereference in c-ares
 * ares_parse_a_reply / ares_parse_aaaa_reply.
 *
 * Vulnerability: ares__parse_into_addrinfo2() counts ALL address nodes
 * regardless of family. ares_parse_a_reply() allocates based on naddrs
 * but only populates AF_INET entries. If the DNS response contains AAAA
 * records but no A records, naddrs > 0 but no h_addr_list entries are
 * filled (they stay NULL). The function reports *naddrttls = naddrs,
 * causing callers to dereference NULL h_addr_list entries.
 *
 * This harness calls ares_parse_a_reply and then accesses the returned
 * hostent data the way real callers do, triggering the null deref.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "ares.h"

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

    unsigned char *buf = malloc(st.st_size);
    if (!buf) {
        perror("malloc");
        close(fd);
        return 1;
    }

    ssize_t nread = read(fd, buf, st.st_size);
    close(fd);

    if (nread != st.st_size) {
        fprintf(stderr, "Short read\n");
        free(buf);
        return 1;
    }

    fprintf(stderr, "[harness] Processing %zd bytes from %s\n", nread, argv[1]);

    /* ---- Test ares_parse_a_reply (the vulnerable function) ---- */
    struct hostent *host = NULL;
    struct ares_addrttl info[16];
    int count = 16;

    memset(info, 0, sizeof(info));

    int status = ares_parse_a_reply(buf, (int)nread, &host, info, &count);

    fprintf(stderr, "[harness] ares_parse_a_reply returned status=%d, count=%d, host=%p\n",
            status, count, (void *)host);

    if (status == ARES_SUCCESS && host) {
        fprintf(stderr, "[harness] h_name=%s, h_addrtype=%d, h_length=%d\n",
                host->h_name ? host->h_name : "(null)",
                host->h_addrtype, host->h_length);

        /*
         * This is where the null pointer dereference occurs.
         * The function returned success with count > 0, so a caller
         * naturally iterates h_addr_list. But when the DNS response
         * contained only AAAA records (wrong family for A-reply parser),
         * h_addr_list[0] is NULL despite count saying addresses exist.
         */
        fprintf(stderr, "[harness] Iterating %d reported addresses...\n", count);
        for (int i = 0; i < count; i++) {
            fprintf(stderr, "[harness] h_addr_list[%d] = %p\n", i,
                    (void *)host->h_addr_list[i]);

            /* Dereference h_addr_list[i] -- triggers NULL deref when
             * the entry was never populated (AAAA-only response). */
            char addr_str[INET_ADDRSTRLEN];
            struct in_addr *addr = (struct in_addr *)host->h_addr_list[i];
            inet_ntop(AF_INET, addr, addr_str, sizeof(addr_str));
            fprintf(stderr, "[harness]   -> %s (ttl=%d)\n", addr_str, info[i].ttl);
        }

        ares_free_hostent(host);
    }

    /* ---- Also test ares_parse_aaaa_reply (same bug pattern) ---- */
    host = NULL;
    struct ares_addr6ttl info6[16];
    count = 16;
    memset(info6, 0, sizeof(info6));

    status = ares_parse_aaaa_reply(buf, (int)nread, &host, info6, &count);

    fprintf(stderr, "[harness] ares_parse_aaaa_reply returned status=%d, count=%d, host=%p\n",
            status, count, (void *)host);

    if (status == ARES_SUCCESS && host) {
        fprintf(stderr, "[harness] Iterating %d reported AAAA addresses...\n", count);
        for (int i = 0; i < count; i++) {
            fprintf(stderr, "[harness] h_addr_list[%d] = %p\n", i,
                    (void *)host->h_addr_list[i]);

            char addr_str[INET6_ADDRSTRLEN];
            struct in6_addr *addr = (struct in6_addr *)host->h_addr_list[i];
            inet_ntop(AF_INET6, addr, addr_str, sizeof(addr_str));
            fprintf(stderr, "[harness]   -> %s (ttl=%d)\n", addr_str, info6[i].ttl);
        }

        ares_free_hostent(host);
    }

    fprintf(stderr, "[harness] Done.\n");
    free(buf);
    return 0;
}
