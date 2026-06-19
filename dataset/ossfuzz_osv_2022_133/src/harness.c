/*
 * Harness for OSV-2022-133: heap-buffer-overflow in coap_split_uri_sub
 *
 * Bug: In libcoap's OSS-Fuzz pdu_parse_target, the return value of
 * coap_pdu_parse() was not checked. When coap_pdu_parse() fails (returns 0),
 * the PDU contents are undefined/malformed, but the buggy code proceeds to
 * call coap_get_uri_path() and coap_get_query() on the broken PDU. This
 * causes coap_split_uri_sub() to read past the allocated buffer boundaries
 * when iterating over malformed CoAP options, resulting in a heap-buffer-
 * overflow READ.
 *
 * Fix commit ba585f848ff527f2181f8f2bfd40520563e9e68d wraps the calls to
 * coap_get_query(), coap_get_uri_path(), coap_show_pdu(), and
 * coap_pdu_encode_header() inside an if-block that only executes when
 * coap_pdu_parse() returns non-zero (success).
 *
 * This harness reproduces the buggy path: it reads a binary file containing
 * raw CoAP PDU data, calls coap_pdu_parse() WITHOUT checking its return
 * value, and then calls coap_get_uri_path() on the result, triggering the
 * heap OOB read.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "coap3/coap.h"

/* Declare prototype for internal function coap_pdu_encode_header() */
size_t coap_pdu_encode_header(coap_pdu_t *, coap_proto_t);

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    /* Read input file */
    struct stat st;
    if (stat(argv[1], &st) != 0) {
        perror("stat");
        return 1;
    }
    size_t size = (size_t)st.st_size;

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    uint8_t *data = (uint8_t *)malloc(size);
    if (!data) {
        perror("malloc");
        close(fd);
        return 1;
    }

    ssize_t nread = read(fd, data, size);
    close(fd);
    if (nread < 0 || (size_t)nread != size) {
        fprintf(stderr, "Failed to read input file\n");
        free(data);
        return 1;
    }

    /* Print input size and hex dump of first 64 bytes */
    printf("Input size: %zu bytes\n", size);
    printf("Hex dump (first %zu bytes):\n", size < 64 ? size : (size_t)64);
    for (size_t i = 0; i < size && i < 64; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    /* Reproduce the buggy code path from pdu_parse_target.c (pre-fix):
     * coap_pdu_parse() is called but its return value is IGNORED.
     * Then coap_get_uri_path() and coap_get_query() are called on the
     * potentially-invalid PDU, triggering heap OOB in coap_split_uri_sub.
     */
    coap_pdu_t *pdu = coap_pdu_init(0, 0, 0, size);
    if (pdu) {
        coap_set_log_level(LOG_DEBUG);

        /* BUG: return value of coap_pdu_parse() is intentionally ignored
         * to reproduce the vulnerable code path */
        int parse_result = coap_pdu_parse(COAP_PROTO_UDP, data, size, pdu);
        printf("coap_pdu_parse returned: %d\n", parse_result);

        /* These calls proceed regardless of parse_result, matching the
         * buggy pre-fix code. When parse fails, PDU contents are undefined
         * and these functions may read out of bounds. */
        coap_string_t *query = coap_get_query(pdu);
        coap_string_t *uri_path = coap_get_uri_path(pdu);

        printf("coap_get_query returned: %s\n", query ? "non-NULL" : "NULL");
        printf("coap_get_uri_path returned: %s\n", uri_path ? "non-NULL" : "NULL");

        if (query) {
            printf("Query length: %zu\n", query->length);
        }
        if (uri_path) {
            printf("URI path length: %zu\n", uri_path->length);
        }

        coap_show_pdu(LOG_DEBUG, pdu);
        coap_pdu_encode_header(pdu, COAP_PROTO_UDP);

        coap_delete_string(query);
        coap_delete_string(uri_path);
        coap_delete_pdu(pdu);
    }

    free(data);
    printf("Done.\n");
    return 0;
}
