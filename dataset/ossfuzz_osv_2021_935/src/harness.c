/*
 * Harness for OSV-2021-935 (dnsmasq heap-buffer-overflow WRITE 1 in answer_request)
 *
 * Reads a PoC file and calls answer_request() with a crafted DNS
 * query packet, mirroring the fuzz_rfc1035 FuzzAnswerTheRequest
 * (sub-target 1) path.
 */
#include "dnsmasq.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <netinet/in.h>


#define GB_SIZE 100
void *pointer_arr[GB_SIZE];
static int pointer_idx = 0;

void gb_init() {
    pointer_idx = 0;
    for (int i = 0; i < GB_SIZE; i++) pointer_arr[i] = NULL;
}
void gb_cleanup() {
    for (int i = 0; i < GB_SIZE; i++)
        if (pointer_arr[i]) free(pointer_arr[i]);
}
char *gb_alloc_data(size_t len) {
    char *p = calloc(1, len);
    if (p && pointer_idx < GB_SIZE) pointer_arr[pointer_idx++] = p;
    return p;
}
void fuzz_blockdata_cleanup(void) {}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "Usage: %s <poc>\n", argv[0]); return 1; }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    size_t sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(sz);
    fread(buf, 1, sz, f);
    fclose(f);

    gb_init();

    daemon = (struct daemon *)gb_alloc_data(sizeof(struct daemon));
    if (!daemon) { gb_cleanup(); free(buf); return 1; }
    daemon->namebuff = gb_alloc_data(MAXDNAME);
    daemon->addrbuff = gb_alloc_data(200);

    struct bogus_addr *bb = (struct bogus_addr *)gb_alloc_data(sizeof(struct bogus_addr));
    if (bb) daemon->ignore_addr = bb;

    struct doctor *doctors = (struct doctor *)gb_alloc_data(sizeof(struct doctor));
    if (doctors) { doctors->next = NULL; daemon->doctors = doctors; }

    cache_init();
    blockdata_init();

    /* FuzzAnswerTheRequest path */
    if (sz > sizeof(struct dns_header) + 50) {
        char *new_data = malloc(sz);
        if (new_data) {
            memset(new_data, 0, sz);
            memcpy(new_data, buf, sz);
            pointer_arr[pointer_idx++] = new_data;

            struct in_addr local_addr = {0};
            struct in_addr local_netmask = {0};
            time_t now = 0;

            answer_request((struct dns_header *)new_data,
                           new_data + sz, sz,
                           local_addr, local_netmask, now, 0, 0, 0);
        }
    }

    cache_start_insert();
    gb_cleanup();
    free(buf);
    return 0;
}
