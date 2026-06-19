/*
 * Harness for OSV-2021-932 (dnsmasq heap-buffer-overflow WRITE in resize_packet)
 *
 * Reads a PoC file and calls resize_packet() with a crafted DNS packet,
 * mirroring the fuzz_rfc1035 FuzzResizePacket (sub-target 5) path.
 */
#include "dnsmasq.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


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

    struct doctor *doctors = (struct doctor *)gb_alloc_data(sizeof(struct doctor));
    if (doctors) { doctors->next = NULL; daemon->doctors = doctors; }

    cache_init();
    blockdata_init();

    /* FuzzResizePacket path */
    if (sz > sizeof(struct dns_header) + 50) {
        char *new_packet = malloc(50);
        char *new_data = malloc(sz + 1);
        if (new_data && new_packet) {
            memset(new_data, 0, sz);
            memcpy(new_data, buf, sz);
            new_data[sz] = '\0';

            resize_packet((struct dns_header *)new_data, sz,
                          (unsigned char *)new_packet, 50);
        }
        free(new_packet);
        free(new_data);
    }

    gb_cleanup();
    free(buf);
    return 0;
}
