/*
 * Harness for OSV-2021-924 (dnsmasq heap-buffer-overflow WRITE 1)
 *
 * Vulnerability in check_for_bogus_wildcard() in src/rfc1035.c
 * This harness reads a PoC binary file and feeds it through the same
 * path as the OSS-Fuzz fuzz_rfc1035 FuzzCheckForBogusWildcard target.
 *
 * The PoC file format mirrors the OSS-Fuzz convention:
 *   byte 0:        sub-target selector (should be 7 for bogus wildcard)
 *   bytes 1..N:    consumed by init_daemon() to set up daemon struct
 *   remaining:     MAXDNAME-length name + DNS packet data
 */
#include "dnsmasq.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>


/* Forward declarations from fuzz infrastructure */
extern void cache_start_insert(void);

/* Minimal garbage collector */
#define GB_SIZE 100
void *pointer_arr[GB_SIZE];
static int pointer_idx = 0;

void gb_init() {
    pointer_idx = 0;
    for (int i = 0; i < GB_SIZE; i++)
        pointer_arr[i] = NULL;
}

void gb_cleanup() {
    for (int i = 0; i < GB_SIZE; i++) {
        if (pointer_arr[i] != NULL)
            free(pointer_arr[i]);
    }
}

char *gb_alloc_data(size_t len) {
    char *ptr = calloc(1, len);
    if (ptr && pointer_idx < GB_SIZE)
        pointer_arr[pointer_idx++] = (void *)ptr;
    return ptr;
}

short get_short(const uint8_t **data, size_t *size) {
    if (*size <= 0) return 0;
    short c = (short)(*data)[0];
    *data += 1;
    *size -= 1;
    return c;
}

int get_int(const uint8_t **data, size_t *size) {
    if (*size <= 4) return 0;
    int val;
    memcpy(&val, *data, 4);
    *data += 4;
    *size -= 4;
    return val;
}

char *get_len_null_terminated(const uint8_t **data, size_t *size, size_t to_get) {
    if (*size < to_get || (int)*size < 0) return NULL;
    char *new_s = malloc(to_get + 1);
    memcpy(new_s, *data, to_get);
    new_s[to_get] = '\0';
    *data = *data + to_get;
    *size -= to_get;
    return new_s;
}

char *get_null_terminated(const uint8_t **data, size_t *size) {
#define STR_SIZE 75
    return get_len_null_terminated(data, size, STR_SIZE);
}

char *gb_get_null_terminated(const uint8_t **data, size_t *size) {
    char *nstr = get_null_terminated(data, size);
    if (nstr == NULL) return NULL;
    if (pointer_idx < GB_SIZE)
        pointer_arr[pointer_idx++] = (void *)nstr;
    return nstr;
}

char *gb_get_len_null_terminated(const uint8_t **data, size_t *size, size_t to_get) {
    char *nstr = get_len_null_terminated(data, size, to_get);
    if (nstr != NULL && pointer_idx < GB_SIZE)
        pointer_arr[pointer_idx++] = (void *)nstr;
    return nstr;
}

char *gb_get_random_data(const uint8_t **data, size_t *size, size_t to_get) {
    if (*size < to_get || (int)*size < 0) return NULL;
    char *new_s = malloc(to_get);
    memcpy(new_s, *data, to_get);
    if (pointer_idx < GB_SIZE)
        pointer_arr[pointer_idx++] = (void *)new_s;
    *data = *data + to_get;
    *size -= to_get;
    return new_s;
}

/* Stub for blockdata cleanup */
void fuzz_blockdata_cleanup(void) {}

/* Minimal init_daemon -- sets up enough for check_for_bogus_wildcard */
int init_daemon_minimal(const uint8_t **data, size_t *size) {
    daemon = (struct daemon *)gb_alloc_data(sizeof(struct daemon));
    if (!daemon) return -1;

    daemon->namebuff = gb_alloc_data(MAXDNAME);
    if (!daemon->namebuff) return -1;

    daemon->addrbuff = gb_alloc_data(200);
    if (!daemon->addrbuff) return -1;

    /* Set up ignore_addr for check_for_bogus_wildcard */
    struct bogus_addr *bb = (struct bogus_addr *)gb_alloc_data(sizeof(struct bogus_addr));
    if (!bb) return -1;
    daemon->ignore_addr = bb;

    /* Set up doctors */
    struct doctor *doctors = (struct doctor *)gb_alloc_data(sizeof(struct doctor));
    if (!doctors) return -1;
    doctors->next = NULL;
    daemon->doctors = doctors;

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <poc_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    size_t total_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *buf = (uint8_t *)malloc(total_size);
    if (!buf) { fclose(f); return 1; }
    fread(buf, 1, total_size, f);
    fclose(f);

    if (total_size < 1) { free(buf); return 0; }

    gb_init();

    const uint8_t *data = buf;
    size_t size = total_size;

    /* Skip target selector byte */
    data += 1;
    size -= 1;

    if (init_daemon_minimal(&data, &size) != 0) {
        gb_cleanup();
        free(buf);
        return 0;
    }

    cache_init();
    blockdata_init();

    /* FuzzCheckForBogusWildcard path */
    char *nname = gb_get_len_null_terminated(&data, &size, MAXDNAME);
    if (nname != NULL && size > (sizeof(struct dns_header) + 50)) {
        char *new_data = malloc(size + 1);
        memset(new_data, 0, size);
        memcpy(new_data, data, size);
        new_data[size] = '\0';
        if (pointer_idx < GB_SIZE)
            pointer_arr[pointer_idx++] = (void *)new_data;

        time_t now = 0;
        check_for_bogus_wildcard((struct dns_header *)new_data, size, nname, now);
    }

    cache_start_insert();

    gb_cleanup();
    free(buf);
    return 0;
}
