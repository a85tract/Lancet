/*
 * OSV-2023-1117: Heap-buffer-overflow in cmsMLUsetWide
 *
 * Bug: In Type_Text_Description_Read(), the UnicodeString buffer is allocated
 *      as exactly UnicodeCount * sizeof(wchar_t) with no room for a null
 *      terminator. After reading UnicodeCount wide chars, the string is passed
 *      to cmsMLUsetWide() which internally calls mywcslen() to measure the
 *      string length. Since there is no null terminator, mywcslen reads past
 *      the end of the heap buffer -- heap-buffer-overflow READ.
 *
 * Fix commit: 178d734163b315db3009fa473930688a9047656f
 *      Allocates (UnicodeCount + 1) * sizeof(wchar_t), writes null terminator,
 *      rejects UnicodeCount==0, and fixes memory leak in error path.
 *
 * Harness: Opens profile from file, reads tags (triggering desc tag parsing),
 *          which hits the vulnerable Type_Text_Description_Read code path.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "lcms2.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <icc_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = (uint8_t *)malloc(sz);
    if (!buf) { fclose(f); return 1; }
    fread(buf, 1, sz, f);
    fclose(f);

    cmsHPROFILE hProfile = cmsOpenProfileFromMem(buf, sz);
    free(buf);
    if (!hProfile) {
        fprintf(stderr, "Failed to open profile\n");
        return 1;
    }

    /* Reading the 'desc' tag triggers Type_Text_Description_Read */
    cmsUInt32Number n = cmsGetTagCount(hProfile);
    printf("Tag count: %u\n", n);

    for (cmsUInt32Number i = 0; i < n; i++) {
        cmsTagSignature sig = cmsGetTagSignature(hProfile, i);
        void *tag = cmsReadTag(hProfile, sig);
        if (tag) {
            printf("  Tag 0x%08x read OK\n", sig);
        } else {
            printf("  Tag 0x%08x read FAILED\n", sig);
        }
    }

    cmsCloseProfile(hProfile);
    printf("Done.\n");
    return 0;
}
