/*
 * OSV-2022-647: Heap-use-after-free in cmsFreeNamedColorList
 *
 * Bug: _cmsReadHeader() does not validate the profile version or device class.
 *      A crafted profile with an absurd version (e.g., > 5.0) or invalid device
 *      class triggers unexpected code paths. Specifically, an invalid device class
 *      like cmsSigNamedColorClass combined with bad internal structures causes
 *      Type_NamedColor_Free -> cmsFreeNamedColorList to operate on already-freed
 *      memory during cmsCloseProfile.
 *
 * Fix commit: f3f6b7bceb629bc4b6f1dea3e45b44dc3f8674af
 *      Adds version check (must be <= 5.0) and device class validation via
 *      validDeviceClass() whitelist.
 *
 * Harness: Opens profile from file and closes it. The UAF happens during
 *          cmsCloseProfile -> Type_NamedColor_Free -> cmsFreeNamedColorList.
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

    /* Open profile -- this reads the header and tags */
    cmsHPROFILE hProfile = cmsOpenProfileFromMem(buf, sz);
    free(buf);

    if (!hProfile) {
        fprintf(stderr, "Failed to open profile\n");
        return 1;
    }

    /* Try to read tags to trigger internal processing */
    cmsUInt32Number n = cmsGetTagCount(hProfile);
    printf("Tag count: %u\n", n);

    for (cmsUInt32Number i = 0; i < n; i++) {
        cmsTagSignature sig = cmsGetTagSignature(hProfile, i);
        void *tag = cmsReadTag(hProfile, sig);
        if (tag) {
            printf("  Tag 0x%08x: read OK\n", sig);
        }
    }

    /* Close profile -- UAF happens here in the vulnerable version */
    printf("Closing profile...\n");
    cmsCloseProfile(hProfile);
    printf("Profile closed.\n");

    return 0;
}
