/*
 * OSV-2022-615: Heap-buffer-overflow in TetrahedralInterp16
 *
 * Bug: _cmsReadHeader() does not reject ICC tags with size==0 or offset==0.
 *      A zero-offset/zero-size tag passes the existing "offset+size > HeaderSize"
 *      check (0+0=0 <= anything). The tag is registered, and when later code
 *      tries to read/interpret its data it reads from offset 0 of the profile
 *      (the ICC header itself), misinterpreting header bytes as tag payload.
 *      This corrupts internal structures, and during pipeline evaluation
 *      TetrahedralInterp16 performs an OOB heap read.
 *
 * Fix commit: 1394d740d96886b501e0ad04fe926a72eca3f01c
 *      Adds: if (Tag.size == 0 || Tag.offset == 0) continue;
 *      Also rejects profiles with TagCount==0 after filtering.
 *
 * Harness: Opens profile from file, creates sRGB dest, runs cmsDoTransform.
 *          This exercises the full pipeline including TetrahedralInterp16.
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

    cmsHPROFILE srcProfile = cmsOpenProfileFromMem(buf, sz);
    free(buf);
    if (!srcProfile) {
        fprintf(stderr, "Failed to open source profile\n");
        return 1;
    }

    cmsHPROFILE dstProfile = cmsCreate_sRGBProfile();
    if (!dstProfile) {
        cmsCloseProfile(srcProfile);
        return 1;
    }

    cmsColorSpaceSignature srcCS = cmsGetColorSpace(srcProfile);
    cmsUInt32Number nSrcComponents = cmsChannelsOf(srcCS);
    cmsUInt32Number srcFormat;

    if (srcCS == cmsSigLabData) {
        srcFormat = COLORSPACE_SH(PT_Lab) | CHANNELS_SH(nSrcComponents) | BYTES_SH(0);
    } else {
        srcFormat = COLORSPACE_SH(PT_ANY) | CHANNELS_SH(nSrcComponents) | BYTES_SH(1);
    }

    cmsHTRANSFORM hTransform = cmsCreateTransform(
        srcProfile, srcFormat,
        dstProfile, TYPE_BGR_8,
        INTENT_PERCEPTUAL, 0);

    cmsCloseProfile(srcProfile);
    cmsCloseProfile(dstProfile);

    if (!hTransform) {
        fprintf(stderr, "Failed to create transform\n");
        return 1;
    }

    uint8_t output[4] = {0};
    if (T_BYTES(srcFormat) == 0) {
        double input[16] = {0};
        for (uint32_t i = 0; i < nSrcComponents && i < 16; i++) input[i] = 0.5;
        cmsDoTransform(hTransform, input, output, 1);
    } else {
        uint8_t input[16] = {0};
        for (uint32_t i = 0; i < nSrcComponents && i < 16; i++) input[i] = 128;
        cmsDoTransform(hTransform, input, output, 1);
    }

    printf("Transform output: %02x %02x %02x %02x\n",
           output[0], output[1], output[2], output[3]);

    cmsDeleteTransform(hTransform);
    return 0;
}
