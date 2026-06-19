/*
 * OSV-2023-1164: Heap-buffer-overflow in WriteCLUT
 *
 * Bug: In WriteOutputLUT() (src/cmsps2.c), the return value of
 *      _cmsOptimizePipeline() is not checked. When optimization fails
 *      (e.g., due to a malformed profile that cannot produce a valid CLUT),
 *      execution continues with an invalid/incomplete DeviceLink pipeline.
 *      This pipeline is passed to WriteCLUT(), which attempts to iterate
 *      over CLUT table entries that don't exist or are undersized,
 *      causing a heap-buffer-overflow READ.
 *
 * Fix commit: 1176e61afea4b58c5f92c6f226cdb7b1c76797d5
 *      Checks _cmsOptimizePipeline() return value and bails out on failure.
 *
 * Harness: Based on OSS-Fuzz cms_postscript_fuzzer. Opens profile from file
 *          and calls both cmsGetPostScriptCSA and cmsGetPostScriptCRD with
 *          fuzz-derived intent/flags to exercise WriteOutputLUT -> WriteCLUT.
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
    uint8_t *data = (uint8_t *)malloc(sz);
    if (!data) { fclose(f); return 1; }
    fread(data, 1, sz, f);
    fclose(f);

    if (sz < 16) { free(data); return 1; }

    cmsContext context = cmsCreateContext(NULL, (void *)data);
    if (!context) { free(data); return 1; }

    cmsHPROFILE hProfile = cmsOpenProfileFromMem(data, sz);
    if (!hProfile) {
        cmsDeleteContext(context);
        free(data);
        fprintf(stderr, "Failed to open profile\n");
        return 1;
    }

    /* Use bytes from the input as flags/intent like cms_postscript_fuzzer */
    uint32_t flags  = *((const uint32_t *)(data + 8));
    uint32_t intent = *((const uint32_t *)(data + 12)) % 16;

    /* Try CRD generation (triggers WriteOutputLUT -> WriteCLUT) */
    cmsUInt32Number crd_size = cmsGetPostScriptCRD(context, hProfile, intent, flags, NULL, sz);
    printf("CRD: intent=%u, flags=0x%08x, size=%u\n", intent, flags, crd_size);

    if (crd_size > 0 && crd_size < 10*1024*1024) {
        char *crd_buf = (char *)malloc(crd_size);
        if (crd_buf) {
            cmsGetPostScriptCRD(context, hProfile, intent, flags, crd_buf, crd_size);
            printf("CRD generated OK (%u bytes)\n", crd_size);
            free(crd_buf);
        }
    }

    /* Also try CSA */
    cmsUInt32Number csa_size = cmsGetPostScriptCSA(context, hProfile, intent, flags, NULL, sz);
    printf("CSA: intent=%u, flags=0x%08x, size=%u\n", intent, flags, csa_size);

    if (csa_size > 0 && csa_size < 10*1024*1024) {
        char *csa_buf = (char *)malloc(csa_size);
        if (csa_buf) {
            cmsGetPostScriptCSA(context, hProfile, intent, flags, csa_buf, csa_size);
            printf("CSA generated OK (%u bytes)\n", csa_size);
            free(csa_buf);
        }
    }

    /* Try all standard intents too */
    for (int i = 0; i < 4; i++) {
        cmsGetPostScriptCRD(context, hProfile, i, 0, NULL, 0);
        cmsGetPostScriptCSA(context, hProfile, i, 0, NULL, 0);
    }

    cmsCloseProfile(hProfile);
    cmsDeleteContext(context);
    free(data);
    printf("Done.\n");
    return 0;
}
