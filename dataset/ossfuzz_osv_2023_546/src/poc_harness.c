/*
 * Harness for OSV-2023-546: heap-buffer-overflow leading to invalid-free
 * in jpeg_free_large during JPEG transformation (libjpeg-turbo)
 *
 * Bug: The OSS-Fuzz transform fuzzer (fuzz/transform.cc) allocates the
 * destination buffer for grayscale transformation using
 *   tjBufSize(w, h, TJSAMP_GRAY)
 * instead of the correct
 *   tjBufSize(w, h, jpegSubsamp)
 *
 * The critical mechanism (turbojpeg.c line 2043): when TJFLAG_NOREALLOC
 * is set, tjTransform() overwrites dstSizes[i] with
 *   tjBufSize(w, h, jpegSubsamp)
 * before calling jpeg_mem_dest_tj(). This tells the library's
 * destination manager that the buffer is the FULL subsampling size,
 * even though the user only allocated the smaller GRAY size. The
 * library then writes output data past the actual allocation.
 *
 * For a JPEG with extra COM markers (which get copied to the output
 * when TJXOPT_COPYNONE is not set), the output exceeds the GRAY buffer
 * allocation, causing a heap-buffer-overflow. The heap corruption then
 * leads to invalid-free when the library cleans up internal structures.
 *
 * Fix commit: 95881ce8241deb2ca70dd35399009bbdfc99cff5
 *   Changed tjBufSize(..., TJSAMP_GRAY) to tjBufSize(..., jpegSubsamp)
 *   in fuzz/transform.cc at lines 101 and 105.
 */

#include <turbojpeg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <jpeg_file>\n", argv[0]);
        return 1;
    }

    /* Read JPEG from file */
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "[harness] Error: cannot open '%s'\n", argv[1]);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    rewind(f);

    unsigned char *jpegBuf = (unsigned char *)malloc(fsize);
    if (!jpegBuf) {
        fclose(f);
        fprintf(stderr, "[harness] Error: malloc failed\n");
        return 1;
    }
    fread(jpegBuf, 1, fsize, f);
    fclose(f);

    fprintf(stderr, "[harness] Input file: %s (%ld bytes)\n", argv[1], fsize);

    /* Hex dump of first 32 bytes */
    fprintf(stderr, "[harness] First bytes (hex): ");
    int dumpLen = fsize < 32 ? (int)fsize : 32;
    for (int i = 0; i < dumpLen; i++)
        fprintf(stderr, "%02x ", jpegBuf[i]);
    fprintf(stderr, "\n");

    /* Initialize TurboJPEG transform handle */
    tjhandle handle = tjInitTransform();
    if (!handle) {
        fprintf(stderr, "[harness] tjInitTransform failed\n");
        free(jpegBuf);
        return 1;
    }

    /* Parse JPEG header to get dimensions and subsampling */
    int width = 0, height = 0, jpegSubsamp = 0, jpegColorspace = 0;
    tjDecompressHeader3(handle, jpegBuf, (unsigned long)fsize,
                        &width, &height, &jpegSubsamp, &jpegColorspace);

    fprintf(stderr, "[harness] Dimensions: %dx%d\n", width, height);
    fprintf(stderr, "[harness] Subsampling: %d (0=444, 1=422, 2=420, 3=GRAY, 4=440, 5=411)\n",
            jpegSubsamp);
    fprintf(stderr, "[harness] Colorspace: %d\n", jpegColorspace);

    if (width < 1 || height < 1) {
        fprintf(stderr, "[harness] Invalid dimensions\n");
        tjDestroy(handle);
        free(jpegBuf);
        return 1;
    }

    if (jpegSubsamp < 0 || jpegSubsamp >= TJ_NUMSAMP)
        jpegSubsamp = TJSAMP_444;

    /* Display the buffer size discrepancy -- this is the root cause */
    unsigned long correctSize = tjBufSize(width, height, jpegSubsamp);
    unsigned long graySize = tjBufSize(width, height, TJSAMP_GRAY);
    fprintf(stderr, "[harness] tjBufSize(subsamp=%d) = %lu (correct, library assumes this)\n",
            jpegSubsamp, correctSize);
    fprintf(stderr, "[harness] tjBufSize(TJSAMP_GRAY) = %lu (buggy, what we allocate)\n",
            graySize);
    fprintf(stderr, "[harness] Buffer deficit: %lu bytes\n",
            correctSize - graySize);

    /* ---------------------------------------------------------------
     * BUG REPRODUCTION
     *
     * Set up a grayscale transform (TJXOPT_GRAY) WITHOUT TJXOPT_COPYNONE.
     * This makes the library copy COM markers from the input to the
     * output, inflating the output size.
     *
     * Allocate the destination buffer using tjBufSize(w, h, TJSAMP_GRAY)
     * -- the bug. With TJFLAG_NOREALLOC, the library overwrites
     * dstSizes[0] to tjBufSize(w, h, jpegSubsamp) and configures the
     * destination manager to think the buffer is that large.
     *
     * When the output exceeds our actual allocation (graySize), the
     * library writes past the buffer boundary.
     * --------------------------------------------------------------- */

    fprintf(stderr, "\n[harness] === Grayscale transform with undersized buffer ===\n");

    tjtransform xform;
    memset(&xform, 0, sizeof(xform));
    xform.op = TJXOP_NONE;
    /* TJXOPT_GRAY converts to grayscale.
     * NO TJXOPT_COPYNONE: markers (COM) will be copied to output,
     * inflating the output past the GRAY buffer limit. */
    xform.options = TJXOPT_GRAY;

    /* BUG: allocate buffer using TJSAMP_GRAY (too small) */
    unsigned long userBufSize = tjBufSize(width, height, TJSAMP_GRAY);
    unsigned char *dstBufs[1];
    unsigned long dstSizes[1] = { 0 };

    dstBufs[0] = (unsigned char *)malloc(userBufSize);
    if (!dstBufs[0]) {
        fprintf(stderr, "[harness] malloc failed\n");
        tjDestroy(handle);
        free(jpegBuf);
        return 1;
    }

    fprintf(stderr, "[harness] Allocated dst buffer: %lu bytes\n", userBufSize);
    fprintf(stderr, "[harness] Library will assume:  %lu bytes (after NOREALLOC overwrite)\n",
            correctSize);
    fprintf(stderr, "[harness] Calling tjTransform (TJXOP_NONE | TJXOPT_GRAY | NOREALLOC)...\n");

    int ret = tjTransform(handle, jpegBuf, (unsigned long)fsize,
                          1, dstBufs, dstSizes, &xform,
                          TJFLAG_LIMITSCANS | TJFLAG_NOREALLOC);

    fprintf(stderr, "[harness] tjTransform returned: %d\n", ret);
    if (ret != 0)
        fprintf(stderr, "[harness] error: %s\n", tjGetErrorStr2(handle));
    fprintf(stderr, "[harness] Output size: %lu bytes (buffer: %lu)\n",
            dstSizes[0], userBufSize);

    /* Free the buffer -- if heap was corrupted, this may crash */
    fprintf(stderr, "[harness] Freeing destination buffer...\n");
    free(dstBufs[0]);

    fprintf(stderr, "[harness] Destroying TJ handle...\n");
    tjDestroy(handle);
    free(jpegBuf);

    fprintf(stderr, "[harness] Done.\n");
    return 0;
}
