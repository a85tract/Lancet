/*
 * OSV-2023-90: Heap-buffer-overflow in scanf_one
 *
 * The bug: In LibRaw_buffer_datastream::scanf_one(), the loop condition
 * is "while (streampos < streamsize)" but the loop body can increment
 * streampos to exactly streamsize, then the next iteration reads
 * buf[streamsize] which is one byte past the end of the buffer (off-by-one).
 *
 * This is triggered through the MOS (Leaf/Mamiya) metadata parsing path:
 * parse_tiff_ifd -> parse_mos -> scanf_one.
 *
 * Fixed in commit 443b7fb51e1c by changing the loop condition from
 * "streampos < streamsize" to "streampos < streamsize-1".
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <libraw/libraw.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <raw_image_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "Cannot open %s\n", argv[1]);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *buf = (unsigned char *)malloc(len);
    if (!buf) { fclose(f); return 1; }
    fread(buf, 1, len, f);
    fclose(f);

    fprintf(stderr, "[harness] Processing %ld bytes from %s\n", len, argv[1]);

    LibRaw raw;
    raw.imgdata.rawparams.max_raw_memory_mb = 300;

    int ret = raw.open_buffer(buf, len);
    if (ret != LIBRAW_SUCCESS) {
        fprintf(stderr, "[harness] open_buffer failed: %s\n", libraw_strerror(ret));
        free(buf);
        return 0;
    }

    ret = raw.unpack();
    if (ret != LIBRAW_SUCCESS) {
        fprintf(stderr, "[harness] unpack failed: %s\n", libraw_strerror(ret));
        free(buf);
        return 0;
    }

    ret = raw.unpack_thumb();
    if (ret != LIBRAW_SUCCESS) {
        fprintf(stderr, "[harness] unpack_thumb failed: %s\n", libraw_strerror(ret));
    }

    ret = raw.raw2image();
    if (ret != LIBRAW_SUCCESS) {
        fprintf(stderr, "[harness] raw2image failed: %s\n", libraw_strerror(ret));
    }

    raw.recycle();
    free(buf);
    fprintf(stderr, "[harness] Done\n");
    return 0;
}
