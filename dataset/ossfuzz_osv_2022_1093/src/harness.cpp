/*
 * OSV-2022-1093: Heap-buffer-overflow in kodak_rgb_load_raw
 *
 * The bug: kodak_thumb_loader() does not validate thumbnail dimensions
 * (T.twidth, T.theight) against reasonable bounds, and kodak_jpeg_load_raw()
 * does not check data_size against the max_raw_memory_mb limit. A crafted
 * raw image with excessively large or zero thumbnail dimensions causes
 * out-of-bounds writes during Kodak thumbnail decoding.
 *
 * Fixed in commit dc0c984edfc9 by adding dimension bounds checks
 * (16..8192) in kodak_thumb_loader and data_size limit checks in
 * kodak_jpeg_load_raw.
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
