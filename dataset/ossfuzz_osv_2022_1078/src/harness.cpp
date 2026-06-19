/*
 * OSV-2022-1078: Heap-buffer-overflow in LibRaw_buffer_datastream::read
 *
 * The bug: In kodak_thumb_loader(), S.iheight and S.iwidth are not set
 * from S.height and S.width before the calloc that allocates imgdata.image.
 * This causes the buffer to be allocated based on uninitialized/stale
 * S.iheight * S.iwidth values, while subsequent reads via
 * kodak_thumb_load_raw -> read_shorts write based on S.height * S.width,
 * causing a heap-buffer-overflow.
 *
 * Fixed in commit 63794a2471b4 by adding:
 *   S.iheight = S.height;
 *   S.iwidth = S.width;
 * before the calloc in kodak_thumb_loader.
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
