#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "libexif/exif-data.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ExifData *exif_data = exif_data_new_from_data(data, size);
    if (exif_data) {
        exif_data_unref(exif_data);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = (uint8_t *)malloc(fsize);
    if (!buf) { fclose(f); return 1; }
    fread(buf, 1, fsize, f);
    fclose(f);
    LLVMFuzzerTestOneInput(buf, fsize);
    free(buf);
    return 0;
}
