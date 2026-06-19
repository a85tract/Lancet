#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <image_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "Cannot open %s\n", argv[1]);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *data = (unsigned char *)malloc(size);
    if (!data) {
        fclose(f);
        fprintf(stderr, "Out of memory\n");
        return 1;
    }

    fread(data, 1, size, f);
    fclose(f);

    int x, y, channels;
    /*
     * OSV-2021-979: Requesting 4 channels (req_comp=4) on a 16-bit PGM
     * triggers stbi__convert_format() (8-bit) instead of
     * stbi__convert_format16() (16-bit). The 8-bit convert treats the
     * 16-bit-sized buffer as 8-bit, producing a result that is too small.
     * Later, stbi__convert_16_to_8 reads 2x the allocated size -> heap OOB.
     */
    unsigned char *img = stbi_load_from_memory(data, (int)size, &x, &y, &channels, 4);
    if (img) {
        printf("Loaded: %dx%d channels=%d\n", x, y, channels);
        stbi_image_free(img);
    } else {
        printf("Failed to load: %s\n", stbi_failure_reason());
    }

    free(data);
    return 0;
}
