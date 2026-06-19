/*
 * OSV-2020-1897: Heap-buffer-overflow in stbi__tga_load
 *
 * A TGA file with colormap_type=1 (colormapped) but colormap_length=0
 * causes stb_image to allocate a zero-size palette buffer and then
 * read from it when looking up pixel indices, resulting in a
 * heap-buffer-overflow.
 *
 * Fixed in stb commit bfaccab17a648b315543d366c63aee575a0756b7
 * by adding: if (tga_palette_len == 0) { ... return error; }
 */

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <tga_file>\n", argv[0]);
        return 1;
    }

    /* Read the entire file into memory */
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "Cannot open %s\n", argv[1]);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *buf = (unsigned char *)malloc(len);
    if (!buf) {
        fclose(f);
        fprintf(stderr, "malloc failed\n");
        return 1;
    }

    fread(buf, 1, len, f);
    fclose(f);

    /* Decode from memory -- this triggers the vulnerability */
    int x, y, comp;
    unsigned char *img = stbi_load_from_memory(buf, (int)len, &x, &y, &comp, 0);

    if (img) {
        printf("Decoded %dx%d, comp=%d\n", x, y, comp);
        stbi_image_free(img);
    } else {
        printf("stbi_load_from_memory failed: %s\n", stbi_failure_reason());
    }

    free(buf);
    return 0;
}
