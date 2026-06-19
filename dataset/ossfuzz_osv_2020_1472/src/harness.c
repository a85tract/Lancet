#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <image_file>\n", argv[0]);
        return 1;
    }

    /* Read the entire file into memory */
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "Error: cannot open '%s'\n", argv[1]);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *data = (unsigned char *)malloc(len);
    if (!data) {
        fprintf(stderr, "Error: malloc failed\n");
        fclose(f);
        return 1;
    }

    if ((long)fread(data, 1, len, f) != len) {
        fprintf(stderr, "Error: short read\n");
        free(data);
        fclose(f);
        return 1;
    }
    fclose(f);

    /* Decode the image - this is where the OOB read occurs on vulnerable versions */
    int x, y, comp;
    unsigned char *img = stbi_load_from_memory(data, (int)len, &x, &y, &comp, 0);

    if (img) {
        printf("Decoded: %dx%d, %d components\n", x, y, comp);
        stbi_image_free(img);
    } else {
        printf("Decode failed: %s\n", stbi_failure_reason());
    }

    free(data);
    return 0;
}
