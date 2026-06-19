/*
 * Standalone harness for mupdf PDF fuzzer (OSV-2018-247).
 * Mimics the OSS-Fuzz pdf_fuzzer: opens a PDF from memory,
 * iterates pages, renders each to an RGB pixmap.
 *
 * The UAF triggers during context cleanup (fz_drop_context ->
 * fz_drop_colorspace_context -> fz_drop_key_storable) because
 * pdf_dict_put_drop() corrupts refcounts on shared static
 * PDF name objects.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mupdf/fitz.h>

int main(int argc, char **argv)
{
    fz_context *ctx;
    fz_stream *stream = NULL;
    fz_document *doc = NULL;
    fz_pixmap *pix = NULL;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pdf_file>\n", argv[0]);
        return 1;
    }

    /* Read input file */
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *data = malloc(size);
    if (!data) {
        fclose(f);
        return 1;
    }
    fread(data, 1, size, f);
    fclose(f);

    /* Initialize mupdf context */
    ctx = fz_new_context(NULL, NULL, FZ_STORE_DEFAULT);
    if (!ctx) {
        fprintf(stderr, "Cannot create mupdf context\n");
        free(data);
        return 1;
    }

    fz_var(stream);
    fz_var(doc);
    fz_var(pix);

    fz_try(ctx)
    {
        fz_register_document_handlers(ctx);
        stream = fz_open_memory(ctx, data, size);
        doc = fz_open_document_with_stream(ctx, "pdf", stream);

        int pages = fz_count_pages(ctx, doc);
        for (int i = 0; i < pages; i++) {
            pix = fz_new_pixmap_from_page_number(ctx, doc, i,
                &fz_identity, fz_device_rgb(ctx), 0);
            fz_drop_pixmap(ctx, pix);
            pix = NULL;
        }
    }
    fz_always(ctx)
    {
        fz_drop_pixmap(ctx, pix);
        fz_drop_document(ctx, doc);
        fz_drop_stream(ctx, stream);
    }
    fz_catch(ctx)
    {
        /* Silently ignore errors - we're fuzzing */
    }

    fz_drop_context(ctx);
    free(data);
    return 0;
}
