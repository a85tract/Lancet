/*
 * ZIP archive read fuzzer for libzip
 *
 * OSV-2023-31: Heap-use-after-free in zip_source_open
 * The vulnerability occurs in zip_check_torrentzip() in zip_open.c.
 * After the ownership model change for layered sources, an explicit
 * zip_source_free(src_window) freed memory that src_crc still referenced.
 * When zip_source_open(src_crc) was called, it accessed freed memory.
 * OSS-Fuzz issue: 55365
 * Fix commit: e907b0bd (single line deletion)
 * Vulnerable version: just before e907b0bd
 */
#include <stdint.h>
#include <stdio.h>
#include <zip.h>

static void fuzzer_read(zip_t *za, zip_error_t *error, const char *password)
{
    zip_int64_t i, n, ret;
    char buf[32768];

    if (za == NULL) {
        zip_error_fini(error);
        return;
    }

    zip_set_default_password(za, password);
    zip_error_fini(error);

    n = zip_get_num_entries(za, 0);
    for (i = 0; i < n; i++) {
        zip_file_t *f = zip_fopen_index(za, i, 0);
        if (f == NULL)
            continue;

        while ((ret = zip_fread(f, buf, sizeof(buf))) > 0)
            ;

        zip_fclose(f);
    }

    if (zip_close(za) < 0)
        zip_discard(za);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    zip_source_t *src;
    zip_error_t error;
    zip_t *za;

    zip_error_init(&error);

    if ((src = zip_source_buffer_create(data, size, 0, &error)) == NULL) {
        zip_error_fini(&error);
        return 0;
    }

    za = zip_open_from_source(src, 0, &error);

    fuzzer_read(za, &error, "secretpassword");

    if (za == NULL)
        zip_source_free(src);

    return 0;
}
