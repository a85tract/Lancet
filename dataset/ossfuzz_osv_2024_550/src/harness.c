/*
 * Harness for OSV-2024-550 (miniz heap-buffer-overflow in mz_zip_mem_read_func)
 *
 * Reads a file into memory, passes it to mz_zip_reader_init_mem().
 * If the archive opens, iterates entries and attempts to extract the first file.
 *
 * Vulnerability: A malformed ZIP where eocd_ofs < cdir_ofs + cdir_size causes
 * archive_ofs to underflow (wrap to a huge value). This corrupted offset is then
 * applied to the memory buffer in mz_zip_mem_read_func, producing a heap-OOB read.
 *
 * Fix commit: 8573fd7cd6f49b262a0ccc447f3c6acfc415e556 (merge of PR #310)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "miniz.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input.zip>\n", argv[0]);
        return 1;
    }

    /* Read input file into memory */
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0) {
        fclose(f);
        fprintf(stderr, "Empty or unreadable file\n");
        return 1;
    }

    unsigned char *data = (unsigned char *)malloc((size_t)fsize);
    if (!data) {
        fclose(f);
        fprintf(stderr, "malloc failed\n");
        return 1;
    }
    fread(data, 1, (size_t)fsize, f);
    fclose(f);

    /* Initialize zip archive from memory */
    mz_zip_archive zip;
    memset(&zip, 0, sizeof(zip));

    fprintf(stderr, "[*] Opening archive from memory (%ld bytes)...\n", fsize);

    if (mz_zip_reader_init_mem(&zip, data, (size_t)fsize, 0)) {
        mz_uint num_files = mz_zip_reader_get_num_files(&zip);
        fprintf(stderr, "[*] Archive opened, %u file(s) found\n", num_files);

        /* Try to extract the first file to trigger the OOB read */
        if (num_files > 0) {
            size_t uncomp_size = 0;
            void *extracted = mz_zip_reader_extract_to_heap(&zip, 0, &uncomp_size, 0);
            if (extracted) {
                fprintf(stderr, "[*] Extracted file 0: %zu bytes\n", uncomp_size);
                free(extracted);
            } else {
                fprintf(stderr, "[*] Extraction of file 0 failed (expected for malformed input)\n");
            }
        }

        mz_zip_reader_end(&zip);
    } else {
        fprintf(stderr, "[*] mz_zip_reader_init_mem failed (error %d)\n",
                mz_zip_get_last_error(&zip));
    }

    free(data);
    return 0;
}
