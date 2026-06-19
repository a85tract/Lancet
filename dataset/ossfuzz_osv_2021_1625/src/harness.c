/*
 * OSV-2021-1625: Heap-buffer-overflow READ in junkscan (curl)
 *
 * Bug: In lib/urlapi.c, when parsing a short URL that resembles a file
 * scheme (e.g., "FI:/"), the URL parser in seturl() executes
 * strcpy(path, &url[5]) where url is only 4 bytes long. This reads
 * past the end of the heap-allocated URL buffer. The junkscan()
 * function then processes the over-read data via strlen()/strcspn(),
 * triggering a heap-buffer-overflow READ 16.
 *
 * Fix: Restructured URL validation in seturl()/parseurl() to add
 * bounds checks before the path extraction.
 *
 * Introducing commit: a5f5687368a5f95415d58d37e8dfb10c6b6d44c5
 * Actual code fix: 4183b8fe9a8558b8f62c9dbf8271deed75bff28b
 *
 * Harness: Reads input file as a URL string, passes it to curl_url_set()
 * which exercises the seturl() -> junkscan() code path.
 */

#include <curl/curl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
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
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz <= 0 || sz > 65536) {
        fprintf(stderr, "Invalid file size\n");
        fclose(f);
        return 1;
    }

    /* Allocate exact size + 1 for null terminator.
     * The bug is that curl's internal parsing indexes past
     * the end of the URL string. */
    char *data = (char *)malloc(sz + 1);
    if (!data) {
        fclose(f);
        return 1;
    }

    fread(data, 1, sz, f);
    fclose(f);
    data[sz] = '\0';

    fprintf(stderr, "[harness] Processing %ld bytes from %s\n", sz, argv[1]);
    fprintf(stderr, "[harness] URL: %s\n", data);

    curl_global_init(CURL_GLOBAL_DEFAULT);

    CURLU *url_handle = curl_url();
    if (url_handle) {
        /* This triggers the vulnerable code path in seturl() -> junkscan() */
        CURLUcode rc = curl_url_set(url_handle, CURLUPART_URL, data,
                                     CURLU_GUESS_SCHEME);
        fprintf(stderr, "[harness] curl_url_set returned: %d\n", rc);
        curl_url_cleanup(url_handle);
    }

    curl_global_cleanup();
    free(data);

    fprintf(stderr, "[harness] Done\n");
    return 0;
}
