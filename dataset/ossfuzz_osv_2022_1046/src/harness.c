/*
 * OSV-2022-1046: Stack-buffer-overflow in Curl_output_aws_sigv4 (curl)
 *
 * Bug: In lib/http_aws_sigv4.c, the make_headers() function declares:
 *   #define FULL_HOST_LEN (255 + sizeof("host:"))
 *   char full_host[FULL_HOST_LEN];
 *
 * Two problems:
 * 1. Buffer lacks +1 for null terminator.
 * 2. The length check: if(strlen(hostname) > FULL_HOST_LEN) uses the
 *    wrong limit -- FULL_HOST_LEN includes the "host:" prefix size,
 *    so hostnames up to ~261 bytes pass the check but overflow the
 *    buffer when "host:" + hostname is copied.
 *
 * When CURLOPT_AWS_SIGV4 is set and the URL has a hostname > 255 bytes,
 * msnprintf(full_host, FULL_HOST_LEN, "host:%s", hostname) overflows.
 *
 * Fix commit: 57ba1dd51975c95628cc3936ab086f80cba4c2d0
 * Parent (vulnerable): 0bb2f64905d52a902767fea39bfa0f426a87a53f
 *
 * Harness: Uses libcurl API to set up a transfer with AWS SigV4 auth
 * and a long hostname URL. The URL is read from the input file.
 */

#include <curl/curl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Dummy write callback - discard data */
static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *data)
{
    (void)ptr; (void)data;
    return size * nmemb;
}

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

    if (sz <= 0 || sz > 4096) {
        fprintf(stderr, "Invalid file size\n");
        fclose(f);
        return 1;
    }

    char *data = (char *)malloc(sz + 1);
    if (!data) {
        fclose(f);
        return 1;
    }

    fread(data, 1, sz, f);
    fclose(f);
    data[sz] = '\0';

    fprintf(stderr, "[harness] Processing %ld bytes from %s\n", sz, argv[1]);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL *curl = curl_easy_init();

    if (curl) {
        /* Set the URL from input - it should contain a URL with a long hostname */
        curl_easy_setopt(curl, CURLOPT_URL, data);

        /* Enable AWS SigV4 - this triggers the vulnerable code path */
        curl_easy_setopt(curl, CURLOPT_AWS_SIGV4, "aws:amz:us-east-1:s3");

        /* Set write callback to discard output */
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);

        /* Don't actually connect - we just need to trigger the auth header
         * generation which happens during request setup */
        curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 0L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 1L);

        /* Set dummy credentials */
        curl_easy_setopt(curl, CURLOPT_USERNAME, "AKIAIOSFODNN7EXAMPLE");
        curl_easy_setopt(curl, CURLOPT_PASSWORD, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");

        fprintf(stderr, "[harness] Performing request...\n");
        CURLcode res = curl_easy_perform(curl);
        fprintf(stderr, "[harness] curl_easy_perform returned: %d\n", res);

        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
    free(data);

    fprintf(stderr, "[harness] Done\n");
    return 0;
}
