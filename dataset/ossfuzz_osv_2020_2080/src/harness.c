/*
 * Harness for OSV-2020-2080: heap-buffer-overflow in coap_opt_length
 *
 * Bug: In coap_pdu_parse_opt() (src/pdu.c), coap_opt_length(opt) is called
 * BEFORE next_option_safe() validates the option header. The function
 * coap_opt_length() reads bytes beyond the initial option byte based on the
 * delta and length nibbles (e.g., 0xd0/0xe0 delta skips 1-2 extra bytes,
 * and 0x0d/0x0e length reads 1-2 more). On a malformed option near the end
 * of the PDU buffer, this causes a heap-buffer-overflow read.
 *
 * Fix (238fded2d8d6288429810573c2b27dc73898134f): Calls next_option_safe()
 * first to validate bounds, then calls coap_opt_length() only on the
 * already-validated option pointer.
 *
 * This harness reads a file, parses it as a CoAP UDP PDU, triggering the
 * vulnerable coap_pdu_parse_opt -> coap_opt_length path.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "coap2/coap.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    /* Read input file */
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        perror("fstat");
        close(fd);
        return 1;
    }

    size_t input_size = (size_t)st.st_size;
    if (input_size == 0) {
        fprintf(stderr, "Empty input file\n");
        close(fd);
        return 1;
    }

    uint8_t *input = (uint8_t *)malloc(input_size);
    if (!input) {
        perror("malloc");
        close(fd);
        return 1;
    }

    ssize_t n = read(fd, input, input_size);
    close(fd);
    if (n != (ssize_t)input_size) {
        fprintf(stderr, "Short read: got %zd, expected %zu\n", n, input_size);
        free(input);
        return 1;
    }

    /* Print input size and hex dump of first 64 bytes */
    printf("Input size: %zu bytes\n", input_size);
    printf("Hex dump (first %zu bytes):\n", input_size < 64 ? input_size : (size_t)64);
    for (size_t i = 0; i < input_size && i < 64; i++) {
        printf("%02x ", input[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    /* Initialize libcoap */
    coap_startup();

    /* Create a PDU to parse into.
     * coap_pdu_init(type, code, message_id, max_size)
     * We use large max_size to ensure the PDU buffer can hold the input.
     */
    coap_pdu_t *pdu = coap_pdu_init(0, 0, 0, 0);
    if (!pdu) {
        fprintf(stderr, "coap_pdu_init failed\n");
        free(input);
        coap_cleanup();
        return 1;
    }

    /* Parse the raw input as a CoAP UDP PDU.
     * This calls coap_pdu_parse_header() then coap_pdu_parse_opt().
     * The bug is in coap_pdu_parse_opt() where coap_opt_length() is called
     * without prior bounds validation.
     */
    printf("Parsing as CoAP UDP PDU...\n");
    int ret = coap_pdu_parse(COAP_PROTO_UDP, input, input_size, pdu);
    printf("coap_pdu_parse returned: %d\n", ret);

    if (ret) {
        /* If parsing succeeded, iterate options to exercise coap_opt_length */
        printf("PDU parsed successfully, iterating options...\n");
        coap_opt_iterator_t opt_iter;
        coap_opt_t *option;

        coap_option_iterator_init(pdu, &opt_iter, COAP_OPT_ALL);
        while ((option = coap_option_next(&opt_iter))) {
            uint32_t opt_len = coap_opt_length(option);
            printf("  Option %u: length=%u\n", opt_iter.type, opt_len);
        }
    } else {
        printf("PDU parse failed (expected for malformed input)\n");
    }

    /* Cleanup */
    coap_delete_pdu(pdu);
    free(input);
    coap_cleanup();

    printf("Done.\n");
    return 0;
}
