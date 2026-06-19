/*
 * Harness for kamailio SIP parser heap-buffer-overflow
 *
 * Reads a file containing a raw SIP message and passes it through
 * kamailio's SIP message parser and all header-specific sub-parsers.
 * This mirrors the OSS-Fuzz fuzz_parse_msg target.
 *
 * Compile with: -I<kamailio>/src/ -I<kamailio>/src/core/parser
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/config.h"
#include "core/parser/sdp/sdp.h"
#include "core/parser/parse_hname2.h"
#include "core/parser/contact/parse_contact.h"
#include "core/parser/parse_from.h"
#include "core/parser/parse_to.h"
#include "core/parser/parse_rr.h"
#include "core/parser/parse_refer_to.h"
#include "core/parser/parse_ppi_pai.h"
#include "core/parser/parse_privacy.h"
#include "core/parser/parse_diversion.h"
#include "core/parser/parse_identityinfo.h"
#include "core/parser/parse_disposition.h"
#include "core/parser/msg_parser.h"

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
    size_t len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = (char *)malloc(len + 1);
    if (!buf) {
        fclose(f);
        return 1;
    }
    fread(buf, 1, len, f);
    fclose(f);
    buf[len] = '\0';

    /* Initialize header name index (same as LLVMFuzzerInitialize) */
    ksr_hname_init_index();

    sip_msg_t orig_inv = {};
    orig_inv.buf = buf;
    orig_inv.len = len;

    if (parse_msg(orig_inv.buf, orig_inv.len, &orig_inv) < 0) {
        goto cleanup;
    }

    parse_headers(&orig_inv, HDR_EOH_F, 0);
    parse_sdp(&orig_inv);
    parse_from_header(&orig_inv);
    parse_from_uri(&orig_inv);
    parse_to_header(&orig_inv);
    parse_to_uri(&orig_inv);
    parse_contact_headers(&orig_inv);
    parse_refer_to_header(&orig_inv);
    parse_pai_header(&orig_inv);
    parse_diversion_header(&orig_inv);
    parse_privacy(&orig_inv);
    parse_content_disposition(&orig_inv);
    parse_identityinfo_header(&orig_inv);

cleanup:
    free_sip_msg(&orig_inv);
    free(buf);
    return 0;
}
