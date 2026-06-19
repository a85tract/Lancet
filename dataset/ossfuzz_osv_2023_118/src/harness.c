/*
 * Harness for OSV-2023-118 (mruby heap-use-after-free in mrb_gc_mark)
 *
 * Reads a file containing mruby source code, passes it to mrb_load_string().
 * This mirrors the OSS-Fuzz mruby_fuzzer target.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mruby.h>
#include <mruby/compile.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file.rb>\n", argv[0]);
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
    if (!buf) { fclose(f); return 1; }
    fread(buf, 1, len, f);
    fclose(f);
    buf[len] = '\0';

    mrb_state *mrb = mrb_open();
    if (!mrb) {
        fprintf(stderr, "mrb_open() failed\n");
        free(buf);
        return 1;
    }
    mrb_load_string(mrb, buf);
    mrb_close(mrb);
    free(buf);
    return 0;
}
