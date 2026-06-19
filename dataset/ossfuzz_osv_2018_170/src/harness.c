#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <yara.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    YR_RULES* rules;
    YR_COMPILER* compiler;

    char* buffer = (char*)malloc(size + 1);
    if (!buffer) return 0;

    strncpy(buffer, (const char*)data, size);
    buffer[size] = 0;

    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        free(buffer);
        return 0;
    }

    if (yr_compiler_add_string(compiler, (const char*)buffer, NULL) == 0) {
        if (yr_compiler_get_rules(compiler, &rules) == ERROR_SUCCESS)
            yr_rules_destroy(rules);
    }

    yr_compiler_destroy(compiler);
    free(buffer);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    yr_initialize();

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = (uint8_t*)malloc(fsize);
    if (!buf) { fclose(f); return 1; }
    fread(buf, 1, fsize, f);
    fclose(f);

    LLVMFuzzerTestOneInput(buf, fsize);
    free(buf);

    yr_finalize();
    return 0;
}
