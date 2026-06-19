#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <yara.h>

static YR_RULES* rules = NULL;

static int callback(int message, void* message_data, void* user_data) {
    return CALLBACK_CONTINUE;
}

static void init_rules(void) {
    YR_COMPILER* compiler;
    const char* rule_text =
        "import \"dotnet\" "
        "rule test { "
        " condition: "
        "   dotnet.module_name == \"foo.exe\" "
        "}";

    if (yr_initialize() != ERROR_SUCCESS) return;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) return;
    if (yr_compiler_add_string(compiler, rule_text, NULL) == 0)
        yr_compiler_get_rules(compiler, &rules);
    yr_compiler_destroy(compiler);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (rules == NULL) return 0;

    yr_rules_scan_mem(
        rules,
        data,
        size,
        SCAN_FLAGS_NO_TRYCATCH,
        callback,
        NULL,
        0);

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    init_rules();

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

    if (rules) yr_rules_destroy(rules);
    yr_finalize();
    return 0;
}
