/*
 * Fuzz target for file/libmagic (OSV-2022-468).
 * Exercises magic_buffer() which internally calls file_is_json() -> json_parse().
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <magic.h>

static magic_t magic;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0)
        return 0;

    if (!magic) {
        magic = magic_open(MAGIC_NONE | MAGIC_NO_CHECK_COMPRESS |
                           MAGIC_NO_CHECK_ELF | MAGIC_NO_CHECK_APPTYPE);
        if (!magic)
            return 0;
        /* Use the built magic database from the source tree */
        const char *magic_file = getenv("MAGIC");
        if (magic_load(magic, magic_file) == -1) {
            /* Fall back to default system database */
            if (magic_load(magic, NULL) == -1) {
                magic_close(magic);
                magic = NULL;
                return 0;
            }
        }
    }

    magic_buffer(magic, data, size);

    return 0;
}
