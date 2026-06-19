/* OSS-Fuzz ia_fuzz harness for radare2
 * Feeds binary input through radare2's binary info analysis pipeline.
 * This is the same harness used by google/oss-fuzz for radare2.
 */
#include <stdio.h>
#include <r_core.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    RCore *r = r_core_new();
    if (!r) return 0;

    r_core_cmdf(r, "o malloc://%zu", Size);
    r_io_write_at(r->io, 0, Data, Size);

    r_core_cmd0(r, "oba 0");
    r_core_cmd0(r, "ia");

    r_core_free(r);
    return 0;
}
