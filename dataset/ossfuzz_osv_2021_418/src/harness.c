/*
 * OSV-2021-418: Double-free in mfree via freep()
 *
 * The bug: In systemd's src/basic/alloc-util.h, the freep() cleanup
 * function is defined as:
 *
 *   static inline void freep(void *p) {
 *       free(*(void**) p);
 *   }
 *
 * After calling free(), the pointer is NOT set to NULL. When freep()
 * is used as a _cleanup_ attribute handler and the same pointer is
 * freed again (e.g., by static_destruct() between fuzzer iterations),
 * a double-free occurs.
 *
 * Fixed in commit 5800f0fc682b by changing freep() to:
 *   *(void**)p = mfree(*(void**) p);
 * which NULLs the pointer after freeing.
 *
 * The fuzz target is fuzz-systemctl-parse-argv, which parses
 * null-separated command-line arguments.
 *
 * This harness reproduces the bug pattern: freep() is called on a
 * pointer, but the pointer value remains dangling, and a second
 * free through the same pointer causes a double-free.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Reproduce the vulnerable freep() from systemd */
static inline void *mfree_systemd(void *memory) {
    free(memory);
    return NULL;
}

/* VULNERABLE version: does not NULL the pointer */
static inline void freep_vulnerable(void *p) {
    free(*(void**) p);
    /* BUG: *(void**)p is NOT set to NULL */
}

/* FIXED version would be:
 * static inline void freep_fixed(void *p) {
 *     *(void**)p = mfree_systemd(*(void**) p);
 * }
 */

/*
 * Simulate the pattern: parse_path_argument stores into a global,
 * freep runs at scope exit, then static_destruct frees the same global.
 */
static char *global_path = NULL;

void parse_path_argument(const char *input) {
    /* Simulates systemctl's parse_path_argument storing into a global */
    free(global_path);
    global_path = strdup(input);
}

void simulate_scope_cleanup(void) {
    /* This simulates what happens when _cleanup_free_ triggers freep
     * on a local variable that aliases the global pointer */
    char *local_alias = global_path;
    freep_vulnerable(&local_alias);
    /* After this, local_alias is freed but global_path still points
     * to the freed memory (dangling pointer) */
}

void static_destruct(void) {
    /* This simulates static_destruct() freeing global_path again */
    /* DOUBLE FREE: global_path was already freed by freep_vulnerable */
    free(global_path);
    global_path = NULL;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "Cannot open %s\n", argv[1]);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = (char *)malloc(len + 1);
    if (!buf) { fclose(f); return 1; }
    fread(buf, 1, len, f);
    buf[len] = '\0';
    fclose(f);

    fprintf(stderr, "[harness] Processing %ld bytes from %s\n", len, argv[1]);

    /* Simulate fuzzer iteration: parse argv-like input */
    /* Split on null bytes to simulate systemctl argv parsing */
    char *p = buf;
    char *end = buf + len;
    while (p < end) {
        size_t arg_len = strnlen(p, end - p);
        if (arg_len > 0) {
            parse_path_argument(p);
        }
        p += arg_len + 1;
    }

    /* Simulate _cleanup_free_ scope exit calling freep_vulnerable */
    simulate_scope_cleanup();

    /* Simulate static_destruct between fuzzer iterations */
    /* This triggers the double-free */
    static_destruct();

    free(buf);
    fprintf(stderr, "[harness] Done\n");
    return 0;
}
