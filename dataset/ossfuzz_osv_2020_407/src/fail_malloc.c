/*
 * LD_PRELOAD library to trigger double-free in libpcap opt_init().
 *
 * The double-free in OSV-2020-407 occurs when:
 * 1. opt_init() in optimize.c allocates blocks, edges, levels, space, vmap, vnode_base
 * 2. One of the LATER allocations (e.g., vmap or vnode_base) fails
 * 3. opt_init() frees the earlier ones and calls opt_error() -> longjmp
 * 4. bpf_optimize() catches the longjmp and calls opt_cleanup()
 * 5. opt_cleanup() frees the same pointers AGAIN (double-free!)
 *
 * We need to fail a specific calloc call INSIDE opt_init, after the first
 * few succeed. We identify the target by tracking calloc calls with specific
 * sizes that match the opt_init allocation pattern.
 *
 * Environment:
 *   FAILMALLOC_CALLOC_N=N  -- fail the Nth calloc call (1-based)
 *
 * Build:
 *   gcc -shared -fPIC -o libfailmalloc.so fail_malloc.c -ldl
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

static void *(*real_malloc)(size_t) = NULL;
static void *(*real_calloc)(size_t, size_t) = NULL;
static int calloc_count = 0;
static int fail_calloc_n = -1;
static int initialized = 0;
static int in_init = 0;
static int verbose = 0;

/* Simple bump allocator for calls during dlsym */
static char bump_buf[131072];
static size_t bump_offset = 0;

static void init(void) {
    if (initialized) return;
    in_init = 1;

    real_malloc = dlsym(RTLD_NEXT, "malloc");
    real_calloc = dlsym(RTLD_NEXT, "calloc");

    const char *env = getenv("FAILMALLOC_CALLOC_N");
    if (env) {
        fail_calloc_n = atoi(env);
    }
    const char *v = getenv("FAILMALLOC_VERBOSE");
    if (v) {
        verbose = atoi(v);
    }

    in_init = 0;
    initialized = 1;
}

void *malloc(size_t size) {
    if (!initialized && !in_init) init();
    if (!real_malloc) {
        if (bump_offset + size < sizeof(bump_buf)) {
            void *p = bump_buf + bump_offset;
            bump_offset += (size + 15) & ~15;
            return p;
        }
        return NULL;
    }
    return real_malloc(size);
}

void *calloc(size_t nmemb, size_t size) {
    if (!initialized && !in_init) init();
    if (!real_calloc) {
        size_t total = nmemb * size;
        if (bump_offset + total < sizeof(bump_buf)) {
            void *p = bump_buf + bump_offset;
            bump_offset += (total + 15) & ~15;
            memset(p, 0, total);
            return p;
        }
        return NULL;
    }

    calloc_count++;
    if (verbose) {
        fprintf(stderr, "[failmalloc] calloc #%d: nmemb=%zu size=%zu total=%zu\n",
                calloc_count, nmemb, size, nmemb * size);
    }

    if (fail_calloc_n > 0 && calloc_count == fail_calloc_n) {
        if (verbose) {
            fprintf(stderr, "[failmalloc] FAILING calloc #%d\n", calloc_count);
        }
        errno = ENOMEM;
        return NULL;
    }

    return real_calloc(nmemb, size);
}
