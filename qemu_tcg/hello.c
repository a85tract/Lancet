#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <glib.h>
#include <inttypes.h>
#include <qemu-plugin.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zstd.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/*
 * Full QLancet TCG plugin.
 *
 * The legacy text logger is kept for debugging/compatibility, but the default
 * output is QLT1: block-compressed binary records consumed by the Rust analyzer.
 * QLT records intentionally do not store assembly text; disassembly is used only
 * inside the plugin to decide which registers/value probes to sample.
 */

/* ===================== QLT constants ===================== */
#define QLT_MAGIC "QLT1"
#define QLT_VERSION 1
#define QLT_REG_TABLE_X86_64_V1 1
#define QLT_HEADER_SIZE 36ULL
#define QLT_DEFAULT_BLOCK_SIZE (4U * 1024U * 1024U)

#define TRACE_FLAG_HAS_BRANCH_TARGET (1u << 0)
#define TRACE_FLAG_HAS_VALUE         (1u << 1)
#define TRACE_FLAG_HAS_CR3           (1u << 2)
#define TRACE_FLAG_IS_CALL           (1u << 3)
#define TRACE_FLAG_IS_RET            (1u << 4)
#define TRACE_FLAG_IS_REP            (1u << 5)
#define TRACE_FLAG_REGS_FALLBACK_ALL_GPR (1u << 6)

typedef enum {
    QREG_RAX = 0, QREG_RBX, QREG_RCX, QREG_RDX, QREG_RSI, QREG_RDI, QREG_RBP, QREG_RSP,
    QREG_R8, QREG_R9, QREG_R10, QREG_R11, QREG_R12, QREG_R13, QREG_R14, QREG_R15,
    QREG_RIP, QREG_RFLAGS, QREG_CR3, QREG_COUNT
} fixed_reg_id_t;

static const char *const fixed_reg_names[QREG_COUNT] = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip", "rflags", "cr3"
};

typedef struct QltIndex {
    uint64_t compressed_offset;
    uint64_t compressed_size;
    uint64_t uncompressed_size;
    uint64_t first_step;
    uint64_t record_count;
} QltIndex;

typedef struct QltRecord {
    uint64_t pc;
    uint16_t cpu_id;
    uint32_t flags;
    guint8 bytes[32];
    guint8 byte_len;
    uint64_t reg_mask;
    uint64_t reg_values[QREG_COUNT];
    gboolean has_branch_target;
    uint64_t branch_target;
    gboolean has_value;
    uint64_t value;
    gboolean has_cr3;
    uint64_t cr3;
} QltRecord;

/* ===================== Global options/state ===================== */
static FILE *fp = NULL;
static GMutex mtx;
static gboolean qlt_mode = TRUE;
static gboolean use_stdout = FALSE;
static char out_path[512] = "trace.qlt";
static gboolean flush_each = FALSE;
static gboolean want_disas = TRUE;
static gboolean want_insn_bytes = FALSE;
static gboolean use_reg_pc = FALSE;
static uint64_t range_lo = 0, range_hi = UINT64_MAX;
static char target_name[64] = {0};
static int only_cpu = -1;
static int trigger_only_cpu = -2; /* -2: follow only_cpu, -1: all CPUs */
static gboolean dump_guest_vmmap = FALSE;
static size_t qlt_block_limit = QLT_DEFAULT_BLOCK_SIZE;
static int qlt_zstd_level = 3;

typedef enum {
    TRACE_ADDR_KERNEL = 0,
    TRACE_ADDR_USER = 1,
    TRACE_ADDR_ALL = 2
} trace_addr_mode_t;
static trace_addr_mode_t trace_addr_mode = TRACE_ADDR_KERNEL;
static trace_addr_mode_t trigger_addr_mode = TRACE_ADDR_ALL;

typedef enum {
    REGS_NONE = 0,
    REGS_ALL = 1,
    REGS_CR3 = 2,
    REGS_USED = 3,
    REGS_MOVLEA = 4
} regs_mode_t;
static regs_mode_t regs_mode = REGS_NONE;
static gboolean saw_regs_arg = FALSE;

static gboolean use_addr_whitelist = FALSE;
static gboolean use_trigger_mode = FALSE;
static gboolean trigger_pc_from_reg = FALSE;
static char addrfile_path[512] = "/tmp/addr.txt";
static gboolean use_config_json = FALSE;
static char config_path[512] = "config.json";

static uint64_t trigger_addr = 0;
static uint64_t trigger_reg_window = 0x20000ULL;
static gboolean have_stop_addr = FALSE;
static uint64_t stop_addr = 0;
static volatile gint triggered_flag = 0;

static gboolean use_proc_filter = FALSE;
static GHashTable *want_proc_names = NULL;
static GHashTable *name_to_cr3 = NULL;
static GHashTable *allowed_cr3 = NULL;
static GHashTable *addr_whitelist = NULL;
static GHashTable *guest_exec_pages = NULL;

/* QLT writer state. Protected by mtx when emitting records. */
static GByteArray *qlt_block_buf = NULL;
static GArray *qlt_block_index = NULL; /* QltIndex */
static uint64_t qlt_prev_step = 0;
static uint64_t qlt_step_counter = 0;
static uint64_t qlt_first_step_in_block = 0;
static uint64_t qlt_records_in_block = 0;

/* ===================== config.json value probes ===================== */
typedef struct ConfigEntry {
    uint64_t pc;
    char *reg_name;
    int64_t offset;
    size_t size;
    gboolean is_call;
} ConfigEntry;
static GPtrArray *config_entries = NULL;

typedef struct HostMapEntry {
    uint64_t start;
    uint64_t end;
    char perms[8];
    char *path;
} HostMapEntry;

/* ===================== Basic helpers ===================== */
static void plugin_log(const char *fmt, ...) G_GNUC_PRINTF(1, 2);
static void plugin_log(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char *msg = g_strdup_vprintf(fmt, ap);
    va_end(ap);
    if (msg) {
        qemu_plugin_outs(msg);
        g_free(msg);
    }
}

static inline gboolean cpu_ok(unsigned int vcpu_index)
{
    return only_cpu < 0 || (int)vcpu_index == only_cpu;
}

static inline gboolean trigger_cpu_ok(unsigned int vcpu_index)
{
    int cpu = trigger_only_cpu == -2 ? only_cpu : trigger_only_cpu;
    return cpu < 0 || (int)vcpu_index == cpu;
}

static gboolean is_kernel_addr_default(uint64_t va)
{
    if (strstr(target_name, "x86_64") || strstr(target_name, "aarch64") ||
        strstr(target_name, "riscv64") || strstr(target_name, "ppc64")) {
        return (va >> 63) == 1;
    }
    if (strstr(target_name, "i386") || strstr(target_name, "arm")) {
        return va >= 0xC0000000ULL;
    }
    if (strstr(target_name, "mips")) {
        return va >= 0x80000000ULL;
    }
    return (va >> 63) == 1;
}

static inline gboolean addr_matches_mode(uint64_t va, trace_addr_mode_t mode)
{
    const gboolean is_kernel = is_kernel_addr_default(va);
    if (mode == TRACE_ADDR_KERNEL) {
        return is_kernel;
    }
    if (mode == TRACE_ADDR_USER) {
        return !is_kernel;
    }
    return TRUE;
}

static inline gboolean addr_matches_trace_mode(uint64_t va)
{
    return addr_matches_mode(va, trace_addr_mode);
}

static inline gboolean addr_matches_trigger_mode(uint64_t va)
{
    return addr_matches_mode(va, trigger_addr_mode);
}

static inline gboolean addr_in_trigger_reg_window(uint64_t va)
{
    if (trigger_reg_window == 0) {
        return TRUE;
    }
    return (va >= trigger_addr && va - trigger_addr <= trigger_reg_window) ||
           (trigger_addr > va && trigger_addr - va <= trigger_reg_window);
}

static gboolean target_is_little_endian(void)
{
    if (strstr(target_name, "x86_64") || strstr(target_name, "i386") ||
        strstr(target_name, "aarch64") || strstr(target_name, "arm") ||
        strstr(target_name, "riscv") || strstr(target_name, "ppc64le") ||
        strstr(target_name, "mipsel") || strstr(target_name, "mips64el")) {
        return TRUE;
    }
    if (strstr(target_name, "ppc64") || strstr(target_name, "mips")) {
        return FALSE;
    }
    return TRUE;
}

static inline void gstring_append_hex_target_word(GString *out,
                                                  const guint8 *bytes,
                                                  int sz,
                                                  gboolean target_le)
{
    g_string_append(out, "0x");
    if (target_le) {
        for (int j = sz - 1; j >= 0; --j) {
            g_string_append_printf(out, "%02x", bytes[j]);
        }
    } else {
        for (int j = 0; j < sz; ++j) {
            g_string_append_printf(out, "%02x", bytes[j]);
        }
    }
}

static inline uint64_t bytes_to_u64_target(const guint8 *bytes, int sz, gboolean target_le)
{
    uint64_t v = 0;
    if (target_le) {
        for (int i = sz - 1; i >= 0; --i) {
            v = (v << 8) | bytes[i];
        }
    } else {
        for (int i = 0; i < sz; ++i) {
            v = (v << 8) | bytes[i];
        }
    }
    return v;
}

static inline uint64_t bytes_to_u64_target_limited(const guint8 *bytes, int sz, gboolean target_le)
{
    if (sz <= 8) {
        return bytes_to_u64_target(bytes, sz, target_le);
    }
    if (target_le) {
        return bytes_to_u64_target(bytes, 8, target_le);
    }
    return bytes_to_u64_target(bytes + (sz - 8), 8, target_le);
}

static inline char *trim(char *s)
{
    if (!s) {
        return s;
    }
    while (*s && g_ascii_isspace((guchar)*s)) {
        s++;
    }
    if (*s == 0) {
        return s;
    }
    char *end = s + strlen(s) - 1;
    while (end > s && g_ascii_isspace((guchar)*end)) {
        *end-- = 0;
    }
    return s;
}

static gboolean parse_u64_token(const char *tok, uint64_t *out)
{
    if (!tok || !*tok) {
        return FALSE;
    }
    char *endp = NULL;
    errno = 0;
    unsigned long long v = g_ascii_strtoull(tok, &endp, 0);
    if (errno != 0 || endp == tok) {
        return FALSE;
    }
    if (*trim(endp) != '\0') {
        return FALSE;
    }
    *out = (uint64_t)v;
    return TRUE;
}

static gboolean parse_i64_token(const char *tok, int64_t *out)
{
    if (!tok || !*tok) {
        return FALSE;
    }
    char *tmp = g_strdup(tok);
    char *t = trim(tmp);
    int sign = 1;
    if (*t == '+') {
        t++;
    } else if (*t == '-') {
        sign = -1;
        t++;
    }
    uint64_t u = 0;
    gboolean ok = parse_u64_token(t, &u);
    if (ok) {
        if (sign < 0) {
            if (u > (uint64_t)INT64_MAX + 1ULL) {
                ok = FALSE;
            } else {
                *out = -(int64_t)u;
            }
        } else {
            if (u > (uint64_t)INT64_MAX) {
                ok = FALSE;
            } else {
                *out = (int64_t)u;
            }
        }
    }
    g_free(tmp);
    return ok;
}

static inline char *str_tolower_dup(const char *s)
{
    if (!s) {
        return NULL;
    }
    size_t n = strlen(s);
    char *r = g_malloc(n + 1);
    for (size_t i = 0; i < n; ++i) {
        r[i] = g_ascii_tolower(s[i]);
    }
    r[n] = '\0';
    return r;
}

static void free_config_entry(gpointer p)
{
    ConfigEntry *e = (ConfigEntry *)p;
    if (!e) {
        return;
    }
    g_free(e->reg_name);
    g_free(e);
}

static void free_host_map_entry(gpointer p)
{
    HostMapEntry *e = (HostMapEntry *)p;
    if (!e) {
        return;
    }
    g_free(e->path);
    g_free(e);
}

static void config_entries_init_if_needed(void)
{
    if (!config_entries) {
        config_entries = g_ptr_array_new_with_free_func(free_config_entry);
    }
}

/* ===================== JSON-ish parser for qemu config ===================== */
static const char *find_json_key(const char *obj, const char *key)
{
    if (!obj || !key) {
        return NULL;
    }
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    return g_strstr_len(obj, -1, pattern);
}

static gboolean parse_json_string_field(const char *obj, const char *key, char **out)
{
    const char *p = find_json_key(obj, key);
    if (!p) {
        return FALSE;
    }
    p = strchr(p, ':');
    if (!p) {
        return FALSE;
    }
    p++;
    while (*p && g_ascii_isspace((guchar)*p)) {
        p++;
    }
    if (*p == '"') {
        p++;
        const char *q = strchr(p, '"');
        if (!q) {
            return FALSE;
        }
        *out = g_strndup(p, (gsize)(q - p));
        return TRUE;
    }
    const char *q = p;
    while (*q && !g_ascii_isspace((guchar)*q) && *q != ',' && *q != '}') {
        q++;
    }
    *out = g_strndup(p, (gsize)(q - p));
    return TRUE;
}

static gboolean parse_json_u64_field(const char *obj, const char *key, uint64_t *out)
{
    char *tok = NULL;
    if (!parse_json_string_field(obj, key, &tok)) {
        return FALSE;
    }
    char *t = trim(tok);
    gboolean ok = parse_u64_token(t, out);
    g_free(tok);
    return ok;
}

static gboolean parse_json_i64_field(const char *obj, const char *key, int64_t *out)
{
    char *tok = NULL;
    if (!parse_json_string_field(obj, key, &tok)) {
        return FALSE;
    }
    char *t = trim(tok);
    gboolean ok = parse_i64_token(t, out);
    g_free(tok);
    return ok;
}

static gboolean parse_json_bool_field(const char *obj, const char *key, gboolean *out)
{
    char *tok = NULL;
    if (!parse_json_string_field(obj, key, &tok)) {
        return FALSE;
    }
    char *t = trim(tok);
    gboolean ok = FALSE;
    if (g_ascii_strcasecmp(t, "true") == 0 || g_strcmp0(t, "1") == 0) {
        *out = TRUE;
        ok = TRUE;
    } else if (g_ascii_strcasecmp(t, "false") == 0 || g_strcmp0(t, "0") == 0) {
        *out = FALSE;
        ok = TRUE;
    }
    g_free(tok);
    return ok;
}

static gboolean parse_json_u64_field_multi(const char *obj, const char *const *keys, uint64_t *out)
{
    for (const char *const *k = keys; k && *k; k++) {
        if (parse_json_u64_field(obj, *k, out)) {
            return TRUE;
        }
    }
    return FALSE;
}

static gboolean parse_json_i64_field_multi(const char *obj, const char *const *keys, int64_t *out)
{
    for (const char *const *k = keys; k && *k; k++) {
        if (parse_json_i64_field(obj, *k, out)) {
            return TRUE;
        }
    }
    return FALSE;
}

static gboolean parse_json_string_field_multi(const char *obj, const char *const *keys, char **out)
{
    for (const char *const *k = keys; k && *k; k++) {
        if (parse_json_string_field(obj, *k, out)) {
            return TRUE;
        }
    }
    return FALSE;
}

static gboolean parse_config_object(const char *obj)
{
    const char *const addr_keys[] = {"address", "addr", "pc", NULL};
    const char *const reg_keys[] = {"reg", "register", "import_reg", NULL};
    const char *const offset_keys[] = {"offset", NULL};
    const char *const size_keys[] = {"size", "value_size", "valueSize", NULL};

    uint64_t addr = 0;
    int64_t offset = 0;
    uint64_t size_u64 = 8;
    char *reg = NULL;
    gboolean is_call = FALSE;

    if (!parse_json_u64_field_multi(obj, addr_keys, &addr)) {
        return FALSE;
    }
    if (!parse_json_string_field_multi(obj, reg_keys, &reg)) {
        return FALSE;
    }
    (void)parse_json_i64_field_multi(obj, offset_keys, &offset);
    (void)parse_json_u64_field_multi(obj, size_keys, &size_u64);
    (void)parse_json_bool_field(obj, "is_call", &is_call);
    if (size_u64 == 0) {
        size_u64 = 8;
    }
    if (size_u64 > 64) {
        size_u64 = 64;
    }

    ConfigEntry *e = g_new0(ConfigEntry, 1);
    e->pc = addr;
    e->reg_name = reg;
    e->offset = offset;
    e->size = (size_t)size_u64;
    e->is_call = is_call;
    g_ptr_array_add(config_entries, e);
    return TRUE;
}

static void load_config_json(const char *path)
{
    config_entries_init_if_needed();
    GError *err = NULL;
    gchar *contents = NULL;
    gsize len = 0;
    if (!g_file_get_contents(path, &contents, &len, &err)) {
        plugin_log("[warn] open config json failed: %s\n", err ? err->message : "unknown error");
        if (err) {
            g_error_free(err);
        }
        return;
    }

    gboolean in_str = FALSE;
    gboolean esc = FALSE;
    int depth = 0;
    const char *start = NULL;
    int start_depth = 0;
    gsize parsed = 0;
    for (gsize i = 0; i < len; i++) {
        char c = contents[i];
        if (in_str) {
            if (esc) {
                esc = FALSE;
            } else if (c == '\\') {
                esc = TRUE;
            } else if (c == '"') {
                in_str = FALSE;
            }
            continue;
        }
        if (c == '"') {
            in_str = TRUE;
            continue;
        }
        if (c == '{') {
            if (depth == 1 && !start) {
                start = &contents[i];
                start_depth = depth + 1;
            }
            depth++;
        } else if (c == '}') {
            if (start && depth == start_depth) {
                gsize obj_len = (gsize)(&contents[i] - start + 1);
                char *obj = g_strndup(start, obj_len);
                if (parse_config_object(obj)) {
                    parsed++;
                }
                g_free(obj);
                start = NULL;
                start_depth = 0;
                depth--;
                continue;
            }
            if (depth > 0) {
                depth--;
            }
        }
    }
    if (parsed == 0 && len > 0) {
        char *obj = g_strndup(contents, len);
        if (parse_config_object(obj)) {
            parsed++;
        }
        g_free(obj);
    }
    plugin_log("[info] loaded %zu config entries from %s\n",
               (size_t)(config_entries ? config_entries->len : 0), path);
    g_free(contents);
}

/* ===================== Address whitelist ===================== */
static void addrset_init_if_needed(void)
{
    if (!addr_whitelist) {
        addr_whitelist = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, NULL);
    }
}

static void load_addr_whitelist(const char *path)
{
    addrset_init_if_needed();
    FILE *f = fopen(path, "r");
    if (!f) {
        plugin_log("[warn] open addrfile %s failed: %s\n", path, strerror(errno));
        return;
    }
    char linebuf[1024];
    size_t count = 0;
    while (fgets(linebuf, sizeof(linebuf), f)) {
        char *line = trim(linebuf);
        if (!*line || *line == '#') {
            continue;
        }
        gchar **tokens = g_strsplit_set(line, ", \t\r\n", -1);
        for (gchar **p = tokens; p && *p; ++p) {
            char *tok = trim(*p);
            if (!*tok || *tok == '#') {
                continue;
            }
            uint64_t val;
            if (parse_u64_token(tok, &val)) {
                uint64_t *key = g_new(uint64_t, 1);
                *key = val;
                g_hash_table_insert(addr_whitelist, key, NULL);
                count++;
            }
        }
        g_strfreev(tokens);
    }
    fclose(f);
    plugin_log("[info] loaded %zu addrs from %s\n", count, path);
}

static inline gboolean addr_is_whitelisted(uint64_t va)
{
    if (!addr_whitelist) {
        return FALSE;
    }
    uint64_t temp = va;
    return g_hash_table_contains(addr_whitelist, &temp);
}

/* ===================== CR3/process filter ===================== */
static void procfilter_init_tables(void)
{
    if (!want_proc_names) {
        want_proc_names = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    }
    if (!name_to_cr3) {
        name_to_cr3 = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    }
    if (!allowed_cr3) {
        allowed_cr3 = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, NULL);
    }
}

static void add_proc_name(const char *name)
{
    if (!name || !*name) {
        return;
    }
    use_proc_filter = TRUE;
    procfilter_init_tables();
    char *copy = g_strdup(name);
    char *lc = str_tolower_dup(trim(copy));
    if (*lc) {
        g_hash_table_add(want_proc_names, lc);
    } else {
        g_free(lc);
    }
    g_free(copy);
}

static void load_proc_names_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        plugin_log("[warn] open procfile %s failed: %s\n", path, strerror(errno));
        return;
    }
    use_proc_filter = TRUE;
    procfilter_init_tables();
    char linebuf[1024];
    while (fgets(linebuf, sizeof(linebuf), f)) {
        char *line = trim(linebuf);
        if (!*line || *line == '#') {
            continue;
        }
        gchar **tokens = g_strsplit_set(line, ",\t\r\n ", -1);
        for (gchar **p = tokens; p && *p; ++p) {
            add_proc_name(*p);
        }
        g_strfreev(tokens);
    }
    fclose(f);
}

static void add_allowed_cr3(uint64_t cr3)
{
    use_proc_filter = TRUE;
    procfilter_init_tables();
    uint64_t *key = g_new(uint64_t, 1);
    *key = cr3;
    g_hash_table_add(allowed_cr3, key);
}

static void load_cr3_map(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        plugin_log("[warn] open cr3map %s failed: %s\n", path, strerror(errno));
        return;
    }
    use_proc_filter = TRUE;
    procfilter_init_tables();

    char linebuf[1024];
    size_t count = 0, bound = 0;
    while (fgets(linebuf, sizeof(linebuf), f)) {
        char *line = trim(linebuf);
        if (!*line || *line == '#') {
            continue;
        }
        char *sep = strchr(line, '=');
        if (!sep) {
            sep = strchr(line, ':');
        }
        if (!sep) {
            continue;
        }
        *sep = '\0';
        char *name = trim(line);
        char *valstr = trim(sep + 1);
        if (!*name || !*valstr) {
            continue;
        }

        uint64_t cr3;
        if (!parse_u64_token(valstr, &cr3)) {
            continue;
        }

        char *lc = str_tolower_dup(name);
        uint64_t *pcr3 = g_new(uint64_t, 1);
        *pcr3 = cr3;
        gpointer old = NULL;
        if (g_hash_table_lookup_extended(name_to_cr3, lc, NULL, &old)) {
            g_free(old);
        }
        g_hash_table_replace(name_to_cr3, lc, pcr3);
        count++;

        if (want_proc_names && g_hash_table_contains(want_proc_names, lc)) {
            add_allowed_cr3(cr3);
            add_allowed_cr3(cr3 & ~0xFFFULL);
            bound++;
        }
    }
    fclose(f);
    plugin_log("[info] loaded %zu name-to-CR3, bound %zu by name filter\n", count, bound);
}

/* ===================== Per-vCPU register cache ===================== */
typedef qemu_plugin_reg_descriptor reg_desc_t;
static GHashTable *regs_by_vcpu = NULL;
static int idx_reg_cr3 = -1;
static int idx_reg_rsp = -1;
static int idx_reg_rbp = -1;
static int idx_reg_rip = -1;

static inline GArray *get_or_fetch_vcpu_regs(unsigned int vcpu_index)
{
    GArray *arr = NULL;
    if (regs_by_vcpu) {
        arr = g_hash_table_lookup(regs_by_vcpu, GINT_TO_POINTER(vcpu_index));
    }
    if (!arr) {
        arr = qemu_plugin_get_registers();
        if (arr) {
            if (!regs_by_vcpu) {
                regs_by_vcpu = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                                                     (GDestroyNotify)g_array_unref);
            }
            g_hash_table_replace(regs_by_vcpu, GINT_TO_POINTER(vcpu_index), arr);
        }
    }
    return arr;
}

static void locate_cr3_index(GArray *arr)
{
    if (!arr || idx_reg_cr3 >= 0) {
        return;
    }
    for (guint i = 0; i < arr->len; i++) {
        reg_desc_t *d = &g_array_index(arr, reg_desc_t, i);
        if (d->name && g_ascii_strcasecmp(d->name, "cr3") == 0) {
            idx_reg_cr3 = (int)i;
            break;
        }
    }
}

static void locate_rsp_index(GArray *arr)
{
    if (!arr || idx_reg_rsp >= 0) {
        return;
    }
    for (guint i = 0; i < arr->len; i++) {
        reg_desc_t *d = &g_array_index(arr, reg_desc_t, i);
        if (d->name && g_ascii_strcasecmp(d->name, "rsp") == 0) {
            idx_reg_rsp = (int)i;
            break;
        }
    }
}

static void locate_rbp_index(GArray *arr)
{
    if (!arr || idx_reg_rbp >= 0) {
        return;
    }
    for (guint i = 0; i < arr->len; i++) {
        reg_desc_t *d = &g_array_index(arr, reg_desc_t, i);
        if (d->name && g_ascii_strcasecmp(d->name, "rbp") == 0) {
            idx_reg_rbp = (int)i;
            break;
        }
    }
}

static void locate_rip_index(GArray *arr)
{
    if (!arr || idx_reg_rip >= 0) {
        return;
    }
    for (guint i = 0; i < arr->len; i++) {
        reg_desc_t *d = &g_array_index(arr, reg_desc_t, i);
        if (d->name && (g_ascii_strcasecmp(d->name, "rip") == 0 ||
                        g_ascii_strcasecmp(d->name, "eip") == 0 ||
                        g_ascii_strcasecmp(d->name, "pc") == 0)) {
            idx_reg_rip = (int)i;
            break;
        }
    }
}

static int fixed_reg_id_from_name(const char *name)
{
    if (!name) {
        return -1;
    }
    for (int i = 0; i < QREG_COUNT; i++) {
        if (g_ascii_strcasecmp(name, fixed_reg_names[i]) == 0) {
            return i;
        }
    }
    if (g_ascii_strcasecmp(name, "eflags") == 0) {
        return QREG_RFLAGS;
    }
    if (g_ascii_strcasecmp(name, "eip") == 0 || g_ascii_strcasecmp(name, "ip") == 0) {
        return QREG_RIP;
    }
    return -1;
}

static gboolean read_reg_descriptor_value(reg_desc_t *d, uint64_t *out)
{
    if (!d || !out) {
        return FALSE;
    }
    GByteArray *val = g_byte_array_sized_new(16);
    int sz = qemu_plugin_read_register(d->handle, val);
    if (sz <= 0 || val->len != (guint)sz) {
        g_byte_array_free(val, TRUE);
        return FALSE;
    }
    *out = bytes_to_u64_target_limited(val->data, sz, target_is_little_endian());
    g_byte_array_free(val, TRUE);
    return TRUE;
}

static gboolean read_reg_by_name(GArray *arr, const char *name, uint64_t *out)
{
    if (!arr || !name || !out) {
        return FALSE;
    }
    for (guint i = 0; i < arr->len; i++) {
        reg_desc_t *d = &g_array_index(arr, reg_desc_t, i);
        if (d->name && g_ascii_strcasecmp(d->name, name) == 0) {
            return read_reg_descriptor_value(d, out);
        }
    }
    return FALSE;
}

static gboolean read_pc_register(GArray *arr, uint64_t *out)
{
    if (!arr || !out) {
        return FALSE;
    }
    locate_rip_index(arr);
    if (idx_reg_rip >= 0) {
        reg_desc_t *d = &g_array_index(arr, reg_desc_t, (guint)idx_reg_rip);
        if (read_reg_descriptor_value(d, out)) {
            return TRUE;
        }
    }
    return read_reg_by_name(arr, "rip", out) ||
           read_reg_by_name(arr, "eip", out) ||
           read_reg_by_name(arr, "pc", out);
}

static int find_reg_index_by_name(GArray *arr, const char *name_ci)
{
    if (!arr || !name_ci) {
        return -1;
    }
    for (guint i = 0; i < arr->len; i++) {
        reg_desc_t *d = &g_array_index(arr, reg_desc_t, i);
        if (d->name && g_ascii_strcasecmp(d->name, name_ci) == 0) {
            return (int)i;
        }
    }
    return -1;
}

/* ===================== Disassembly register extraction ===================== */
static const char *const x86_regs[] = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip",
    "ax", "bx", "cx", "dx", "si", "di", "bp", "sp", "ip",
    "al", "ah", "bl", "bh", "cl", "ch", "dl", "dh", "sil", "dil", "bpl", "spl",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
    "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
    "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
    "cs", "ds", "es", "fs", "gs", "ss", "eflags", "rflags", "cr0", "cr2", "cr3", "cr4"
};
static const char *const arm64_regs[] = {
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11",
    "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "x24", "x25", "x26", "x27", "x28", "x29", "x30", "w0", "w1", "w2", "w3", "w4",
    "w5", "w6", "w7", "w8", "w9", "w10", "w11", "w12", "w13", "w14", "w15", "w16",
    "w17", "w18", "w19", "w20", "w21", "w22", "w23", "w24", "w25", "w26", "w27", "w28",
    "w29", "w30", "sp", "xzr", "wzr", "lr", "fp", "pc"
};
static const char *const arm_regs[] = {
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc", "ip", "fp"
};
static const char *const riscv_regs[] = {
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13",
    "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x26", "x27",
    "x28", "x29", "x30", "x31", "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1",
    "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"
};
static const char *const mips_regs[] = {
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra", "hi", "lo", "pc"
};
static const char *const ppc_regs[] = {
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23", "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31", "lr", "ctr", "xer", "cr", "pc", "spr", "gpr"
};

static inline gboolean is_x86_call_mnemonic(const char *mn)
{
    if (!mn) {
        return FALSE;
    }
    if (strstr(target_name, "x86_64") || strstr(target_name, "i386")) {
        char buf[32];
        int i = 0;
        while (*mn && g_ascii_isspace((guchar)*mn)) {
            mn++;
        }
        while (mn[i] && i < (int)sizeof(buf) - 1 && (g_ascii_isalnum(mn[i]) || mn[i] == '_')) {
            buf[i] = g_ascii_tolower(mn[i]);
            i++;
        }
        buf[i] = 0;
        return (g_strcmp0(buf, "call") == 0 || g_strcmp0(buf, "callq") == 0 || g_strcmp0(buf, "jmp") == 0);
    }
    return FALSE;
}

static inline gboolean is_x86_ret_mnemonic(const char *mn)
{
    if (!mn) {
        return FALSE;
    }
    while (*mn && g_ascii_isspace((guchar)*mn)) {
        mn++;
    }
    char buf[32];
    int i = 0;
    while (mn[i] && i < (int)sizeof(buf) - 1 && (g_ascii_isalnum(mn[i]) || mn[i] == '_')) {
        buf[i] = g_ascii_tolower(mn[i]);
        i++;
    }
    buf[i] = 0;
    return g_str_has_prefix(buf, "ret") || g_strcmp0(buf, "iret") == 0 || g_strcmp0(buf, "iretq") == 0;
}

static inline gboolean is_x86_mov_lea_mnemonic(const char *mn)
{
    if (!mn) {
        return FALSE;
    }
    if (strstr(target_name, "x86_64") || strstr(target_name, "i386")) {
        char buf[32];
        int i = 0;
        while (*mn && g_ascii_isspace((guchar)*mn)) {
            mn++;
        }
        while (mn[i] && i < (int)sizeof(buf) - 1 && (g_ascii_isalnum(mn[i]) || mn[i] == '_')) {
            buf[i] = g_ascii_tolower(mn[i]);
            i++;
        }
        buf[i] = 0;
        return g_str_has_prefix(buf, "mov") || g_str_has_prefix(buf, "lea");
    }
    return FALSE;
}

static inline gboolean is_x86_rep_movs_mnemonic(const char *mn)
{
    if (!mn) {
        return FALSE;
    }
    if (strstr(target_name, "x86_64") || strstr(target_name, "i386")) {
        char buf[32];
        int i = 0;
        while (*mn && g_ascii_isspace((guchar)*mn)) {
            mn++;
        }
        while (mn[i] && i < (int)sizeof(buf) - 1 && (g_ascii_isalnum(mn[i]) || mn[i] == '_')) {
            buf[i] = g_ascii_tolower(mn[i]);
            i++;
        }
        buf[i] = 0;
        if (!(g_strcmp0(buf, "rep") == 0 || g_strcmp0(buf, "repz") == 0 ||
              g_strcmp0(buf, "repnz") == 0 || g_strcmp0(buf, "repne") == 0)) {
            return FALSE;
        }
        mn += i;
        while (*mn && g_ascii_isspace((guchar)*mn)) {
            mn++;
        }
        i = 0;
        while (mn[i] && i < (int)sizeof(buf) - 1 && (g_ascii_isalnum(mn[i]) || mn[i] == '_')) {
            buf[i] = g_ascii_tolower(mn[i]);
            i++;
        }
        buf[i] = 0;
        return g_str_has_prefix(buf, "movs");
    }
    return FALSE;
}

static inline gboolean is_x86_rep_prefix_mnemonic(const char *mn)
{
    if (!mn) {
        return FALSE;
    }
    if (strstr(target_name, "x86_64") || strstr(target_name, "i386")) {
        char buf[32];
        int i = 0;
        while (*mn && g_ascii_isspace((guchar)*mn)) {
            mn++;
        }
        while (mn[i] && i < (int)sizeof(buf) - 1 && (g_ascii_isalnum(mn[i]) || mn[i] == '_')) {
            buf[i] = g_ascii_tolower(mn[i]);
            i++;
        }
        buf[i] = 0;
        return (g_strcmp0(buf, "rep") == 0 || g_strcmp0(buf, "repz") == 0 ||
                g_strcmp0(buf, "repnz") == 0 || g_strcmp0(buf, "repne") == 0);
    }
    return FALSE;
}

static char *x86_alias_to_canonical(const char *tok_lower)
{
    if (!tok_lower || !*tok_lower) {
        return NULL;
    }
    if (tok_lower[0] == 'r' && g_ascii_isdigit(tok_lower[1])) {
        const char *p = tok_lower;
        while (*p && g_ascii_isalnum(*p)) {
            p++;
        }
        size_t n = (size_t)(p - tok_lower);
        if (n >= 3) {
            char last = tok_lower[n - 1];
            if (last == 'd' || last == 'w' || last == 'b') {
                return g_strndup(tok_lower, (gssize)(n - 1));
            }
        }
        return g_strdup(tok_lower);
    }
    if (!g_ascii_strcasecmp(tok_lower, "eax") || !g_ascii_strcasecmp(tok_lower, "ax") ||
        !g_ascii_strcasecmp(tok_lower, "al") || !g_ascii_strcasecmp(tok_lower, "ah")) {
        return g_strdup("rax");
    }
    if (!g_ascii_strcasecmp(tok_lower, "ebx") || !g_ascii_strcasecmp(tok_lower, "bx") ||
        !g_ascii_strcasecmp(tok_lower, "bl") || !g_ascii_strcasecmp(tok_lower, "bh")) {
        return g_strdup("rbx");
    }
    if (!g_ascii_strcasecmp(tok_lower, "ecx") || !g_ascii_strcasecmp(tok_lower, "cx") ||
        !g_ascii_strcasecmp(tok_lower, "cl") || !g_ascii_strcasecmp(tok_lower, "ch")) {
        return g_strdup("rcx");
    }
    if (!g_ascii_strcasecmp(tok_lower, "edx") || !g_ascii_strcasecmp(tok_lower, "dx") ||
        !g_ascii_strcasecmp(tok_lower, "dl") || !g_ascii_strcasecmp(tok_lower, "dh")) {
        return g_strdup("rdx");
    }
    if (!g_ascii_strcasecmp(tok_lower, "esi") || !g_ascii_strcasecmp(tok_lower, "si") || !g_ascii_strcasecmp(tok_lower, "sil")) {
        return g_strdup("rsi");
    }
    if (!g_ascii_strcasecmp(tok_lower, "edi") || !g_ascii_strcasecmp(tok_lower, "di") || !g_ascii_strcasecmp(tok_lower, "dil")) {
        return g_strdup("rdi");
    }
    if (!g_ascii_strcasecmp(tok_lower, "ebp") || !g_ascii_strcasecmp(tok_lower, "bp") || !g_ascii_strcasecmp(tok_lower, "bpl")) {
        return g_strdup("rbp");
    }
    if (!g_ascii_strcasecmp(tok_lower, "esp") || !g_ascii_strcasecmp(tok_lower, "sp") || !g_ascii_strcasecmp(tok_lower, "spl")) {
        return g_strdup("rsp");
    }
    if (!g_ascii_strcasecmp(tok_lower, "eip") || !g_ascii_strcasecmp(tok_lower, "ip")) {
        return g_strdup("rip");
    }
    if (!g_ascii_strcasecmp(tok_lower, "eflags")) {
        return g_strdup("rflags");
    }
    return g_strdup(tok_lower);
}

static void maybe_add_token_to_regset(const char *token, GHashTable *set_lower,
                                      const char *const *tbl, size_t tbl_sz)
{
    if (!token || !*token || !set_lower) {
        return;
    }
    char *tok = str_tolower_dup(token);
    gboolean matched_tbl = FALSE;
    for (size_t i = 0; i < tbl_sz; i++) {
        if (g_strcmp0(tok, tbl[i]) == 0) {
            matched_tbl = TRUE;
            break;
        }
    }
    if (matched_tbl) {
        if (!g_hash_table_contains(set_lower, tok)) {
            g_hash_table_add(set_lower, g_strdup(tok));
        }
        if (strstr(target_name, "x86_64") || strstr(target_name, "i386")) {
            char *canon = x86_alias_to_canonical(tok);
            if (canon) {
                if (!g_hash_table_contains(set_lower, canon)) {
                    g_hash_table_add(set_lower, canon);
                } else {
                    g_free(canon);
                }
            }
        }
    }
    g_free(tok);
}

static void build_regname_set_from_disas(const char *disas, GHashTable *set_lower)
{
    if (!disas || !*disas) {
        return;
    }
    const char *const *tbl = x86_regs;
    size_t tbl_sz = sizeof(x86_regs) / sizeof(x86_regs[0]);
    if (strstr(target_name, "aarch64")) {
        tbl = arm64_regs;
        tbl_sz = sizeof(arm64_regs) / sizeof(arm64_regs[0]);
    } else if (strstr(target_name, "arm")) {
        tbl = arm_regs;
        tbl_sz = sizeof(arm_regs) / sizeof(arm_regs[0]);
    } else if (strstr(target_name, "riscv")) {
        tbl = riscv_regs;
        tbl_sz = sizeof(riscv_regs) / sizeof(riscv_regs[0]);
    } else if (strstr(target_name, "mips")) {
        tbl = mips_regs;
        tbl_sz = sizeof(mips_regs) / sizeof(mips_regs[0]);
    } else if (strstr(target_name, "ppc")) {
        tbl = ppc_regs;
        tbl_sz = sizeof(ppc_regs) / sizeof(ppc_regs[0]);
    }

    const char *p = disas;
    char mnbuf[32];
    int mi = 0;
    while (*p && g_ascii_isspace((guchar)*p)) {
        p++;
    }
    while (*p && (g_ascii_isalnum(*p) || *p == '_')) {
        if (mi < (int)sizeof(mnbuf) - 1) {
            mnbuf[mi++] = *p;
        }
        p++;
    }
    mnbuf[mi] = 0;
    if (strstr(target_name, "x86_64") || strstr(target_name, "i386")) {
        if (g_ascii_strncasecmp(mnbuf, "cmov", 4) == 0 || g_ascii_strncasecmp(mnbuf, "set", 3) == 0) {
            g_hash_table_add(set_lower, g_strdup("rflags"));
            g_hash_table_add(set_lower, g_strdup("eflags"));
        }
    }
    while (*p && !g_ascii_isalnum(*p)) {
        p++;
    }

    char buf[64];
    int bi = 0;
    while (*p) {
        if (g_ascii_isalnum(*p) || *p == '_') {
            if (bi < (int)sizeof(buf) - 1) {
                buf[bi++] = *p;
            }
        } else {
            if (bi > 0) {
                buf[bi] = 0;
                maybe_add_token_to_regset(buf, set_lower, tbl, tbl_sz);
                bi = 0;
            }
        }
        p++;
    }
    if (bi > 0) {
        buf[bi] = 0;
        maybe_add_token_to_regset(buf, set_lower, tbl, tbl_sz);
    }
}

static gboolean disas_get_direct_target(const char *disas, uint64_t *out)
{
    if (!disas || !out) {
        return FALSE;
    }
    const char *p = disas;
    while ((p = strstr(p, "0x")) != NULL) {
        char *endp = NULL;
        errno = 0;
        unsigned long long v = g_ascii_strtoull(p, &endp, 0);
        if (errno == 0 && endp && endp > p) {
            *out = (uint64_t)v;
            return TRUE;
        }
        p += 2;
    }
    return FALSE;
}

/* ===================== QLT writer helpers ===================== */
static void qlt_wr16_file(uint16_t v)
{
    guint8 b[2] = {(guint8)(v & 0xff), (guint8)((v >> 8) & 0xff)};
    fwrite(b, 1, sizeof(b), fp);
}

static void qlt_wr64_file(uint64_t v)
{
    guint8 b[8];
    for (int i = 0; i < 8; i++) {
        b[i] = (guint8)((v >> (8 * i)) & 0xff);
    }
    fwrite(b, 1, sizeof(b), fp);
}

static void qlt_ba16(GByteArray *a, uint16_t v)
{
    guint8 b[2] = {(guint8)(v & 0xff), (guint8)((v >> 8) & 0xff)};
    g_byte_array_append(a, b, sizeof(b));
}

static void qlt_ba32(GByteArray *a, uint32_t v)
{
    guint8 b[4];
    for (int i = 0; i < 4; i++) {
        b[i] = (guint8)((v >> (8 * i)) & 0xff);
    }
    g_byte_array_append(a, b, sizeof(b));
}

static void qlt_ba64(GByteArray *a, uint64_t v)
{
    guint8 b[8];
    for (int i = 0; i < 8; i++) {
        b[i] = (guint8)((v >> (8 * i)) & 0xff);
    }
    g_byte_array_append(a, b, sizeof(b));
}

static void qlt_bavar(GByteArray *a, uint64_t v)
{
    do {
        guint8 b = (guint8)(v & 0x7f);
        v >>= 7;
        if (v) {
            b |= 0x80;
        }
        g_byte_array_append(a, &b, 1);
    } while (v);
}

static void qlt_write_header(uint64_t block_count, uint64_t index_offset)
{
    if (!fp) {
        return;
    }
    fseeko(fp, 0, SEEK_SET);
    fwrite(QLT_MAGIC, 1, 4, fp);
    qlt_wr16_file(QLT_VERSION);
    qlt_wr16_file(0); /* flags */
    qlt_wr16_file(QLT_REG_TABLE_X86_64_V1);
    qlt_wr16_file(0); /* reserved */
    qlt_wr64_file(block_count);
    qlt_wr64_file(index_offset);
    qlt_wr64_file(QLT_HEADER_SIZE);
}

static void qlt_record_add_reg(QltRecord *rec, int id, uint64_t value)
{
    if (!rec || id < 0 || id >= QREG_COUNT) {
        return;
    }
    rec->reg_mask |= (1ULL << id);
    rec->reg_values[id] = value;
    if (id == QREG_CR3) {
        rec->has_cr3 = TRUE;
        rec->cr3 = value;
    }
}

static void qlt_record_add_reg_by_desc(QltRecord *rec, reg_desc_t *d, uint64_t value)
{
    int id = fixed_reg_id_from_name(d ? d->name : NULL);
    if (id >= 0) {
        qlt_record_add_reg(rec, id, value);
    }
}

static void qlt_flush_block_locked(void)
{
    if (!qlt_mode || !fp || !qlt_block_buf || qlt_records_in_block == 0) {
        return;
    }
    size_t bound = ZSTD_compressBound(qlt_block_buf->len);
    void *dst = g_malloc(bound);
    size_t csz = ZSTD_compress(dst, bound, qlt_block_buf->data, qlt_block_buf->len, qlt_zstd_level);
    if (ZSTD_isError(csz)) {
        plugin_log("[warn] zstd compress failed: %s\n", ZSTD_getErrorName(csz));
        g_free(dst);
        return;
    }
    uint64_t off = (uint64_t)ftello(fp);
    fwrite(dst, 1, csz, fp);
    QltIndex idx = {off, (uint64_t)csz, (uint64_t)qlt_block_buf->len,
                    qlt_first_step_in_block, qlt_records_in_block};
    g_array_append_val(qlt_block_index, idx);
    g_free(dst);
    g_byte_array_set_size(qlt_block_buf, 0);
    qlt_records_in_block = 0;
    qlt_first_step_in_block = 0;
}

static void qlt_append_record_locked(QltRecord *rec)
{
    if (!rec || !qlt_mode || !fp) {
        return;
    }
    uint64_t step = ++qlt_step_counter;
    if (qlt_records_in_block == 0) {
        qlt_first_step_in_block = step;
    }
    if (rec->has_branch_target) {
        rec->flags |= TRACE_FLAG_HAS_BRANCH_TARGET;
    }
    if (rec->has_value) {
        rec->flags |= TRACE_FLAG_HAS_VALUE;
    }
    if (rec->has_cr3) {
        rec->flags |= TRACE_FLAG_HAS_CR3;
    }

    qlt_bavar(qlt_block_buf, step - qlt_prev_step);
    qlt_prev_step = step;
    qlt_ba16(qlt_block_buf, rec->cpu_id);
    qlt_ba64(qlt_block_buf, rec->pc);
    qlt_ba32(qlt_block_buf, rec->flags);
    g_byte_array_append(qlt_block_buf, &rec->byte_len, 1);
    if (rec->byte_len > 0) {
        g_byte_array_append(qlt_block_buf, rec->bytes, rec->byte_len);
    }
    qlt_ba64(qlt_block_buf, rec->reg_mask);
    for (int i = 0; i < QREG_COUNT; i++) {
        if (rec->reg_mask & (1ULL << i)) {
            qlt_ba64(qlt_block_buf, rec->reg_values[i]);
        }
    }
    if (rec->has_branch_target) {
        qlt_ba64(qlt_block_buf, rec->branch_target);
    }
    if (rec->has_value) {
        qlt_ba64(qlt_block_buf, rec->value);
    }
    if (rec->has_cr3) {
        qlt_ba64(qlt_block_buf, rec->cr3);
    }
    qlt_records_in_block++;
    if (qlt_block_buf->len >= qlt_block_limit) {
        qlt_flush_block_locked();
    }
}

static void qlt_finish_locked(void)
{
    if (!qlt_mode || !fp) {
        return;
    }
    qlt_flush_block_locked();
    uint64_t index_off = (uint64_t)ftello(fp);
    for (guint i = 0; qlt_block_index && i < qlt_block_index->len; i++) {
        QltIndex *idx = &g_array_index(qlt_block_index, QltIndex, i);
        qlt_wr64_file(idx->compressed_offset);
        qlt_wr64_file(idx->compressed_size);
        qlt_wr64_file(idx->uncompressed_size);
        qlt_wr64_file(idx->first_step);
        qlt_wr64_file(idx->record_count);
    }
    qlt_write_header(qlt_block_index ? qlt_block_index->len : 0, index_off);
    fseeko(fp, 0, SEEK_END);
}

/* ===================== Optional user-mode vmmap dump ===================== */
#define GUEST_PAGE_SIZE 0x1000ULL

static gint cmp_u64_asc(gconstpointer a, gconstpointer b)
{
    const uint64_t va = *(const uint64_t *)a;
    const uint64_t vb = *(const uint64_t *)b;
    if (va < vb) {
        return -1;
    }
    if (va > vb) {
        return 1;
    }
    return 0;
}

static void guest_exec_pages_init_if_needed(void)
{
    if (!guest_exec_pages) {
        guest_exec_pages = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, NULL);
    }
}

static void guest_exec_record_vaddr(uint64_t vaddr)
{
    if (!dump_guest_vmmap || is_kernel_addr_default(vaddr)) {
        return;
    }
    uint64_t page = vaddr & ~(GUEST_PAGE_SIZE - 1);
    g_mutex_lock(&mtx);
    guest_exec_pages_init_if_needed();
    uint64_t temp = page;
    if (!g_hash_table_contains(guest_exec_pages, &temp)) {
        uint64_t *key = g_new(uint64_t, 1);
        *key = page;
        g_hash_table_add(guest_exec_pages, key);
    }
    g_mutex_unlock(&mtx);
}

static GPtrArray *load_host_maps(void)
{
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        return NULL;
    }
    GPtrArray *arr = g_ptr_array_new_with_free_func(free_host_map_entry);
    char linebuf[4096];
    while (fgets(linebuf, sizeof(linebuf), maps)) {
        unsigned long long start = 0, end = 0, offset = 0, inode = 0;
        char perms[8] = {0};
        char dev[32] = {0};
        int nconsumed = 0;
        int n = sscanf(linebuf, "%llx-%llx %7s %llx %31s %llu %n",
                       &start, &end, perms, &offset, dev, &inode, &nconsumed);
        if (n < 6) {
            continue;
        }
        char *path = trim(linebuf + nconsumed);
        if (!path || !*path) {
            path = "[anon]";
        }
        HostMapEntry *e = g_new0(HostMapEntry, 1);
        e->start = (uint64_t)start;
        e->end = (uint64_t)end;
        g_strlcpy(e->perms, perms, sizeof(e->perms));
        e->path = g_strdup(path);
        g_ptr_array_add(arr, e);
    }
    fclose(maps);
    return arr;
}

static HostMapEntry *find_host_exec_map_for_addr(GPtrArray *maps, uint64_t addr)
{
    if (!maps) {
        return NULL;
    }
    for (guint i = 0; i < maps->len; i++) {
        HostMapEntry *e = g_ptr_array_index(maps, i);
        if (addr >= e->start && addr < e->end) {
            return e;
        }
    }
    return NULL;
}

static gboolean detect_guest_base(uint64_t *out_base)
{
    if (!out_base) {
        return FALSE;
    }
    const char *env = getenv("QEMU_GUEST_BASE");
    if (env && *env && parse_u64_token(env, out_base)) {
        return TRUE;
    }
    GError *err = NULL;
    gchar *cmdline = NULL;
    gsize len = 0;
    if (!g_file_get_contents("/proc/self/cmdline", &cmdline, &len, &err)) {
        if (err) {
            g_error_free(err);
        }
        return FALSE;
    }
    gboolean found = FALSE;
    char *token = cmdline;
    char *end = cmdline + len;
    while (token < end) {
        char *nul = memchr(token, '\0', (size_t)(end - token));
        if (!nul) {
            break;
        }
        size_t tlen = (size_t)(nul - token);
        if (tlen == 0) {
            token++;
            continue;
        }
        if (g_strcmp0(token, "-B") == 0 || g_strcmp0(token, "--guest-base") == 0) {
            char *next = token + tlen + 1;
            if (next < end && *next && parse_u64_token(next, out_base)) {
                found = TRUE;
                break;
            }
        } else if (g_str_has_prefix(token, "-B") && token[2] != '\0') {
            if (parse_u64_token(token + 2, out_base)) {
                found = TRUE;
                break;
            }
        } else if (g_str_has_prefix(token, "--guest-base=")) {
            if (parse_u64_token(token + strlen("--guest-base="), out_base)) {
                found = TRUE;
                break;
            }
        }
        token = nul + 1;
    }
    g_free(cmdline);
    return found;
}

static gboolean translate_with_delta(uint64_t addr, gint64 delta, uint64_t *out)
{
    if (!out) {
        return FALSE;
    }
    if (delta >= 0) {
        uint64_t d = (uint64_t)delta;
        if (UINT64_MAX - addr < d) {
            return FALSE;
        }
        *out = addr + d;
        return TRUE;
    }
    uint64_t d = (uint64_t)(-delta);
    if (addr < d) {
        return FALSE;
    }
    *out = addr - d;
    return TRUE;
}

static HostMapEntry *resolve_guest_page_map(uint64_t guest_page, GPtrArray *host_maps,
                                            gboolean have_guest_base, uint64_t guest_base)
{
    HostMapEntry *e = find_host_exec_map_for_addr(host_maps, guest_page);
    if (e) {
        return e;
    }
    if (!have_guest_base) {
        return NULL;
    }
    if (UINT64_MAX - guest_page >= guest_base) {
        e = find_host_exec_map_for_addr(host_maps, guest_page + guest_base);
        if (e) {
            return e;
        }
    }
    if (guest_page >= guest_base) {
        e = find_host_exec_map_for_addr(host_maps, guest_page - guest_base);
        if (e) {
            return e;
        }
    }
    return NULL;
}

static gboolean autodetect_guest_host_delta(GArray *guest_pages, GPtrArray *host_maps, gint64 *out_delta)
{
    if (!guest_pages || guest_pages->len == 0 || !host_maps || host_maps->len == 0 || !out_delta) {
        return FALSE;
    }
    const guint sample_pages = guest_pages->len < 64 ? guest_pages->len : 64;
    const uint64_t anchor = g_array_index(guest_pages, uint64_t, 0);
    guint best_score = 0;
    gint64 best_delta = 0;
    for (guint mi = 0; mi < host_maps->len; mi++) {
        HostMapEntry *m = g_ptr_array_index(host_maps, mi);
        gint64 delta = (gint64)m->start - (gint64)anchor;
        guint score = 0;
        for (guint pi = 0; pi < sample_pages; pi++) {
            uint64_t g = g_array_index(guest_pages, uint64_t, pi);
            uint64_t translated = 0;
            if (translate_with_delta(g, delta, &translated) && find_host_exec_map_for_addr(host_maps, translated)) {
                score++;
            }
        }
        if (score > best_score) {
            best_score = score;
            best_delta = delta;
        }
    }
    if (best_score < 4) {
        return FALSE;
    }
    *out_delta = best_delta;
    return TRUE;
}

static void dump_guest_vmmap_to_file(void)
{
    if (!dump_guest_vmmap) {
        return;
    }
    FILE *out = fopen("mmap.txt", "w");
    if (!out) {
        plugin_log("[warn] failed to open mmap.txt: %s\n", strerror(errno));
        return;
    }
    if (!guest_exec_pages || g_hash_table_size(guest_exec_pages) == 0) {
        fputs("# no guest user-mode code pages captured\n", out);
        fclose(out);
        return;
    }

    GPtrArray *host_maps = load_host_maps();
    uint64_t guest_base = 0;
    gboolean have_guest_base = detect_guest_base(&guest_base);
    gint64 guessed_delta = 0;
    gboolean have_guessed_delta = FALSE;

    GArray *pages = g_array_sized_new(FALSE, FALSE, sizeof(uint64_t), g_hash_table_size(guest_exec_pages));
    GHashTableIter it;
    gpointer k, v;
    g_hash_table_iter_init(&it, guest_exec_pages);
    while (g_hash_table_iter_next(&it, &k, &v)) {
        const uint64_t page = *(const uint64_t *)k;
        g_array_append_val(pages, page);
    }
    g_array_sort(pages, cmp_u64_asc);
    if (!have_guest_base) {
        have_guessed_delta = autodetect_guest_host_delta(pages, host_maps, &guessed_delta);
    }

    uint64_t start = g_array_index(pages, uint64_t, 0);
    uint64_t prev = start;
    HostMapEntry *start_map = resolve_guest_page_map(start, host_maps, have_guest_base, guest_base);
    if (!start_map && have_guessed_delta) {
        uint64_t translated = 0;
        if (translate_with_delta(start, guessed_delta, &translated)) {
            start_map = find_host_exec_map_for_addr(host_maps, translated);
        }
    }
    const char *start_perms = start_map ? start_map->perms : "r-xp";
    const char *start_path = start_map ? start_map->path : "[unknown]";
    for (guint i = 1; i < pages->len; i++) {
        const uint64_t cur = g_array_index(pages, uint64_t, i);
        HostMapEntry *cur_map = resolve_guest_page_map(cur, host_maps, have_guest_base, guest_base);
        if (!cur_map && have_guessed_delta) {
            uint64_t translated = 0;
            if (translate_with_delta(cur, guessed_delta, &translated)) {
                cur_map = find_host_exec_map_for_addr(host_maps, translated);
            }
        }
        const char *cur_perms = cur_map ? cur_map->perms : "r-xp";
        const char *cur_path = cur_map ? cur_map->path : "[unknown]";
        if (cur == prev + GUEST_PAGE_SIZE && g_strcmp0(cur_perms, start_perms) == 0 &&
            g_strcmp0(cur_path, start_path) == 0) {
            prev = cur;
            continue;
        }
        fprintf(out, "%016" PRIx64 "-%016" PRIx64 " %s %s\n",
                start, (uint64_t)(prev + GUEST_PAGE_SIZE), start_perms, start_path);
        start = cur;
        prev = cur;
        start_map = cur_map;
        start_perms = cur_perms;
        start_path = cur_path;
    }
    fprintf(out, "%016" PRIx64 "-%016" PRIx64 " %s %s\n",
            start, (uint64_t)(prev + GUEST_PAGE_SIZE), start_perms, start_path);

    g_array_free(pages, TRUE);
    if (host_maps) {
        g_ptr_array_free(host_maps, TRUE);
    }
    fclose(out);
}

/* ===================== Execution callback data ===================== */
typedef struct ExecUData {
    uint64_t vaddr;
    guint8 bytes[32];
    guint8 byte_len;
    int insn_size;
    char *disas_only;
    gboolean is_call;
    gboolean is_ret;
    gboolean is_mov_lea;
    gboolean is_rep_movs;
    gboolean is_rep;
    gboolean has_direct_target;
    uint64_t direct_target;
    gboolean can_trigger;
} ExecUData;

static void text_append_insn_bytes(GString *out, ExecUData *ud)
{
    if (!out || !ud || !want_insn_bytes) {
        return;
    }
    for (guint i = 0; i < ud->byte_len; i++) {
        g_string_append_printf(out, "%02x", ud->bytes[i]);
        if (i + 1 < ud->byte_len) {
            g_string_append_c(out, ' ');
        }
    }
    if (ud->byte_len == 0 && ud->insn_size > 0) {
        g_string_append_printf(out, "<%d bytes unavailable>", ud->insn_size);
    }
}

static void emit_reg_value(QltRecord *rec, GString *text, reg_desc_t *d, uint64_t value)
{
    if (rec) {
        qlt_record_add_reg_by_desc(rec, d, value);
    }
    if (text) {
        g_string_append_printf(text, " %s=0x%016" PRIx64, d && d->name ? d->name : "reg", value);
    }
}

static void collect_all_regs(GArray *arr, QltRecord *rec, GString *text)
{
    if (!arr) {
        return;
    }
    if (rec) {
        rec->flags |= TRACE_FLAG_REGS_FALLBACK_ALL_GPR;
    }
    if (text) {
        g_string_append(text, "|regs:");
    }
    for (guint i = 0; i < arr->len; i++) {
        reg_desc_t *d = &g_array_index(arr, reg_desc_t, i);
        if (!d->name) {
            continue;
        }
        if (rec && fixed_reg_id_from_name(d->name) < 0) {
            continue;
        }
        uint64_t value = 0;
        if (read_reg_descriptor_value(d, &value)) {
            emit_reg_value(rec, text, d, value);
        }
    }
}

static void collect_cr3_reg(GArray *arr, QltRecord *rec, GString *text)
{
    if (!arr) {
        return;
    }
    locate_cr3_index(arr);
    if (idx_reg_cr3 < 0) {
        return;
    }
    reg_desc_t *d = &g_array_index(arr, reg_desc_t, (guint)idx_reg_cr3);
    uint64_t value = 0;
    if (!read_reg_descriptor_value(d, &value)) {
        return;
    }
    if (text) {
        g_string_append(text, "|regs:");
    }
    emit_reg_value(rec, text, d, value);
}

static void add_need(GHashTable *need, const char *name)
{
    if (!need || !name || !*name) {
        return;
    }
    if (!g_hash_table_contains(need, name)) {
        g_hash_table_add(need, g_strdup(name));
    }
}

static gboolean descriptor_in_need(reg_desc_t *d, GHashTable *need)
{
    if (!d || !d->name || !need) {
        return FALSE;
    }
    char *nm = str_tolower_dup(d->name);
    gboolean wanted = g_hash_table_contains(need, nm);
    if (!wanted && (strstr(target_name, "x86_64") || strstr(target_name, "i386"))) {
        char *canon = x86_alias_to_canonical(nm);
        if (canon) {
            wanted = g_hash_table_contains(need, canon);
            g_free(canon);
        }
    }
    g_free(nm);
    return wanted;
}

static void collect_needed_regs(GArray *arr, ExecUData *ud, QltRecord *rec, GString *text,
                                gboolean call_context, gboolean base_context)
{
    if (!arr || !ud) {
        return;
    }
    GHashTable *need = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    build_regname_set_from_disas(ud->disas_only, need);

    if (base_context) {
        add_need(need, "cr3");
        add_need(need, "rsp");
        add_need(need, "rbp");
    }
    if (call_context) {
        static const char *const call_context_regs[] = {
            "rdi", "rsi", "rdx", "rcx", "r8", "r9", "rsp", "rbp", "cr3", NULL
        };
        for (size_t i = 0; call_context_regs[i] != NULL; i++) {
            add_need(need, call_context_regs[i]);
        }
    }
    if (ud->is_rep) {
        add_need(need, "rcx");
        add_need(need, "ecx");
        add_need(need, "rflags");
        add_need(need, "eflags");
    }

    if (text) {
        g_string_append(text, "|regs:");
    }
    for (guint i = 0; i < arr->len; i++) {
        reg_desc_t *d = &g_array_index(arr, reg_desc_t, i);
        if (!descriptor_in_need(d, need)) {
            continue;
        }
        if (rec && fixed_reg_id_from_name(d->name) < 0) {
            continue;
        }
        uint64_t value = 0;
        if (read_reg_descriptor_value(d, &value)) {
            emit_reg_value(rec, text, d, value);
        }
    }
    g_hash_table_destroy(need);
}

static void collect_regs_for_record(GArray *arr, ExecUData *ud, QltRecord *rec, GString *text)
{
    if (regs_mode == REGS_NONE) {
        return;
    }
    if (regs_mode == REGS_ALL) {
        collect_all_regs(arr, rec, text);
    } else if (regs_mode == REGS_CR3) {
        collect_cr3_reg(arr, rec, text);
    } else if (regs_mode == REGS_USED) {
        collect_needed_regs(arr, ud, rec, text, ud && ud->is_call, TRUE);
    } else if (regs_mode == REGS_MOVLEA) {
        if (ud && ud->is_mov_lea) {
            collect_needed_regs(arr, ud, rec, text, FALSE, FALSE);
        }
    }
}

static gboolean add_signed_offset(uint64_t base, int64_t offset, uint64_t *out)
{
    if (!out) {
        return FALSE;
    }
    if (offset >= 0) {
        uint64_t off = (uint64_t)offset;
        if (UINT64_MAX - base < off) {
            return FALSE;
        }
        *out = base + off;
        return TRUE;
    }
    uint64_t off = (uint64_t)(-offset);
    if (base < off) {
        return FALSE;
    }
    *out = base - off;
    return TRUE;
}

static gboolean config_entry_matches(ConfigEntry *e, ExecUData *ud)
{
    if (!e || !ud) {
        return FALSE;
    }
    if (e->is_call) {
        return ud->is_call && ud->has_direct_target && ud->direct_target == e->pc;
    }
    return e->pc == ud->vaddr;
}

static void probe_config_values(GArray *arr, ExecUData *ud, QltRecord *rec, GString *text)
{
    if (!use_config_json || !config_entries || config_entries->len == 0 || !ud) {
        return;
    }
    GByteArray *mem_val = NULL;
    for (guint i = 0; i < config_entries->len; i++) {
        ConfigEntry *e = (ConfigEntry *)g_ptr_array_index(config_entries, i);
        if (!config_entry_matches(e, ud)) {
            continue;
        }
        gboolean ok = FALSE;
        uint64_t value = 0;
        if (arr) {
            int idx = find_reg_index_by_name(arr, e->reg_name);
            if (idx >= 0) {
                reg_desc_t *d = &g_array_index(arr, reg_desc_t, (guint)idx);
                uint64_t base = 0, mem_addr = 0;
                if (read_reg_descriptor_value(d, &base) && add_signed_offset(base, e->offset, &mem_addr)) {
                    if (!mem_val) {
                        mem_val = g_byte_array_sized_new(e->size);
                    }
                    g_byte_array_set_size(mem_val, 0);
                    if (qemu_plugin_read_memory_vaddr(mem_addr, mem_val, e->size) && mem_val->len >= e->size) {
                        value = bytes_to_u64_target_limited(mem_val->data, (int)e->size, target_is_little_endian());
                        ok = TRUE;
                    }
                }
            }
        }
        if (ok) {
            if (rec && !rec->has_value) {
                rec->has_value = TRUE;
                rec->value = value;
            }
            if (text) {
                g_string_append_printf(text, "|value:0x%016" PRIx64 " (0x%" PRIx64 ")", value, (uint64_t)e->offset);
            }
        } else if (text) {
            g_string_append_printf(text, "|value:<unavailable> (0x%" PRIx64 ")", (uint64_t)e->offset);
        }
    }
    if (mem_val) {
        g_byte_array_free(mem_val, TRUE);
    }
}

static gboolean cr3_allowed_for_cpu(unsigned int vcpu_index)
{
    if (!use_proc_filter) {
        return TRUE;
    }
    if (!allowed_cr3 || g_hash_table_size(allowed_cr3) == 0) {
        return FALSE;
    }
    GArray *arr = get_or_fetch_vcpu_regs(vcpu_index);
    if (!arr) {
        return FALSE;
    }
    locate_cr3_index(arr);
    if (idx_reg_cr3 < 0) {
        return FALSE;
    }
    reg_desc_t *d = &g_array_index(arr, reg_desc_t, (guint)idx_reg_cr3);
    uint64_t cr3v = 0;
    if (!read_reg_descriptor_value(d, &cr3v)) {
        return FALSE;
    }
    uint64_t k1 = cr3v, k2 = (cr3v & ~0xFFFULL);
    return g_hash_table_contains(allowed_cr3, &k1) || g_hash_table_contains(allowed_cr3, &k2);
}

static void insn_exec(unsigned int vcpu_index, void *udata)
{
    const gboolean can_trace_cpu = cpu_ok(vcpu_index);
    const gboolean can_trigger_cpu = trigger_cpu_ok(vcpu_index);
    if (!can_trace_cpu && !can_trigger_cpu) {
        return;
    }
    ExecUData *ud = (ExecUData *)udata;

    GArray *arr = NULL;
    uint64_t exec_pc = ud->vaddr;
    uint64_t trigger_pc = ud->vaddr;
    if (use_reg_pc) {
        arr = get_or_fetch_vcpu_regs(vcpu_index);
        if (!read_pc_register(arr, &exec_pc)) {
            exec_pc = ud->vaddr;
        }
        trigger_pc = exec_pc;
    } else if (trigger_pc_from_reg && use_trigger_mode && can_trigger_cpu && ud->can_trigger &&
               !g_atomic_int_get(&triggered_flag)) {
        arr = get_or_fetch_vcpu_regs(vcpu_index);
        if (!read_pc_register(arr, &trigger_pc)) {
            trigger_pc = ud->vaddr;
        }
    }

    if (use_trigger_mode) {
        if (can_trigger_cpu &&
            !g_atomic_int_get(&triggered_flag) &&
            trigger_pc == trigger_addr &&
            addr_matches_trigger_mode(trigger_pc)) {
            g_atomic_int_set(&triggered_flag, 1);
        }
        if (!g_atomic_int_get(&triggered_flag)) {
            return;
        }
    }
    if (!can_trace_cpu) {
        return;
    }
    if (!addr_matches_trace_mode(exec_pc)) {
        return;
    }
    if (use_addr_whitelist) {
        if (!addr_is_whitelisted(exec_pc)) {
            return;
        }
    } else if (exec_pc < range_lo || exec_pc > range_hi) {
        return;
    }
    if (!cr3_allowed_for_cpu(vcpu_index)) {
        return;
    }

    QltRecord rec;
    memset(&rec, 0, sizeof(rec));
    rec.pc = exec_pc;
    rec.cpu_id = (uint16_t)vcpu_index;
    rec.byte_len = ud->byte_len;
    if (rec.byte_len > sizeof(rec.bytes)) {
        rec.byte_len = sizeof(rec.bytes);
    }
    if (rec.byte_len > 0) {
        memcpy(rec.bytes, ud->bytes, rec.byte_len);
    }
    if (ud->is_call) {
        rec.flags |= TRACE_FLAG_IS_CALL;
    }
    if (ud->is_ret) {
        rec.flags |= TRACE_FLAG_IS_RET;
    }
    if (ud->is_rep) {
        rec.flags |= TRACE_FLAG_IS_REP;
    }
    if (ud->has_direct_target) {
        rec.has_branch_target = TRUE;
        rec.branch_target = ud->direct_target;
    }

    ExecUData eff_ud = *ud;
    eff_ud.vaddr = exec_pc;

    GString *text = NULL;
    if (!qlt_mode) {
        text = g_string_new("");
        g_string_append_printf(text, "%u|0x%016" PRIx64 "|%s|",
                               vcpu_index, exec_pc,
                               (want_disas && ud->disas_only) ? ud->disas_only : "");
        text_append_insn_bytes(text, &eff_ud);
    }

    if (!arr) {
        arr = get_or_fetch_vcpu_regs(vcpu_index);
    }
    collect_regs_for_record(arr, &eff_ud, qlt_mode ? &rec : NULL, text);
    probe_config_values(arr, &eff_ud, qlt_mode ? &rec : NULL, text);

    g_mutex_lock(&mtx);
    if (qlt_mode) {
        qlt_append_record_locked(&rec);
    } else if (text) {
        if (text->len == 0 || text->str[text->len - 1] != '\n') {
            g_string_append_c(text, '\n');
        }
        if (fp) {
            fputs(text->str, fp);
            if (flush_each) {
                fflush(fp);
            }
        } else {
            qemu_plugin_outs(text->str);
        }
    }
    g_mutex_unlock(&mtx);

    if (text) {
        g_string_free(text, TRUE);
    }

    if (use_trigger_mode && have_stop_addr && exec_pc == stop_addr) {
        g_atomic_int_set(&triggered_flag, 0);
    }
}

static void vcpu_init_cb(qemu_plugin_id_t id, unsigned int vcpu_index)
{
    (void)id;
    GArray *arr = qemu_plugin_get_registers();
    if (arr) {
        if (!regs_by_vcpu) {
            regs_by_vcpu = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
                                                 (GDestroyNotify)g_array_unref);
        }
        g_hash_table_replace(regs_by_vcpu, GINT_TO_POINTER(vcpu_index), arr);
        locate_cr3_index(arr);
        locate_rsp_index(arr);
        locate_rbp_index(arr);
        locate_rip_index(arr);
    }
}

static inline gchar *now_ts(void)
{
    GDateTime *dt = g_date_time_new_now_local();
    gchar *s = g_date_time_format(dt, "%Y-%m-%d %H:%M:%S.%f%z");
    g_date_time_unref(dt);
    return s;
}

static void tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    (void)id;
    size_t n = qemu_plugin_tb_n_insns(tb);
    if (n == 0) {
        return;
    }
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t vaddr = qemu_plugin_insn_vaddr(insn);
        int ilen = qemu_plugin_insn_size(insn);

        if (dump_guest_vmmap) {
            guest_exec_record_vaddr(vaddr);
        }
        gboolean trigger_candidate = FALSE;
        if (use_trigger_mode) {
            if (trigger_pc_from_reg) {
                /*
                 * A user-mode architectural RIP trigger in system emulation
                 * may have a translated address that is not equal to RIP.
                 * Register a small translated-PC window around the trigger when
                 * possible and compare against the real PC in insn_exec().  A
                 * trigger-window=0 override deliberately disables this rough
                 * translated-PC prefilter, so callers can combine ONLYCPU with
                 * guest CPU pinning and still catch a user _start whose TB
                 * virtual address does not resemble the architectural RIP.
                 */
                trigger_candidate =
                    trigger_reg_window == 0 ||
                    (addr_matches_trigger_mode(vaddr) &&
                     addr_in_trigger_reg_window(vaddr));
            } else {
                trigger_candidate = (vaddr == trigger_addr &&
                                     addr_matches_trigger_mode(vaddr));
            }
        }

        if (!use_reg_pc && !addr_matches_trace_mode(vaddr) && !trigger_candidate) {
            continue;
        }

        gboolean should_register = FALSE;
        if (use_reg_pc) {
            /*
             * In system emulation some QEMU versions expose translated
             * instruction addresses as physical/identity-mapped addresses,
             * while the architectural RIP register still contains the guest
             * virtual PC.  Register broadly and apply mode/range/trigger
             * filters in insn_exec() after reading RIP.
             */
            should_register = TRUE;
        } else if (trigger_candidate) {
            should_register = TRUE;
            if (use_addr_whitelist && addr_whitelist) {
                gchar *ts = now_ts();
                plugin_log("[%s] [info] trigger addr reached, whitelist size: %zu\n",
                           ts, (size_t)g_hash_table_size(addr_whitelist));
                g_free(ts);
            }
        }
        if (use_addr_whitelist) {
            if (addr_is_whitelisted(vaddr)) {
                should_register = TRUE;
            }
        } else if (vaddr >= range_lo && vaddr <= range_hi) {
            should_register = TRUE;
        }
        if (!should_register) {
            continue;
        }

        ExecUData *ud = g_new0(ExecUData, 1);
        ud->vaddr = vaddr;
        ud->can_trigger = trigger_candidate;
        ud->insn_size = ilen;
        int copy_len = ilen;
        if (copy_len < 0) {
            copy_len = 0;
        }
        if (copy_len > (int)sizeof(ud->bytes)) {
            copy_len = (int)sizeof(ud->bytes);
        }
        if (copy_len > 0) {
            size_t copied = qemu_plugin_insn_data(insn, ud->bytes, (size_t)copy_len);
            ud->byte_len = (guint8)(copied > sizeof(ud->bytes) ? sizeof(ud->bytes) : copied);
        }

        gboolean need_disas = qlt_mode || want_disas || regs_mode == REGS_USED ||
                              regs_mode == REGS_MOVLEA || use_config_json;
        char *dis = need_disas ? qemu_plugin_insn_disas(insn) : NULL;
        if (dis) {
            ud->disas_only = g_strdup(dis);
            ud->is_call = is_x86_call_mnemonic(dis);
            ud->is_ret = is_x86_ret_mnemonic(dis);
            ud->is_mov_lea = is_x86_mov_lea_mnemonic(dis);
            ud->is_rep_movs = is_x86_rep_movs_mnemonic(dis);
            ud->is_rep = is_x86_rep_prefix_mnemonic(dis) || ud->is_rep_movs;
            if (ud->is_call && disas_get_direct_target(dis, &ud->direct_target)) {
                ud->has_direct_target = TRUE;
            }
            g_free(dis);
        }

        qemu_plugin_register_vcpu_insn_exec_cb(insn, insn_exec, QEMU_PLUGIN_CB_R_REGS, ud);
    }
}

/* ===================== Lifecycle and argument parsing ===================== */
static void parse_early_arg(const char *arg)
{
    if (g_strcmp0(arg, "stdout") == 0) {
        use_stdout = TRUE;
        qlt_mode = FALSE;
    } else if (g_str_has_prefix(arg, "out=")) {
        g_strlcpy(out_path, arg + 4, sizeof(out_path));
    } else if (g_strcmp0(arg, "format=text") == 0 || g_strcmp0(arg, "format=legacy") == 0) {
        qlt_mode = FALSE;
    } else if (g_strcmp0(arg, "format=qlt") == 0 || g_strcmp0(arg, "format=binary") == 0) {
        qlt_mode = TRUE;
    } else if (g_str_has_prefix(arg, "regs")) {
        saw_regs_arg = TRUE;
    }
}

static void parse_arg(const char *arg)
{
    if (g_str_has_prefix(arg, "out=") || g_strcmp0(arg, "stdout") == 0 || g_str_has_prefix(arg, "format=")) {
        return;
    } else if (g_strcmp0(arg, "flush") == 0) {
        flush_each = TRUE;
    } else if (g_strcmp0(arg, "noflush") == 0) {
        flush_each = FALSE;
    } else if (g_strcmp0(arg, "no-disas") == 0) {
        want_disas = FALSE;
    } else if (g_strcmp0(arg, "pc=reg") == 0 ||
               g_strcmp0(arg, "pc=rip") == 0) {
        use_reg_pc = TRUE;
        trigger_pc_from_reg = TRUE;
    } else if (g_strcmp0(arg, "trigger-pc=reg") == 0 ||
               g_strcmp0(arg, "trigger-pc=rip") == 0 ||
               g_strcmp0(arg, "trigger-reg") == 0) {
        trigger_pc_from_reg = TRUE;
    } else if (g_strcmp0(arg, "trigger-mode=user") == 0 ||
               g_strcmp0(arg, "trigger-trace=user") == 0) {
        trigger_addr_mode = TRACE_ADDR_USER;
    } else if (g_strcmp0(arg, "trigger-mode=kernel") == 0 ||
               g_strcmp0(arg, "trigger-trace=kernel") == 0) {
        trigger_addr_mode = TRACE_ADDR_KERNEL;
    } else if (g_strcmp0(arg, "trigger-mode=all") == 0 ||
               g_strcmp0(arg, "trigger-trace=all") == 0) {
        trigger_addr_mode = TRACE_ADDR_ALL;
    } else if (g_strcmp0(arg, "user-mode") == 0 || g_strcmp0(arg, "mode=user") == 0 || g_strcmp0(arg, "trace=user") == 0) {
        trace_addr_mode = TRACE_ADDR_USER;
    } else if (g_strcmp0(arg, "kernel-mode") == 0 || g_strcmp0(arg, "mode=kernel") == 0 || g_strcmp0(arg, "trace=kernel") == 0) {
        trace_addr_mode = TRACE_ADDR_KERNEL;
    } else if (g_strcmp0(arg, "all-mode") == 0 || g_strcmp0(arg, "mode=all") == 0 || g_strcmp0(arg, "trace=all") == 0) {
        trace_addr_mode = TRACE_ADDR_ALL;
    } else if (g_str_has_prefix(arg, "from=")) {
        range_lo = g_ascii_strtoull(arg + 5, NULL, 0);
    } else if (g_str_has_prefix(arg, "to=")) {
        range_hi = g_ascii_strtoull(arg + 3, NULL, 0);
    } else if (g_str_has_prefix(arg, "onlycpu=")) {
        only_cpu = atoi(arg + 8);
    } else if (g_str_has_prefix(arg, "trigger-onlycpu=")) {
        const char *val = arg + 16;
        trigger_only_cpu = (g_strcmp0(val, "all") == 0) ? -1 : atoi(val);
    } else if (g_str_has_prefix(arg, "trigger-cpu=")) {
        const char *val = arg + 12;
        trigger_only_cpu = (g_strcmp0(val, "all") == 0) ? -1 : atoi(val);
    } else if (g_strcmp0(arg, "regs=none") == 0 || g_strcmp0(arg, "no-regs") == 0) {
        regs_mode = REGS_NONE;
    } else if (g_strcmp0(arg, "regs") == 0 || g_strcmp0(arg, "regs=all") == 0) {
        regs_mode = REGS_ALL;
    } else if (g_strcmp0(arg, "regs=cr3") == 0) {
        regs_mode = REGS_CR3;
    } else if (g_strcmp0(arg, "regs=used") == 0 || g_strcmp0(arg, "regs=insn") == 0) {
        regs_mode = REGS_USED;
    } else if (g_strcmp0(arg, "regs=movlea") == 0) {
        regs_mode = REGS_MOVLEA;
    } else if (g_strcmp0(arg, "insn=bytes") == 0) {
        want_insn_bytes = TRUE;
    } else if (g_strcmp0(arg, "use-addr-file") == 0) {
        use_addr_whitelist = TRUE;
    } else if (g_str_has_prefix(arg, "addrfile=")) {
        use_addr_whitelist = TRUE;
        g_strlcpy(addrfile_path, arg + 9, sizeof(addrfile_path));
    } else if (g_str_has_prefix(arg, "trigger=")) {
        use_trigger_mode = TRUE;
        trigger_addr = g_ascii_strtoull(arg + 8, NULL, 0);
    } else if (g_str_has_prefix(arg, "trigger-window=")) {
        trigger_reg_window = g_ascii_strtoull(arg + 15, NULL, 0);
    } else if (g_str_has_prefix(arg, "stop=")) {
        have_stop_addr = TRUE;
        stop_addr = g_ascii_strtoull(arg + 5, NULL, 0);
    } else if (g_str_has_prefix(arg, "proc=")) {
        use_proc_filter = TRUE;
        const char *list = arg + 5;
        gchar **tokens = g_strsplit_set(list, ",", -1);
        for (gchar **p = tokens; p && *p; ++p) {
            add_proc_name(*p);
        }
        g_strfreev(tokens);
    } else if (g_str_has_prefix(arg, "procfile=")) {
        use_proc_filter = TRUE;
        load_proc_names_file(arg + 9);
    } else if (g_str_has_prefix(arg, "cr3=")) {
        use_proc_filter = TRUE;
        uint64_t v = g_ascii_strtoull(arg + 4, NULL, 0);
        add_allowed_cr3(v);
        add_allowed_cr3(v & ~0xFFFULL);
    } else if (g_str_has_prefix(arg, "cr3map=")) {
        use_proc_filter = TRUE;
        load_cr3_map(arg + 7);
    } else if (g_str_has_prefix(arg, "config=")) {
        use_config_json = TRUE;
        g_strlcpy(config_path, arg + 7, sizeof(config_path));
    } else if (g_str_has_prefix(arg, "block-size=")) {
        uint64_t v = g_ascii_strtoull(arg + 11, NULL, 0);
        if (v >= 4096) {
            qlt_block_limit = (size_t)v;
        }
    } else if (g_str_has_prefix(arg, "block-mb=")) {
        uint64_t v = g_ascii_strtoull(arg + 9, NULL, 0);
        if (v > 0 && v < 1024) {
            qlt_block_limit = (size_t)v * 1024U * 1024U;
        }
    } else if (g_str_has_prefix(arg, "zstd=")) {
        qlt_zstd_level = atoi(arg + 5);
        if (qlt_zstd_level == 0) {
            qlt_zstd_level = 3;
        }
    }
}

static void at_exit_cb(qemu_plugin_id_t id, void *userdata)
{
    (void)id;
    (void)userdata;
    g_mutex_lock(&mtx);
    if (qlt_mode) {
        qlt_finish_locked();
    }
    if (fp) {
        fflush(fp);
        fclose(fp);
        fp = NULL;
    }
    if (qlt_block_buf) {
        g_byte_array_free(qlt_block_buf, TRUE);
        qlt_block_buf = NULL;
    }
    if (qlt_block_index) {
        g_array_free(qlt_block_index, TRUE);
        qlt_block_index = NULL;
    }
    if (regs_by_vcpu) {
        g_hash_table_destroy(regs_by_vcpu);
        regs_by_vcpu = NULL;
    }
    if (addr_whitelist) {
        g_hash_table_destroy(addr_whitelist);
        addr_whitelist = NULL;
    }
    if (want_proc_names) {
        g_hash_table_destroy(want_proc_names);
        want_proc_names = NULL;
    }
    if (name_to_cr3) {
        g_hash_table_destroy(name_to_cr3);
        name_to_cr3 = NULL;
    }
    if (allowed_cr3) {
        g_hash_table_destroy(allowed_cr3);
        allowed_cr3 = NULL;
    }
    if (config_entries) {
        g_ptr_array_free(config_entries, TRUE);
        config_entries = NULL;
    }
    g_mutex_unlock(&mtx);

    dump_guest_vmmap_to_file();

    g_mutex_lock(&mtx);
    if (guest_exec_pages) {
        g_hash_table_destroy(guest_exec_pages);
        guest_exec_pages = NULL;
    }
    g_mutex_unlock(&mtx);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                           int argc, char **argv)
{
    if (info && info->target_name) {
        g_strlcpy(target_name, info->target_name, sizeof(target_name));
    }
    g_mutex_init(&mtx);

    gboolean saw_out = FALSE;
    for (int i = 0; i < argc; i++) {
        if (g_str_has_prefix(argv[i], "out=")) {
            saw_out = TRUE;
        }
        parse_early_arg(argv[i]);
    }
    if (use_stdout) {
        qlt_mode = FALSE;
    }
    if (qlt_mode && !saw_regs_arg) {
        regs_mode = REGS_USED;
    }

    if (qlt_mode || saw_out) {
        fp = fopen(out_path, qlt_mode ? "wb+" : "w");
        if (!fp) {
            plugin_log("[error] failed to open output %s: %s\n", out_path, strerror(errno));
            return -1;
        }
    } else if (use_stdout) {
        fp = NULL;
    }

    if (qlt_mode) {
        qlt_block_buf = g_byte_array_sized_new((guint)MIN(qlt_block_limit, (size_t)(16U * 1024U * 1024U)));
        qlt_block_index = g_array_new(FALSE, FALSE, sizeof(QltIndex));
        qlt_write_header(0, QLT_HEADER_SIZE);
    }

    for (int i = 0; i < argc; i++) {
        parse_arg(argv[i]);
    }
    dump_guest_vmmap = (trace_addr_mode == TRACE_ADDR_USER);

    if (use_addr_whitelist) {
        load_addr_whitelist(addrfile_path);
    }
    if (use_config_json) {
        load_config_json(config_path);
    }
    if (use_proc_filter) {
        procfilter_init_tables();
        if (want_proc_names && name_to_cr3) {
            GHashTableIter it;
            gpointer k, v;
            g_hash_table_iter_init(&it, name_to_cr3);
            while (g_hash_table_iter_next(&it, &k, &v)) {
                const char *nm = (const char *)k;
                uint64_t *pcr3 = (uint64_t *)v;
                if (g_hash_table_contains(want_proc_names, nm)) {
                    add_allowed_cr3(*pcr3);
                    add_allowed_cr3((*pcr3) & ~0xFFFULL);
                }
            }
        }
    }

    plugin_log("[info] QLancet plugin installed: format=%s out=%s regs=%d target=%s\n",
               qlt_mode ? "qlt" : "text", fp ? out_path : "stdout", regs_mode,
               target_name[0] ? target_name : "unknown");

    qemu_plugin_register_vcpu_init_cb(id, vcpu_init_cb);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans_cb);
    qemu_plugin_register_atexit_cb(id, at_exit_cb, NULL);
    return 0;
}
