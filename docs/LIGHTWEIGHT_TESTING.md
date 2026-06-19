# Lancet Advanced — Lightweight Testing (No Docker, No Heavy Datasets)

All tests below compile from public source repos with system glibc. Total download ~1MB.

## 1. how2heap (22 exploit techniques)

Source: [github.com/shellphish/how2heap](https://github.com/shellphish/how2heap) (MIT license)

```bash
# Clone and compile
git clone https://github.com/shellphish/how2heap.git
cd how2heap

# Use the glibc_2.35 versions (works with system glibc 2.31+)
for f in glibc_2.35/*.c; do
  name=$(basename "$f" .c)
  gcc -o "bin_${name}" "$f" -g -no-pie 2>/dev/null && echo "[OK] $name" || echo "[FAIL] $name"
done
```

### Run all 22 with Lancet

```bash
cd /path/to/lancet_advanced
PIN=/path/to/pin-3.28/pin

for bin in /path/to/how2heap/bin_*; do
  name=$(basename "$bin" | sed 's/bin_//')
  rm -f logs/ownership.log
  timeout 15 $PIN -t ./obj-intel64/lancet.so -nolog 0 -- "$bin" > /dev/null 2>&1
  cross=$(grep -c "CROSSBOUNDARY" logs/ownership.log 2>/dev/null || echo 0)
  uaf=$(grep -c "UAF" logs/ownership.log 2>/dev/null || echo 0)
  dang=$(grep -c "dangling" logs/ownership.log 2>/dev/null || echo 0)
  echo "$name: CROSS=$cross UAF=$uaf DANG=$dang"
done
```

### Expected: 22/22 detected, 18/22 full primitive coverage

| Technique | Detected Primitives | Complete? |
|-----------|-------------------|-----------|
| decrypt_safe_linking | UAF-R, DANG, EXPIRED | Yes |
| fastbin_dup | DANG, EXPIRED, DBLF, OVERLAP | Yes |
| fastbin_dup_consolidate | DANG, EXPIRED, DBLF | Yes |
| fastbin_dup_into_stack | DANG, EXPIRED, DBLF, OVERLAP | Yes |
| fastbin_reverse_into_tcache | CROSS, UAF-W, DANG, EXPIRED | Yes |
| house_of_botcake | UAF-R, DANG, EXPIRED, DBLF, OVERLAP | Yes |
| house_of_einherjar | CROSS(4), UAF-W, DANG, OVERLAP | Yes |
| house_of_lore | CROSS, UAF-W, DANG | Yes |
| house_of_mind_fastbin | CROSS | Partial* |
| house_of_spirit | **INVALID-FREE**, DANG, EXPIRED | Yes |
| house_of_tangerine | CROSS | Yes |
| house_of_water | CROSS(19), UAF-R/W, DANG(22), DBLF | Yes |
| large_bin_attack | CROSS, UAF-W, DANG, EXPIRED | Yes |
| mmap_overlapping_chunks | CROSS | Partial** |
| overlapping_chunks | CROSS | Partial*** |
| poison_null_byte | CROSS, UAF-R, DANG, EXPIRED | Yes |
| safe_link_double_protect | DANG, OVERLAP | Yes |
| sysmalloc_int_free | CROSS(3) | Yes |
| tcache_house_of_spirit | **INVALID-FREE**, DBLF | Yes |
| tcache_poisoning | UAF-W, DANG, EXPIRED | Yes |
| tcache_stashing_unlink_attack | CROSS(5), UAF-W, DANG | Yes |
| unsafe_unlink | CROSS | Partial**** |

*   house_of_mind_fastbin: missing OVERLAP (alloc returns arena address)
**  mmap_overlapping_chunks: mmap not hooked (only malloc/calloc/realloc)
*** overlapping_chunks: memset (REP STOSB) skipped by instruction filter
**** unsafe_unlink: arbitrary write through corrupted global ptr — .data/.bss not tracked

## 2. Juliet Test Suite (NIST CWE test cases)

Source: [github.com/AcademySoftwareFoundation/juliet-test-suite-c](https://github.com/AcademySoftwareFoundation/juliet-test-suite-c) or NIST SAMATE

```bash
# Clone
git clone https://github.com/AcademySoftwareFoundation/juliet-test-suite-c.git
cd juliet-test-suite-c

# Compile individual CWE cases (example: CWE416 UAF)
# Each CWE has its own directory with CMakeLists.txt
cd testcases/CWE416_Use_After_Free
mkdir build && cd build
cmake .. -DCMAKE_C_FLAGS="-g -O0" -DCMAKE_CXX_FLAGS="-g -O0"
make -j$(nproc)
```

### Key CWE categories Lancet detects

| CWE | Type | Expected Detection |
|-----|------|-------------------|
| CWE415 | Double Free | `double free detected` + dangling |
| CWE416 | Use After Free | UAF read/write + expired pointer |
| CWE122 | Heap Buffer Overflow | CROSSBOUNDARY |
| CWE124 | Buffer Underwrite | CROSSBOUNDARY |
| CWE126 | Buffer Overread | CROSSBOUNDARY |
| CWE476 | NULL Pointer Deref | `[MovRead nullptr deref]` |
| CWE761 | Free Not at Start | `INVALID FREE` (free error) |

## 3. Custom Micro-Tests

For quick validation without any external repos:

```bash
# Save as test_suite.c, compile with: gcc -o test_suite test_suite.c -g -no-pie
cat > test_suite.c << 'CEOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void test_uaf_write() {
    char *p = (char *)malloc(64);
    free(p);
    p[16] = 'A';  // UAF write
}

void test_uaf_read() {
    char *p = (char *)malloc(64);
    free(p);
    volatile char c = p[16];  // UAF read
}

void test_double_free() {
    char *p = (char *)malloc(100);
    free(p);
    free(p);  // double free
}

void test_oob_write() {
    char *a = (char *)malloc(32);
    char *b = (char *)malloc(32);
    a[0x40] = 'X';  // OOB into b's territory → CROSSBOUNDARY
    free(a);
    free(b);
}

void test_dangling_chain() {
    char **arr = (char **)malloc(sizeof(char*) * 2);
    arr[0] = (char *)malloc(32);
    arr[1] = (char *)malloc(32);
    free(arr[0]);
    volatile char c = arr[0][0];  // dangling pointer use
    free(arr[1]);
    free(arr);
}

void test_realloc() {
    char *p = (char *)malloc(64);
    strcpy(p, "hello");
    p = (char *)realloc(p, 256);
    strcat(p, " world");
    free(p);
}

int main(int argc, char *argv[]) {
    int t = argc > 1 ? atoi(argv[1]) : 0;
    switch(t) {
        case 1: test_uaf_write(); break;
        case 2: test_uaf_read(); break;
        case 3: test_double_free(); break;
        case 4: test_oob_write(); break;
        case 5: test_dangling_chain(); break;
        case 6: test_realloc(); break;
        default:
            test_realloc();        // normal (no vuln)
            test_uaf_write();      // UAF
            test_dangling_chain(); // dangling
            break;
    }
    return 0;
}
CEOF
```

```bash
# Run:
gcc -o test_suite test_suite.c -g -no-pie
pin -t lancet.so -nolog 0 -- ./test_suite
cat logs/ownership.log
# Expected: UAF write + dangling pointer detections
```

## 4. Recommended Minimal Validation Sequence

On a fresh server, after build:

```bash
# Step 1: Micro-test (30 seconds)
./run.sh -nolog 0 -- ./test_suite

# Step 2: how2heap house_of_einherjar (10 seconds)
./run.sh -nolog 0 -- ./bin_house_of_einherjar
# Must see: CROSSBOUNDARY + UAF

# Step 3: how2heap full suite (5 minutes)
# Run all 22, expect 22/22 detected

# Step 4 (optional): Juliet CWE415/416 if compiled
# Run 10 cases, expect 10/10
```

Total time: ~6 minutes, total disk: ~50MB (PIN SDK not counted).
