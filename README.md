# Experiment 1

### 1. Pull the Docker Image
```bash
docker pull ghcr.io/a85tract/lancet:cpv15
```

### 2. Run Baseline Mode
```bash
docker run ghcr.io/a85tract/lancet:cpv15 baseline
```

### Expected Output

```txt
real    0m7.396s
user    0m4.435s
sys     0m2.864s
```

### 3. Run Lancet Mode
```bash
docker run ghcr.io/a85tract/lancet:cpv15 lancet
```

### Expected Output

```txt
Stack Trace:
Frame 0: ngx_http_userid_get_uid at /src/harnesses/bld/src/http/modules/ngx_http_userid_filter_module.c:334
Frame 1: Unknown Module
Frame 2: Unknown Module
Frame 3: Unknown Module
Frame 4: Unknown Module
Frame 5: Unknown Module
Frame 6: Unknown Module
Frame 7: Unknown Module
Frame 8: Unknown Module
Frame 9: Unknown Module
Frame 10: /app/pov_harness + 0x168944
Frame 11: /app/pov_harness + 0x1d0e6d
Frame 12: Unknown Module
Frame 13: Unknown Module
Frame 14: Unknown Module
vo: 426 co: 429
[MovRead high untrusted deref] ip: main+0x168a55 final_ea: 0x6363636363636371

real    0m11.940s
user    0m7.472s
sys     0m4.350s
```

### Ouput Explanation

[MovRead high untrusted deref] means Lancet detects a UNTRUSTEDPTRDEREF1, program is trying to dereference pointer 0x6363636363636371. 429 is the cell owner ID, and 426 is the value owner ID of the memory buffer holding this pointer. The printed stack trace indicates where the corrupted buffer was allocated.
Time consumption: 11.940s - 7.396 = 4.544s


# Experiment 2

### 1. Pull the Docker Image
```bash
docker pull ghcr.io/a85tract/lancet:cve_2024_41965
```

### 2. Run Baseline Mode
```bash
docker run ghcr.io/a85tract/lancet:cve_2024_41965 baseline
```

### Expected Output

```txt
...
src/ownership.cpp:124 error: double free detected
free(): double free detected in tcache 2
...
real    0m46.393s
user    0m32.899s
sys     0m12.932s
```

### 3. Run Lancet Mode
```bash
docker run ghcr.io/a85tract/lancet:cve_2024_41965 lancet
```

### Expected Output

```txt
...
src/ownership.cpp:124 error: double free detected
free(): double free detected in tcache 2
...
real    1m17.721s
user    0m54.533s
sys     0m22.573s
--------------------------------
Ownership log:
--------------------------------
main+0xd1769 Read a dangling pointer 0x5ac6a115dca0 from 0x5ac6a1143808
main+0xd177c Using expired pointer: 0x5ac6a115dca0 from 0x5ac6a1143808
first time found dangling pointer at: 10521637 distance: 4
main+0xd177c Read a dangling pointer 0x5ac6a115dca0 from 0x5ac6a1143808
main+0x3ae82 Store dangling pointer: 0x5ac6a115dca0 at: 0x7ffd032c71a8
main+0x3ae86 Using expired pointer: 0x5ac6a115dca0 from 0x7ffd032c71a8
first time found dangling pointer at: 10521637 distance: 12
main+0x3ae86 Read a dangling pointer 0x5ac6a115dca0 from 0x7ffd032c71a8
main+0x3ae97 Using expired pointer: 0x5ac6a115dca0 from 0x7ffd032c71a8
first time found dangling pointer at: 10521637 distance: 17
main+0x3ae97 Read a dangling pointer 0x5ac6a115dca0 from 0x7ffd032c71a8
```

### Ouput Explanation

Lancet first detects the use of a dangling pointer at main+0xd1769; main+0x3ae97 corresponds to a double free. The number following 'first time found dangling pointer at:' represents the analyzed instruction count. 'distance' refers to how many instructions Lancet is ahead of the actual bug site.
Time consumption: 1m17.721s - 0m46.393s = 31.328s

# Experiment 3

### 1. Pull the Docker Image
```bash
docker pull ghcr.io/a85tract/lancet:cve_2019_6977
```

### 2. Run Baseline Mode
```bash
docker run ghcr.io/a85tract/lancet:cve_2019_6977 baseline
```

### Expected Output

```txt
...
real    3m51.586s
user    2m36.392s
sys     1m14.692s
```

### 3. Run Lancet Mode
```bash
docker run ghcr.io/a85tract/lancet:cve_2019_6977 lancet
```

### Expected Output

```txt
...
ip: main+0x3a2d68 add rax, rdx id before: 4145 after: ffffffffffffffff value: 0x76511da6d1d8
Stack Trace:
Frame 0: _safe_emalloc at /app/php-src/Zend/zend_alloc.c:2489
Frame 1: Unknown Module
Frame 2: Unknown Module
Frame 3: /app/php-src/sapi/cli/php + 0xd505e8
Frame 4: Unknown Module
Frame 5: Unknown Module
Frame 6: Unknown Module
Frame 7: Unknown Module
Frame 8: php_gd_gdImageColorMatch at /app/php-src/ext/gd/libgd/gd_color_match.c:36
Frame 9: Unknown Module
Frame 10: Unknown Module
Frame 11: Unknown Module
Frame 12: Unknown Module
Frame 13: /app/php-src/sapi/cli/php + 0xd2fa8b
Frame 14: Unknown Module
Frame 15: Unknown Module
Frame 16: Unknown Module
Frame 17: Unknown Module
Frame 18: Unknown Module
Frame 19: Unknown Module
Frame 20: zif_imagecolormatch at /app/php-src/ext/gd/gd.c:1650
Frame 21: Unknown Module
Frame 22: Unknown Module
Frame 23: Unknown Module
Frame 24: Unknown Module
Frame 25: Unknown Module
Frame 26: Unknown Module
Frame 27: Unknown Module
Frame 28: Unknown Module
Frame 29: Unknown Module

real    5m46.239s
user    4m22.683s
sys     1m23.018s
```

### Ouput Explanation

Lancet detects the out-of-bound access at main+0x3a2d68, the pointer originally pointed to subject 4145, after adding the offset it locates outside the buffer thus violates CROSSBOUNDARY. The printed stack trace indicates where the corrupted buffer was allocated.

Time consumption: 5m46.239s - 3m51.586s = 114.653s

# Experiment 4

### 1. Pull the Docker Image
```bash
docker pull ghcr.io/a85tract/lancet:cve_2023_33476
```

### 2. Disable ASLR (need root permission)
```bash
echo 0 > /proc/sys/kernel/randomize_va_space
```

### 3. Launch terminal A
```bash
docker run -it ghcr.io/a85tract/lancet:cve_2023_33476
(inside docker) cd /app/src/minidlna-git
```

### 4. Launch terminal B
```bash
docker exec -it <contianer_id> bash
(inside docker) cd /app/src-asan/minidlna-git
```

### 4. Launch terminal C
```bash
docker exec -it <contianer_id> bash
(inside docker) cd /app/exploits
```

### 4. Boot minidlna with Lancet (terminal A)
```bash
(inside docker) /app/pin/pin -t /app/lancet.so -- ./minidlnad -R -f minidlna.conf -d
```

### Expected Output

```txt
...
monitor_inotify.c:156: info: Added watch to /opt [1]
...
(wait until no new logs are printed)
```

### 4. Run exploit (terminal C)
```bash
(inside docker) python3 tpoison-nopie-x64_reverse-shell.py 127.0.0.1 --system_addr 0x7ffff63a52f0 --got_addr 0x45e150
```

### Expected Output

#### terminal A
```txt
...
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b5310 dst: 2f0b5300 src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b5311 dst: 2f0b5301 src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b5312 dst: 2f0b5302 src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b5313 dst: 2f0b5303 src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b5314 dst: 2f0b5304 src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b5315 dst: 2f0b5305 src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b5316 dst: 2f0b5306 src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b5317 dst: 2f0b5307 src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b5318 dst: 2f0b5308 src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b5319 dst: 2f0b5309 src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b531a dst: 2f0b530a src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b531b dst: 2f0b530b src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b531c dst: 2f0b530c src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b531d dst: 2f0b530d src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b531e dst: 2f0b530e src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b531f dst: 2f0b530f src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b5320 dst: 2f0b5310 src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b5321 dst: 2f0b5311 src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b5322 dst: 2f0b5312 src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b5323 dst: 2f0b5313 src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b5324 dst: 2f0b5314 src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b5325 dst: 2f0b5315 src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b5326 dst: 2f0b5316 src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b5327 dst: 2f0b5317 src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b5328 dst: 2f0b5318 src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b5329 dst: 2f0b5319 src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b532a dst: 2f0b531a src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b532b dst: 2f0b531b src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b532c dst: 2f0b531c src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b532d dst: 2f0b531d src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b532e dst: 2f0b531e src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b532f dst: 2f0b531f src_vo: 17c0 dst_co: 0
memmove violation: 2f0b52e1 2f0b52f1 0x40 actual addr: src: 2f0b5330 dst: 2f0b5320 src_vo: 17c0 dst_co: 0
...
[exploit primitive] write in .got.plt region at: 0x45e158 by: libc+0x9a20b mov qword ptr [r8+0x8], 0x0 write size: 8
[exploit primitive] alloc in .got.plt region: 45e150
[exploit primitive] write in .got.plt region at: 0x45e150 by: libc+0x18ba58 vmovdqu ymmword ptr [rdi], ymm0 write size: 20
[exploit primitive] write in .got.plt region at: 0x45e170 by: libc+0x18ba5c vmovdqu ymmword ptr [rdi+0x20], ymm1 write size: 20
[exploit primitive] write in .got.plt region at: 0x45e188 by: libc+0x18ba61 vmovdqu ymmword ptr [rdi+rdx*1-0x20], ymm2 write size: 20
[exploit primitive] write in .got.plt region at: 0x45e168 by: libc+0x18ba67 vmovdqu ymmword ptr [rdi+rdx*1-0x40], ymm3 write size: 20
[exploit primitive] write in .got.plt region at: 0x45e1a8 by: main+0xad16 mov byte ptr [rax+rcx*1], 0x0 write size: 1
```

#### terminal C
```txt
...
[+]: target: 127.0.0.1:8200
...
Waiting for connections on :::1337
...
[!] ERROR: =ERROR=: Timed out waiting...
...
```

### Ouput Explanation

Outputs in terminal A: memmove violations indicate that a CROSSBOUNDARY event has occurred. src refers to the source address, and dst is the destination address—data is moved from src to dst. In general, the cell owner (co) and value owner (vo) should be the same. However, when co is 0, it indicates that the memory unit belongs to the heap. In our case, memmove causes some user data to overwrite a region in the heap. The following exploit primitives are observed: 'alloc in .got.plt region' indicates that the user has allocated a chunk overlapping the GOT table region, while 'write in .got.plt region' suggests an attempt to hijack the GOT table via malformed input.

Although the output from terminal C may suggest that the exploit failed, this is only because the script expects a reverse shell connection, which may not occur. However, this step is not necessary to demonstrate how Lancet analyzes the exploit. All memory-related exploit primitives are already completed once the GOT table is written—this is widely recognized as the final step in exploitation within the vulnerability research community.

### 5. Boot minidlna with Asan (terminal B)
Note: If minidlnad is still running, press Ctrl+C in terminal A to stop it before proceeding with the following experiment. However, do not close or exit terminal A.
```bash
(inside docker) ./minidlnad -R -f minidlna.conf -d
```

### 4. Run exploit (terminal C)
```bash
(inside docker) python3 tpoison-nopie-x64_reverse-shell.py 127.0.0.1 --system_addr 0x7ffff63a52f0 --got_addr 0x5f1350
```

### Expected Output

#### terminal A
```txt
...
AddressSanitizer: heap-buffer-overflow
...
AddressSanitizer: heap-buffer-overflow
...
AddressSanitizer: heap-buffer-overflow
...
```

# Experiment 5

### 1. Pull the Docker Image
```bash
docker pull ghcr.io/a85tract/lancet:juliet_how2heap
```

### 2. Run Modes
```bash
docker run ghcr.io/a85tract/lancet:cve_2019_6977 <tool> <case>
```
tool options: Asan, lancet, baseline  
case options: how2heap, CWE124, CWE126, CWE415, CWE416, CWE457

### Expected Output

#### Asan Mode

**how2heap**
```txt
...
AddressSanitizer: heap-buffer-overflow
...
AddressSanitizer: heap-buffer-overflow
...
AddressSanitizer: heap-buffer-overflow
...
```

**CWE124**
```txt
...
AddressSanitizer: heap-buffer-overflow
...
```

**CWE126**
```txt
...
AddressSanitizer: heap-buffer-overflow
...
```

**CWE415**
```txt
...
AddressSanitizer: attempting double-free
...
```

**CWE416**
```txt
...
AddressSanitizer: heap-use-after-free
...
```

**CWE457**
```txt
No useful outputs.
```

#### baseline Mode

**how2heap**
```txt
...
memory overlapping
...
time
```

**CWE124**
```txt
...
time
```

**CWE126**
```txt
...
time
```

**CWE415**
```txt
...
time
```

**CWE416**
```txt
...
time
```

**CWE457**
```txt
...
time
```

#### lancet Mode

**how2heap**
```txt
...
memory overlapping detected
...
time
...
INCONSISTENCY arithmetic
INCONSISTENCY mov write
...
INCONSISTENCY mov write reg UAF
```

**CWE124**
```txt
...
time
...
[INCONSISTENCY arithmetic] ip: main+0x126d
[INCONSISTENCY mov write reg] ip: main+0x11d9
...
```

**CWE126**
```txt
...
time
...
[UNINITIALIZED mov read] ip: main+0x1356
...
[INCONSISTENCY mov read] ip: main+0x1226
...
```

**CWE415**
```txt
...
src/ownership.cpp:124 error: double free detected
free(): double free detected in tcache 2
...
first time found dangling pointer at: ... distance: 107
...
main+0x1209 Read a dangling pointer 0x5efd6472e2b0 from ...
time
```

**CWE416**
```txt
...
time
first time found dangling pointer at: ... distance: 8
main+0x11b8 Read a dangling pointer ... from ...
```

**CWE457**
```txt
...
time
[UNINITIALIZED mov read] ip: main+0x11f1 co: 5 vo: -1
...
```