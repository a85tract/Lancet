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
analyzed_ins_cnt

real    0m11.940s
user    0m7.472s
sys     0m4.350s
```

### Output Explanation

[MovRead high untrusted deref] means Lancet detects a UNTRUSTEDPTRDEREF1, program is trying to dereference pointer 0x6363636363636371. 429 is the cell owner ID, and 426 is the value owner ID of the memory buffer holding this pointer. The printed stack trace indicates where the corrupted buffer was allocated.
Time consumption: 11.940 - 7.396 = 4.544


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
analyzed_ins_cnt
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

### Output Explanation

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
analyzed_ins_cnt
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

### Output Explanation

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
docker exec -it <container_id> bash
(inside docker) cd /app/src-asan/minidlna-git
```

### 4. Launch terminal C
```bash
docker exec -it <container_id> bash
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

### 5. Run exploit (terminal C)
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
analyzed_ins_cnt
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

### Output Explanation

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
docker run ghcr.io/a85tract/lancet:cve_2019_6977 <tool> <target> <case>
```
> tool options: Asan, lancet, baseline  
> case options: how2heap, juliet
> how2heap case options: fastbin_reverse_into_tcache, house_of_einherjar, poison_null_byte
juliet case options:
```txt
CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_01-bad,CWE416_Use_After_Free__new_delete_class_01-bad,CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_loop_01-bad,CWE416_Use_After_Free__operator_equals_01-bad,CWE121_Stack_Based_Buffer_Overflow__CWE805_int_alloca_loop_13-bad,CWE416_Use_After_Free__return_freed_ptr_01,CWE121_Stack_Based_Buffer_Overflow__CWE805_struct_alloca_memmove_01-bad,CWE416_Use_After_Free__return_freed_ptr_01_asan,CWE122_Heap_Based_Buffer_Overflow__cpp_CWE129_fgets_09-bad,CWE416_Use_After_Free__return_freed_ptr_01-bad,CWE122_Heap_Based_Buffer_Overflow__cpp_CWE193_char_cpy_01-bad,CWE457_Use_of_Uninitialized_Variable__char_pointer_01-bad,CWE122_Heap_Based_Buffer_Overflow__cpp_CWE805_char_loop_01-bad,CWE457_Use_of_Uninitialized_Variable__double_array_alloca_partial_init_01-bad,CWE122_Heap_Based_Buffer_Overflow__cpp_dest_char_cat_01-bad,CWE457_Use_of_Uninitialized_Variable__double_array_malloc_no_init_01-bad,CWE122_Heap_Based_Buffer_Overflow__CWE131_memcpy_66-bad,CWE457_Use_of_Uninitialized_Variable__empty_constructor_01-bad,CWE123_Write_What_Where_Condition__fgets_01-bad,CWE457_Use_of_Uninitialized_Variable__int_array_malloc_partial_init_01,CWE124_Buffer_Underwrite__char_declare_cpy_01-bad,CWE457_Use_of_Uninitialized_Variable__int_array_malloc_partial_init_01_asan,CWE124_Buffer_Underwrite__CWE839_fgets_01-bad,CWE457_Use_of_Uninitialized_Variable__twointsclass_array_malloc_partial_init_01-bad,CWE124_Buffer_Underwrite__malloc_char_loop_65,CWE476_NULL_Pointer_Dereference__binary_if_01-bad,CWE124_Buffer_Underwrite__malloc_char_loop_65_asan,CWE476_NULL_Pointer_Dereference__class_01-bad,CWE124_Buffer_Underwrite__malloc_char_loop_65-bad,CWE476_NULL_Pointer_Dereference__deref_after_check_01-bad,CWE124_Buffer_Underwrite__malloc_char_memcpy_01-bad,CWE476_NULL_Pointer_Dereference__long_66-bad,CWE126_Buffer_Overread__CWE129_fgets_01-bad,CWE476_NULL_Pointer_Dereference__struct_01-bad,CWE126_Buffer_Overread__malloc_char_loop_01-bad,CWE562_Return_of_Stack_Variable_Address__return_buf_01-bad,CWE126_Buffer_Overread__malloc_wchar_t_loop_66,CWE562_Return_of_Stack_Variable_Address__return_local_class_member_01-bad,CWE126_Buffer_Overread__malloc_wchar_t_loop_66_asan,CWE562_Return_of_Stack_Variable_Address__return_pointer_buf_01-bad,CWE126_Buffer_Overread__malloc_wchar_t_loop_66-bad,CWE587_Assignment_of_Fixed_Address_to_Pointer__basic_06-bad,CWE126_Buffer_Overread__new_char_loop_01-bad,CWE590_Free_Memory_Not_on_Heap__delete_array_char_static_01-bad,CWE126_Buffer_Overread__new_char_memmove_01-bad,CWE590_Free_Memory_Not_on_Heap__delete_array_class_declare_01-bad,CWE127_Buffer_Underread__char_alloca_memcpy_01-bad,CWE590_Free_Memory_Not_on_Heap__delete_array_class_static_01-bad,CWE127_Buffer_Underread__CWE839_fgets_01-bad,CWE590_Free_Memory_Not_on_Heap__delete_char_placement_new_01-bad,CWE127_Buffer_Underread__CWE839_negative_01-bad,CWE590_Free_Memory_Not_on_Heap__free_int_static_01-bad,CWE127_Buffer_Underread__malloc_char_loop_66-bad,CWE667_Improper_Locking__basic_01-bad,CWE134_Uncontrolled_Format_String__char_console_fprintf_01-bad,CWE680_Integer_Overflow_to_Buffer_Overflow__malloc_fgets_01-bad,CWE190_Integer_Overflow__char_max_add_01-bad,CWE680_Integer_Overflow_to_Buffer_Overflow__malloc_fixed_01-bad,CWE190_Integer_Overflow__char_max_multiply_01-bad,CWE680_Integer_Overflow_to_Buffer_Overflow__new_fgets_01-bad,CWE190_Integer_Overflow__char_max_square_01-bad,CWE680_Integer_Overflow_to_Buffer_Overflow__new_fixed_01-bad,CWE252_Unchecked_Return_Value__char_fgets_01-bad,CWE690_NULL_Deref_From_Return__char_calloc_01-bad,CWE252_Unchecked_Return_Value__char_fread_01-bad,CWE690_NULL_Deref_From_Return__char_malloc_01-bad,CWE252_Unchecked_Return_Value__char_putc_01-bad,CWE690_NULL_Deref_From_Return__int64_t_realloc_01-bad,CWE252_Unchecked_Return_Value__char_putchar_01-bad,CWE758_Undefined_Behavior__char_alloca_use_01-bad,CWE252_Unchecked_Return_Value__char_rename_01-bad,CWE758_Undefined_Behavior__char_malloc_use_01-bad,CWE401_Memory_Leak__char_calloc_01-bad,CWE758_Undefined_Behavior__char_new_use_01-bad,CWE401_Memory_Leak__char_malloc_01-bad,CWE758_Undefined_Behavior__char_pointer_new_use_01-bad,CWE401_Memory_Leak__char_realloc_01-bad,CWE758_Undefined_Behavior__int_malloc_use_06-bad,CWE401_Memory_Leak__new_TwoIntsClass_01-bad,CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_fixed_string_01-bad,CWE415_Double_Free__malloc_free_char_72-bad,CWE761_Free_Pointer_Not_at_Start_of_Buffer__wchar_t_console_66-bad,CWE415_Double_Free__malloc_free_long_21,CWE762_Mismatched_Memory_Management_Routines__calloc_delete_01-bad,CWE415_Double_Free__malloc_free_long_21_asan,CWE762_Mismatched_Memory_Management_Routines__delete_array_char_malloc_01-bad,CWE415_Double_Free__malloc_free_long_21-bad,CWE762_Mismatched_Memory_Management_Routines__new_array_delete_int64_t_01-bad,CWE415_Double_Free__new_delete_array_char_01-bad,CWE762_Mismatched_Memory_Management_Routines__new_delete_array_class_01-bad,CWE415_Double_Free__new_delete_class_01-bad,CWE762_Mismatched_Memory_Management_Routines__new_free_class_01-bad,CWE415_Double_Free__no_assignment_op_01-bad,CWE789_Uncontrolled_Mem_Alloc__malloc_wchar_t_fgets_01-bad,CWE416_Use_After_Free__malloc_free_struct_01-bad,CWE789_Uncontrolled_Mem_Alloc__new_wchar_t_fgets_01-bad,CWE416_Use_After_Free__new_delete_array_struct_01-bad
```

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

Since there are many cases, we only present the output for the one with the most straightforward results for each bug type. The outputs of the other cases are similar. Additionally, the difference in time consumption between Lancet and the baseline is the analysis time.

**how2heap house_of_einherjar**  
Example: docker run ghcr.io/a85tract/lancet:juliet_how2heap lancet how2heap house_of_einherjar
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

**juliet CrossBoundary**  
Example: docker run ghcr.io/a85tract/lancet:juliet_how2heap lancet juliet CWE121_Stack_Based_Buffer_Overflow__CWE193_char_declare_loop_01-bad
```txt
...
analyzed_ins_cnt
time
...
Ownership log:
--------------------------------
[INCONSISTENCY mov write reg] ip: main+0x1285 co: -1 vo: 3, 3 write -1
[INCONSISTENCY mov write reg] ip: main+0x1285 co: -1 vo: 3, 3 write -1
[INCONSISTENCY mov write reg] ip: main+0x1285 co: -1 vo: 3, 3 write -1
[INCONSISTENCY mov write reg] ip: main+0x1285 co: -1 vo: 3, 3 write -1
[INCONSISTENCY mov write reg] ip: main+0x1285 co: -1 vo: 3, 3 write -1
...
```

**juliet DoubleFree**  
Example: docker run ghcr.io/a85tract/lancet:juliet_how2heap lancet juliet CWE415_Double_Free__malloc_free_long_21
```txt
...
src/ownership.cpp:124 error: double free detected
...
analyzed_ins_cnt
time
...
main+0x1316 Read a dangling pointer 0x55555555a2b0 from 0x7fffffffe978
Store dangling pointer: 0x55555555a2b0 at: 0x7fffffffe958
main+0x138e Using expired pointer: 0x55555555a2b0 from 0x7fffffffe978
first time found dangling pointer at: 3848 distance: 24
main+0x13a3 Using expired pointer: 0x55555555a2b0 from 0x7fffffffe978
first time found dangling pointer at: 3848 distance: 26
main+0x13b6 Using expired pointer: 0x55555555a2b0 from 0x7fffffffe978
first time found dangling pointer at: 3848 distance: 30
main+0x13b6 Read a dangling pointer 0x55555555a2b0 from 0x7fffffffe978
Store dangling pointer: 0x55555555a2b0 at: 0x7fffffffe958
main+0x140e Using expired pointer: 0x55555555a2b0 from 0x7fffffffe978
first time found dangling pointer at: 3848 distance: 52
main+0x142d Using expired pointer: 0x55555555a2b0 from 0x7fffffffe978
first time found dangling pointer at: 3848 distance: 55
main+0x1459 Using expired pointer: 0x55555555a2b0 from 0x7fffffffe958
first time found dangling pointer at: 3848 distance: 63
main+0x11d6 Read a dangling pointer 0x55555555a2b0 from 0x7fffffffe988
Store dangling pointer: 0x55555555a2b0 at: 0x7fffffffe968
main+0x1209 Using expired pointer: 0x55555555a2b0 from 0x7fffffffe968
first time found dangling pointer at: 3848 distance: 107
main+0x1209 Read a dangling pointer 0x55555555a2b0 from 0x7fffffffe968
...
```

** UAF/DANGLINGPTR**  
Example: docker run ghcr.io/a85tract/lancet:juliet_how2heap lancet juliet CWE416_Use_After_Free__return_freed_ptr_01
```txt
...
src/ownership.cpp:124 error: double free detected
...
analyzed_ins_cnt
time
...
main+0x1284 Read a dangling pointer 0x55555555a2d0 from 0x7fffffffe938
Store dangling pointer: 0x55555555a2d0 at: 0x7fffffffe958
main+0x1299 Using expired pointer: 0x55555555a2d0 from 0x7fffffffe958
first time found dangling pointer at: 4781 distance: 3
main+0x1299 Read a dangling pointer 0x55555555a2d0 from 0x7fffffffe958
Store dangling pointer: 0x55555555a2d0 at: 0x7fffffffe978
main+0x11b8 Using expired pointer: 0x55555555a2d0 from 0x7fffffffe978
first time found dangling pointer at: 4781 distance: 8
main+0x11b8 Read a dangling pointer 0x55555555a2d0 from 0x7fffffffe978
main+0x1209 Read a dangling pointer 0x55555555a2b0 from 0x7fffffffe968
...
```

**UninitRead**  
Example: docker run ghcr.io/a85tract/lancet:juliet_how2heap lancet juliet CWE457_Use_of_Uninitialized_Variable__char_pointer_01-bad
```txt
...
analyzed_ins_cnt
time
...
[UNINITIALIZED mov read] ip: main+0x11fa co: 3 vo: -1
...
```

**NllPtrDeref**  
Example: docker run ghcr.io/a85tract/lancet:juliet_how2heap lancet juliet CWE476_NULL_Pointer_Dereference__long_66
```txt
...
[MovRead nullptr deref] ip: main+0x126c final_ea: 0x0
analyzed_ins_cnt
time
...
```

**UNTRUSTEDPTRDEREF**  
Example: docker run ghcr.io/a85tract/lancet:juliet_how2heap lancet juliet CWE587_Assignment_of_Fixed_Address_to_Pointer__basic_06-bad
```txt
...
[UNTRUSTEDPTRDEREF] ip: main+0x11e5 final_ea: 0x400000
analyzed_ins_cnt
time
...
```

**INVALIDFREE**  
Example: docker run ghcr.io/a85tract/lancet:juliet_how2heap lancet juliet CWE590_Free_Memory_Not_on_Heap__delete_array_char_static_01-bad
```txt
...
src/ownership.cpp:89[INVALID FREE] free error: cell_ownership_map does not contain addr: 0x555555558040 Maybe realloc/calloc?
free(): invalid pointer
...
analyzed_ins_cnt
time
...
```

**STACKREADUSEAFTERSCOPE**  
Example: docker run ghcr.io/a85tract/lancet:juliet_how2heap lancet juliet CWE562_Return_of_Stack_Variable_Address__return_buf_01-bad
```txt
...
STACKREADUSEAFTERSCOPE at:
...
analyzed_ins_cnt
time
...

### 3. hacknote

This experiment need interactive mode, these are reproduce steps:
```bash
docker run -it --entrypoint /bin/bash ghcr.io/a85tract/lancet:juliet_how2heap
```

```bash
(inside docker)
cd hacknote
python3 exp.py
```

Wait until no more output is generated and receive "Your choice :$", then input 4 with enter Then:

```bash
(inside docker)
cat logs/ownership.log
```

You will get:

```txt
main+0x1291 Read a dangling pointer 0x5555555592a0 from 0x555555558090
main+0x1479 Using expired pointer: 0x5555555592a0 from 0x555555558090
first time found dangling pointer at: 5035 distance: 167
main+0x148f Using expired pointer: 0x5555555592a0 from 0x555555558090
first time found dangling pointer at: 5035 distance: 171
main+0x14a1 Using expired pointer: 0x5555555592a0 from 0x555555558090
first time found dangling pointer at: 5035 distance: 175
```

# Experiment 6

### 1. Pull the Docker Image
```bash
docker pull ghcr.io/a85tract/lancet:osv_2024_204
```

### 2. Run Baseline Mode
```bash
docker run ghcr.io/a85tract/lancet:osv_2024_204 baseline
```

### Expected Output

```txt
real    0m6.932s
user    0m4.804s
sys     0m1.914s
```

### 3. Run Lancet Mode
```bash
docker run ghcr.io/a85tract/lancet:osv_2024_204 lancet
```

### Expected Output

```txt
...
analyzed_ins_cnt
real    0m14.916s
user    0m10.390s
sys     0m4.354s
--------------------------------
Ownership log:
--------------------------------
main+0x1b6f7 Read a dangling pointer 0x55555567214f from 0x7fffffffd6d0
main+0xbe676 Using expired pointer: 0x55555567214f from 0x7fffffffd6d0
first time found dangling pointer at: 753005 distance: 112
main+0xbe676 Read a dangling pointer 0x55555567214f from 0x7fffffffd6d0
main+0x1b6f7 Read a dangling pointer 0x55555567214f from 0x7fffffffcc20
main+0xbe676 Using expired pointer: 0x55555567214f from 0x7fffffffcc20
main+0xbe676 Read a dangling pointer 0x55555567214f from 0x7fffffffcc20
main+0x1b6f7 Read a dangling pointer 0x55555567214f from 0x7fffffffc890
main+0xbe676 Using expired pointer: 0x55555567214f from 0x7fffffffc890
main+0xbe676 Read a dangling pointer 0x55555567214f from 0x7fffffffc890
main+0x1b6f7 Read a dangling pointer 0x555555675552 from 0x7fffffffbd30
main+0xbe676 Using expired pointer: 0x555555675552 from 0x7fffffffbd30
first time found dangling pointer at: 897997 distance: 112
main+0xbe676 Read a dangling pointer 0x555555675552 from 0x7fffffffbd30
main+0x1b6f7 Read a dangling pointer 0x555555675a52 from 0x7fffffffc410
main+0xbe676 Using expired pointer: 0x555555675a52 from 0x7fffffffc410
first time found dangling pointer at: 952383 distance: 112
main+0xbe676 Read a dangling pointer 0x555555675a52 from 0x7fffffffc410
Store dangling pointer: 0x55555567aa00 at: 0x7fffffffe318
main+0x176dc Read a dangling pointer 0x55555565df68 from 0x555555659340
```

### Output Explanation

The ownership log indicates that Lancet detects the dangling pointer 112 instructions before the UAF occurs.

Time consumption: 14.916 - 6.932 = 7.984

# Experiment 7

### 1. Pull the Docker Image
```bash
docker pull ghcr.io/a85tract/lancet:ffmpeg_11228
```

### 2. Run Baseline Mode
```bash
docker run ghcr.io/a85tract/lancet:ffmpeg_11228 baseline
```

### Expected Output

```txt
real    0m52.944s
user    0m36.308s
sys     0m15.578s
```

### 3. Run Lancet Mode
```bash
docker run ghcr.io/a85tract/lancet:ffmpeg_11228 lancet
```

### Expected Output

```txt
...
[MovRead nullptr deref] ip: main+0x4ad0be final_ea: 0x10
analyzed_ins_cnt
...
real    1m18.019s
user    0m56.291s
sys     0m26.168s
```

### Output Explanation

MovRead nullptr deref means lancet detects a NULL pointer dereference at 0x10, ip is main+0x4ad0be.

Time consumption: 1m18.019 - 52.944 = 25.075

# Experiment 8

### 1. Pull the Docker Image
```bash
docker pull ghcr.io/a85tract/lancet:ffmpeg_10749
```

### 2. Run Baseline Mode
```bash
docker run ghcr.io/a85tract/lancet:ffmpeg_10749 baseline
```

### Expected Output

```txt
real    4m14.763s
user    4m0.229s
sys     0m19.076s
```

### 3. Run Lancet Mode
```bash
docker run ghcr.io/a85tract/lancet:ffmpeg_10749 lancet
```

### Expected Output

```txt
...
[MovRead nullptr deref] ip: main+0x1fd286 final_ea: 0x70
analyzed_ins_cnt
...
real    4m25.287s
user    4m9.947s
sys     0m21.018s
```

### Output Explanation

MovRead nullptr deref means lancet detects a NULL pointer dereference at 0x70, ip is main+0x1fd286.

Time consumption: 4m25.287 - 4m14.763 = 10.524

# Experiment 9

### 1. Pull the Docker Image
```bash
docker pull ghcr.io/a85tract/lancet:osv_2023_1276
```

### 2. Run Baseline Mode
```bash
docker run ghcr.io/a85tract/lancet:osv_2023_1276 baseline
```

### Expected Output

```txt
real    0m15.110s
user    0m10.695s
sys     0m4.084s
```

### 3. Run Lancet Mode
```bash
docker run ghcr.io/a85tract/lancet:osv_2023_1276 lancet
```

### Expected Output

```txt
...
analyzed_ins_cnt
real    0m41.222s
user    0m28.023s
sys     0m12.875s
--------------------------------
Ownership log:
--------------------------------
main+0x3a322 Read a dangling pointer 0x5555558a4650 from 0x7fffffffd9c8
main+0x3a330 Using expired pointer: 0x5555558a4650 from 0x7fffffffd9c8
first time found dangling pointer at: 2601373 distance: 3
main+0x3a330 Read a dangling pointer 0x5555558a4650 from 0x7fffffffd9c8
[INCONSISTENCY mov write imm UAF] ip: main+0x3a334 UAF write at: 0x5555558a4818
main+0x3a33e Using expired pointer: 0x5555558a4650 from 0x7fffffffd9c8
first time found dangling pointer at: 2601373 distance: 5
main+0x3a33e Read a dangling pointer 0x5555558a4650 from 0x7fffffffd9c8
Store dangling pointer: 0x5555558a4650 at: 0x7fffffffda38
main+0x120874 Using expired pointer: 0x5555558a4650 from 0x7fffffffda38
```

### Output Explanation

The ownership log indicates that Lancet detects the dangling pointer 5 instructions before the UAF occurs.

Time consumption: 0m41.222 - 0m15.110 = 26.112

# Experiment 10

### 1. Pull the Docker Image
```bash
docker pull ghcr.io/a85tract/lancet:cve_2024_43374
```

### 2. Run Baseline Mode
```bash
docker run ghcr.io/a85tract/lancet:cve_2024_43374 baseline
```

### Expected Output

```txt
real    0m13.670s
user    0m9.192s
sys     0m3.821s
```

### 3. Run Lancet Mode
```bash
docker run ghcr.io/a85tract/lancet:cve_2024_43374 lancet
```

### Expected Output

```txt
...
analyzed_ins_cnt
real    0m14.631s
user    0m10.212s
sys     0m4.261s
--------------------------------
Ownership log:
--------------------------------
first time found dangling pointer at: 206328 distance: 223891
main+0xbb943 Read a dangling pointer 0x5555558f7770 from 0x5555558ec3e8
main+0x7b37b Using expired pointer: 0x5555558f7770 from 0x5555558ec3e8
first time found dangling pointer at: 206328 distance: 223899
main+0x7b37b Read a dangling pointer 0x5555558f7770 from 0x5555558ec3e8
main+0x7a96e Using expired pointer: 0x5555558f7770 from 0x5555558ec3e8
first time found dangling pointer at: 206328 distance: 223912
main+0x7a96e Read a dangling pointer 0x5555558f7770 from 0x5555558ec3e8
main+0xce7fb Using expired pointer: 0x5555558f7770 from 0x5555558ec3e8
first time found dangling pointer at: 206328 distance: 226177
main+0xce7fb Read a dangling pointer 0x5555558f7770 from 0x5555558ec3e8
main+0xb1580 Using expired pointer: 0x5555558f7770 from 0x5555558ec3e8
first time found dangling pointer at: 206328 distance: 227502
main+0xb1580 Read a dangling pointer 0x5555558f7770 from 0x5555558ec3e8
main+0xb1587 Using expired pointer: 0x55555590b1c0 from 0x5555558f96b8
first time found dangling pointer at: 205903 distance: 227928
main+0xb1587 Read a dangling pointer 0x55555590b1c0 from 0x5555558f96b8
Store dangling pointer: 0x55555590b1d0 at: 0x7fffffff7958
main+0xb31d6 Using expired pointer: 0x5555559078b0 from 0x555555907800
first time found dangling pointer at: 2003 distance: 431843
```

### Output Explanation

The ownership log indicates that Lancet detects the dangling pointer 431843 instructions before the UAF occurs.

Time consumption: 0m14.631 - 0m13.670 = 0.961

# Experiment 11

### 1. Pull the Docker Image
```bash
docker pull ghcr.io/a85tract/lancet:gpac_2701
```

### 2. Run Baseline Mode
```bash
docker run ghcr.io/a85tract/lancet:gpac_2701 baseline
```

### Expected Output

```txt
real    0m26.050s
user    0m19.476s
sys     0m5.717s
```

### 3. Run Lancet Mode
```bash
docker run ghcr.io/a85tract/lancet:gpac_2701 lancet
```

### Expected Output

```txt
...
src/ownership.cpp:124 error: double free detected
double free or corruption (fasttop)
...
analyzed_ins_cnt
...
real    0m38.218s
user    0m28.167s
sys     0m9.336s
0x7fffe3c373c6 Using expired pointer: 0x5555555f4140 from 0x5555555f9788
first time found dangling pointer at: 2570461 distance: 1
0x7fffe3c373c6 Read a dangling pointer 0x5555555f4140 from 0x5555555f9788
Store dangling pointer: 0x5555555ef270 at: 0x7fffffff88d0
Store dangling pointer: 0x5555555f50f0 at: 0x7fffffff88e8
0x7ffff7fd8dc2 Using expired pointer: 0x5555555f50f0 from 0x7fffffff88e8
first time found dangling pointer at: 2572332 distance: 54
0x7ffff7fd8dc2 Read a dangling pointer 0x5555555f50f0 from 0x7fffffff88e8
0x7ffff7fd8dd1 Using expired pointer: 0x5555555ef270 from 0x7fffffff88d0
first time found dangling pointer at: 2572329 distance: 55
0x7ffff7fd8dd1 Read a dangling pointer 0x5555555ef270 from 0x7fffffff88d0
0x7fffe3aaa703 Read a dangling pointer 0x555555616ef0 from 0x555555616eb8
[INCONSISTENCY mov read UAF] ip: 0x7fffe3c34284 UAF read at: 0x555555616f00
[INCONSISTENCY mov read UAF] ip: 0x7fffe3c34288 UAF read at: 0x555555616f08
[INCONSISTENCY mov write imm UAF] ip: 0x7fffe3c3428c UAF write at: 0x555555616f08
```

### Output Explanation

The ownership log indicates that Lancet detects the dangling pointer 55 instructions before the UAF occurs.

Time consumption: 0m38.218 - 0m26.050 = 12.168

# Experiment 12

### 1. Pull the Docker Image
```bash
docker pull ghcr.io/a85tract/lancet:gpac_2583
```

### 2. Run Baseline Mode
```bash
docker run ghcr.io/a85tract/lancet:gpac_2583 baseline
```

### Expected Output

```txt
real    0m30.883s
user    0m23.663s
sys     0m6.806s
```

### 3. Run Lancet Mode
```bash
docker run ghcr.io/a85tract/lancet:gpac_2583 lancet
```

### Expected Output

```txt
...
analyzed_ins_cnt
--------------------------------
Ownership log:
--------------------------------

real    3m59.961s
user    2m46.541s
sys     1m12.966s
0x7ffff7fd8dc2 Using expired pointer: 0x5555555d7710 from 0x7fffffff8928
first time found dangling pointer at: 38494986 distance: 757
0x7ffff7fd8dc2 Read a dangling pointer 0x5555555d7710 from 0x7fffffff8928
Store dangling pointer: 0x555555611570 at: 0x7fffffff8910
Store dangling pointer: 0x55555560ffb0 at: 0x7fffffff8928
0x7ffff7fd8dc2 Using expired pointer: 0x55555560ffb0 from 0x7fffffff8928
first time found dangling pointer at: 38496294 distance: 645
0x7ffff7fd8dc2 Read a dangling pointer 0x55555560ffb0 from 0x7fffffff8928
0x7ffff7fd8dd1 Using expired pointer: 0x555555611570 from 0x7fffffff8910
first time found dangling pointer at: 38496291 distance: 651
0x7ffff7fd8dd1 Read a dangling pointer 0x555555611570 from 0x7fffffff8910
Store dangling pointer: 0x5555555d6c20 at: 0x7fffffff8910
Store dangling pointer: 0x5555555d0f90 at: 0x7fffffff8928
0x7ffff7fd8dc2 Using expired pointer: 0x5555555d0f90 from 0x7fffffff8928
first time found dangling pointer at: 38593289 distance: 645
0x7ffff7fd8dc2 Read a dangling pointer 0x5555555d0f90 from 0x7fffffff8928
0x7ffff7fd8dd1 Using expired pointer: 0x5555555d6c20 from 0x7fffffff8910
first time found dangling pointer at: 38593286 distance: 651
0x7ffff7fd8dd1 Read a dangling pointer 0x5555555d6c20 from 0x7fffffff8910
Store dangling pointer: 0x5555555d0b80 at: 0x7fffffff8c80
```

### Output Explanation

The ownership log indicates that Lancet detects the dangling pointer 651 instructions before the UAF occurs.

Time consumption: 3m59.961 - 0m30.883 = 229.078

# Experiment 13

### 1. Pull the Docker Image
```bash
docker pull ghcr.io/a85tract/lancet:php_16595
```

### 2. Run Baseline Mode
```bash
docker run ghcr.io/a85tract/lancet:php_16595 baseline
```

### Expected Output

```txt
real    0m22.047s
user    0m15.245s
sys     0m6.073s
```

### 3. Run Lancet Mode
```bash
docker run ghcr.io/a85tract/lancet:php_16595 lancet
```

### Expected Output

```txt
...
analyzed_ins_cnt
...
real    1m0.043s
user    0m41.399s
sys     0m17.802s
main+0x63bfb5 Read a dangling pointer 0x7fffd4e02578 from 0x7fffd4e89080
[INCONSISTENCY mov read UAF] ip: main+0x63bfd0 UAF read at: 0x7fffd4e02598
[INCONSISTENCY mov read UAF] ip: main+0x63bfd0 UAF read at: 0x7fffd4e02590
main+0x63bfd0 Using expired pointer: 0x7fffd4e562a0 from 0x7fffd4e02590
main+0x63bfd0 Read a dangling pointer 0x7fffd4e562a0 from 0x7fffd4e02590
[INCONSISTENCY mov read UAF] ip: main+0x63bfd0 UAF read at: 0x7fffd4e02588
main+0x63bfd0 Using expired pointer: 0x7fffd4e56260 from 0x7fffd4e02588
main+0x63bfd0 Read a dangling pointer 0x7fffd4e56260 from 0x7fffd4e02588
[INCONSISTENCY mov read UAF] ip: main+0x63bfd0 UAF read at: 0x7fffd4e02580
main+0x63bfd0 Using expired pointer: 0x7fffd4e56220 from 0x7fffd4e02580
main+0x63bfd0 Read a dangling pointer 0x7fffd4e56220 from 0x7fffd4e02580
[INCONSISTENCY mov read UAF] ip: main+0x63bfd0 UAF read at: 0x7fffd4e02578
main+0x560c5d Using expired pointer: 0x7fffd4e02550 from 0x7fffd4e00088
main+0x560c5d Read a dangling pointer 0x7fffd4e02550 from 0x7fffd4e00088
Store dangling pointer: 0x7fffd4e02550 at: 0x7fffd4e02578
[INCONSISTENCY mov write reg UAF] ip: main+0x560c62 UAF write at: 0x7fffd4e02578
[INCONSISTENCY mov write reg UAF] ip: main+0x560c6c UAF write at: 0x7fffd4e02598
Store dangling pointer: 0x7fffd4e02578 at: 0x7fffd4e00088
[INCONSISTENCY mov write reg UAF] ip: main+0x560c62 UAF write at: 0x7fffd4e8f000
Store dangling pointer: 0x7fffd4e8f000 at: 0x7fffd4e00138
main+0x560c5d Using expired pointer: 0x7fffd4e88180 from 0x7fffd4e000a0
first time found dangling pointer at: 8041008 distance: 667
main+0x560c5d Read a dangling pointer 0x7fffd4e88180 from 0x7fffd4e000a0
Store dangling pointer: 0x7fffd4e88180 at: 0x7fffd4e88040
[INCONSISTENCY mov write reg UAF] ip: main+0x560c62 UAF write at: 0x7fffd4e88040
[INCONSISTENCY mov write reg UAF] ip: main+0x560c6c UAF write at: 0x7fffd4e88078
Store dangling pointer: 0x7fffd4e88040 at: 0x7fffd4e000a0
main+0x560c5d Using expired pointer: 0x7fffd4e01040 from 0x7fffd4e00070
main+0x560c5d Read a dangling pointer 0x7fffd4e01040 from 0x7fffd4e00070
Store dangling pointer: 0x7fffd4e01040 at: 0x7fffd4e01060
```

### Output Explanation

The ownership log indicates that Lancet detects the dangling pointer 667 instructions before the UAF occurs.

Time consumption: 1m0.043 - 0m22.047 = 38.004

# Experiment 14

### 1. Pull the Docker Image
```bash
docker pull ghcr.io/a85tract/lancet:osv_2024_96
```

### 2. Run Baseline Mode
```bash
docker run ghcr.io/a85tract/lancet:osv_2024_96 baseline
```

### Expected Output

```txt
real    0m7.479s
user    0m5.162s
sys     0m2.092s
```

### 3. Run Lancet Mode
```bash
docker run ghcr.io/a85tract/lancet:osv_2024_96 lancet
```

### Expected Output

```txt
...
analyzed_ins_cnt
...
real    0m20.858s
user    0m13.940s
sys     0m6.767s
--------------------------------
Ownership log:
--------------------------------
[INCONSISTENCY arithmetic -> CROSSBOUNDARY] ip: main+0x4444d id before: 762 after: 0 value: 0x5555556a63f0
```

### Output Explanation

Time consumption: 0m20.858 - 0m7.479 = 13.379

# Experiment 15

### 1. Pull the Docker Image
```bash
docker pull ghcr.io/a85tract/lancet:php_76041
```

### 2. Run Baseline Mode
```bash
docker run ghcr.io/a85tract/lancet:php_76041 baseline
```

### Expected Output

```txt
real    0m16.358s
user    0m10.980s
sys     0m4.573s
```

### 3. Run Lancet Mode
```bash
docker run ghcr.io/a85tract/lancet:php_76041 lancet
```

### Expected Output

```txt
...
[MovRead nullptr deref] ip: main+0x38b9aa final_ea: 0x0
analyzed_ins_cnt

real    0m32.506s
user    0m23.937s
sys     0m8.304s
```

### Output Explanation

Time consumption: 0m32.506 - 0m16.358 = 16.148

# Experiment 16

### 1. Pull the Docker Image
```bash
docker pull ghcr.io/a85tract/lancet:cve_2004_1287
```

### 2. Run Baseline Mode
```bash
docker run ghcr.io/a85tract/lancet:cve_2004_1287 baseline
```

### Expected Output

```txt
real    0m3.886s
user    0m2.477s
sys     0m1.044s
```

### 3. Run Lancet Mode
```bash
docker run ghcr.io/a85tract/lancet:cve_2004_1287 lancet
```

### Expected Output

```txt
...
analyzed_ins_cnt
...
real    0m7.675s
user    0m4.386s
sys     0m2.983s
--------------------------------
Ownership log:
--------------------------------
[INCONSISTENCY mov write reg] ip: main+0x36e83 co: 5 vo: -1, -1 write 5
```

### Output Explanation

The ownership log indicates that Lancet detects CROSSBOUNDARY.

Time consumption: 0m7.675 - 0m3.886 = 3.789

# Experiment 17

### 1. Pull the Docker Image
```bash
docker pull ghcr.io/a85tract/lancet:cve_2007_1001
```

### 2. Run Baseline Mode
```bash
docker run ghcr.io/a85tract/lancet:cve_2007_1001 baseline
```

### Expected Output

```txt
real    0m10.853s
user    0m7.264s
sys     0m3.032s
```

### 3. Run Lancet Mode
```bash
docker run ghcr.io/a85tract/lancet:cve_2007_1001 lancet
```

### Expected Output

```txt
...
analyzed_ins_cnt: 7053782
...
real    0m29.296s
user    0m20.095s
sys     0m8.698s
[INCONSISTENCY mov read] ip: main+0xa6dd8 base: 0x0 pointee: 1 read from -1
```

### Output Explanation

The ownership log indicates that Lancet detects CROSSBOUNDARY.

Time consumption: 0m29.296 - 0m10.853 = 18.443

# Experiment 18

### 1. Pull the Docker Image
```bash
docker pull ghcr.io/a85tract/lancet:cve_2012_2386
```

### 2. Run Baseline Mode
```bash
docker run ghcr.io/a85tract/lancet:cve_2012_2386 baseline
```

### Expected Output

```txt
real    0m18.819s
user    0m12.894s
sys     0m5.095s
```

### 3. Run Lancet Mode
```bash
docker run ghcr.io/a85tract/lancet:cve_2012_2386 lancet
```

### Expected Output

```txt
...
analyzed_ins_cnt
...
real    0m27.889s
user    0m19.649s
sys     0m8.058s
...
[INCONSISTENCY arithmetic -> CROSSBOUNDARY] ip: 0x7fffe16b195c add rax, rcx id before: 140736899628432 after: -1 value: 0x7fffe0f53e79
```

### Output Explanation

Time consumption: 0m27.889 - 0m18.819 = 9.07