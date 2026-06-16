# QEMU TCG QLT plugin

This is the full QLancet QEMU plugin. It keeps the old runtime controls while
writing QLT binary traces by default.

## Build in the QEMU plugin Docker environment

```bash
cd /home/ubuntu/aixcc/a85_QLancet
docker build -t a85_qlancet_qemu -f Dockerfile .
docker run --rm -ti --security-opt seccomp=unconfined \
  -v "$PWD":/work/a85 a85_qlancet_qemu bash
# inside container:
cd /work/a85/qemu_tcg
./build.sh
```

The build needs `qemu-plugin.h`, `glib-2.0`, and `libzstd`:

```bash
gcc -fPIC -shared hello.c -o hello.so -I/usr/local/include \
  $(pkg-config --cflags --libs glib-2.0) -lzstd
```

## Common plugin arguments

```bash
-plugin ./hello.so,format=qlt,out=trace.qlt,trigger=0x401650,onlycpu=1,regs=insn,insn=bytes,config=config.json,mode=user
```

- `format=qlt|text`: QLT is default; text preserves the legacy pipe-delimited trace.
- `out=<path>`: output path; default is `trace.qlt` for QLT.
- `regs=insn|all|cr3|movlea|none`: QLT defaults to `regs=insn` if omitted.
- `insn=bytes`: include bytes in text mode; QLT always stores instruction bytes.
- `trigger=<pc>`, `stop=<pc>`, `onlycpu=<n>`, `mode=user|kernel|all`, `addrfile=<path>`: same filtering controls as the old plugin.
- `trigger-mode=user|kernel|all`: address-space filter for the trigger PC only.
  This lets a user-space PoC marker arm a kernel-only trace without recording
  user instructions.
- `trigger-pc=reg` / `trigger-pc=rip`: read the architectural PC only for
  trigger matching. Unlike `pc=reg`, recorded PCs still use the translated PC,
  so kernel tracing stays cheaper.
- `trigger-window=<bytes>`: when `trigger-pc=reg` is used, register trigger
  callbacks only for translated PCs near `trigger` by default.  Use
  `trigger-window=0` only when the CPU filter is narrow enough for broad
  callbacks.
- `trigger-onlycpu=<n>|all`: CPU filter for arming the trigger. By default it
  follows `onlycpu`. Use `trigger-onlycpu=all` when `_start` runs on one CPU but
  the PoC later migrates to the isolated trace CPU.
- `pc=reg` / `pc=rip`: use the architectural PC register for trigger/range/record PCs. This is useful in system-mode QEMU where translated addresses may be physical/identity-mapped while RIP contains the guest virtual address.
- `config=<path>`: qemu value-probe config. Matching entries read `import_reg + offset` and write the result to the QLT `value` field.
- `block-mb=<n>` / `block-size=<bytes>` and `zstd=<level>` tune QLT block compression.

QLT stores pc, instruction bytes, selected x86_64 registers, branch target,
value probes, and cr3. When the QEMU register API exposes FS/GS base registers,
the plugin also writes QLT v2 segment-base fields for x86 FS:/GS: memory
accesses; the analyzer remains backward-compatible with QLT v1. QLT does not
store asm text; the Rust analyzer re-decodes bytes with `iced-x86`.

## KernelCTF smoke trace collection

The old project required a telnet monitor and QEMU `log plugin` redirection.  This
rewrite writes QLT directly, so the optimized flow is:

```bash
# Uses an existing kernelCTF simulator directory from the old checkout.
IMAGE=test_q ./qemu_tcg/docker_kernel_smoke.sh lts-6.1.70 /tmp/a85_kernel_smoke/lts-6.1.70.qlt

# Or, from inside a plugin-enabled QEMU container:
cd /work/a85/qemu_tcg
./build.sh
ONLYCPU=0 ./collect_kernel_trace.sh --smoke --timeout 120 --init /bin/exp --start 0xfffffff0 /sim lts-6.1.70 /out/lts-6.1.70.qlt
```

`docker_kernel_smoke.sh` defaults to `SMOKE_TRIGGER=reset`, `INIT=/bin/exp`,
and `ONLYCPU=0`, so it records the reset-vector instruction quickly while still
booting the kernel path.  Use `SMOKE_TRIGGER=exp` to try the slower guest `_start`
smoke path, which enables `pc=reg` so triggers compare against architectural RIP.
`--smoke` records a single instruction using `trigger=start,stop=start,from=start,to=start`;
this validates the kernel/QEMU trace path without producing a huge trace.  For
full collection, omit `--smoke` and keep an explicit `out=...` path; tune
`QLT_BLOCK_MB` and `QLT_ZSTD` for the block-compressed QLT writer.

## Scheme-B kernel trace collection

For PoC-driven kernel analysis, prefer a user-space marker/PC trigger and a
kernel-only trace.  This avoids static net/TLS address ranges, so owner
propagation is not broken by missing allocator/free/copy instructions outside
the hand-picked range:

```bash
# The start address can be _start, main, or a noinline marker inserted just
# before the interesting syscalls.
PLUGIN_MODE=kernel \
TRIGGER_MODE=user \
TRIGGER_PC_FROM_REG=1 \
ONLYCPU=1 \
TRIGGER_WINDOW=0x20000 \
./collect_kernel_trace.sh --start 0x4017b5 --timeout 180 \
  /sim mitigation-v4-6.6 /out/kernel_scheme_b.qlt
```

If the PoC is pinned/migrated to CPU 1 after `_start`, either trigger on a later
marker that is already on CPU 1, or keep `ONLYCPU=1` and set
`TRIGGER_ONLYCPU=all` so `_start` can arm the trace before migration.
