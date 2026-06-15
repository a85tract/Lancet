# QEMU TCG QLT plugin

This is the full QLancet QEMU plugin. It keeps the old runtime controls while
writing QLT binary traces by default.

## Build in the QEMU plugin Docker environment

```bash
cd /home/ubuntu/aixcc/a85_QLancet
docker build -t a85_qlancet_qemu -f Dockerfile .
./run_qemu_tcg_docker.sh
# inside container:
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
- `config=<path>`: qemu value-probe config. Matching entries read `import_reg + offset` and write the result to the QLT `value` field.
- `block-mb=<n>` / `block-size=<bytes>` and `zstd=<level>` tune QLT block compression.

QLT stores pc, instruction bytes, selected x86_64 registers, branch target,
value probes, and cr3. It does not store asm text; the Rust analyzer re-decodes
bytes with `iced-x86`.
