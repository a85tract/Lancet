# QLancet

A clean rewrite of QLancet's trace analyzer based on the Lancet ownership model.

## Trace formats

- `qlt`: compact binary trace (`QLT1`) with block-level zstd compression and a tail block index.
- `legacy`: compatible with the old `cpu|pc|asm|bytecode|regs:` text trace.
- `auto`: detect QLT by magic, otherwise parse legacy text.

The analyzer processes traces in streaming mode, so QLT blocks are decompressed and
analyzed one at a time instead of materializing the whole trace in memory.

## Build and test

```bash
cargo build
cargo test --verbose
```

## QEMU TCG plugin

The full plugin lives in `qemu_tcg/hello.c` and writes QLT by default:

```bash
docker build -t a85_qlancet_qemu -f Dockerfile .
./run_qemu_tcg_docker.sh
# inside the container:
cd /qemu/contrib/plugins/test/qemu_tcg
./build.sh
```

## Run

```bash
cargo run -- klancet <trace> <config.json> <output_dir> --trace-format auto
```
