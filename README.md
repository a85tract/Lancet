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

The full plugin lives in `qemu_tcg/hello.c` and writes QLT by default.
For kernelCTF-style smoke collection with the old simulator assets, use
`qemu_tcg/docker_kernel_smoke.sh` or `qemu_tcg/collect_kernel_trace.sh`; the
script writes QLT directly and does not need the old telnet monitor/logfile step.
The Docker smoke defaults to a fast reset-vector trigger; set `SMOKE_TRIGGER=exp`
when you specifically want to test the guest exploit `_start` trigger path.

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
