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

### One-shot Docker trace collection

Use `get_trace.sh` to build/run inside a disposable Docker container and remove
the container automatically when QEMU exits:

```bash
./get_trace.sh mitigation-v4-6.6 qlt ./pocs/tls.c ./out/tls.qlt
```

For repeatable cases, put a manifest under `cases/<name>/config.json` and run:

```bash
./get_trace.sh cve39682
```

Case layout:

```text
cases/cve39682/
  config.json   # release, simulator name, output_dir, trigger/CPU settings
  build.sh      # optional; runs in Docker with EXP_IN and EXP_OUT
  exp.c         # or poc.c / prebuilt exp

simulators/kernelctf/
  config.json   # shared core/releases/rootfs/flag/plugin_config paths
  prepare.sh    # downloads missing kernelCTF assets into this project
  core/         # shared initramfs template
  releases/     # shared bzImage directories
  rootfs_v3.img
  ramdisk_v1.img
  flag
  plugin_config.json
```

Cases should reference reusable simulator manifests, e.g. `"simulator":
"kernelctf"`, instead of carrying a private simulator copy. The script copies
the shared simulator `core/` into a container-local overlay, installs the
case PoC as `/bin/exp`, rebuilds `ramdisk_v1`, starts QEMU with
`isolcpus=1 nohz_full=1 rcu_nocbs=1 irqaffinity=0`, and collects a kernel-only
CPU1 trace after the user `_start` trigger. The serial log is written to
`<trace>.serial`.

To populate the reusable simulator from kernelCTF storage without relying on an
external checkout:

```bash
cd simulators/kernelctf
./prepare.sh mitigation-v4-6.6
# Optional manual boot, matching the kernelCTF helper:
./prepare.sh mitigation-v4-6.6 --run
./prepare.sh mitigation-v4-6.6 --root --run
```

## Run

```bash
cargo run -- klancet <trace> <config.json> <output_dir> --trace-format auto
```
