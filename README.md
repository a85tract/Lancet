# QLancet

A clean rewrite of QLancet's trace analyzer based on the Lancet ownership model.

## One-shot: collect and analyze a case

Use `get_trace.sh` to build/run inside a disposable Docker container and remove
the container automatically when QEMU exits. For the built-in CVE case:

```bash
./get_trace.sh cve39682
./analyzer.sh cve39682
```

Run `./get_trace.sh` or `./analyzer.sh` without arguments to list supported
cases discovered under `cases/*/config.json`.

The trace is written to `qemu_tcg/traces/cve39682.qlt`, the serial log to
`qemu_tcg/traces/cve39682.qlt.serial`, and analyzer output to
`out/cve39682/summary.json`.

For direct/custom collection, enable config generation and pass the generated
config to `analyzer.sh`:

```bash
AUTO_CONFIG=1 ./get_trace.sh mitigation-v4-6.6 qlt ./cases/cve39682/exp.c ./out/cve39682.qlt
./analyzer.sh ./out/cve39682.qlt ./out/cve39682.qlt.analyzer_config.json ./out/cve39682 qlt
```

Case runs default to `auto_config=true`. `get_trace.sh` downloads the release
`vmlinux.gz` when needed and generates:

```text
cases/<case>/generated/<release>/analyzer_config.json
cases/<case>/generated/<release>/qemu_config.json
```

The generated QEMU config is used for value probes; the generated analyzer
config is consumed by `analyzer.sh`. Use `REGENERATE_CONFIG=1` with either
script to force regeneration.

## Case and simulator layout

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

## Build and test

```bash
cargo build
cargo test --verbose
```

## Trace formats

- `qlt`: compact binary trace (`QLT1`) with block-level zstd compression and a tail block index.
- `legacy`: compatible with the old `cpu|pc|asm|bytecode|regs:` text trace.
- `auto`: detect QLT by magic, otherwise parse legacy text.

The analyzer processes traces in streaming mode, so QLT blocks are decompressed
and analyzed one at a time instead of materializing the whole trace in memory.

## Analyzer CLI

The wrapper resolves case paths and generated configs:

```bash
./analyzer.sh <case-name-or-dir> [out-dir]
./analyzer.sh <trace> <config.json> [out-dir] [trace-format]
```

The underlying Rust command remains:

```bash
cargo run -- klancet <trace> <config.json> <output_dir> --trace-format auto
```

## QEMU TCG plugin

The full plugin lives in `qemu_tcg/hello.c` and writes QLT by default.
For lower-level kernelCTF-style collection use
`qemu_tcg/collect_kernel_trace.sh`; it writes QLT directly and does not need the
old telnet monitor/logfile step.

```bash
docker build -t a85_qlancet_qemu -f Dockerfile .
./run_qemu_tcg_docker.sh
# inside the container:
cd /qemu/contrib/plugins/test/qemu_tcg
./build.sh
```
