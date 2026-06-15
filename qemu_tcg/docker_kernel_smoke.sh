#!/usr/bin/env bash
# Build the plugin in the QEMU-plugin Docker image and run a bounded kernelCTF
# smoke trace against an existing simulator directory.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: docker_kernel_smoke.sh [release-name] [out.qlt]

Environment:
  IMAGE=a85_qlancet_qemu                         Docker image with plugin-enabled QEMU.
  SIM_DIR=/home/ubuntu/aixcc/QLancet/qemu_tcg/simulator
  TIMEOUT=120                                    QEMU timeout seconds.
  SMOKE_TRIGGER=reset                            Fast reset-vector smoke; use exp for _start.
  INIT=/bin/exp                                  Non-interactive guest init for smoke.
  ONLYCPU=0                                      PID 1 /bin/exp and reset run on CPU0.
  PC_FROM_REG=0                                  reset smoke uses translated PC; exp uses RIP.
  TRACE_SMOKE=1                                  Use one-instruction smoke trace.
  QLT_BLOCK_MB=1 QLT_ZSTD=1                      Small/fast smoke defaults.
  SERIAL_LOG=<out>.serial                        Redirect guest serial output.

Example:
  IMAGE=test_q ./qemu_tcg/docker_kernel_smoke.sh lts-6.1.70 /tmp/a85_kernel_smoke.qlt
USAGE
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  usage
  exit 0
fi

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
IMAGE=${IMAGE:-a85_qlancet_qemu}
SIM_DIR=${SIM_DIR:-/home/ubuntu/aixcc/QLancet/qemu_tcg/simulator}
RELEASE=${1:-lts-6.1.70}
OUT=${2:-/tmp/a85_kernel_smoke/$RELEASE.qlt}
OUT_DIR=$(mkdir -p "$(dirname "$OUT")" && cd "$(dirname "$OUT")" && pwd)
OUT_BASE=$(basename "$OUT")
TIMEOUT=${TIMEOUT:-120}
TRACE_SMOKE=${TRACE_SMOKE:-1}
SMOKE_TRIGGER=${SMOKE_TRIGGER:-reset}
INIT=${INIT:-/bin/exp}
ONLYCPU=${ONLYCPU:-0}
START_ADDR=${START_ADDR:-}
case "$SMOKE_TRIGGER" in
  reset)
    START_ADDR=${START_ADDR:-0xfffffff0}
    PC_FROM_REG=${PC_FROM_REG:-0}
    ;;
  exp)
    PC_FROM_REG=${PC_FROM_REG:-1}
    ;;
  *)
    echo "unsupported SMOKE_TRIGGER=$SMOKE_TRIGGER (expected reset or exp)" >&2
    exit 2
    ;;
esac
QLT_BLOCK_MB=${QLT_BLOCK_MB:-1}
QLT_ZSTD=${QLT_ZSTD:-1}
SERIAL_LOG=${SERIAL_LOG:-/out/$OUT_BASE.serial}

if [[ ! -d "$SIM_DIR" ]]; then
  echo "missing simulator dir: $SIM_DIR" >&2
  exit 1
fi

DOCKER=${DOCKER:-docker}
if ! command -v "$DOCKER" >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1; then
  DOCKER="sudo docker"
fi

# Keep the apt install conditional: the legacy test_q image has qemu-plugin.h
# but may not have zstd.h, while this repo's Dockerfile already includes it.
exec $DOCKER run --rm --network host --security-opt seccomp=unconfined \
  -v "$ROOT_DIR":/work/a85 \
  -v "$SIM_DIR":/sim \
  -v "$OUT_DIR":/out \
  -e TIMEOUT="$TIMEOUT" \
  -e TRACE_SMOKE="$TRACE_SMOKE" \
  -e QLT_BLOCK_MB="$QLT_BLOCK_MB" \
  -e INIT="$INIT" \
  -e ONLYCPU="$ONLYCPU" \
  -e PC_FROM_REG="$PC_FROM_REG" \
  -e START_ADDR="$START_ADDR" \
  -e QLT_ZSTD="$QLT_ZSTD" \
  -e SERIAL_LOG="$SERIAL_LOG" \
  -e RELEASE="$RELEASE" \
  -e OUT_BASE="$OUT_BASE" \
  "$IMAGE" bash -lc '
    set -euo pipefail
    if ! printf "#include <zstd.h>\n" | gcc -E - >/dev/null 2>&1; then
      apt-get update
      apt-get install -y libzstd-dev
    fi
    cd /work/a85/qemu_tcg
    ./build.sh
    start_args=()
    if [[ -n "$START_ADDR" ]]; then
      start_args=(--start "$START_ADDR")
    fi
    PC_FROM_REG="$PC_FROM_REG" ./collect_kernel_trace.sh --smoke --timeout "$TIMEOUT" --init "$INIT" "${start_args[@]}" /sim "$RELEASE" "/out/$OUT_BASE"
  '
