#!/usr/bin/env bash
# Collect a QLT trace from a kernelCTF-style QEMU simulator directory.
#
# This replaces the old monitor/logfile workflow: the plugin writes QLT directly
# through out=..., so no telnet monitor or `log plugin` step is needed.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: collect_kernel_trace.sh [options] <sim-dir> <release-name> <out.qlt>

Arguments:
  sim-dir       Directory containing releases/, rootfs_v3.img, ramdisk_v1, flag, core/exp.
  release-name Name under <sim-dir>/releases, e.g. lts-6.1.70.
  out.qlt      QLT output path written by the QEMU plugin.

Options:
  --plugin PATH       QEMU plugin .so (default: ./hello.so next to this script).
  --config PATH       Plugin value-probe config (default: <sim-dir>/config.json if present).
  --flag PATH         Virtio flag drive (default: <sim-dir>/flag).
  --init PATH         Guest init command (default: /home/user/run.sh).
  --start ADDR        Trigger address (default: _start from <sim-dir>/core/exp).
  --stop ADDR         Stop address. In --smoke mode defaults to start address.
  --smoke             One-instruction smoke trace: trigger=start, stop=start, from=to=start.
  --timeout SEC       Kill QEMU after SEC seconds (default: no timeout). Env TIMEOUT also works.
  --no-snapshot       Do not add snapshot=on to the rootfs drive.
  -h, --help          Show this help.

Environment knobs:
  QEMU_BIN=qemu-system-x86_64  MEMORY=3.5G  SMP=2  QLT_BLOCK_MB=16  QLT_ZSTD=3
  PLUGIN_MODE=user|kernel|all  ONLYCPU=1  PC_FROM_REG=0|1  EXTRA_PLUGIN_ARGS='proc=exp,...'
  SERIAL_LOG=/tmp/qemu.serial.log  EXTRA_QEMU_ARGS='...'  TRACE_SMOKE=1

Notes:
  * The default PLUGIN_MODE=user matches the old QLancet simulator flow: boot a
    kernel but collect the exploit/user process trace starting at core/exp::_start.
  * In system-mode QEMU, guest user virtual PCs may require PC_FROM_REG=1; this
    is slower because RIP is sampled at runtime. The fast smoke path normally
    uses --start 0xfffffff0 with ONLYCPU=0 and PC_FROM_REG=0.
  * For true kernel-address tracing, set PLUGIN_MODE=kernel and provide a kernel
    --start/--stop or addrfile/range through EXTRA_PLUGIN_ARGS.
USAGE
}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PLUGIN="$SCRIPT_DIR/hello.so"
CONFIG=""
FLAG=""
INIT="/home/user/run.sh"
START_ADDR=""
STOP_ADDR=""
SMOKE="${TRACE_SMOKE:-0}"
TIMEOUT_SEC="${TIMEOUT:-0}"
SNAPSHOT=1

ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --plugin) PLUGIN=${2:?missing --plugin value}; shift 2;;
    --config) CONFIG=${2:?missing --config value}; shift 2;;
    --flag) FLAG=${2:?missing --flag value}; shift 2;;
    --init) INIT=${2:?missing --init value}; shift 2;;
    --start) START_ADDR=${2:?missing --start value}; shift 2;;
    --stop) STOP_ADDR=${2:?missing --stop value}; shift 2;;
    --smoke) SMOKE=1; shift;;
    --timeout) TIMEOUT_SEC=${2:?missing --timeout value}; shift 2;;
    --no-snapshot) SNAPSHOT=0; shift;;
    -h|--help) usage; exit 0;;
    --) shift; while [[ $# -gt 0 ]]; do ARGS+=("$1"); shift; done;;
    -*) echo "Unknown option: $1" >&2; usage >&2; exit 2;;
    *) ARGS+=("$1"); shift;;
  esac
done

if [[ ${#ARGS[@]} -ne 3 ]]; then
  usage >&2
  exit 2
fi

SIM_DIR=$(cd "${ARGS[0]}" && pwd)
RELEASE_NAME=${ARGS[1]}
OUT_PATH=${ARGS[2]}
RELEASE_DIR="$SIM_DIR/releases/$RELEASE_NAME"
KERNEL="$RELEASE_DIR/bzImage"
RAMDISK="$SIM_DIR/ramdisk_v1"
ROOTFS="$SIM_DIR/rootfs_v3.img"
EXP="$SIM_DIR/core/exp"
CONFIG=${CONFIG:-$SIM_DIR/config.json}
FLAG=${FLAG:-$SIM_DIR/flag}

for required in "$PLUGIN" "$KERNEL" "$RAMDISK" "$ROOTFS" "$EXP" "$FLAG"; do
  if [[ ! -e "$required" ]]; then
    echo "missing required file: $required" >&2
    exit 1
  fi
done
if [[ ! -f "$CONFIG" ]]; then
  echo "warning: config not found, running without value probes: $CONFIG" >&2
  CONFIG=""
fi
mkdir -p "$(dirname "$OUT_PATH")"

normalize_addr() {
  local v=$1
  # Accept 0x... or plain hex. Preserve full-width kernel addresses.
  if [[ "$v" =~ ^0[xX][0-9a-fA-F]+$ ]]; then
    printf '0x%x' "$((v))"
  elif [[ "$v" =~ ^[0-9a-fA-F]+$ ]]; then
    printf '0x%x' "$((0x$v))"
  else
    echo "invalid address: $v" >&2
    exit 1
  fi
}

if [[ -z "$START_ADDR" ]]; then
  START_ADDR=$(nm "$EXP" | awk '/ T _start$/ {print $1; found=1} END { if (!found) exit 1 }')
  if [[ -z "$START_ADDR" ]]; then
    echo "failed to resolve _start from $EXP" >&2
    exit 1
  fi
fi
START_ADDR=$(normalize_addr "$START_ADDR")
if [[ "$SMOKE" == "1" && -z "$STOP_ADDR" ]]; then
  STOP_ADDR="$START_ADDR"
elif [[ -n "$STOP_ADDR" ]]; then
  STOP_ADDR=$(normalize_addr "$STOP_ADDR")
fi

QEMU_BIN=${QEMU_BIN:-qemu-system-x86_64}
MEMORY=${MEMORY:-3.5G}
SMP=${SMP:-2}
ONLYCPU=${ONLYCPU:-1}
PLUGIN_MODE=${PLUGIN_MODE:-user}
QLT_BLOCK_MB=${QLT_BLOCK_MB:-16}
QLT_ZSTD=${QLT_ZSTD:-3}
EXTRA_PLUGIN_ARGS=${EXTRA_PLUGIN_ARGS:-}
PC_FROM_REG=${PC_FROM_REG:-0}
EXTRA_QEMU_ARGS=${EXTRA_QEMU_ARGS:-}
SERIAL_LOG=${SERIAL_LOG:-}

HARDENING=""
if [[ "$RELEASE_NAME" == mitigation-v3* ]]; then
  HARDENING="sysctl.kernel.dmesg_restrict=1 sysctl.kernel.kptr_restrict=2 sysctl.kernel.unprivileged_bpf_disabled=2 sysctl.net.core.bpf_jit_harden=1 sysctl.kernel.yama.ptrace_scope=1"
fi

PLUGIN_ARG="format=qlt,out=$OUT_PATH,trigger=$START_ADDR,regs=insn,onlycpu=$ONLYCPU,mode=$PLUGIN_MODE,block-mb=$QLT_BLOCK_MB,zstd=$QLT_ZSTD"
if [[ "$PC_FROM_REG" == "1" ]]; then
  PLUGIN_ARG+=",pc=reg"
fi
if [[ -n "$STOP_ADDR" ]]; then
  PLUGIN_ARG+=",stop=$STOP_ADDR"
fi
if [[ -n "$CONFIG" ]]; then
  PLUGIN_ARG+=",config=$CONFIG"
fi
# For translated-PC smoke tests, this also avoids registering callbacks for
# every instruction before the trigger. With PC_FROM_REG=1, the plugin registers
# broadly and applies this range at runtime after reading the architectural PC.
# Full traces intentionally keep the default wide range so all post-trigger
# instructions are collected.
if [[ "$SMOKE" == "1" ]]; then
  PLUGIN_ARG+=",from=$START_ADDR,to=$START_ADDR"
fi
if [[ -n "$EXTRA_PLUGIN_ARGS" ]]; then
  PLUGIN_ARG+=",$EXTRA_PLUGIN_ARGS"
fi

ROOTFS_DRIVE="file=$ROOTFS,if=virtio,cache=none,aio=native,format=raw,discard=on"
if [[ "$SNAPSHOT" == "1" ]]; then
  ROOTFS_DRIVE+=",snapshot=on"
fi

APPEND="console=ttyS0 nokaslr root=/dev/vda1 rootfstype=ext4 rootflags=discard rw $HARDENING init=$INIT hostname=$RELEASE_NAME isolcpus=1 nohz_full=1 rcu_nocbs=1 irqaffinity=0 nopti"

META="$OUT_PATH.meta"
{
  echo "sim_dir=$SIM_DIR"
  echo "release=$RELEASE_NAME"
  echo "kernel=$KERNEL"
  echo "plugin=$PLUGIN"
  echo "out=$OUT_PATH"
  echo "start=$START_ADDR"
  echo "stop=$STOP_ADDR"
  echo "smoke=$SMOKE"
  echo "plugin_arg=$PLUGIN_ARG"
  echo "append=$APPEND"
} > "$META"

echo "[*] release: $RELEASE_NAME"
echo "[*] start addr: $START_ADDR"
if [[ -n "$STOP_ADDR" ]]; then echo "[*] stop addr: $STOP_ADDR"; fi
echo "[*] out: $OUT_PATH"
echo "[*] meta: $META"

CMD=(
  "$QEMU_BIN" -m "$MEMORY" -nographic -no-reboot
  -cpu max -smp "cores=$SMP"
  -monitor none
  -kernel "$KERNEL"
  -initrd "$RAMDISK"
  -plugin "$PLUGIN,$PLUGIN_ARG"
  -nic user,model=virtio-net-pci
  -drive "$ROOTFS_DRIVE"
  -drive "file=$FLAG,if=virtio,format=raw,readonly=on"
  -append "$APPEND"
  -s
)

if [[ -n "$SERIAL_LOG" ]]; then
  mkdir -p "$(dirname "$SERIAL_LOG")"
  CMD+=(-serial "file:$SERIAL_LOG")
  echo "serial_log=$SERIAL_LOG" >> "$META"
fi

if [[ -n "$EXTRA_QEMU_ARGS" ]]; then
  # shellcheck disable=SC2206 # Deliberately allow callers to pass a shell-split list.
  EXTRA_QEMU_ARR=($EXTRA_QEMU_ARGS)
  CMD+=("${EXTRA_QEMU_ARR[@]}")
fi

if [[ "$TIMEOUT_SEC" != "0" && "$TIMEOUT_SEC" != "" ]]; then
  exec timeout --kill-after=10s "${TIMEOUT_SEC}s" "${CMD[@]}"
else
  exec "${CMD[@]}"
fi
