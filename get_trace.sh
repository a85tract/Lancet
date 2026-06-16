#!/usr/bin/env bash
# One-shot Docker wrapper for collecting QLancet QEMU traces.
#
# Example:
#   ./get_trace.sh mitigation-v4-6.6 qlt ./poc.c ./out/poc.qlt
#
# The container is started with --rm and a per-run name; it is removed
# automatically when collection finishes or this wrapper is interrupted.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)

list_supported_cases() {
  local cases_dir=${CASES_DIR:-$ROOT_DIR/cases}
  if [[ -f "$ROOT_DIR/scripts/list_cases.py" ]]; then
    python3 "$ROOT_DIR/scripts/list_cases.py" "$cases_dir" "$ROOT_DIR" || true
  else
    echo "Supported cases:"
    find "$cases_dir" -mindepth 2 -maxdepth 2 -name config.json -printf '  %h\n' 2>/dev/null | sed "s#^  $cases_dir/#  #" || true
  fi
}

usage() {
  cat <<'USAGE'
Usage:
  ./get_trace.sh <case-name-or-dir>
  ./get_trace.sh <linux-kernel-version> <trace-format> <exp-path> <trace-path> [sim-dir]

Arguments:
  case-name-or-dir      Case under ./cases or a direct case directory containing config.json.
  linux-kernel-version  Release directory under simulator/releases, e.g. mitigation-v4-6.6.
  trace-format          qlt or text. qlt is the normal binary QLT format.
  exp-path              PoC source (.c, compiled static in Docker) or executable to place at /bin/exp.
  trace-path            Host output trace path. Serial log is written to <trace-path>.serial.
  sim-dir               Optional legacy simulator dir or simulator name.

Common environment overrides:
  IMAGE=a85_qlancet_qemu           Docker image name.
  BUILD_IMAGE=auto|1|0             Build Dockerfile if missing (default: auto).
  DOCKERFILE=./Dockerfile          Dockerfile used when building IMAGE.
  TIMEOUT=900                      QEMU timeout seconds.
  TRACE_CPU=1                      Guest CPU to trace.
  TASKSET_MASK=0x2                 CPU mask for running /bin/exp.
  FIFO_PRIO=99                     chrt FIFO priority.
  START_ADDR=0x...                 Override trigger address; default resolves exp::_start.
  START_SYMBOL=name                Resolve trigger from this symbol when START_ADDR is unset.
  STOP_ADDR=0x...                  Optional stop address to disarm tracing.
  STOP_SYMBOL=name                 Resolve stop address from this symbol when STOP_ADDR is unset.
  EXP_KIND=auto|c|bin              How to handle exp-path (default: auto).
  EXP_CFLAGS='...' EXP_LDFLAGS='...'  Extra flags for default .c compilation.
  EXP_BUILD_CMD='...'              Custom build command; uses EXP_IN and EXP_OUT variables.
  DOCKER_NETWORK=none              Docker network mode; use host if the PoC needs host networking.

Case config keys:
  release, trace_format, exp, build, simulator, output_dir, trace/trace_path,
  timeout, trace_cpu, taskset_mask, fifo_prio, analyzer_config, qemu_config,
  plugin_config, auto_config, start_addr, start_symbol.
  stop_addr and stop_symbol are also supported for bounded user-mode traces.
  Relative paths are resolved from the case directory.

Simulator manifests live under ./simulators/<name>/config.json and point to
shared core/, releases/, rootfs, flag, and plugin config assets.

Default collection policy:
  user-space _start trigger, kernel-only trace, regs=insn, only CPU1, zstd QLT blocks.
USAGE
  echo
  list_supported_cases
}

die() {
  echo "error: $*" >&2
  exit 1
}

abs_file() {
  local p=$1
  [[ -e "$p" ]] || die "missing path: $p"
  if command -v readlink >/dev/null 2>&1; then
    readlink -f "$p"
    return
  fi
  local d b
  d=$(dirname "$p")
  b=$(basename "$p")
  d=$(cd "$d" && pwd -P)
  printf '%s/%s\n' "$d" "$b"
}

abs_dir() {
  local p=$1
  [[ -d "$p" ]] || die "missing directory: $p"
  (cd "$p" && pwd -P)
}

set_env_default() {
  local k=$1
  local v=$2
  if [[ -n "$v" && -z "${!k+x}" ]]; then
    export "$k=$v"
  fi
}

truthy() {
  case "${1,,}" in
    1|true|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
}

resolve_simulator() {
  local ref=${1:-}
  local manifest=""

  if [[ -z "$ref" ]]; then
    if [[ -n "${SIMULATOR:-}" ]]; then
      ref=$SIMULATOR
    elif [[ -n "${SIM_DIR:-}" ]]; then
      ref=$SIM_DIR
    elif [[ -f "$ROOT_DIR/simulators/kernelctf/config.json" ]]; then
      ref=kernelctf
    else
      die "no simulator configured; set SIMULATOR/SIM_DIR or add simulators/<name>/config.json"
    fi
  fi

  if [[ -f "$ROOT_DIR/simulators/$ref/config.json" ]]; then
    manifest="$ROOT_DIR/simulators/$ref/config.json"
  elif [[ -f "$ref" ]]; then
    manifest=$(abs_file "$ref")
  elif [[ -d "$ref" ]]; then
    # A legacy simulator directory contains all assets directly. Do not treat
    # its plugin config.json as a simulator manifest.
    if [[ -d "$ref/core" && -d "$ref/releases" && -e "$ref/rootfs_v3.img" ]]; then
      SIM_DESC=$(abs_dir "$ref")
      CORE_DIR=$(abs_dir "$SIM_DESC/core")
      RELEASES_DIR=$(abs_dir "$SIM_DESC/releases")
      ROOTFS_PATH=$(abs_file "$SIM_DESC/rootfs_v3.img")
      FLAG_PATH=$(abs_file "$SIM_DESC/flag")
      CONFIG_PATH=""
      if [[ -e "$SIM_DESC/config.json" ]]; then
        CONFIG_PATH=$(abs_file "$SIM_DESC/config.json")
      fi
      return
    elif [[ -f "$ref/config.json" ]]; then
      manifest=$(abs_file "$ref/config.json")
    else
      die "invalid simulator directory: $ref"
    fi
  elif [[ -f "$ROOT_DIR/simulators/$ref.json" ]]; then
    manifest="$ROOT_DIR/simulators/$ref.json"
  else
    die "simulator not found: $ref"
  fi

  eval "$(
    python3 - "$manifest" <<'PY'
import json
import os
import shlex
import sys

manifest = os.path.abspath(sys.argv[1])
base = os.path.dirname(manifest)
with open(manifest, "r", encoding="utf-8") as f:
    cfg = json.load(f)

def first(*names, default=""):
    for name in names:
        if name in cfg and cfg[name] is not None:
            return cfg[name]
    return default

def path_value(value):
    if value in (None, ""):
        return ""
    value = str(value)
    if os.path.isabs(value):
        return os.path.normpath(value)
    return os.path.normpath(os.path.join(base, value))

values = {
    "SIM_DESC": first("name", default=os.path.basename(base)),
    "SIM_PREPARE_PATH": path_value(first("prepare", "prepare_script")),
    "SIM_CORE_DIR": path_value(first("core", "core_dir")),
    "SIM_RELEASES_DIR": path_value(first("releases", "releases_dir")),
    "SIM_ROOTFS_PATH": path_value(first("rootfs", "rootfs_img", "rootfs_v3")),
    "SIM_RAMDISK_PATH": path_value(first("ramdisk", "ramdisk_img", "ramdisk_v1")),
    "SIM_FLAG_PATH": path_value(first("flag", "flag_path")),
    "SIM_CONFIG_PATH": path_value(first("plugin_config", "qlt_config", "config_path", "config")),
}
missing = [k for k, v in values.items() if k not in ("SIM_DESC", "SIM_PREPARE_PATH", "SIM_RAMDISK_PATH", "SIM_CONFIG_PATH") and not v]
if missing:
    raise SystemExit("simulator manifest missing keys: " + ", ".join(missing))
for key, value in values.items():
    print(f"{key}={shlex.quote(str(value))}")
PY
  )"

  if [[ -n "${SIM_PREPARE_PATH:-}" ]]; then
    if [[ ! -d "$SIM_CORE_DIR" ||
          ! -d "$SIM_RELEASES_DIR" ||
          ! -f "$SIM_RELEASES_DIR/$RELEASE/bzImage" ||
          ! -f "$SIM_ROOTFS_PATH" ||
          ! -f "$SIM_FLAG_PATH" ]]; then
      echo "[*] preparing simulator assets via $SIM_PREPARE_PATH"
      bash "$SIM_PREPARE_PATH" "$RELEASE"
    fi
  fi

  CORE_DIR=$(abs_dir "$SIM_CORE_DIR")
  RELEASES_DIR=$(abs_dir "$SIM_RELEASES_DIR")
  ROOTFS_PATH=$(abs_file "$SIM_ROOTFS_PATH")
  FLAG_PATH=$(abs_file "$SIM_FLAG_PATH")
  CONFIG_PATH=""
  if [[ -n "${SIM_CONFIG_PATH:-}" ]]; then
    CONFIG_PATH=$(abs_file "$SIM_CONFIG_PATH")
  fi
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  usage
  exit 0
fi

CASE_MODE=0
if [[ $# -eq 1 ]]; then
  CASE_MODE=1
  CASE_ARG=$1
  CASES_DIR=${CASES_DIR:-$ROOT_DIR/cases}
  if [[ -d "$CASE_ARG" ]]; then
    CASE_DIR=$(abs_dir "$CASE_ARG")
  elif [[ -d "$CASES_DIR/$CASE_ARG" ]]; then
    CASE_DIR=$(abs_dir "$CASES_DIR/$CASE_ARG")
  else
    die "case not found: $CASE_ARG (looked in $CASES_DIR)"
  fi
  CASE_JSON=${CASE_CONFIG:-$CASE_DIR/config.json}
  [[ -f "$CASE_JSON" ]] || die "missing case config: $CASE_JSON"

  eval "$(
    python3 - "$CASE_JSON" "$CASE_DIR" <<'PY'
import json
import os
import shlex
import sys

cfg_path, case_dir = sys.argv[1], sys.argv[2]
with open(cfg_path, "r", encoding="utf-8") as f:
    cfg = json.load(f)

def first(*names, default=""):
    for name in names:
        if name in cfg and cfg[name] is not None:
            return cfg[name]
    return default

def path_value(value):
    if value in (None, ""):
        return ""
    value = str(value)
    if os.path.isabs(value):
        return os.path.normpath(value)
    return os.path.normpath(os.path.join(case_dir, value))

def ref_value(value):
    """Simulator references may be names (kernelctf) or paths."""
    if value in (None, ""):
        return ""
    value = str(value)
    if os.path.isabs(value) or value.startswith(".") or "/" in value:
        return path_value(value)
    return value

case_name = first("name", default=os.path.basename(case_dir))
release = first("release", "linux_kernel_version", "kernel")
if not release:
    raise SystemExit("case config requires 'release'")
fmt = first("trace_format", "format", default="qlt")

exp = first("exp", "exp_path", "poc")
if not exp:
    for candidate in ("exp.c", "poc.c", "exp"):
        if os.path.exists(os.path.join(case_dir, candidate)):
            exp = candidate
            break
if not exp:
    raise SystemExit("case config requires 'exp' or an exp.c/poc.c file")
exp_path = path_value(exp)

trace_path = first("trace_path", "out", "output")
if trace_path:
    trace_path = path_value(trace_path)
else:
    output_dir = path_value(first("output_dir", "trace_dir", default="out"))
    trace_name = first("trace", "trace_name", default=f"{case_name}.{fmt}")
    trace_path = os.path.normpath(os.path.join(output_dir, str(trace_name)))

build = first("build", "build_script")
build_rel = ""
if build:
    build_path = path_value(build)
    exp_dir = os.path.dirname(exp_path)
    try:
        common = os.path.commonpath([os.path.abspath(build_path), os.path.abspath(exp_dir)])
    except ValueError:
        common = ""
    if common != os.path.abspath(exp_dir):
        raise SystemExit("case build script must live in the same directory as exp or below it")
    build_rel = os.path.relpath(build_path, exp_dir)

values = {
    "CASE_RELEASE": release,
    "CASE_TRACE_FORMAT": fmt,
    "CASE_EXP_PATH": exp_path,
    "CASE_TRACE_PATH": trace_path,
    "CASE_SIM_REF": ref_value(first("simulator", "sim", "sim_dir", "simulator_dir")),
    "CASE_ANALYZER_CONFIG": path_value(first("analyzer_config", "qlancet_config")),
    "CASE_QEMU_CONFIG": path_value(first("qemu_config", "qemu_output")),
    "CASE_AUTO_CONFIG": first("auto_config", default="1"),
    "CASE_BUILD_REL": build_rel,
    "CASE_PLUGIN_CONFIG": path_value(first("plugin_config", "qlt_config")),
    "CASE_TIMEOUT": first("timeout"),
    "CASE_TRACE_CPU": first("trace_cpu", "cpu"),
    "CASE_TASKSET_MASK": first("taskset_mask"),
    "CASE_FIFO_PRIO": first("fifo_prio"),
    "CASE_START_ADDR": first("start_addr", "trigger"),
    "CASE_START_SYMBOL": first("start_symbol", "trigger_symbol"),
    "CASE_STOP_ADDR": first("stop_addr", "stop"),
    "CASE_STOP_SYMBOL": first("stop_symbol"),
    "CASE_QEMU_BIN": first("qemu_bin"),
    "CASE_MEMORY": first("memory"),
    "CASE_SMP": first("smp"),
    "CASE_QLT_BLOCK_MB": first("qlt_block_mb", "block_mb"),
    "CASE_QLT_ZSTD": first("qlt_zstd", "zstd"),
    "CASE_PLUGIN_MODE": first("plugin_mode"),
    "CASE_TRIGGER_MODE": first("trigger_mode"),
    "CASE_TRIGGER_PC_FROM_REG": first("trigger_pc_from_reg"),
    "CASE_TRIGGER_ONLYCPU": first("trigger_onlycpu"),
    "CASE_TRIGGER_WINDOW": first("trigger_window"),
    "CASE_EXTRA_PLUGIN_ARGS": first("extra_plugin_args"),
    "CASE_EXTRA_QEMU_ARGS": first("extra_qemu_args"),
    "CASE_DOCKER_NETWORK": first("docker_network"),
}
for key, value in values.items():
    if isinstance(value, bool):
        value = "1" if value else "0"
    elif value is None:
        value = ""
    else:
        value = str(value)
    print(f"{key}={shlex.quote(value)}")
PY
  )"

  set_env_default TIMEOUT "$CASE_TIMEOUT"
  set_env_default TRACE_CPU "$CASE_TRACE_CPU"
  set_env_default TASKSET_MASK "$CASE_TASKSET_MASK"
  set_env_default FIFO_PRIO "$CASE_FIFO_PRIO"
  set_env_default START_ADDR "$CASE_START_ADDR"
  set_env_default START_SYMBOL "$CASE_START_SYMBOL"
  set_env_default STOP_ADDR "$CASE_STOP_ADDR"
  set_env_default STOP_SYMBOL "$CASE_STOP_SYMBOL"
  set_env_default AUTO_CONFIG "$CASE_AUTO_CONFIG"
  set_env_default ANALYZER_CONFIG "$CASE_ANALYZER_CONFIG"
  set_env_default QEMU_CONFIG "$CASE_QEMU_CONFIG"
  set_env_default PLUGIN_CONFIG "$CASE_PLUGIN_CONFIG"
  set_env_default QEMU_BIN "$CASE_QEMU_BIN"
  set_env_default MEMORY "$CASE_MEMORY"
  set_env_default SMP "$CASE_SMP"
  set_env_default QLT_BLOCK_MB "$CASE_QLT_BLOCK_MB"
  set_env_default QLT_ZSTD "$CASE_QLT_ZSTD"
  set_env_default PLUGIN_MODE "$CASE_PLUGIN_MODE"
  set_env_default TRIGGER_MODE "$CASE_TRIGGER_MODE"
  set_env_default TRIGGER_PC_FROM_REG "$CASE_TRIGGER_PC_FROM_REG"
  set_env_default TRIGGER_ONLYCPU "$CASE_TRIGGER_ONLYCPU"
  set_env_default TRIGGER_WINDOW "$CASE_TRIGGER_WINDOW"
  set_env_default EXTRA_PLUGIN_ARGS "$CASE_EXTRA_PLUGIN_ARGS"
  set_env_default EXTRA_QEMU_ARGS "$CASE_EXTRA_QEMU_ARGS"
  set_env_default DOCKER_NETWORK "$CASE_DOCKER_NETWORK"

  if [[ -n "$CASE_BUILD_REL" && -z "${EXP_BUILD_CMD+x}" ]]; then
    build_exec=$CASE_BUILD_REL
    if [[ "$build_exec" != */* ]]; then
      build_exec="./$build_exec"
    fi
    printf -v build_exec_q '%q' "$build_exec"
    export EXP_BUILD_CMD="cd \"\$(dirname \"\$EXP_IN\")\" && bash $build_exec_q"
  fi

  if [[ -n "$CASE_SIM_REF" ]]; then
    set -- "$CASE_RELEASE" "$CASE_TRACE_FORMAT" "$CASE_EXP_PATH" "$CASE_TRACE_PATH" "$CASE_SIM_REF"
  else
    set -- "$CASE_RELEASE" "$CASE_TRACE_FORMAT" "$CASE_EXP_PATH" "$CASE_TRACE_PATH"
  fi
fi

if [[ $# -lt 4 || $# -gt 5 ]]; then
  usage >&2
  exit 2
fi

RELEASE=$1
TRACE_FORMAT=$2
EXP_PATH=$(abs_file "$3")
TRACE_PATH=$4

case "$TRACE_FORMAT" in
  qlt|text) ;;
  *) die "unsupported trace-format '$TRACE_FORMAT' (expected qlt or text)" ;;
esac

SIM_REF=""
if [[ $# -eq 5 ]]; then
  SIM_REF=$5
fi

TRACE_DIR=$(dirname "$TRACE_PATH")
TRACE_BASE=$(basename "$TRACE_PATH")
mkdir -p "$TRACE_DIR"
TRACE_DIR=$(cd "$TRACE_DIR" && pwd -P)
TRACE_PATH="$TRACE_DIR/$TRACE_BASE"

resolve_simulator "$SIM_REF"

AUTO_CONFIG=${AUTO_CONFIG:-}
if [[ -z "$AUTO_CONFIG" ]]; then
  if [[ "$CASE_MODE" == "1" ]]; then
    AUTO_CONFIG=1
  else
    AUTO_CONFIG=0
  fi
fi

ANALYZER_CONFIG=${ANALYZER_CONFIG:-}
QEMU_CONFIG=${QEMU_CONFIG:-}
if truthy "$AUTO_CONFIG"; then
  if [[ -z "$ANALYZER_CONFIG" ]]; then
    if [[ -n "${CASE_DIR:-}" ]]; then
      ANALYZER_CONFIG="$CASE_DIR/generated/$RELEASE/analyzer_config.json"
    else
      ANALYZER_CONFIG="$TRACE_PATH.analyzer_config.json"
    fi
  fi
  if [[ -z "$QEMU_CONFIG" ]]; then
    if [[ -n "${CASE_DIR:-}" ]]; then
      QEMU_CONFIG="$CASE_DIR/generated/$RELEASE/qemu_config.json"
    else
      QEMU_CONFIG="$TRACE_PATH.qemu_config.json"
    fi
  fi
  ANALYZER_CONFIG=$(mkdir -p "$(dirname "$ANALYZER_CONFIG")" && cd "$(dirname "$ANALYZER_CONFIG")" && pwd -P)/$(basename "$ANALYZER_CONFIG")
  QEMU_CONFIG=$(mkdir -p "$(dirname "$QEMU_CONFIG")" && cd "$(dirname "$QEMU_CONFIG")" && pwd -P)/$(basename "$QEMU_CONFIG")
  if [[ "${REGENERATE_CONFIG:-0}" == "1" || ! -s "$ANALYZER_CONFIG" || ! -s "$QEMU_CONFIG" ]]; then
    echo "[*] generating analyzer/qemu configs for $RELEASE"
    python3 "$ROOT_DIR/scripts/gen_config.py" \
      --kernel "$RELEASE" \
      --releases-dir "$RELEASES_DIR" \
      --qlancet-output "$ANALYZER_CONFIG" \
      --qemu-output "$QEMU_CONFIG"
  fi
  CONFIG_PATH="$QEMU_CONFIG"
fi

if [[ -n "${PLUGIN_CONFIG:-}" ]]; then
  CONFIG_PATH=$(abs_file "$PLUGIN_CONFIG")
fi

[[ -f "$RELEASES_DIR/$RELEASE/bzImage" ]] || die "missing kernel: $RELEASES_DIR/$RELEASE/bzImage"

EXP_DIR=$(dirname "$EXP_PATH")
EXP_BASE=$(basename "$EXP_PATH")
ROOTFS_DIR=$(dirname "$ROOTFS_PATH")
ROOTFS_BASE=$(basename "$ROOTFS_PATH")
FLAG_DIR=$(dirname "$FLAG_PATH")
FLAG_BASE=$(basename "$FLAG_PATH")
CONFIG_DIR=""
CONFIG_BASE=""
if [[ -n "$CONFIG_PATH" ]]; then
  CONFIG_DIR=$(dirname "$CONFIG_PATH")
  CONFIG_BASE=$(basename "$CONFIG_PATH")
fi

IMAGE=${IMAGE:-a85_qlancet_qemu}
BUILD_IMAGE=${BUILD_IMAGE:-auto}
DOCKERFILE=${DOCKERFILE:-$ROOT_DIR/Dockerfile}
TIMEOUT=${TIMEOUT:-900}
TRACE_CPU=${TRACE_CPU:-1}
TASKSET_MASK=${TASKSET_MASK:-0x2}
FIFO_PRIO=${FIFO_PRIO:-99}
EXP_KIND=${EXP_KIND:-auto}
START_ADDR=${START_ADDR:-}
DOCKER_NETWORK=${DOCKER_NETWORK:-none}
CONTAINER_NAME=${CONTAINER_NAME:-a85_get_trace_$(date +%s)_$$}

case "$EXP_KIND" in
  auto|c|bin) ;;
  *) die "invalid EXP_KIND=$EXP_KIND (expected auto, c, or bin)" ;;
esac

if command -v docker >/dev/null 2>&1; then
  DOCKER_CMD=(docker)
elif command -v sudo >/dev/null 2>&1; then
  DOCKER_CMD=(sudo docker)
else
  die "docker not found"
fi

NEED_BUILD=0
if [[ "$BUILD_IMAGE" == "1" ]]; then
  NEED_BUILD=1
elif [[ "$BUILD_IMAGE" == "auto" ]]; then
  if ! "${DOCKER_CMD[@]}" image inspect "$IMAGE" >/dev/null 2>&1; then
    NEED_BUILD=1
  fi
fi

if [[ "$NEED_BUILD" == "1" ]]; then
  [[ -f "$DOCKERFILE" ]] || die "missing Dockerfile: $DOCKERFILE"
  echo "[*] building Docker image $IMAGE from $DOCKERFILE"
  "${DOCKER_CMD[@]}" build -t "$IMAGE" -f "$DOCKERFILE" "$ROOT_DIR"
fi

cleanup() {
  "${DOCKER_CMD[@]}" rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "[*] release       : $RELEASE"
echo "[*] trace format  : $TRACE_FORMAT"
echo "[*] exp           : $EXP_PATH"
echo "[*] simulator     : $SIM_DESC"
echo "[*] simulator core: $CORE_DIR"
if [[ -n "${ANALYZER_CONFIG:-}" ]]; then
  echo "[*] analyzer cfg  : $ANALYZER_CONFIG"
fi
if [[ -n "${CONFIG_PATH:-}" ]]; then
  echo "[*] qemu cfg      : $CONFIG_PATH"
fi
echo "[*] output        : $TRACE_PATH"
echo "[*] serial        : $TRACE_PATH.serial"
echo "[*] docker image  : $IMAGE"
echo "[*] container     : $CONTAINER_NAME (--rm)"

DOCKER_ARGS=(
  run --rm -i --name "$CONTAINER_NAME"
  --network "$DOCKER_NETWORK"
  --security-opt seccomp=unconfined
  -v "$ROOT_DIR":/work/a85
  -v "$CORE_DIR":/inputs/core:ro
  -v "$RELEASES_DIR":/inputs/releases:ro
  -v "$ROOTFS_DIR":/inputs/rootfs_dir:ro
  -v "$FLAG_DIR":/inputs/flag_dir:ro
  -v "$EXP_DIR":/inputs/exp_dir:ro
  -v "$TRACE_DIR":/out
  -e RELEASE="$RELEASE"
  -e TRACE_FORMAT="$TRACE_FORMAT"
  -e OUT_BASE="$TRACE_BASE"
  -e TIMEOUT="$TIMEOUT"
  -e TRACE_CPU="$TRACE_CPU"
  -e TASKSET_MASK="$TASKSET_MASK"
  -e FIFO_PRIO="$FIFO_PRIO"
  -e EXP_BASE="$EXP_BASE"
  -e EXP_KIND="$EXP_KIND"
  -e ROOTFS_BASE="$ROOTFS_BASE"
  -e FLAG_BASE="$FLAG_BASE"
  -e START_ADDR="$START_ADDR"
  -e START_SYMBOL="${START_SYMBOL:-}"
  -e STOP_ADDR="${STOP_ADDR:-}"
  -e STOP_SYMBOL="${STOP_SYMBOL:-}"
  -e EXP_CFLAGS="${EXP_CFLAGS:-}"
  -e EXP_LDFLAGS="${EXP_LDFLAGS:-}"
  -e EXP_BUILD_CMD="${EXP_BUILD_CMD:-}"
  -e QLT_BLOCK_MB="${QLT_BLOCK_MB:-16}"
  -e QLT_ZSTD="${QLT_ZSTD:-1}"
  -e MEMORY="${MEMORY:-3.5G}"
  -e SMP="${SMP:-2}"
  -e QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
  -e PLUGIN_MODE="${PLUGIN_MODE:-kernel}"
  -e TRIGGER_MODE="${TRIGGER_MODE:-user}"
  -e TRIGGER_PC_FROM_REG="${TRIGGER_PC_FROM_REG:-1}"
  -e TRIGGER_ONLYCPU="${TRIGGER_ONLYCPU:-all}"
  -e TRIGGER_WINDOW="${TRIGGER_WINDOW:-0}"
  -e EXTRA_PLUGIN_ARGS="${EXTRA_PLUGIN_ARGS:-}"
  -e EXTRA_QEMU_ARGS="${EXTRA_QEMU_ARGS:-}"
)

if [[ -n "$CONFIG_PATH" ]]; then
  DOCKER_ARGS+=(-v "$CONFIG_DIR":/inputs/config_dir:ro -e CONFIG_BASE="$CONFIG_BASE")
else
  DOCKER_ARGS+=(-e CONFIG_BASE="")
fi

set +e
"${DOCKER_CMD[@]}" "${DOCKER_ARGS[@]}" "$IMAGE" bash -s <<'IN_CONTAINER'
set -euo pipefail

echo "[container] building QEMU plugin"
cd /work/a85/qemu_tcg
if ! printf '#include <zstd.h>\n' | gcc -E - >/dev/null 2>&1; then
  echo "container image is missing libzstd-dev; rebuild with: BUILD_IMAGE=1 ./get_trace.sh ..." >&2
  exit 1
fi
./build.sh

echo "[container] preparing simulator overlay"
rm -rf /run_sim
mkdir -p /run_sim
cp -a /inputs/core /run_sim/core
ln -s /inputs/releases /run_sim/releases
ln -s "/inputs/rootfs_dir/$ROOTFS_BASE" /run_sim/rootfs_v3.img
ln -s "/inputs/flag_dir/$FLAG_BASE" /run_sim/flag
if [[ -n "${CONFIG_BASE:-}" ]]; then
  ln -s "/inputs/config_dir/$CONFIG_BASE" /run_sim/config.json
fi

EXP_IN="/inputs/exp_dir/$EXP_BASE"
EXP_OUT="/run_sim/core/exp"
if [[ -n "${EXP_BUILD_CMD:-}" ]]; then
  echo "[container] building exp with custom EXP_BUILD_CMD"
  export EXP_IN EXP_OUT
  eval "$EXP_BUILD_CMD"
else
  kind=$EXP_KIND
  if [[ "$kind" == "auto" ]]; then
    case "$EXP_IN" in
      *.c) kind=c ;;
      *) kind=bin ;;
    esac
  fi
  case "$kind" in
    c)
      echo "[container] compiling C PoC -> /run_sim/core/exp"
      # shellcheck disable=SC2086 # EXP_CFLAGS/LDFLAGS are intentionally shell-split.
      gcc -static -no-pie -O0 -g -I"$(dirname "$EXP_IN")" $EXP_CFLAGS "$EXP_IN" -o "$EXP_OUT" $EXP_LDFLAGS
      ;;
    bin)
      echo "[container] copying executable PoC -> /run_sim/core/exp"
      cp "$EXP_IN" "$EXP_OUT"
      ;;
    *)
      echo "invalid EXP_KIND=$kind" >&2
      exit 2
      ;;
  esac
fi
chmod +x "$EXP_OUT"

cat > /run_sim/core/test.sh <<EOS
#!/bin/bash
set -x
echo "[run.sh] cmdline: \$(cat /proc/cmdline 2>/dev/null || true)"
mount -t tmpfs -o size=100M,mode=1777 tmp /tmp || true
ifconfig ens3 10.0.2.15 netmask 255.255.255.0 up || true
ifconfig enp0s3 10.0.2.15 netmask 255.255.255.0 up || true
ifconfig eth0 10.0.2.15 netmask 255.255.255.0 up || true
ifconfig lo 127.0.0.1 netmask 255.0.0.0 up || true
route add default gw 10.0.2.2 || true
cd /
echo "[run.sh] launching exp pinned to CPU$TRACE_CPU mask=$TASKSET_MASK FIFO=$FIFO_PRIO"
if command -v taskset >/dev/null 2>&1 && command -v chrt >/dev/null 2>&1; then
  taskset "$TASKSET_MASK" chrt -f "$FIFO_PRIO" /bin/exp
else
  /bin/exp
fi
rc=\$?
echo "[run.sh] exp exited rc=\$rc"
poweroff -f || reboot -f || halt -f || exit "\$rc"
EOS
chmod +x /run_sim/core/test.sh

if [[ -z "${START_ADDR:-}" ]]; then
  if [[ -n "${START_SYMBOL:-}" ]] && START_ADDR=$(nm "$EXP_OUT" 2>/dev/null | awk -v sym="$START_SYMBOL" '$2 ~ /^[Tt]$/ && $3 == sym {print "0x"$1; found=1} END {exit found ? 0 : 1}'); then
    :
  elif START_ADDR=$(nm "$EXP_OUT" 2>/dev/null | awk '/ T _start$/ {print "0x"$1; found=1} END {exit found ? 0 : 1}'); then
    :
  else
    START_ADDR=$(readelf -h "$EXP_OUT" | awk '/Entry point address:/ {print $4; found=1} END {exit found ? 0 : 1}')
  fi
fi
if [[ -n "${START_SYMBOL:-}" ]]; then
  echo "[container] trigger START_SYMBOL=$START_SYMBOL"
fi
echo "[container] trigger START_ADDR=$START_ADDR"
if [[ -z "${STOP_ADDR:-}" && -n "${STOP_SYMBOL:-}" ]]; then
  if STOP_ADDR=$(nm "$EXP_OUT" 2>/dev/null | awk -v sym="$STOP_SYMBOL" '$2 ~ /^[Tt]$/ && $3 == sym {print "0x"$1; found=1} END {exit found ? 0 : 1}'); then
    :
  else
    echo "failed to resolve STOP_SYMBOL=$STOP_SYMBOL from $EXP_OUT" >&2
    exit 1
  fi
fi
if [[ -n "${STOP_SYMBOL:-}" ]]; then
  echo "[container] stop STOP_SYMBOL=$STOP_SYMBOL"
fi
if [[ -n "${STOP_ADDR:-}" ]]; then
  echo "[container] stop STOP_ADDR=$STOP_ADDR"
fi
echo "[container] exp symbols:"
nm -n "$EXP_OUT" 2>/dev/null | grep -E ' _start$| main$| ql_trace_start$| ql_trace_stop$' || true

echo "[container] rebuilding initramfs"
(cd /run_sim/core && find . | cpio -o --format=newc > /run_sim/ramdisk_v1)

echo "[container] collecting trace"
cd /work/a85/qemu_tcg
STOP_ARGS=()
if [[ -n "${STOP_ADDR:-}" ]]; then
  STOP_ARGS=(--stop "$STOP_ADDR")
fi
TRACE_FORMAT="$TRACE_FORMAT" \
QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}" \
PLUGIN_MODE="${PLUGIN_MODE:-kernel}" \
TRIGGER_MODE="${TRIGGER_MODE:-user}" \
TRIGGER_PC_FROM_REG="${TRIGGER_PC_FROM_REG:-1}" \
TRIGGER_ONLYCPU="${TRIGGER_ONLYCPU:-all}" \
TRIGGER_WINDOW="${TRIGGER_WINDOW:-0}" \
ONLYCPU="$TRACE_CPU" \
QLT_BLOCK_MB="$QLT_BLOCK_MB" \
QLT_ZSTD="$QLT_ZSTD" \
MEMORY="$MEMORY" \
SMP="$SMP" \
EXTRA_PLUGIN_ARGS="$EXTRA_PLUGIN_ARGS" \
EXTRA_QEMU_ARGS="$EXTRA_QEMU_ARGS" \
SERIAL_LOG="/out/$OUT_BASE.serial" \
./collect_kernel_trace.sh --timeout "$TIMEOUT" --start "$START_ADDR" "${STOP_ARGS[@]}" --init /home/user/run.sh /run_sim "$RELEASE" "/out/$OUT_BASE"
IN_CONTAINER
docker_rc=$?
set -e

if [[ $docker_rc -ne 0 ]]; then
  echo "[!] docker/qemu exited with status $docker_rc; validating output anyway" >&2
fi

echo "[*] output files:"
ls -lh "$TRACE_PATH"* 2>/dev/null || true

if [[ "$TRACE_FORMAT" == "qlt" && -f "$TRACE_PATH" ]]; then
  set +e
  python3 - "$TRACE_PATH" <<'PY'
import os
import struct
import sys

p = sys.argv[1]
size = os.path.getsize(p)
print("[*] qlt path:", p)
print("[*] qlt size:", size)
if size < 36:
    print("[!] qlt too small; QEMU probably did not finalize the writer")
    sys.exit(3)

with open(p, "rb") as f:
    h = f.read(36)
magic = h[:4]
if magic != b"QLT1":
    print("[!] invalid magic:", magic)
    sys.exit(3)
version, flags, regtab, reserved = struct.unpack_from("<HHHH", h, 4)
blocks, index_off, header_size = struct.unpack_from("<QQQ", h, 12)
print("[*] qlt header: version=%d flags=%d reg_table=%d blocks=%d index_offset=%d header_size=%d" %
      (version, flags, regtab, blocks, index_off, header_size))
if blocks == 0:
    print("[!] block_count is 0; trace is not useful/finalized")
    sys.exit(3)
if size < index_off + blocks * 40:
    print("[!] index is incomplete")
    sys.exit(3)
total = 0
first = last = None
with open(p, "rb") as f:
    f.seek(index_off)
    for i in range(blocks):
        e = struct.unpack("<QQQQQ", f.read(40))
        if first is None:
            first = e
        last = e
        total += e[4]
print("[*] qlt records:", total)
print("[*] first index:", first)
print("[*] last index :", last)
PY
  validate_rc=$?
  set -e
else
  validate_rc=0
fi

if [[ $docker_rc -ne 0 && ( ! -s "$TRACE_PATH" || ${validate_rc:-0} -ne 0 ) ]]; then
  exit "$docker_rc"
fi
if [[ -n "${ANALYZER_CONFIG:-}" ]]; then
  echo "[*] analyze with:"
  echo "    cargo run -- klancet '$TRACE_PATH' '$ANALYZER_CONFIG' 'out/${TRACE_BASE%.*}' --trace-format $TRACE_FORMAT"
fi
exit "${validate_rc:-0}"
