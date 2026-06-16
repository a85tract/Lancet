#!/usr/bin/env bash
# Helpers for building user/kernel PoCs for the x86_64 guest architecture even
# when the Docker container itself is arm64/aarch64. QEMU/plugin builds should
# still use the native compiler; source and call setup_x86_64_target_toolchain
# only immediately before building the PoC.
set -euo pipefail

ensure_x86_64_target_cc() {
  if [[ -n "${TARGET_CC:-}" ]]; then
    command -v "$TARGET_CC" >/dev/null 2>&1 || {
      echo "TARGET_CC=$TARGET_CC not found" >&2
      return 1
    }
    printf '%s\n' "$TARGET_CC"
    return 0
  fi

  case "$(uname -m)" in
    x86_64|amd64)
      printf '%s\n' gcc
      return 0
      ;;
  esac

  if ! command -v x86_64-linux-gnu-gcc >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      echo "[target-x86_64] installing x86_64 cross compiler" >&2
      apt-get update >&2
      DEBIAN_FRONTEND=noninteractive apt-get install -y \
        gcc-x86-64-linux-gnu g++-x86-64-linux-gnu \
        binutils-x86-64-linux-gnu libc6-dev-amd64-cross >&2
    fi
  fi

  command -v x86_64-linux-gnu-gcc >/dev/null 2>&1 || {
    cat >&2 <<'MSG'
missing x86_64 target compiler in a non-x86_64 container.
Either rebuild the Docker image with gcc-x86-64-linux-gnu installed, or run with:
  DOCKER_PLATFORM=linux/amd64 BUILD_IMAGE=1 ./lancet.sh user <case>
MSG
    return 1
  }
  printf '%s\n' x86_64-linux-gnu-gcc
}

setup_x86_64_target_toolchain() {
  local cc
  cc=$(ensure_x86_64_target_cc)
  export TARGET_CC="$cc"
  export CC_FOR_TARGET="$cc"
  export CC="$cc"

  local target_prefix=""
  if [[ "$cc" == *-*gcc ]]; then
    target_prefix=${cc%gcc}
  elif command -v x86_64-linux-gnu-objdump >/dev/null 2>&1; then
    target_prefix=x86_64-linux-gnu-
  fi
  if [[ -n "$target_prefix" ]] &&
     ! command -v "${target_prefix}objdump" >/dev/null 2>&1 &&
     command -v apt-get >/dev/null 2>&1; then
    echo "[target-x86_64] installing x86_64 binutils" >&2
    apt-get update >&2
    DEBIAN_FRONTEND=noninteractive apt-get install -y binutils-x86-64-linux-gnu >&2
  fi
  local target_nm=${TARGET_NM:-}
  local target_objdump=${TARGET_OBJDUMP:-}
  local target_readelf=${TARGET_READELF:-}
  local target_objcopy=${TARGET_OBJCOPY:-}
  local target_strip=${TARGET_STRIP:-}
  local target_addr2line=${TARGET_ADDR2LINE:-}
  if [[ -n "$target_prefix" ]]; then
    [[ -n "$target_nm" || ! -x "$(command -v "${target_prefix}nm" 2>/dev/null || true)" ]] || target_nm="${target_prefix}nm"
    [[ -n "$target_objdump" || ! -x "$(command -v "${target_prefix}objdump" 2>/dev/null || true)" ]] || target_objdump="${target_prefix}objdump"
    [[ -n "$target_readelf" || ! -x "$(command -v "${target_prefix}readelf" 2>/dev/null || true)" ]] || target_readelf="${target_prefix}readelf"
    [[ -n "$target_objcopy" || ! -x "$(command -v "${target_prefix}objcopy" 2>/dev/null || true)" ]] || target_objcopy="${target_prefix}objcopy"
    [[ -n "$target_strip" || ! -x "$(command -v "${target_prefix}strip" 2>/dev/null || true)" ]] || target_strip="${target_prefix}strip"
    [[ -n "$target_addr2line" || ! -x "$(command -v "${target_prefix}addr2line" 2>/dev/null || true)" ]] || target_addr2line="${target_prefix}addr2line"
  fi
  export TARGET_NM="${target_nm:-nm}"
  export TARGET_OBJDUMP="${target_objdump:-objdump}"
  export TARGET_READELF="${target_readelf:-readelf}"
  export TARGET_OBJCOPY="${target_objcopy:-objcopy}"
  export TARGET_STRIP="${target_strip:-strip}"
  export TARGET_ADDR2LINE="${target_addr2line:-addr2line}"

  # Put target-compiler shims first so case build scripts that hardcode `gcc`
  # still emit x86_64 ELFs. Also shim binutils so scripts that hardcode
  # objdump/readelf/nm can inspect x86_64 ELFs correctly inside arm64 images.
  # This is intentionally done after building the QEMU plugin so the plugin
  # remains native to the QEMU binary in the container.
  local shim_dir=${TARGET_TOOLCHAIN_SHIM_DIR:-/tmp/ql-target-x86_64-bin}
  mkdir -p "$shim_dir"
  ln -sf "$(command -v "$cc")" "$shim_dir/gcc"
  ln -sf "$(command -v "$cc")" "$shim_dir/cc"
  if command -v x86_64-linux-gnu-g++ >/dev/null 2>&1; then
    ln -sf "$(command -v x86_64-linux-gnu-g++)" "$shim_dir/g++"
    ln -sf "$(command -v x86_64-linux-gnu-g++)" "$shim_dir/c++"
  fi
  local tool var resolved
  for tool in nm objdump readelf objcopy strip addr2line; do
    var="TARGET_${tool^^}"
    # shellcheck disable=SC2154 # indirect variable name is constructed above.
    resolved=${!var:-}
    if command -v "$resolved" >/dev/null 2>&1; then
      ln -sf "$(command -v "$resolved")" "$shim_dir/$tool"
    fi
  done
  case ":$PATH:" in
    *":$shim_dir:"*) ;;
    *) export PATH="$shim_dir:$PATH" ;;
  esac
  echo "[target-x86_64] TARGET_CC=$cc TARGET_OBJDUMP=$TARGET_OBJDUMP PATH shim=$shim_dir" >&2
}

validate_x86_64_elf() {
  local elf=${1:?missing ELF path}
  local label=${2:-ELF}
  if [[ ! -s "$elf" ]]; then
    echo "$label is missing or empty: $elf" >&2
    return 1
  fi
  if command -v file >/dev/null 2>&1; then
    echo "[target-x86_64] $label file: $(file -b "$elf")" >&2 || true
  fi
  local machine class
  machine=$(LC_ALL=C "${TARGET_READELF:-readelf}" -h "$elf" 2>/dev/null | awk -F: '/Machine:/ {gsub(/^[ \t]+/, "", $2); print $2; exit}')
  class=$(LC_ALL=C "${TARGET_READELF:-readelf}" -h "$elf" 2>/dev/null | awk -F: '/Class:/ {gsub(/^[ \t]+/, "", $2); print $2; exit}')
  if [[ "$class" != "ELF64" || "$machine" != *"X86-64"* ]]; then
    cat >&2 <<MSG
architecture mismatch for $label: $elf
  ELF class : ${class:-unknown}
  Machine   : ${machine:-unknown}
This trace flow runs qemu-x86_64 / x86_64 guests, so the PoC must be an x86_64 ELF.
Fix by using the target cross compiler (x86_64-linux-gnu-gcc) or by forcing an amd64 Docker image:
  DOCKER_PLATFORM=linux/amd64 BUILD_IMAGE=1 ./lancet.sh user <case>
MSG
    return 1
  fi
}
