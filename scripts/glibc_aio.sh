#!/usr/bin/env bash
# Helpers intended to run inside the QLancet Docker image.  They install/use
# matrix1001/glibc-all-in-one on demand and patch a user-mode ELF to a selected
# libc/ld pair.
set -euo pipefail

ensure_glibc_aio() {
  local aio_dir=${GLIBC_AIO_DIR:-/opt/glibc-all-in-one}
  if command -v glibc-aio >/dev/null 2>&1; then
    return 0
  fi
  if [[ ! -d "$aio_dir/.git" ]]; then
    echo "[glibc-aio] cloning into $aio_dir" >&2
    git clone https://github.com/matrix1001/glibc-all-in-one.git "$aio_dir"
  fi
  echo "[glibc-aio] installing Python package" >&2
  pip install -e "$aio_dir" >/dev/null
}

ensure_glibc_version() {
  local version=${1:?missing glibc version/package id}
  local aio_dir=${GLIBC_AIO_DIR:-/opt/glibc-all-in-one}
  ensure_glibc_aio
  mkdir -p "$aio_dir"
  cd "$aio_dir"

  local lib_root="$aio_dir/libs/$version"
  if [[ ! -d "$lib_root" ]]; then
    if [[ ! -s "$aio_dir/list" ]]; then
      glibc-aio mirror update || true
    fi
    echo "[glibc-aio] downloading $version" >&2
    glibc-aio download "$version" --no-dbg
  fi
  if [[ ! -d "$lib_root" ]]; then
    # Allow shorthand values such as 2.32 by selecting the first amd64 package.
    local resolved
    resolved=$(glibc-aio search "$version" 2>/dev/null | awk '/amd64/ {print $1; exit}')
    if [[ -z "$resolved" ]]; then
      echo "failed to resolve glibc version/package: $version" >&2
      return 1
    fi
    version="$resolved"
    lib_root="$aio_dir/libs/$version"
    if [[ ! -d "$lib_root" ]]; then
      echo "[glibc-aio] downloading resolved package $version" >&2
      glibc-aio download "$version" --no-dbg
    fi
  fi

  local libc ld
  libc=$(find "$lib_root" -type f -name 'libc.so.6' | head -n1 || true)
  ld=$(find "$lib_root" -type f -name 'ld-linux-x86-64.so.2' | head -n1 || true)
  if [[ -z "$libc" || -z "$ld" ]]; then
    echo "failed to locate libc.so.6 or ld-linux-x86-64.so.2 under $lib_root" >&2
    return 1
  fi
  printf '%s\n%s\n%s\n' "$version" "$ld" "$(dirname "$libc")"
}

patch_elf_to_glibc() {
  local elf=${1:?missing ELF path}
  local version=${2:?missing glibc version/package id}
  command -v patchelf >/dev/null 2>&1 || {
    echo "patchelf is required in the Docker image" >&2
    return 1
  }
  local info resolved ld libdir
  info=$(ensure_glibc_version "$version")
  resolved=$(printf '%s\n' "$info" | sed -n '1p')
  ld=$(printf '%s\n' "$info" | sed -n '2p')
  libdir=$(printf '%s\n' "$info" | sed -n '3p')
  echo "[glibc-aio] patching $elf -> $resolved" >&2
  echo "[glibc-aio] interpreter: $ld" >&2
  echo "[glibc-aio] rpath      : $libdir" >&2
  patchelf --set-interpreter "$ld" --set-rpath "$libdir" "$elf"
}
