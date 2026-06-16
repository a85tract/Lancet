#!/usr/bin/env bash
# Helpers intended to run inside the QLancet Docker image. They install/use
# matrix1001/glibc-all-in-one on demand and patch a user-mode ELF to a selected
# libc/ld pair.
set -euo pipefail

ensure_patchelf() {
  if command -v patchelf >/dev/null 2>&1; then
    return 0
  fi
  if command -v apt-get >/dev/null 2>&1; then
    echo "[glibc-aio] installing patchelf" >&2
    apt-get update >&2
    DEBIAN_FRONTEND=noninteractive apt-get install -y patchelf >&2
  fi
  command -v patchelf >/dev/null 2>&1 || {
    echo "patchelf is required in the Docker image" >&2
    return 1
  }
}

ensure_glibc_aio() {
  local aio_dir=${GLIBC_AIO_DIR:-/opt/glibc-all-in-one}
  if command -v glibc-aio >/dev/null 2>&1; then
    return 0
  fi
  if [[ ! -d "$aio_dir/.git" ]]; then
    echo "[glibc-aio] cloning into $aio_dir" >&2
    rm -rf "$aio_dir"
    git clone https://github.com/matrix1001/glibc-all-in-one.git "$aio_dir" >&2
  fi
  echo "[glibc-aio] installing Python package" >&2
  pip install -e "$aio_dir" >&2
}

resolve_glibc_package() {
  local requested=${1:?missing glibc version/package id}
  local aio_dir=${GLIBC_AIO_DIR:-/opt/glibc-all-in-one}
  if [[ -d "$aio_dir/libs/$requested" ]]; then
    printf '%s\n' "$requested"
    return 0
  fi

  ensure_glibc_aio
  cd "$aio_dir"
  if [[ ! -s "$aio_dir/list" ]]; then
    glibc-aio mirror update >&2 || true
  fi

  # Exact package ids already contain an arch suffix. Otherwise allow shorthands
  # like "2.32" and choose the first amd64 result.
  if [[ "$requested" == *_amd64 ]]; then
    printf '%s\n' "$requested"
    return 0
  fi

  local resolved
  resolved=$(glibc-aio search "$requested" 2>/dev/null | awk '/_amd64/ {print $1; exit}')
  if [[ -z "$resolved" ]]; then
    echo "failed to resolve glibc version/package: $requested" >&2
    return 1
  fi
  printf '%s\n' "$resolved"
}

ensure_glibc_version() {
  local requested=${1:?missing glibc version/package id}
  local aio_dir=${GLIBC_AIO_DIR:-/opt/glibc-all-in-one}
  ensure_glibc_aio
  local version
  version=$(resolve_glibc_package "$requested")
  local lib_root="$aio_dir/libs/$version"
  if [[ ! -d "$lib_root" ]]; then
    cd "$aio_dir"
    echo "[glibc-aio] downloading $version" >&2
    glibc-aio download "$version" --no-dbg >&2
  fi

  local libc ld
  # glibc-all-in-one keeps the canonical sonames as symlinks in many
  # packages (e.g. libc.so.6 -> libc-2.32.so). Prefer those soname paths
  # because their directory is exactly the rpath directory qemu-user needs,
  # then fall back to the real versioned files.
  libc=$(find "$lib_root" \( -type f -o -type l \) -name 'libc.so.6' -print | sort | sed -n '1p' || true)
  if [[ -z "$libc" ]]; then
    libc=$(find "$lib_root" -type f -name 'libc-*.so' -print | sort | sed -n '1p' || true)
  fi
  ld=$(find "$lib_root" \( -type f -o -type l \) -name 'ld-linux-x86-64.so.2' -print | sort | sed -n '1p' || true)
  if [[ -z "$ld" ]]; then
    ld=$(find "$lib_root" -type f -name 'ld-*.so' -print | sort | sed -n '1p' || true)
  fi
  if [[ -z "$libc" || -z "$ld" ]]; then
    echo "failed to locate libc.so.6 or ld-linux-x86-64.so.2 under $lib_root" >&2
    return 1
  fi
  printf '%s\n%s\n%s\n' "$version" "$ld" "$(dirname "$libc")"
}

prepare_glibc_link_env() {
  local version=${1:?missing glibc version/package id}
  local info
  info=$(ensure_glibc_version "$version")
  GLIBC_AIO_RESOLVED=$(printf '%s\n' "$info" | sed -n '1p')
  GLIBC_AIO_LD=$(printf '%s\n' "$info" | sed -n '2p')
  GLIBC_AIO_LIBDIR=$(printf '%s\n' "$info" | sed -n '3p')
  GLIBC_AIO_LINKDIR="/tmp/glibc-aio-link-$GLIBC_AIO_RESOLVED"
  mkdir -p "$GLIBC_AIO_LINKDIR"
  # GNU ld searches for libc.so (not just libc.so.6) when GCC injects -lc.
  # Runtime-only glibc-all-in-one packages often lack that linker name, so
  # provide a private symlink instead of mutating the cached package.
  ln -sf "$GLIBC_AIO_LIBDIR/libc.so.6" "$GLIBC_AIO_LINKDIR/libc.so"
  export GLIBC_AIO_RESOLVED GLIBC_AIO_LD GLIBC_AIO_LIBDIR GLIBC_AIO_LINKDIR
}

compile_c_with_glibc() {
  local src=${1:?missing C source path}
  local out=${2:?missing output ELF path}
  local version=${3:?missing glibc version/package id}
  shift 3
  prepare_glibc_link_env "$version"
  echo "[glibc-aio] compiling $src against $GLIBC_AIO_RESOLVED" >&2
  echo "[glibc-aio] link interpreter: $GLIBC_AIO_LD" >&2
  echo "[glibc-aio] link rpath      : $GLIBC_AIO_LIBDIR" >&2
  local cc=${TARGET_CC:-gcc}
  "$cc" "$@" \
    -Wl,--dynamic-linker="$GLIBC_AIO_LD" \
    -Wl,-rpath="$GLIBC_AIO_LIBDIR" \
    -Wl,-rpath-link="$GLIBC_AIO_LIBDIR" \
    -L"$GLIBC_AIO_LINKDIR" \
    -L"$GLIBC_AIO_LIBDIR" \
    "$src" -o "$out"
}

patch_elf_to_glibc() {
  local elf=${1:?missing ELF path}
  local version=${2:?missing glibc version/package id}
  ensure_patchelf
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
