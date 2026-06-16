#!/usr/bin/env bash
# Prepare reusable kernelCTF simulator assets for this repository.
#
# This is intentionally close to the upstream kernelCTF helper: it downloads the
# requested release kernel, rootfs, ramdisk, qemu_v3.sh, and flag if they are
# missing. It also extracts ramdisk_v1.img into core/ because get_trace.sh needs
# a writable initramfs template where it can install the case PoC as /bin/exp.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: ./prepare.sh <release-name> [--root] [--run] [--force-core]

Options:
  --root        With --run, boot into /bin/bash instead of /home/user/run.sh.
  --run         After preparing assets, exec ./qemu_v3.sh.
  --force-core  Re-extract core/ from ramdisk_v1.img.

Environment:
  KERNELCTF_BASE_URL=https://storage.googleapis.com/kernelctf-build
USAGE
  exit 1
}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
cd "$SCRIPT_DIR"

INIT_FN="/home/user/run.sh"
RUN=0
FORCE_CORE=0

ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --root) INIT_FN="/bin/bash"; shift ;;
    --run) RUN=1; shift ;;
    --force-core) FORCE_CORE=1; shift ;;
    -h|--help) usage ;;
    -*|--*) echo "Unknown option $1" >&2; usage ;;
    *) ARGS+=("$1"); shift ;;
  esac
done
set -- "${ARGS[@]}"

RELEASE_NAME=${1:-}
if [[ -z "$RELEASE_NAME" ]]; then
  usage
fi

BASE_URL=${KERNELCTF_BASE_URL:-https://storage.googleapis.com/kernelctf-build}

fetch() {
  local url=$1
  local out=$2
  local tmp="$out.tmp.$$"
  echo "[kernelctf] fetching $url -> $out"
  if command -v wget >/dev/null 2>&1; then
    wget -O "$tmp" "$url"
  elif command -v curl >/dev/null 2>&1; then
    curl -fL "$url" -o "$tmp"
  else
    echo "missing downloader: install wget or curl" >&2
    exit 1
  fi
  mv "$tmp" "$out"
}

if [[ ! -f qemu_v3.sh ]]; then
  fetch "$BASE_URL/files/qemu_v3.sh" qemu_v3.sh
fi
chmod u+x qemu_v3.sh

mkdir -p "releases/$RELEASE_NAME"
if [[ ! -f "releases/$RELEASE_NAME/bzImage" ]]; then
  fetch "$BASE_URL/releases/$RELEASE_NAME/bzImage" "releases/$RELEASE_NAME/bzImage"
fi

if [[ ! -f rootfs_v3.img ]]; then
  if [[ ! -f rootfs_v3.img.gz ]]; then
    fetch "$BASE_URL/files/rootfs_v3.img.gz" rootfs_v3.img.gz
  fi
  echo "[kernelctf] decompressing rootfs_v3.img.gz"
  gzip -dc rootfs_v3.img.gz > rootfs_v3.img.tmp.$$
  mv rootfs_v3.img.tmp.$$ rootfs_v3.img
fi

if [[ ! -f ramdisk_v1.img ]]; then
  fetch "$BASE_URL/files/ramdisk_v1.img" ramdisk_v1.img
fi

if [[ ! -f flag ]]; then
  echo "kernelCTF{example_flag}" > flag
fi

if [[ "$FORCE_CORE" == "1" || ! -d core || ! -f core/init ]]; then
  if ! command -v file >/dev/null 2>&1; then
    echo "missing dependency: file" >&2
    exit 1
  fi
  echo "[kernelctf] extracting ramdisk_v1.img -> core/"
  rm -rf core.tmp.$$
  mkdir -p core.tmp.$$
  (
    cd core.tmp.$$
    if file ../ramdisk_v1.img | grep -qi gzip; then
      gzip -dc ../ramdisk_v1.img | cpio -idmu
    else
      cpio -idmu < ../ramdisk_v1.img
    fi
  )
  python3 - core.tmp.$$/init <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
if "/busybox cp ./exp /root/bin/exp" not in text:
    marker = "# Chain to real filesystem\n"
    inject = (
        "/busybox cp ./exp /root/chroot/bin 2>/dev/null || true\n"
        "/busybox cp ./exp /root/bin/exp\n"
        "/busybox cp ./test.sh /root/home/user/run.sh\n"
        "/busybox chmod +x /root/home/user/run.sh\n\n"
    )
    if marker not in text:
        raise SystemExit("failed to patch init: marker not found")
    path.write_text(text.replace(marker, inject + marker))
PY
  rm -rf core
  mv core.tmp.$$ core
fi

echo "[kernelctf] ready: release=$RELEASE_NAME rootfs=rootfs_v3.img core=core"

if [[ "$RUN" == "1" ]]; then
  exec ./qemu_v3.sh "releases/$RELEASE_NAME" flag "$INIT_FN"
fi
