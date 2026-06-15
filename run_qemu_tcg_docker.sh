#!/bin/bash
set -euo pipefail
IMAGE=${IMAGE:-a85_qlancet_qemu}
NAME=${NAME:-a85_qlancet_qemu}
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
exec sudo docker run --security-opt seccomp=unconfined --name "$NAME" --rm -ti \
  -p 11156:11156 -p 11157:1234 \
  -v "$ROOT_DIR":/qemu/contrib/plugins/test \
  "$IMAGE"
