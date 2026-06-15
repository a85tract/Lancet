#!/bin/bash
set -euo pipefail
cc=${CC:-gcc}
$cc -fPIC -shared hello.c -o hello.so \
  -I/usr/local/include \
  $(pkg-config --cflags --libs glib-2.0) \
  -lzstd
printf '[+] built %s\n' "$(pwd)/hello.so"
