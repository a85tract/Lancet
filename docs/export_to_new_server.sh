#!/bin/bash
# Export Lancet Advanced + dependencies for porting to another server
# Usage: bash export_to_new_server.sh /path/to/output_dir
#
# This creates:
#   output_dir/
#   ├── lancet_advanced.tar.gz          (~170MB, source + build + docs)
#   ├── pin-3.28.tar.gz                 (~211MB, Intel PIN SDK)
#   ├── juliet_tests.tar.gz             (~5MB, native test binaries)
#   ├── docker/                          (~53GB total, one .tar.gz per image)
#   │   ├── lancet_juliet_how2heap.tar.gz
#   │   ├── lancet_php_16595.tar.gz
#   │   └── ...
#   └── setup_new_server.sh             (extraction + build script)

set -e

OUTDIR="${1:-/tmp/lancet_export}"
LANCET_DIR="/home/seondst/Desktop/Code/lancet_advanced"
PIN_DIR="/home/seondst/Desktop/Code/pin-3.28"
TESTCASES="/home/seondst/Desktop/Code/heapkiller/testcases"

mkdir -p "$OUTDIR/docker"

echo "=== Exporting Lancet Advanced ==="

# 1. Source code
echo "[1/4] Packing lancet_advanced source..."
tar czf "$OUTDIR/lancet_advanced.tar.gz" \
  -C "$(dirname "$LANCET_DIR")" \
  "$(basename "$LANCET_DIR")" \
  --exclude='obj-intel64' \
  --exclude='.git' \
  --exclude='results' \
  --exclude='logs/*.log' \
  --exclude='tmp.mp4'
echo "  → $(du -h "$OUTDIR/lancet_advanced.tar.gz" | cut -f1)"

# 2. PIN SDK
echo "[2/4] Packing PIN 3.28 SDK..."
tar czf "$OUTDIR/pin-3.28.tar.gz" \
  -C "$(dirname "$PIN_DIR")" \
  "$(basename "$PIN_DIR")"
echo "  → $(du -h "$OUTDIR/pin-3.28.tar.gz" | cut -f1)"

# 3. Native test binaries
echo "[3/4] Packing native test binaries..."
tar czf "$OUTDIR/juliet_tests.tar.gz" \
  "$TESTCASES/juliet-test-suite-c/CWE415"* \
  "$TESTCASES/juliet-test-suite-c/CWE416"* \
  "$TESTCASES/juliet_how2heap/how2heap/house_of_einherjar" \
  2>/dev/null || true
echo "  → $(du -h "$OUTDIR/juliet_tests.tar.gz" | cut -f1)"

# 4. Docker images
echo "[4/4] Exporting Docker images (this takes a while)..."

TAGS=(
  juliet_how2heap php_16595 osv_2024_204 cve_2024_41965
  ffmpeg_10749 ffmpeg_11228 cve_2019_6977 gpac_2701 gpac_2583
  osv_2023_1276 cve_2024_43374 cpv15 osv_2024_96 php_76041
  cve_2004_1287 cve_2007_1001 cve_2012_2386
)

for tag in "${TAGS[@]}"; do
  out="$OUTDIR/docker/lancet_${tag}.tar.gz"
  if [ -f "$out" ]; then
    echo "  [skip] $tag (already exported)"
    continue
  fi
  if docker image inspect "ghcr.io/a85tract/lancet:$tag" &>/dev/null; then
    echo "  [save] $tag..."
    docker save "ghcr.io/a85tract/lancet:$tag" | gzip > "$out"
    echo "    → $(du -h "$out" | cut -f1)"
  else
    echo "  [miss] $tag — image not found locally"
  fi
done

# 5. Create setup script for target server
cat > "$OUTDIR/setup_new_server.sh" << 'SETUP'
#!/bin/bash
# Run this on the target server after transferring the export directory
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="${1:-$HOME/lancet}"

echo "=== Installing Lancet Advanced to $INSTALL_DIR ==="
mkdir -p "$INSTALL_DIR"

# Extract PIN SDK
echo "[1/4] Extracting PIN 3.28..."
tar xzf "$SCRIPT_DIR/pin-3.28.tar.gz" -C "$INSTALL_DIR/"

# Extract lancet source
echo "[2/4] Extracting lancet_advanced..."
tar xzf "$SCRIPT_DIR/lancet_advanced.tar.gz" -C "$INSTALL_DIR/"

# Update PIN_ROOT in makefile
echo "[3/4] Configuring build..."
sed -i "s|PIN_ROOT := .*|PIN_ROOT := $INSTALL_DIR/pin-3.28|" \
  "$INSTALL_DIR/lancet_advanced/makefile"

# Build
echo "[4/4] Building..."
cd "$INSTALL_DIR/lancet_advanced"
export CC=gcc CXX=g++
make clean && make -j$(nproc)

echo ""
echo "=== Build complete ==="
echo "Tool: $INSTALL_DIR/lancet_advanced/obj-intel64/lancet.so"
echo ""
echo "To load Docker images:"
echo "  for f in $SCRIPT_DIR/docker/lancet_*.tar.gz; do"
echo "    echo \"Loading \$f...\""
echo "    gunzip -c \"\$f\" | docker load"
echo "  done"
echo ""
echo "Quick test:"
echo "  cd $INSTALL_DIR/lancet_advanced"
echo "  ./run.sh -nolog 0 -- /path/to/test_binary"
SETUP
chmod +x "$OUTDIR/setup_new_server.sh"

echo ""
echo "=== Export complete ==="
echo "Output: $OUTDIR/"
du -sh "$OUTDIR"/*
echo ""
echo "Transfer to new server with:"
echo "  rsync -avP $OUTDIR/ user@newserver:~/lancet_export/"
echo "Then on new server:"
echo "  bash ~/lancet_export/setup_new_server.sh ~/lancet"
