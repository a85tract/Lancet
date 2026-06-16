#!/usr/bin/env python3
"""Generate QLancet analyzer and QEMU plugin configs from a kernelCTF vmlinux."""
import argparse
import gzip
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from collections import OrderedDict
from pathlib import Path

KERNELCTF_BASE_URL = os.environ.get(
    "KERNELCTF_BASE_URL", "https://storage.googleapis.com/kernelctf-build"
)

SYMBOL_TEMPLATE = OrderedDict([
    ("__vmalloc", {"import_reg": "rdi"}),
    ("__kmalloc", {"import_reg": "rdi"}),
    ("kfree", {"import_reg": "rdi"}),
    ("__slab_free", {"import_reg": "rdi"}),
    ("___slab_alloc", {"import_reg": "rdi", "use_value_to_size": True, "value_size": 4, "qemu": {"import_reg": "rdi", "offset": 24, "is_call": True}}),
    ("kmem_cache_free", {"import_reg": "rsi"}),
    ("__kmem_cache_free", {"import_reg": "rsi"}),
    ("skb_attempt_defer_free", {"import_reg": "rdi"}),
    ("krealloc", {"import_reg": "rsi"}),
    ("__kmalloc_node", {"use_value_to_size": True, "value_size": 4, "qemu": {"import_reg": "rdi", "offset": 24, "is_call": True}}),
    ("__kmalloc_node_track_caller", {"import_reg": "rdi"}),
    ("kmalloc_large", {"import_reg": "rdi"}),
    ("kmalloc_large_node", {"import_reg": "rdi"}),
    ("__kfree_skb", {"import_reg": "rdi"}),
    ("kmalloc_slab", {"import_reg": "rdi"}),
    ("__alloc_skb", {"import_reg": "rdi", "offset": "+0x140"}),
    ("kmalloc_node_trace", {"import_reg": "rdi", "use_value_to_size": True, "value_size": 4, "qemu": {"import_reg": "rdi", "offset": 24, "is_call": True}}),
    ("kmalloc_trace", {"import_reg": "rdi", "use_value_to_size": True, "value_size": 4, "qemu": {"import_reg": "rdi", "offset": 24, "is_call": True}}),
    ("kmem_cache_alloc_lru", {"import_reg": "rdi", "use_value_to_size": True, "value_size": 4, "qemu": {"import_reg": "rdi", "offset": 24, "is_call": True}}),
    ("__kmem_cache_alloc_node", {"use_value_to_size": True, "value_size": 4, "qemu": {"import_reg": "rdi", "offset": 24, "is_call": True}}),
    ("kmem_cache_alloc", {"use_value_to_size": True, "value_size": 4, "qemu": {"import_reg": "rdi", "offset": 24, "is_call": True}}),
    ("kmem_cache_alloc_bulk", {"use_value_to_size": True, "value_size": 4, "is_bulk": True, "qemu": {"import_reg": "rdi", "offset": 24, "is_call": True}}),
    ("kmem_cache_alloc_node", {"use_value_to_size": True, "value_size": 4, "qemu": {"import_reg": "rdi", "offset": 24, "is_call": True}}),
    ("kmem_cache_free_bulk", {"import_reg": "rdi"}),
    ("__free_pages", {"import_reg": "rdi"}),
    ("alloc_pages", {"import_reg": "rdi"}),
    ("do_syscall_64", {}),
    ("swapgs_restore_regs_and_return_to_usermode", {}),
    ("memcpy", {}),
    ("__memcpy", {}),
    ("memmove", {}),
    ("memset", {}),
    ("__memset", {}),
    ("memzero_explicit", {}),
    ("clear_user", {}),
])

MALLOC_ADDR_SYMBOLS = [
    "__kmem_cache_alloc_node",
    "kmem_cache_alloc_node",
    "kmalloc_node_trace",
    "kmem_cache_alloc",
    "__kmalloc_node_track_caller",
]
FREE_ADDR_SYMBOLS = ["__kmem_cache_free", "kmem_cache_free"]
VULNERABILITY_TYPES = [
    "uninitializedread",
    "uafread",
    "uafwrite",
    "doublefree",
    "invalidfree",
    "outofboundsread",
    "outofboundswrite",
    "memoryoverlap",
    "danglingptr",
    "crossboundary",
    "expiredptr",
    "nullpointer",
    "untrustedptr",
    "stackuafread",
    "stackuafwrite",
]


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def fetch(url: str, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + f".tmp.{os.getpid()}")
    force4 = os.environ.get("KERNELCTF_FORCE_IPV4", "1") != "0"
    print(f"[gen_config] fetching {url} -> {out}", file=sys.stderr)
    try:
        if shutil.which("wget"):
            cmd = ["wget"]
            if force4:
                cmd.append("-4")
            cmd += ["-O", str(tmp), url]
            run(cmd)
        elif shutil.which("curl"):
            cmd = ["curl", "-fL"]
            if force4:
                cmd.append("-4")
            cmd += [url, "-o", str(tmp)]
            run(cmd)
        else:
            with urllib.request.urlopen(url) as resp, tmp.open("wb") as fh:
                shutil.copyfileobj(resp, fh)
        tmp.replace(out)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


def decompress_gzip(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_suffix(dst.suffix + f".tmp.{os.getpid()}")
    with gzip.open(src, "rb") as inf, tmp.open("wb") as outf:
        shutil.copyfileobj(inf, outf)
    tmp.replace(dst)


def resolve_vmlinux(kernel: str, releases_dir: Path) -> Path:
    candidate = Path(kernel)
    if candidate.exists():
        if candidate.suffix == ".gz":
            out = candidate.with_suffix("")
            if not out.exists():
                decompress_gzip(candidate, out)
            return out
        return candidate
    release_dir = releases_dir / kernel
    release_dir.mkdir(parents=True, exist_ok=True)
    vmlinux = release_dir / "vmlinux"
    gz = release_dir / "vmlinux.gz"
    if not vmlinux.exists():
        if not gz.exists():
            fetch(f"{KERNELCTF_BASE_URL}/releases/{kernel}/vmlinux.gz", gz)
        print(f"[gen_config] decompressing {gz} -> {vmlinux}", file=sys.stderr)
        decompress_gzip(gz, vmlinux)
    return vmlinux


def load_symbols(vmlinux: Path):
    try:
        proc = subprocess.run(
            ["nm", "-n", "--defined-only", str(vmlinux)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as err:
        raise SystemExit("nm is required; install binutils") from err
    except subprocess.CalledProcessError as err:
        raise SystemExit(f"nm failed for {vmlinux}: {err.stderr.strip()}") from err
    symbols = {}
    for line in proc.stdout.splitlines():
        parts = line.strip().split()
        if len(parts) < 3 or not re.fullmatch(r"[0-9a-fA-F]+", parts[0]):
            continue
        symbols.setdefault(parts[-1], int(parts[0], 16))
    return symbols


def fmt(addr: int) -> str:
    return f"0x{addr:016x}"


def build_configs(symbols):
    symbol_names = OrderedDict()
    missing = []
    for name, meta in SYMBOL_TEMPLATE.items():
        addr = symbols.get(name)
        if addr is None:
            missing.append(name)
            continue
        entry = OrderedDict(addr=fmt(addr))
        for k, v in meta.items():
            if k != "qemu":
                entry[k] = v
        symbol_names[name] = entry

    malloc_addrs = [fmt(symbols[name]) for name in MALLOC_ADDR_SYMBOLS if name in symbols]
    free_addrs = [fmt(symbols[name]) for name in FREE_ADDR_SYMBOLS if name in symbols]
    if not malloc_addrs:
        raise SystemExit("failed to resolve any malloc symbols")
    if not free_addrs:
        raise SystemExit("failed to resolve any free symbols")

    analyzer = OrderedDict([
        ("malloc_addrs", malloc_addrs),
        ("free_addrs", free_addrs),
        ("vulnerability_types", VULNERABILITY_TYPES),
        ("symbol_names", symbol_names),
    ])

    qemu = OrderedDict()
    for name, meta in SYMBOL_TEMPLATE.items():
        qspec = meta.get("qemu")
        addr = symbols.get(name)
        if qspec is None or addr is None:
            continue
        qemu[name] = OrderedDict([
            ("addr", fmt(addr)),
            ("import_reg", qspec.get("import_reg", "rdi")),
            ("offset", qspec.get("offset", 24)),
        ])
        if qspec.get("is_call"):
            qemu[name]["is_call"] = True
    return analyzer, qemu, missing


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(value, f, indent=4)
        f.write("\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--kernel", required=True, help="release name or path to vmlinux/vmlinux.gz")
    ap.add_argument("--releases-dir", type=Path, default=Path("simulators/kernelctf/releases"))
    ap.add_argument("--qlancet-output", "-o", type=Path, required=True)
    ap.add_argument("--qemu-output", type=Path, required=True)
    args = ap.parse_args()

    vmlinux = resolve_vmlinux(args.kernel, args.releases_dir)
    symbols = load_symbols(vmlinux)
    analyzer, qemu, missing = build_configs(symbols)
    write_json(args.qlancet_output, analyzer)
    write_json(args.qemu_output, qemu)
    print(f"wrote {args.qlancet_output}")
    print(f"wrote {args.qemu_output}")
    if missing:
        print("warning: missing symbols: " + ", ".join(sorted(set(missing))), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
