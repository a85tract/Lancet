#!/usr/bin/env python3
"""List case manifests in a compact, human-readable form."""
import json
import os
import sys
from pathlib import Path


def first(cfg, *names, default=""):
    for name in names:
        value = cfg.get(name)
        if value is not None and value != "":
            return value
    return default


def rel(path: Path, root: Path) -> str:
    try:
        return os.path.relpath(path, root)
    except ValueError:
        return str(path)


def path_value(value, base: Path) -> Path:
    value = str(value)
    p = Path(value)
    if p.is_absolute():
        return p
    return (base / p).resolve()


def trace_path(cfg, case_dir: Path, case_name: str, fmt: str) -> Path:
    explicit = first(cfg, "trace_path", "out", "output")
    if explicit:
        return path_value(explicit, case_dir)
    output_dir = path_value(first(cfg, "output_dir", "trace_dir", default="out"), case_dir)
    trace_name = str(first(cfg, "trace", "trace_name", default=f"{case_name}.{fmt}"))
    return (output_dir / trace_name).resolve()


def case_mode(cfg) -> str:
    release = str(first(cfg, "release", "linux_kernel_version", "kernel", default="")).lower()
    simulator = str(first(cfg, "simulator", "sim", "sim_dir", "simulator_dir", default="")).lower()
    plugin_mode = str(first(cfg, "plugin_mode", default="")).lower()
    if release == "user" or simulator == "user" or plugin_mode == "user":
        return "user"
    return "kernel"


def main() -> int:
    cases_dir = Path(sys.argv[1] if len(sys.argv) > 1 else "cases").resolve()
    root = Path(sys.argv[2] if len(sys.argv) > 2 else cases_dir.parent).resolve()

    print("Supported cases:")
    manifests = sorted(cases_dir.glob("*/config.json"))
    if not manifests:
        print(f"  (none; add {rel(cases_dir, root)}/<name>/config.json)")
        return 0

    for manifest in manifests:
        case_dir = manifest.parent
        fallback_name = case_dir.name
        try:
            cfg = json.loads(manifest.read_text(encoding="utf-8"))
            name = str(first(cfg, "name", default=fallback_name))
            mode = case_mode(cfg)
            release = str(first(cfg, "release", "linux_kernel_version", "kernel", default="?"))
            fmt = str(first(cfg, "trace_format", "format", default="qlt"))
            trace = rel(trace_path(cfg, case_dir, name, fmt), root)
            print(f"  {mode:<6} {name:<28} release={release:<20} format={fmt:<5} trace={trace}")
        except Exception as err:
            print(f"  {'?':<6} {fallback_name:<28} invalid config: {err}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
