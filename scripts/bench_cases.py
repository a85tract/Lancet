#!/usr/bin/env python3
"""Run analyzer benchmark passes over QLancet case manifests or explicit cases.

This intentionally benchmarks only the Rust analyzer/report pipeline, assuming
traces already exist (for example after ./get_trace.sh <case>). It shells out to
analyzer.sh so case path/config regeneration behavior stays identical to normal
usage, then records elapsed wall-clock time and the generated summary counters.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path


def discover_cases(root: Path, cases_dir: Path) -> list[str]:
    del root
    return [p.parent.name for p in sorted(cases_dir.glob("*/config.json"))]


def run_one(root: Path, case: str, out_root: Path | None, timeout: float | None) -> dict:
    cmd = [str(root / "analyzer.sh"), case]
    out_dir = None
    if out_root is not None:
        out_dir = out_root / case
        cmd.append(str(out_dir))
    start = time.perf_counter()
    proc = subprocess.run(
        cmd,
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    elapsed = time.perf_counter() - start
    if out_dir is None:
        # analyzer.sh prints the resolved output path. Fall back to out/<case> if
        # parsing fails; this keeps the script useful for ad-hoc cases too.
        for line in proc.stdout.splitlines():
            if line.startswith("[*] output       :"):
                out_dir = Path(line.split(":", 1)[1].strip())
                break
        if out_dir is None:
            out_dir = root / "out" / case
    summary_path = out_dir / "summary.json"
    summary = None
    if summary_path.exists():
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    return {
        "case": case,
        "status": proc.returncode,
        "elapsed_seconds": round(elapsed, 6),
        "output_dir": str(out_dir),
        "summary": summary,
        "log_tail": proc.stdout.splitlines()[-20:],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("cases", nargs="*", help="case names/dirs; default: all cases under cases/")
    ap.add_argument("--cases-dir", type=Path, default=Path("cases"))
    ap.add_argument("--out-root", type=Path, help="write each case output under this directory")
    ap.add_argument("--timeout", type=float, default=None, help="per-case timeout in seconds")
    ap.add_argument("--json-out", type=Path, help="optional path for benchmark JSON")
    args = ap.parse_args()

    root = Path(__file__).resolve().parents[1]
    cases_dir = args.cases_dir if args.cases_dir.is_absolute() else root / args.cases_dir
    case_names = args.cases or discover_cases(root, cases_dir)
    if not case_names:
        print("no cases selected", file=sys.stderr)
        return 2

    out_root = args.out_root
    if out_root is not None:
        out_root = out_root if out_root.is_absolute() else root / out_root
        out_root.mkdir(parents=True, exist_ok=True)

    results = []
    for case in case_names:
        print(f"[*] benchmarking {case}...", file=sys.stderr)
        try:
            result = run_one(root, case, out_root, args.timeout)
        except subprocess.TimeoutExpired as err:
            result = {
                "case": case,
                "status": "timeout",
                "elapsed_seconds": args.timeout,
                "output_dir": None,
                "summary": None,
                "log_tail": (err.stdout or "").splitlines()[-20:],
            }
        results.append(result)
        print(
            f"{case}: status={result['status']} elapsed={result['elapsed_seconds']}s "
            f"violations={(result.get('summary') or {}).get('ownership_violations')}",
            file=sys.stderr,
        )

    payload = {
        "root": str(root),
        "cases": results,
    }
    text = json.dumps(payload, indent=2)
    if args.json_out:
        path = args.json_out if args.json_out.is_absolute() else root / args.json_out
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if all(r["status"] == 0 for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
