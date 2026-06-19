#!/usr/bin/env python3
"""Generate metadata.json and analysis.md for all OSS-Fuzz dataset cases."""
import json, os, re, subprocess, sys
from collections import Counter

DATASET = "dataset"
VERIFICATION = "tests/ossfuzz/FULL_VERIFICATION.md"

def parse_verification():
    """Parse FULL_VERIFICATION.md to get bug info per case."""
    info = {}
    if not os.path.exists(VERIFICATION):
        return info
    with open(VERIFICATION) as f:
        for line in f:
            m = re.match(r'\|\s*\d+\s*\|\s*(osv_\d+_\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|', line)
            if m:
                osv = m.group(1)
                info[osv] = {
                    "lines_ref": int(m.group(2)),
                    "uaf_ref": int(m.group(3)),
                    "cross_ref": int(m.group(4)),
                    "key_funcs": m.group(5).strip(),
                    "match": m.group(6).strip(),
                }
    return info

def get_detection_counts(logpath):
    """Parse raw.log and return detection type counts."""
    counts = Counter()
    total = 0
    if not os.path.exists(logpath):
        return 0, counts
    with open(logpath) as f:
        for line in f:
            total += 1
            m = re.match(r'\[([^\]]+)\]', line)
            if m:
                counts[m.group(1)] += 1
    return total, counts

def get_project_name(src_dir):
    """Try to identify the project from source files or build.sh."""
    osv = os.path.basename(src_dir).replace("ossfuzz_", "")
    test_src = os.path.join("tests/ossfuzz", osv)
    build_sh = os.path.join(test_src, "build.sh")
    if os.path.exists(build_sh):
        with open(build_sh) as f:
            content = f.read()
            for proj in ["libxml2", "libpcap", "harfbuzz", "libarchive", "libpng",
                         "openssl", "openh264", "wabt", "lcms", "libgit2", "lz4",
                         "c-ares", "wolfssl", "p11-kit", "systemd", "json-c",
                         "libwebp", "openjpeg", "mruby", "pcre2", "freetype",
                         "libtiff", "curl", "sqlite", "zstd", "brotli", "re2",
                         "blosc", "oniguruma", "clamav"]:
                if proj in content.lower():
                    return proj
    return "unknown"

def main():
    verify_info = parse_verification()

    dirs = sorted([d for d in os.listdir(DATASET) if d.startswith("ossfuzz_")])
    created = 0

    for dirname in dirs:
        dirpath = os.path.join(DATASET, dirname)
        osv = dirname.replace("ossfuzz_", "")
        logpath = os.path.join(dirpath, "lancet", "raw.log")

        total, counts = get_detection_counts(logpath)

        # Get binary name
        bindir = os.path.join(dirpath, "bin")
        bins = os.listdir(bindir) if os.path.exists(bindir) else []
        binname = bins[0] if bins else "unknown"

        # Get poc name
        pocdir = os.path.join(dirpath, "poc")
        pocs = os.listdir(pocdir) if os.path.exists(pocdir) else []
        pocname = pocs[0] if pocs else "none"

        project = get_project_name(dirpath)
        vinfo = verify_info.get(osv, {})

        # metadata.json
        meta = {
            "name": osv,
            "target": project,
            "binary": f"bin/{binname}",
            "poc": f"poc/{pocname}" if pocname != "none" else "none",
            "lancet_output": "lancet/raw.log",
            "detection_summary": {"total_lines": total},
            "detected": total > 0,
        }

        # Add top detection types
        for det_type, cnt in counts.most_common(10):
            key = det_type.replace(" ", "_").replace("->", "").lower()
            meta["detection_summary"][key] = cnt

        if vinfo:
            meta["key_functions"] = vinfo.get("key_funcs", "")
            meta["verification_match"] = vinfo.get("match", "")

        meta_path = os.path.join(dirpath, "metadata.json")
        with open(meta_path, 'w') as f:
            json.dump(meta, f, indent=2)

        # analysis.md — minimal
        top_dets = counts.most_common(5)
        det_table = "  ".join(f"{t}: {c}" for t, c in top_dets) if top_dets else "none"

        # Get first key log line
        key_line = ""
        if os.path.exists(logpath) and total > 0:
            with open(logpath) as f:
                for line in f:
                    if any(k in line for k in ["UAF", "CROSSBOUNDARY", "HIJACK", "CRASH", "PIVOT"]):
                        key_line = line.strip()
                        break
                if not key_line:
                    f.seek(0)
                    key_line = f.readline().strip()

        analysis = f"""# {osv} — {project}

## Detection: {total} lines
{det_table}

## Key line
```
{key_line}
```
"""
        anal_path = os.path.join(dirpath, "analysis.md")
        with open(anal_path, 'w') as f:
            f.write(analysis)

        created += 1

    print(f"Generated metadata+analysis for {created} OSS-Fuzz cases")

if __name__ == "__main__":
    main()
