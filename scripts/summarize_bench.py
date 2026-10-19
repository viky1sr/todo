#!/usr/bin/env python3
"""Review sequential and parallel experimental JSONL trials without external deps.

Marks low sample sizes, identical-output mismatches and one-segment experiments.
Statistics are descriptive (median/P95), not inferential confidence intervals.
"""
import argparse
from collections import defaultdict
import json
import math
from pathlib import Path
import statistics
import sys

REQUIRED = ("case_id", "bench_kind", "implementation", "trial", "original_bytes",
            "compressed_bytes", "polyval_bytes", "segments", "segment_bytes",
            "threads", "total_ns")
NONNEG = ("original_bytes", "compressed_bytes", "polyval_bytes")
POSITIVE = ("segments", "segment_bytes", "threads", "total_ns")


def read_rows(path: Path):
    rows = []
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {line_no}: JSON error {exc}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"line {line_no}: expected JSON object")
        absent = [k for k in REQUIRED if k not in row]
        if absent:
            raise ValueError(f"line {line_no}: missing {', '.join(absent)}")
        if row["implementation"] not in ("sequential", "parallel"):
            raise ValueError(f"line {line_no}: unknown implementation")
        if not isinstance(row["trial"], int) or isinstance(row["trial"], bool) or row["trial"] < 1:
            raise ValueError(f"line {line_no}: trial must be positive integer")
        if not isinstance(row["case_id"], str) or not row["case_id"].strip():
            raise ValueError(f"line {line_no}: case_id missing")
        if not isinstance(row["bench_kind"], str) or not row["bench_kind"].strip():
            raise ValueError(f"line {line_no}: bench_kind missing")
        for k in NONNEG + POSITIVE:
            if not isinstance(row[k], int) or isinstance(row[k], bool) or row[k] < (1 if k in POSITIVE else 0):
                raise ValueError(f"line {line_no}: {k} invalid")
        for optional_key, n in (("tag_hex", 32), ("ciphertext_sha256", 64)):
            if optional_key in row:
                val = row[optional_key]
                if not isinstance(val, str) or len(val) != n or any(c not in "0123456789abcdefABCDEF" for c in val):
                    raise ValueError(f"line {line_no}: {optional_key} should be {n} hex chars")
        rows.append(row)
    if not rows:
        raise ValueError("no benchmark measurements supplied")
    return rows


def percentile(sorted_values, p):
    return sorted_values[max(0, math.ceil(p * len(sorted_values)) - 1)]


def summarize(rows):
    pairs = defaultdict(dict)
    groups = defaultdict(lambda: defaultdict(list))
    errors = []
    warnings = []
    for row in rows:
        pair_key = (row["case_id"], row["bench_kind"], row["trial"])
        impl = row["implementation"]
        if impl in pairs[pair_key]:
            errors.append(f"duplicate pair {pair_key} / {impl}")
        pairs[pair_key][impl] = row
        groups[(row["case_id"], row["bench_kind"])][impl].append(row)
    for pair_key, arms in sorted(pairs.items()):
        if len(arms) != 2:
            warnings.append(f"{pair_key}: unpaired trial")
            continue
        seq, par = arms["sequential"], arms["parallel"]
        for field in ("original_bytes", "compressed_bytes", "polyval_bytes", "segment_bytes", "segments"):
            if seq[field] != par[field]:
                errors.append(f"{pair_key}: different {field}, comparison invalid")
        for field in ("tag_hex", "ciphertext_sha256"):
            if field in seq and field in par and seq[field].lower() != par[field].lower():
                errors.append(f"{pair_key}: {field} mismatch (correctness FAIL)")
            if field not in seq or field not in par:
                warnings.append(f"{pair_key}: {field} not verified")
    print("# Benchmark descriptive summary\n")
    print("| Case / kind | N seq/par | Seq P50 ms | Par P50 ms | Seq P95 ms | Par P95 ms | Speedup | Par threads | Segments |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for key, arms in sorted(groups.items()):
        if "sequential" not in arms or "parallel" not in arms:
            warnings.append(f"{key}: missing comparator")
            continue
        seq, par = arms["sequential"], arms["parallel"]
        sv = sorted(x["total_ns"] / 1e6 for x in seq)
        pv = sorted(x["total_ns"] / 1e6 for x in par)
        s_med, p_med = statistics.median(sv), statistics.median(pv)
        s_p95, p_p95 = percentile(sv, .95), percentile(pv, .95)
        threads = {r["threads"] for r in par}
        segs = {r["segments"] for r in par}
        if len(seq) < 10 or len(par) < 10:
            warnings.append(f"{key}: fewer than 10 trials per arm; exploratory only")
        if max(segs) <= 1:
            warnings.append(f"{key}: parallel_not_exercised (only one segment)")
        if len(threads) != 1 or len(segs) != 1:
            warnings.append(f"{key}: mixed thread/segment config; split case_id")
        print(f"| {key[0]} / {key[1]} | {len(seq)}/{len(par)} | {s_med:.4f} | {p_med:.4f} | {s_p95:.4f} | {p_p95:.4f} | {s_med/p_med:.3f}x | {','.join(map(str, sorted(threads)))} | {','.join(map(str, sorted(segs)))} |")
    if any(r.get("synthetic_example") for r in rows):
        warnings.append("SYNTHETIC SAMPLE DATA: do not cite as thesis results")
    print("\nCorrectness: " + ("FAIL" if errors else "NO DETECTED MISMATCH (not a substitute for oracle tests)"))
    for title, messages in (("ERROR", errors), ("WARN", sorted(set(warnings)))):
        for msg in messages:
            print(f"{title}: {msg}")
    return 1 if errors else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("jsonl", type=Path)
    args = ap.parse_args()
    try:
        return summarize(read_rows(args.jsonl))
    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
