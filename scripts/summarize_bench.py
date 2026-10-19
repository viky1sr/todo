#!/usr/bin/env python3
"""Review sequential and parallel experimental JSONL trials without external deps.

Marks low sample sizes, identical-output mismatches and one-segment experiments.
The first table is descriptive (median/P95). The paired analysis adds, per case:
geometric-mean speedup of per-trial ratios with a seeded percentile-bootstrap 95% CI,
a two-sided Wilcoxon signed-rank test on log(seq/par) (exact for n <= 30 without ties,
normal approximation otherwise), matched-pairs rank-biserial effect size and a
Holm-Bonferroni correction across cases. End-to-end rows with stage timings also get an
Amdahl prediction from the measured crypto share and crypto-stage speedup.
"""
import argparse
from collections import defaultdict
import csv
import json
import math
from pathlib import Path
import random
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


def wilcoxon_signed_rank(diffs):
    """Two-sided Wilcoxon signed-rank test. Returns (n_used, W+, p, method, r_rb)."""
    d = [x for x in diffs if x != 0.0]
    n = len(d)
    if n == 0:
        return 0, 0.0, 1.0, "no-nonzero-differences", 0.0
    order = sorted(range(n), key=lambda i: abs(d[i]))
    ranks = [0.0] * n
    ties = []
    i = 0
    while i < n:
        j = i
        while j + 1 < n and abs(d[order[j + 1]]) == abs(d[order[i]]):
            j += 1
        avg = (i + j + 2) / 2.0
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        if j > i:
            ties.append(j - i + 1)
        i = j + 1
    w_plus = sum(r for r, x in zip(ranks, d) if x > 0)
    total = n * (n + 1) / 2.0
    r_rb = (2.0 * w_plus - total) / total
    if n <= 30 and not ties:
        counts = [0] * (int(total) + 1)
        counts[0] = 1
        for k in range(1, n + 1):
            for s_ in range(int(total), k - 1, -1):
                counts[s_] += counts[s_ - k]
        all_ = 2 ** n
        w = int(round(w_plus))
        lower = sum(counts[: w + 1]) / all_
        upper = sum(counts[w:]) / all_
        return n, w_plus, min(1.0, 2.0 * min(lower, upper)), "exact", r_rb
    mean = total / 2.0
    var = n * (n + 1) * (2 * n + 1) / 24.0 - sum(t ** 3 - t for t in ties) / 48.0
    if var <= 0:
        return n, w_plus, 1.0, "normal", r_rb
    z = (w_plus - mean - math.copysign(0.5, w_plus - mean)) / math.sqrt(var)
    return n, w_plus, math.erfc(abs(z) / math.sqrt(2.0)), "normal", r_rb


def bootstrap_ci(values, stat, resamples, seed, alpha=0.05):
    rng = random.Random(seed)
    n = len(values)
    boots = sorted(stat([values[rng.randrange(n)] for _ in range(n)]) for _ in range(resamples))
    lo = boots[int(math.floor(alpha / 2 * (resamples - 1)))]
    hi = boots[int(math.ceil((1 - alpha / 2) * (resamples - 1)))]
    return lo, hi


def holm(pvalues):
    order = sorted(range(len(pvalues)), key=lambda i: pvalues[i])
    adjusted = [1.0] * len(pvalues)
    running = 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (len(pvalues) - rank) * pvalues[i]))
        adjusted[i] = running
    return adjusted


def cv(values):
    if len(values) < 2:
        return float("nan")
    return statistics.stdev(values) / statistics.mean(values)


def executed_segments(rows):
    return max(r.get("executed_segments", r["segments"]) for r in rows)


def paired_analysis(pairs, groups, resamples, seed, csv_path):
    per_group = defaultdict(list)
    for (case_id, kind, _trial), arms in pairs.items():
        if len(arms) == 2:
            per_group[(case_id, kind)].append((arms["sequential"], arms["parallel"]))
    keys = sorted(k for k, v in per_group.items() if len(v) >= 2)
    results = []
    for key in keys:
        logs = [math.log(s["total_ns"] / p["total_ns"]) for s, p in per_group[key]]
        n_used, w_plus, p, method, r_rb = wilcoxon_signed_rank(logs)
        gm = math.exp(statistics.mean(logs))
        lo, hi = bootstrap_ci(logs, statistics.mean, resamples, seed)
        par_rows = groups[key]["parallel"]
        results.append({
            "case_id": key[0], "bench_kind": key[1], "n_pairs": len(logs),
            "geo_mean_speedup": gm, "ci95_low": math.exp(lo), "ci95_high": math.exp(hi),
            "wilcoxon_n": n_used, "wilcoxon_w_plus": w_plus, "p_value": p, "test": method,
            "rank_biserial": r_rb,
            "cv_seq": cv([s["total_ns"] for s, _ in per_group[key]]),
            "cv_par": cv([q["total_ns"] for _, q in per_group[key]]),
            "executed_segments": executed_segments(par_rows),
            "threads": max(r["threads"] for r in par_rows),
            "compressed_bytes": par_rows[0]["compressed_bytes"],
        })
    for r, adj in zip(results, holm([r["p_value"] for r in results])):
        r["p_holm"] = adj
        exercised = r["executed_segments"] > 1
        if r["n_pairs"] < 10:
            verdict = "exploratory (n<10)"
        elif r["p_holm"] < 0.05 and r["ci95_low"] > 1.0:
            verdict = "parallel faster"
        elif r["p_holm"] < 0.05 and r["ci95_high"] < 1.0:
            verdict = "parallel slower"
        else:
            verdict = "no significant difference"
        r["verdict"] = verdict if exercised else verdict + "; parallel_not_exercised"

    print("\n## Paired analysis (per-trial ratio seq/par)\n")
    print(f"Bootstrap: {resamples} percentile resamples of mean log-ratio, seed {seed}. "
          "Holm-Bonferroni across all listed cases; alpha = 0.05.\n")
    print("| Case / kind | Pairs | Geo-mean speedup | 95% CI | Wilcoxon p (Holm) | Test | r_rb | CV seq/par | Exec. segs | Verdict |")
    print("|---|---:|---:|---|---:|---|---:|---|---:|---|")
    for r in results:
        print(f"| {r['case_id']} / {r['bench_kind']} | {r['n_pairs']} | {r['geo_mean_speedup']:.3f}x | "
              f"[{r['ci95_low']:.3f}, {r['ci95_high']:.3f}] | {r['p_value']:.2e} ({r['p_holm']:.2e}) | "
              f"{r['test']} | {r['rank_biserial']:+.2f} | {r['cv_seq']:.3f}/{r['cv_par']:.3f} | "
              f"{r['executed_segments']} | {r['verdict']} |")
    if csv_path:
        with open(csv_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(results[0].keys()) if results else ["case_id"])
            writer.writeheader()
            writer.writerows(results)
    return results


CRYPTO_STAGES = ("encrypt_total_ns", "decrypt_ns")


def amdahl_analysis(groups):
    lines = []
    for key, arms in sorted(groups.items()):
        seq, par = arms.get("sequential", []), arms.get("parallel", [])
        if not seq or not par or not all(k in r for r in seq + par for k in CRYPTO_STAGES):
            continue
        crypto = lambda r: sum(r[k] for k in CRYPTO_STAGES)
        share = statistics.median(crypto(r) / r["total_ns"] for r in seq)
        s_crypto = statistics.median(crypto(r) for r in seq) / statistics.median(crypto(r) for r in par)
        predicted = 1.0 / ((1.0 - share) + share / s_crypto)
        bound = 1.0 / (1.0 - share) if share < 1 else float("inf")
        observed = statistics.median(r["total_ns"] for r in seq) / statistics.median(r["total_ns"] for r in par)
        lines.append(f"| {key[0]} / {key[1]} | {share * 100:.2f}% | {s_crypto:.3f}x | {predicted:.3f}x | {bound:.3f}x | {observed:.3f}x |")
    if lines:
        print("\n## Amdahl check (stage timings of the sequential arm)\n")
        print("Crypto share f = median((encrypt+decrypt)/total); predicted = 1/((1-f)+f/s_crypto); "
              "bound = 1/(1-f) for infinitely fast crypto. Other stages (e.g. parallel frame "
              "compression) are not modelled, so independent-frames can exceed the bound.\n")
        print("| Case / kind | Crypto share f | Crypto speedup | Amdahl predicted | Bound | Observed (P50) |")
        print("|---|---:|---:|---:|---:|---:|")
        for line in lines:
            print(line)


def summarize(rows, resamples=10000, seed=12345, csv_path=None):
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
        if executed_segments(par) <= 1:
            warnings.append(f"{key}: parallel_not_exercised (only one segment)")
        if len(threads) != 1 or len(segs) != 1:
            warnings.append(f"{key}: mixed thread/segment config; split case_id")
        print(f"| {key[0]} / {key[1]} | {len(seq)}/{len(par)} | {s_med:.4f} | {p_med:.4f} | {s_p95:.4f} | {p_p95:.4f} | {s_med/p_med:.3f}x | {','.join(map(str, sorted(threads)))} | {','.join(map(str, sorted(segs)))} |")
    paired_analysis(pairs, groups, resamples, seed, csv_path)
    amdahl_analysis(groups)
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
    ap.add_argument("--bootstrap", type=int, default=10000, help="bootstrap resamples")
    ap.add_argument("--seed", type=int, default=12345, help="bootstrap seed")
    ap.add_argument("--csv", type=Path, help="write the paired analysis as CSV")
    args = ap.parse_args()
    try:
        return summarize(read_rows(args.jsonl), args.bootstrap, args.seed, args.csv)
    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
