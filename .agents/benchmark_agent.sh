#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "  BENCHMARK AGENT: THROUGHPUT & LATENCY EVALUATION        "
echo "=========================================================="

echo -e "\n[1/2] Executing optimized release evaluation binary..."
cargo run --release

echo -e "\n[2/2] Running Criterion Microbenchmarks (sampling)..."
cargo bench -p todo-crypto --bench polyval_benchmark -- --sample-size 10

echo -e "\n=========================================================="
echo "  [SUCCESS] Benchmark Suite completed!"
echo "=========================================================="
