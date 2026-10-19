#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "  CI/CD VALIDATOR: PARALLEL POLYVAL / AES-GCM-SIV + ZSTD  "
echo "  Rust Edition 2024 | Compiler: $(rustc --version)        "
echo "=========================================================="

echo -e "\n[1/6] Checking formatting..."
cargo fmt --all -- --check

echo -e "\n[2/6] Running clippy (warnings are errors)..."
cargo clippy --workspace --all-targets -- -D warnings

echo -e "\n[3/6] Running all unit and integration tests..."
cargo test --workspace

echo -e "\n[4/6] Running RFC 8452 Appendix C test vectors..."
cargo test -p todo-crypto --test rfc8452_vectors

echo -e "\n[5/6] Running sequential/parallel/upstream equivalence tests..."
cargo test -p todo-crypto --test equivalence_proof

echo -e "\n[6/6] Building benchmarks..."
cargo bench -p todo-crypto --no-run

echo -e "\n=========================================================="
echo "  [SUCCESS] All checks passed."
echo "=========================================================="
