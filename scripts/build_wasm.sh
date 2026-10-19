#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "=== Building todo-wasm for target wasm32-unknown-unknown ==="
rustup target add wasm32-unknown-unknown 2>/dev/null || true
cargo build -p todo-wasm --target wasm32-unknown-unknown --release

mkdir -p crates/web/static/wasm
cp target/wasm32-unknown-unknown/release/todo_wasm.wasm crates/web/static/wasm/todo_wasm.wasm

echo "=== WASM artifact copied to crates/web/static/wasm/todo_wasm.wasm ==="
ls -lh crates/web/static/wasm/todo_wasm.wasm
