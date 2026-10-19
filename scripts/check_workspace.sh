#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)"
MODE=preflight
usage() {
  printf 'Usage: %s [--root DIR] [--mode preflight|check|release]\n' "$0"
}
while (($#)); do
  case "$1" in
    --root) if (($# < 2)); then usage >&2; exit 2; fi; ROOT="$2"; shift 2;;
    --mode) if (($# < 2)); then usage >&2; exit 2; fi; MODE="$2"; shift 2;;
    --help|-h) usage; exit 0;;
    *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 2;;
  esac
done
if [[ ! -d "$ROOT" ]]; then printf 'ERROR: root directory missing: %s\n' "$ROOT" >&2; exit 2; fi
ROOT="$(CDPATH='' cd -- "$ROOT" && pwd)"
if [[ ! -f "$ROOT/Cargo.toml" ]]; then
  printf 'ERROR: Cargo.toml not found in %s (this is a skill bundle, not a Rust repository).\n' "$ROOT" >&2
  exit 2
fi
case "$MODE" in preflight|check|release) ;; *) printf 'Unknown mode: %s\n' "$MODE" >&2; exit 2;; esac
printf 'Root: %s\n' "$ROOT"
if command -v rustc >/dev/null 2>&1; then rustc --version; else printf 'rustc: NOT INSTALLED\n'; fi
if command -v cargo >/dev/null 2>&1; then cargo --version; else printf 'cargo: NOT INSTALLED\n'; fi
if [[ -f "$ROOT/Cargo.lock" ]]; then
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$ROOT/Cargo.lock"; fi
else printf 'WARN: Cargo.lock missing (do not regenerate without review).\n'; fi
missing=0
for p in crates/crypto crates/zstd crates/ipfs crates/web crates/rest; do
  if [[ ! -f "$ROOT/$p/Cargo.toml" ]]; then
    printf 'MISSING MEMBER: %s/Cargo.toml\n' "$p"
    missing=$((missing + 1))
  else
    printf 'FOUND MEMBER: %s\n' "$p"
  fi
done
if ((missing > 0)); then
  printf 'ERROR: %d declared crate manifests are missing. Inspect Cargo.toml and repository checkout.\n' "$missing" >&2
  exit 2
fi
if [[ "$MODE" == preflight ]]; then printf 'PREFLIGHT PASS: structure found; builds/tests NOT RUN.\n'; exit 0; fi
if ! command -v cargo >/dev/null 2>&1; then
  printf 'ERROR: cargo is needed for mode=%s\n' "$MODE" >&2
  exit 2
fi
cd "$ROOT"
commands=(
  'cargo fmt --all -- --check'
  'cargo check --workspace --all-targets'
  'cargo clippy --workspace --all-targets -- -D warnings'
  'cargo test --workspace'
)
if [[ "$MODE" == release ]]; then
  commands+=( 'cargo test --workspace --release' 'cargo build --release' )
fi
for line in "${commands[@]}"; do
  printf '\nRUN: %s\n' "$line"
  # Commands are predefined constants; do not evaluate untrusted CLI inputs.
  if ! bash -c "$line"; then
    printf 'FAILED: %s\n' "$line" >&2
    exit 1
  fi
done
printf '\nPASSED: requested workspace validation commands. Benchmark NOT RUN.\n'
