#!/usr/bin/env python3
"""Self-tests for helper scripts; do not require Rust workspace or network."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def run_tool(tool, *args):
    return subprocess.run([sys.executable, str(HERE / tool), *map(str, args)],
                          text=True, capture_output=True)


class HelperTests(unittest.TestCase):
    def test_valid_cid_v1_base32(self):
        raw = bytes([1, 0x70, 0x12, 0x20]) + hashlib.sha256(b"demo").digest()
        cid = "b" + base64.b32encode(raw).decode("ascii").lower().rstrip("=")
        result = run_tool("check_cid.py", cid)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["structurally_valid"])
        self.assertFalse(json.loads(result.stdout)["content_verified"])

    def test_reject_bad_mock_cid(self):
        result = run_tool("check_cid.py", "bafybeigf7b969b0912a860600000073")
        self.assertEqual(result.returncode, 1)

    def test_benchmark_report_synthetic(self):
        fixture = HERE.parent / "assets" / "bench_example.jsonl"
        result = run_tool("summarize_bench.py", fixture)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SYNTHETIC", result.stdout)
        self.assertIn("1.667x", result.stdout)

    def test_benchmark_mismatch_fails(self):
        fixture = HERE.parent / "assets" / "bench_example.jsonl"
        rows = [json.loads(s) for s in fixture.read_text().splitlines() if s.strip()]
        rows[1]["tag_hex"] = "ff" * 16
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "bad.jsonl"
            out.write_text("\n".join(json.dumps(s) for s in rows) + "\n")
            result = run_tool("summarize_bench.py", out)
            self.assertEqual(result.returncode, 1)
            self.assertIn("correctness FAIL", result.stdout)

    def test_preflight_reports_missing_root(self):
        with tempfile.TemporaryDirectory() as temp:
            result = subprocess.run(["bash", str(HERE / "check_workspace.sh"),
                                     "--root", temp, "--mode", "preflight"],
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 2)
            self.assertIn("Cargo.toml not found", result.stderr)

    def test_preflight_accepts_declared_member_layout(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Cargo.toml").write_text("[workspace]\nresolver = '3'\n")
            for name in ("crypto", "zstd", "ipfs", "web", "rest"):
                member = root / "crates" / name
                member.mkdir(parents=True)
                (member / "Cargo.toml").write_text("[package]\nname='demo'\nversion='0.1.0'\n")
            result = subprocess.run(["bash", str(HERE / "check_workspace.sh"),
                                     "--root", temp, "--mode", "preflight"],
                                    text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("PREFLIGHT PASS", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
