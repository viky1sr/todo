#!/usr/bin/env python3
"""Perform strict structural validation of a CIDv1 base32lower string.

Checks multibase encoding, CID structure and multihash length.
Does NOT verify content or contact an IPFS backend.
"""
import argparse
import base64
import json
import re
import sys


def decode_varint(data: bytes, pos: int):
    value, shift, start = 0, 0, pos
    while pos < len(data) and pos - start < 10:
        byte = data[pos]
        pos += 1
        if shift == 63 and byte > 1:
            raise ValueError("varint exceeds unsigned 64-bit limit")
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            minimal = []
            v = value
            while v >= 0x80:
                minimal.append((v & 0x7F) | 0x80)
                v >>= 7
            minimal.append(v)
            if bytes(minimal) != data[start:pos]:
                raise ValueError("noncanonical varint")
            return value, pos
        shift += 7
    raise ValueError("truncated or oversized varint")


def inspect_cid(cid: str):
    if not cid.startswith("b") or not re.fullmatch(r"b[a-z2-7]+", cid):
        raise ValueError("expected CIDv1 multibase 'b' + base32lower ([a-z2-7])")
    payload = cid[1:]
    padded = payload.upper() + "=" * ((-len(payload)) % 8)
    try:
        raw = base64.b32decode(padded, casefold=False)
    except Exception as exc:
        raise ValueError(f"invalid base32 encoding: {exc}") from exc
    if "b" + base64.b32encode(raw).decode().lower().rstrip("=") != cid:
        raise ValueError("noncanonical Base32 representation")
    version, at = decode_varint(raw, 0)
    if version != 1:
        raise ValueError(f"unsupported version {version}; CIDv1 required")
    codec, at = decode_varint(raw, at)
    mh_code, at = decode_varint(raw, at)
    mh_len, at = decode_varint(raw, at)
    if codec <= 0 or mh_code <= 0 or mh_len <= 0:
        raise ValueError("invalid codec or multihash identifiers/length")
    if mh_len != len(raw) - at:
        raise ValueError(f"multihash length {mh_len} does not match {len(raw) - at}")
    known_lengths = {0x12: 32, 0x13: 64, 0x1E: 32}
    if mh_code in known_lengths and mh_len != known_lengths[mh_code]:
        raise ValueError("digest size does not match known multihash algorithm")
    return {"structurally_valid": True, "cid_version": version,
            "codec_code": codec, "multihash_code": mh_code,
            "digest_bytes": mh_len, "content_verified": False,
            "storage_backend_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cid", help="CIDv1 base32lower string")
    args = parser.parse_args()
    try:
        print(json.dumps(inspect_cid(args.cid), indent=2))
    except ValueError as exc:
        print(f"CID INVALID: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
