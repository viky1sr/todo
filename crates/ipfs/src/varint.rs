//! Multiformats unsigned varint (https://github.com/multiformats/unsigned-varint).
//!
//! LEB128, at most 9 bytes (63 bits), and minimally encoded.

use crate::error::IpfsError;

const MAX_LEN: usize = 9;

pub fn encode(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Decode one varint from the start of `data`; returns the value and bytes consumed.
pub fn decode(data: &[u8]) -> Result<(u64, usize), IpfsError> {
    let mut value = 0u64;
    for (i, &byte) in data.iter().enumerate().take(MAX_LEN) {
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            if byte == 0 && i > 0 {
                return Err(IpfsError::InvalidCid("non-minimal varint".into()));
            }
            return Ok((value, i + 1));
        }
    }
    if data.len() >= MAX_LEN {
        Err(IpfsError::InvalidCid("varint longer than 9 bytes".into()))
    } else {
        Err(IpfsError::InvalidCid("truncated varint".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_examples_roundtrip() {
        for (value, bytes) in [
            (1u64, &[0x01][..]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (255, &[0xff, 0x01]),
            (300, &[0xac, 0x02]),
            (16384, &[0x80, 0x80, 0x01]),
            (0x0129, &[0xa9, 0x02]),
        ] {
            let mut out = Vec::new();
            encode(value, &mut out);
            assert_eq!(out, bytes);
            assert_eq!(decode(bytes).unwrap(), (value, bytes.len()));
        }
        let mut out = Vec::new();
        encode((1 << 63) - 1, &mut out);
        assert_eq!(out.len(), 9);
        assert_eq!(decode(&out).unwrap(), ((1 << 63) - 1, 9));
    }

    #[test]
    fn rejects_invalid() {
        assert!(decode(&[]).is_err());
        assert!(decode(&[0x80]).is_err());
        assert!(decode(&[0x81, 0x00]).is_err());
        assert!(decode(&[0xff; 10]).is_err());
    }
}
