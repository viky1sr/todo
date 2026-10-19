//! The multibase encodings CIDs need (https://github.com/multiformats/multibase):
//! `base32` (RFC 4648, lowercase, no padding, prefix `b`; uppercase `B` accepted on
//! input) and `base58btc` (prefix `z`, and unprefixed for CIDv0).

use crate::error::IpfsError;

const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(BASE32[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Strict decoder: rejects padding, mixed case, invalid lengths and non-zero tail bits.
pub fn base32_decode(text: &str) -> Result<Vec<u8>, IpfsError> {
    let invalid = |why: &str| IpfsError::InvalidCid(format!("base32: {why}"));
    if matches!(text.len() % 8, 1 | 3 | 6) {
        return Err(invalid("invalid length"));
    }
    let upper = text.bytes().any(|c| c.is_ascii_uppercase());
    let lower = text.bytes().any(|c| c.is_ascii_lowercase());
    if upper && lower {
        return Err(invalid("mixed case"));
    }
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in text.bytes() {
        let value = match c.to_ascii_lowercase() {
            c @ b'a'..=b'z' => c - b'a',
            c @ b'2'..=b'7' => c - b'2' + 26,
            _ => return Err(invalid("invalid character")),
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    if buffer & ((1 << bits) - 1) != 0 {
        return Err(invalid("non-zero trailing bits"));
    }
    Ok(out)
}

pub fn base58_encode(data: &[u8]) -> String {
    let zeros = data.iter().take_while(|&&b| b == 0).count();
    // Little-endian base-58 digits.
    let mut digits: Vec<u8> = Vec::with_capacity(data.len() * 138 / 100 + 1);
    for &byte in &data[zeros..] {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut() {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    out.extend(std::iter::repeat_n('1', zeros));
    out.extend(digits.iter().rev().map(|&d| BASE58[d as usize] as char));
    out
}

pub fn base58_decode(text: &str) -> Result<Vec<u8>, IpfsError> {
    let zeros = text.bytes().take_while(|&c| c == b'1').count();
    let mut bytes: Vec<u8> = Vec::with_capacity(text.len());
    for c in text.bytes().skip(zeros) {
        let mut carry = BASE58
            .iter()
            .position(|&a| a == c)
            .ok_or_else(|| IpfsError::InvalidCid("base58btc: invalid character".into()))?
            as u32;
        for byte in bytes.iter_mut() {
            carry += u32::from(*byte) * 58;
            *byte = carry as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push(carry as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_rfc4648_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "my"),
            ("fo", "mzxq"),
            ("foo", "mzxw6"),
            ("foob", "mzxw6yq"),
            ("fooba", "mzxw6ytb"),
            ("foobar", "mzxw6ytboi"),
        ] {
            assert_eq!(base32_encode(plain.as_bytes()), encoded);
            assert_eq!(base32_decode(encoded).unwrap(), plain.as_bytes());
            assert_eq!(
                base32_decode(&encoded.to_ascii_uppercase()).unwrap(),
                plain.as_bytes()
            );
        }
    }

    #[test]
    fn base32_rejects_noncanonical() {
        assert!(base32_decode("mz").is_err()); // non-zero trailing bits
        assert!(base32_decode("m").is_err()); // impossible length
        assert!(base32_decode("mzxW6").is_err()); // mixed case
        assert!(base32_decode("mzx=").is_err());
        assert!(base32_decode("mzx1").is_err());
    }

    #[test]
    fn base58_vectors() {
        for (plain, encoded) in [
            (&b""[..], ""),
            (b"\x00", "1"),
            (b"\x00\x00\x01", "112"),
            (b"hello world", "StV1DL6CwTryKyV"),
            (b"Hello World!", "2NEpo7TZRRrLZSi2U"),
        ] {
            assert_eq!(base58_encode(plain), encoded);
            assert_eq!(base58_decode(encoded).unwrap(), plain);
        }
        assert!(base58_decode("0OIl").is_err());
    }
}
