//! Sequential POLYVAL (RFC 8452 § 3) — the reference baseline.
//!
//! Delegates entirely to the `polyval` crate (`UniversalHash::update_padded`), i.e. the
//! standard Horner evaluation `S_i = dot(S_{i-1} XOR X_i, H)`.

use crate::gf128::{PolyvalPart, dot_pow};
use polyval::Polyval;
use polyval::hazmat::FieldElement;
use universal_hash::UniversalHash;

fn new_polyval(h_key: &[u8; 16]) -> Polyval {
    Polyval::new(&polyval::Key::from(*h_key))
}

/// POLYVAL over `data`, zero-padding the final partial block (if any) to 16 bytes.
///
/// This equals `POLYVAL(H, pad16(data))`, matching how RFC 8452 hashes AAD and plaintext.
pub fn polyval_sequential(h_key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut poly = new_polyval(h_key);
    poly.update_padded(data);
    poly.finalize().into()
}

/// Same as [`polyval_sequential`], returning the self-contained composition state
/// `(hash, blocks, H^blocks)` used by the ordered tree reducer.
pub(crate) fn polyval_part_sequential(h_key: &[u8; 16], data: &[u8]) -> PolyvalPart {
    let blocks = data.len().div_ceil(16) as u64;
    let h = FieldElement::from(*h_key);
    polyval_part_sequential_with_power(h_key, data, blocks, dot_pow(h, blocks))
}

/// Build a local POLYVAL state when the caller already has the correct `H^blocks`.
/// This avoids recomputing the same power for every full-sized parallel segment.
pub(crate) fn polyval_part_sequential_with_power(
    h_key: &[u8; 16],
    data: &[u8],
    blocks: u64,
    power: FieldElement,
) -> PolyvalPart {
    debug_assert_eq!(blocks, data.len().div_ceil(16) as u64);
    let hash: [u8; 16] = polyval_sequential(h_key, data);
    PolyvalPart {
        hash: FieldElement::from(hash),
        blocks,
        power,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn rfc8452_c1_polyval_example() {
        // RFC 8452 Appendix C.1, 16-byte plaintext example (POLYVAL input/result).
        let h = hex!("d9b360279694941ac5dbc6987ada7377");
        let input = hex!("01000000000000000000000000000000 00000000000000008000000000000000");
        assert_eq!(
            polyval_sequential(&h, &input),
            hex!("20806c26e3c1de019e111255708031d6")
        );
    }

    #[test]
    fn rfc8452_appendix_a_worked_example() {
        // RFC 8452 Appendix A worked example.
        let h = hex!("25629347589242761d31f826ba4b757b");
        let input = hex!("4f4f95668c83dfb6401762bb2d01a262 d1a24ddd2721d006bbe45f20d3c9f362");
        assert_eq!(
            polyval_sequential(&h, &input),
            hex!("f7a3b47b846119fae5b7866cf5e5b77e")
        );
    }
}
