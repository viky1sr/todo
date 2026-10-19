//! GF(2^128) helpers for combining POLYVAL segment results (RFC 8452 § 3).
//!
//! The field is GF(2)[x] / (x^128 + x^127 + x^126 + x^121 + 1) with little-endian
//! element encoding. Multiplication of `polyval::hazmat::FieldElement` is the RFC 8452
//! `dot(a, b) = a * b * x^-128`, so the multiplicative identity under `dot` is
//! `x^128 mod P(x)` ([`ONE`]). All powers below are `dot`-powers:
//! `H^(k) = dot(H, dot(H, ... H))` (k factors), with `H^(0) = ONE`.
//!
//! The thesis composition state stores both the local POLYVAL value and `H^blocks`.
//! That makes concatenation self-contained and associative, which is what allows an
//! ordered parallel tree reduction without changing the standard POLYVAL result.
//!
//! This module is crate-private so that the `hazmat` API does not leak to other crates.

use polyval::hazmat::FieldElement;

/// Identity under `dot`: x^128 mod P(x), little-endian.
pub(crate) const ONE: [u8; 16] = [
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xc2,
];

pub(crate) const ZERO: [u8; 16] = [0; 16];

/// `base^(exp)` under `dot`, by square-and-multiply: O(log exp) multiplications.
pub(crate) fn dot_pow(base: FieldElement, mut exp: u64) -> FieldElement {
    let mut acc = FieldElement::from(ONE);
    let mut current = base;
    while exp > 0 {
        if exp & 1 == 1 {
            acc *= current;
        }
        current = current * current;
        exp >>= 1;
    }
    acc
}

/// POLYVAL state for a contiguous block sequence evaluated from the zero state.
///
/// `hash = POLYVAL(H, X_1..X_m)`
/// `blocks = m`
/// `power = H^m` under RFC 8452 `dot` multiplication.
///
/// Keeping `power` in the state makes [`Self::combine`] associative and removes the need
/// for callers to recompute the right-hand exponent during tree reduction.
#[derive(Clone, Copy)]
pub(crate) struct PolyvalPart {
    pub(crate) hash: FieldElement,
    pub(crate) blocks: u64,
    pub(crate) power: FieldElement,
}

impl PolyvalPart {
    /// Identity element for ordered concatenation.
    pub(crate) fn empty() -> Self {
        Self {
            hash: FieldElement::from(ZERO),
            blocks: 0,
            power: FieldElement::from(ONE),
        }
    }

    /// Ordered concatenation of two adjacent POLYVAL parts.
    ///
    /// If `A` precedes `B`, then:
    ///
    /// `P(A || B) = dot(P(A), H^|B|) XOR P(B)`.
    ///
    /// With state `Sigma = (P, n, Q)` and `Q = H^n`, the operator is:
    ///
    /// `(P_A,n_A,Q_A) ⊗ (P_B,n_B,Q_B)`
    /// `= (P_A*Q_B XOR P_B, n_A+n_B, Q_A*Q_B)`.
    ///
    /// This operator is associative but not commutative. Parallel reduction therefore
    /// MUST preserve the original segment order.
    pub(crate) fn combine(self, right: PolyvalPart) -> PolyvalPart {
        PolyvalPart {
            hash: self.hash * right.power + right.hash,
            blocks: self.blocks + right.blocks,
            power: self.power * right.power,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: [u8; 16] = [
        0x25, 0x62, 0x19, 0x0f, 0xd5, 0xa4, 0x0d, 0x13, 0xec, 0xb2, 0x6c, 0xc4, 0x20, 0x95,
        0x7d, 0x5a,
    ];

    fn part(hash_byte: u8, blocks: u64, h: FieldElement) -> PolyvalPart {
        PolyvalPart {
            hash: FieldElement::from([hash_byte; 16]),
            blocks,
            power: dot_pow(h, blocks),
        }
    }

    #[test]
    fn identity_and_zero() {
        let h = FieldElement::from(H);
        let one = FieldElement::from(ONE);
        let zero = FieldElement::from(ZERO);
        assert_eq!(<[u8; 16]>::from(h * one), H);
        assert_eq!(<[u8; 16]>::from(h + zero), H);
        assert_eq!(<[u8; 16]>::from(h + h), ZERO);
    }

    #[test]
    fn dot_pow_laws() {
        let h = FieldElement::from(H);
        assert_eq!(<[u8; 16]>::from(dot_pow(h, 0)), ONE);
        assert_eq!(<[u8; 16]>::from(dot_pow(h, 1)), H);
        assert_eq!(
            <[u8; 16]>::from(dot_pow(h, 3)),
            <[u8; 16]>::from(h * h * h)
        );
        assert_eq!(
            <[u8; 16]>::from(dot_pow(h, 15)),
            <[u8; 16]>::from(dot_pow(h, 7) * dot_pow(h, 8))
        );
    }

    #[test]
    fn empty_is_composition_identity() {
        let h = FieldElement::from(H);
        let a = part(0x11, 3, h);
        let left = PolyvalPart::empty().combine(a);
        let right = a.combine(PolyvalPart::empty());
        assert_eq!(<[u8; 16]>::from(left.hash), <[u8; 16]>::from(a.hash));
        assert_eq!(<[u8; 16]>::from(right.hash), <[u8; 16]>::from(a.hash));
        assert_eq!(left.blocks, a.blocks);
        assert_eq!(right.blocks, a.blocks);
        assert_eq!(<[u8; 16]>::from(left.power), <[u8; 16]>::from(a.power));
        assert_eq!(<[u8; 16]>::from(right.power), <[u8; 16]>::from(a.power));
    }

    #[test]
    fn composition_is_associative() {
        let h = FieldElement::from(H);
        let a = part(0x11, 3, h);
        let b = part(0x22, 5, h);
        let c = part(0x33, 7, h);

        let left = a.combine(b).combine(c);
        let right = a.combine(b.combine(c));

        assert_eq!(<[u8; 16]>::from(left.hash), <[u8; 16]>::from(right.hash));
        assert_eq!(left.blocks, right.blocks);
        assert_eq!(<[u8; 16]>::from(left.power), <[u8; 16]>::from(right.power));
    }
}
