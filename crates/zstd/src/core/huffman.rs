//! Huffman coding of literals (RFC 8878 §4.2).
//!
//! Weights describe a canonical prefix code: a symbol of weight `w > 0` uses
//! `max_bits + 1 - w` bits. The last symbol's weight is implicit. Decoding uses a flat
//! `2^max_bits` lookup table built in the same order as `HUF_readDTableX1`.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use super::bitstream::{BitWriter, ReverseBitReader};
use super::fse::{compress_interleaved2, decompress_interleaved2, highbit};
use super::{CoreError, Result};

/// Maximum code length accepted when decoding (reference decoder: `HUF_TABLELOG_MAX`).
pub const HUF_MAX_BITS_DECODE: u32 = 12;
/// Maximum code length produced by the encoder (RFC 8878: `Max_Number_of_Bits` = 11).
pub const HUF_MAX_BITS_ENCODE: u32 = 11;
/// Accuracy log limit of the FSE table describing Huffman weights.
const WEIGHTS_FSE_MAX_LOG: u32 = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HuffmanTable {
    pub max_bits: u32,
    /// Indexed by the next `max_bits` bits of the stream: `(symbol, code length)`.
    pub decode: Vec<(u8, u8)>,
}

impl HuffmanTable {
    /// Build from explicit weights of symbols `0..weights.len() - 1` plus the implicit last.
    pub fn from_weights(mut weights: Vec<u8>) -> Result<Self> {
        if weights.is_empty() || weights.len() > 255 {
            return Err(CoreError::Corrupted("Huffman weight count"));
        }
        let mut sum: u32 = 0;
        for &w in &weights {
            if u32::from(w) > HUF_MAX_BITS_DECODE {
                return Err(CoreError::Corrupted("Huffman weight too large"));
            }
            if w > 0 {
                sum += 1 << (w - 1);
            }
        }
        if sum == 0 {
            return Err(CoreError::Corrupted("Huffman weights all zero"));
        }
        let max_bits = highbit(sum) + 1;
        if max_bits > HUF_MAX_BITS_DECODE {
            return Err(CoreError::Corrupted("Huffman code too long"));
        }
        let left = (1u32 << max_bits) - sum;
        if !left.is_power_of_two() {
            return Err(CoreError::Corrupted("Huffman weights not a complete code"));
        }
        weights.push((highbit(left) + 1) as u8);

        let mut rank_count = [0u32; HUF_MAX_BITS_DECODE as usize + 2];
        for &w in &weights {
            rank_count[w as usize] += 1;
        }
        let mut rank_start = [0u32; HUF_MAX_BITS_DECODE as usize + 2];
        let mut next = 0u32;
        for w in 1..=max_bits as usize {
            rank_start[w] = next;
            next += rank_count[w] << (w - 1);
        }
        let mut decode = vec![(0u8, 0u8); 1 << max_bits];
        for (s, &w) in weights.iter().enumerate() {
            if w == 0 {
                continue;
            }
            let len = 1u32 << (w - 1);
            let start = rank_start[w as usize];
            let entry = (s as u8, (max_bits + 1 - u32::from(w)) as u8);
            decode[start as usize..(start + len) as usize].fill(entry);
            rank_start[w as usize] += len;
        }
        Ok(Self { max_bits, decode })
    }

    /// Decode one backward stream into exactly `count` symbols appended to `out`.
    pub fn decode_stream(&self, stream: &[u8], count: usize, out: &mut Vec<u8>) -> Result<()> {
        let mut r = ReverseBitReader::new(stream)?;
        out.reserve(count);
        for _ in 0..count {
            let (sym, nb) = self.decode[r.peek(self.max_bits) as usize];
            out.push(sym);
            r.consume(u32::from(nb));
        }
        if !r.is_finished() {
            return Err(CoreError::Corrupted("Huffman stream size mismatch"));
        }
        Ok(())
    }

    /// Decode a 1- or 4-stream Huffman literals payload (after the tree description).
    pub fn decode_literals(
        &self,
        data: &[u8],
        regenerated: usize,
        four_streams: bool,
    ) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(regenerated);
        if !four_streams {
            self.decode_stream(data, regenerated, &mut out)?;
            return Ok(out);
        }
        if data.len() < 6 {
            return Err(CoreError::Truncated("Huffman jump table"));
        }
        let s1 = usize::from(u16::from_le_bytes([data[0], data[1]]));
        let s2 = usize::from(u16::from_le_bytes([data[2], data[3]]));
        let s3 = usize::from(u16::from_le_bytes([data[4], data[5]]));
        let body = &data[6..];
        if s1 + s2 + s3 > body.len() {
            return Err(CoreError::Corrupted("Huffman jump table exceeds payload"));
        }
        let seg = regenerated.div_ceil(4);
        if 3 * seg > regenerated {
            return Err(CoreError::Corrupted("too few literals for four streams"));
        }
        let (a, rest) = body.split_at(s1);
        let (b, rest) = rest.split_at(s2);
        let (c, d) = rest.split_at(s3);
        self.decode_stream(a, seg, &mut out)?;
        self.decode_stream(b, seg, &mut out)?;
        self.decode_stream(c, seg, &mut out)?;
        self.decode_stream(d, regenerated - 3 * seg, &mut out)?;
        Ok(out)
    }
}

/// Parse a Huffman tree description. Returns the table and the bytes consumed.
pub fn read_table(data: &[u8]) -> Result<(HuffmanTable, usize)> {
    let header = *data.first().ok_or(CoreError::Truncated("Huffman header"))? as usize;
    if header < 128 {
        let body = data
            .get(1..1 + header)
            .ok_or(CoreError::Truncated("Huffman FSE weights"))?;
        let weights = decompress_interleaved2(body, WEIGHTS_FSE_MAX_LOG, 255)?;
        Ok((HuffmanTable::from_weights(weights)?, 1 + header))
    } else {
        let count = header - 127;
        let bytes = count.div_ceil(2);
        let body = data
            .get(1..1 + bytes)
            .ok_or(CoreError::Truncated("Huffman direct weights"))?;
        let weights = (0..count)
            .map(|i| {
                let b = body[i / 2];
                if i % 2 == 0 { b >> 4 } else { b & 0x0F }
            })
            .collect();
        Ok((HuffmanTable::from_weights(weights)?, 1 + bytes))
    }
}

/// Encoder-side Huffman code.
#[derive(Debug, Clone)]
pub struct HuffmanEncoder {
    /// `(code, length)` per byte value; length 0 means absent.
    codes: [(u32, u8); 256],
    /// Serialized tree description (header byte + weights).
    pub description: Vec<u8>,
}

/// Length-limited Huffman code lengths. Counts are halved until the limit holds.
fn code_lengths(counts: &[u32; 256], limit: u32) -> [u8; 256] {
    let mut scaled = *counts;
    loop {
        let mut lengths = [0u8; 256];
        // Nodes: leaves 0..256 then internal nodes; parent links give depths.
        let mut parent: Vec<usize> = vec![usize::MAX; 256];
        let mut heap = BinaryHeap::new();
        for (s, &c) in scaled.iter().enumerate() {
            if c > 0 {
                heap.push(Reverse((u64::from(c), s)));
            }
        }
        while heap.len() > 1 {
            let Reverse((w1, n1)) = heap.pop().unwrap();
            let Reverse((w2, n2)) = heap.pop().unwrap();
            let id = parent.len();
            parent.push(usize::MAX);
            parent[n1] = id;
            parent[n2] = id;
            heap.push(Reverse((w1 + w2, id)));
        }
        let mut max = 0u32;
        for s in 0..256 {
            if scaled[s] == 0 {
                continue;
            }
            let mut depth = 0u32;
            let mut n = s;
            while parent[n] != usize::MAX {
                n = parent[n];
                depth += 1;
            }
            lengths[s] = depth as u8;
            max = max.max(depth);
        }
        if max <= limit {
            return lengths;
        }
        for c in scaled.iter_mut().filter(|c| **c > 0) {
            *c = c.div_ceil(2);
        }
    }
}

impl HuffmanEncoder {
    /// Build a code for `literals`; `None` if fewer than two distinct symbols are present
    /// or the weights cannot be described.
    pub fn new(literals: &[u8]) -> Option<Self> {
        let mut counts = [0u32; 256];
        for &b in literals {
            counts[b as usize] += 1;
        }
        if counts.iter().filter(|&&c| c > 0).count() < 2 {
            return None;
        }
        let lengths = code_lengths(&counts, HUF_MAX_BITS_ENCODE);
        let max_bits = u32::from(*lengths.iter().max()?);
        let weights: Vec<u8> = lengths
            .iter()
            .map(|&l| {
                if l == 0 {
                    0
                } else {
                    (max_bits + 1 - u32::from(l)) as u8
                }
            })
            .collect();

        // Canonical assignment matching HuffmanTable::from_weights.
        let mut rank_start = [0u32; HUF_MAX_BITS_ENCODE as usize + 2];
        let mut rank_count = [0u32; HUF_MAX_BITS_ENCODE as usize + 2];
        for &w in &weights {
            rank_count[w as usize] += 1;
        }
        let mut next = 0u32;
        for w in 1..=max_bits as usize {
            rank_start[w] = next;
            next += rank_count[w] << (w - 1);
        }
        debug_assert_eq!(next, 1 << max_bits);
        let mut codes = [(0u32, 0u8); 256];
        for (s, &w) in weights.iter().enumerate() {
            if w == 0 {
                continue;
            }
            codes[s] = (rank_start[w as usize] >> (w - 1), lengths[s]);
            rank_start[w as usize] += 1 << (w - 1);
        }

        let last = weights.iter().rposition(|&w| w > 0)?;
        let explicit = &weights[..last];
        let fse = compress_interleaved2(explicit, WEIGHTS_FSE_MAX_LOG).filter(|c| c.len() < 128);
        let direct_len = explicit.len().div_ceil(2);
        let description = match fse {
            Some(c) if explicit.len() > 128 || c.len() < direct_len => {
                let mut d = Vec::with_capacity(1 + c.len());
                d.push(c.len() as u8);
                d.extend_from_slice(&c);
                d
            }
            _ if explicit.len() <= 128 => {
                let mut d = Vec::with_capacity(1 + direct_len);
                d.push((127 + explicit.len()) as u8);
                for pair in explicit.chunks(2) {
                    d.push((pair[0] << 4) | pair.get(1).copied().unwrap_or(0));
                }
                d
            }
            _ => return None,
        };
        Some(Self { codes, description })
    }

    pub fn encode_stream(&self, literals: &[u8]) -> Vec<u8> {
        let mut w = BitWriter::with_capacity(literals.len());
        for &b in literals.iter().rev() {
            let (code, len) = self.codes[b as usize];
            w.add_bits(u64::from(code), u32::from(len));
        }
        w.finish_reverse()
    }

    /// Encode literals as one stream or four streams with a jump table.
    /// Returns `None` if a four-stream segment exceeds the 16-bit jump table.
    pub fn encode_literals(&self, literals: &[u8], four_streams: bool) -> Option<Vec<u8>> {
        if !four_streams {
            return Some(self.encode_stream(literals));
        }
        let seg = literals.len().div_ceil(4);
        let streams: Vec<Vec<u8>> = literals
            .chunks(seg)
            .map(|c| self.encode_stream(c))
            .collect();
        if streams.len() != 4 {
            return None;
        }
        let mut out = Vec::with_capacity(6 + streams.iter().map(Vec::len).sum::<usize>());
        for s in &streams[..3] {
            out.extend_from_slice(&u16::try_from(s.len()).ok()?.to_le_bytes());
        }
        for s in &streams {
            out.extend_from_slice(s);
        }
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(len: usize, alphabet: u32) -> Vec<u8> {
        let mut x = 0x1234_5678u32;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                // Skewed distribution.
                let r = x % 1000;
                ((r * r / 1000) % alphabet) as u8
            })
            .collect()
    }

    #[test]
    fn rfc_weight_example() {
        // RFC 8878 §4.2.1.1 example: weights for literals 0..=5 = 4,3,2,0,1,(1 implicit).
        let t = HuffmanTable::from_weights(vec![4, 3, 2, 0, 1]).unwrap();
        assert_eq!(t.max_bits, 4);
        let len_of = |s: u8| t.decode.iter().find(|e| e.0 == s).map(|e| e.1);
        assert_eq!(len_of(0), Some(1));
        assert_eq!(len_of(1), Some(2));
        assert_eq!(len_of(2), Some(3));
        assert_eq!(len_of(3), None);
        assert_eq!(len_of(4), Some(4));
        assert_eq!(len_of(5), Some(4));
        // Prefix codes from the RFC table: 0:"1", 1:"01", 2:"001", 4:"0000", 5:"0001".
        assert_eq!(t.decode[0b1000].0, 0);
        assert_eq!(t.decode[0b0100].0, 1);
        assert_eq!(t.decode[0b0010].0, 2);
        assert_eq!(t.decode[0b0000].0, 4);
        assert_eq!(t.decode[0b0001].0, 5);
    }

    #[test]
    fn roundtrip_single_and_four_streams() {
        for (len, alphabet) in [(40usize, 3u32), (300, 17), (5000, 200), (70_000, 256)] {
            let lits = sample(len, alphabet);
            let enc = HuffmanEncoder::new(&lits).unwrap();
            let (table, used) = read_table(&enc.description).unwrap();
            assert_eq!(used, enc.description.len());
            for four in [false, true] {
                if four && len < 256 {
                    continue;
                }
                let payload = enc.encode_literals(&lits, four).unwrap();
                assert_eq!(table.decode_literals(&payload, len, four).unwrap(), lits);
            }
        }
    }

    #[test]
    fn single_symbol_has_no_code() {
        assert!(HuffmanEncoder::new(&[7u8; 100]).is_none());
    }
}
