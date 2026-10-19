//! Little-endian bit I/O used by RFC 8878.
//!
//! - [`BitReader`]: forward, LSB-first (FSE table descriptions).
//! - [`ReverseBitReader`]: backward reader for Huffman/FSE/sequence streams, which end
//!   with a `1` padding marker in the highest set bit of the last byte.
//! - [`BitWriter`]: forward LSB-first writer; [`BitWriter::finish_reverse`] appends the
//!   marker so the stream can be consumed by [`ReverseBitReader`].

use super::{CoreError, Result};

#[inline]
fn mask(n: u32) -> u64 {
    if n >= 64 { u64::MAX } else { (1u64 << n) - 1 }
}

#[inline]
fn load_le_u64(data: &[u8], byte: usize) -> u64 {
    let mut buf = [0u8; 8];
    if byte < data.len() {
        let end = (byte + 8).min(data.len());
        buf[..end - byte].copy_from_slice(&data[byte..end]);
    }
    u64::from_le_bytes(buf)
}

/// Forward LSB-first bit reader. Bits beyond the end read as zero; callers check
/// [`BitReader::bytes_consumed`] against the real input length.
#[derive(Debug, Clone)]
pub struct BitReader<'a> {
    data: &'a [u8],
    bit_pos: usize,
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, bit_pos: 0 }
    }

    /// Read `n <= 56` bits.
    #[inline]
    pub fn read(&mut self, n: u32) -> u64 {
        let v = self.peek(n);
        self.bit_pos += n as usize;
        v
    }

    #[inline]
    pub fn peek(&self, n: u32) -> u64 {
        debug_assert!(n <= 56);
        if n == 0 {
            return 0;
        }
        let word = load_le_u64(self.data, self.bit_pos / 8);
        (word >> (self.bit_pos % 8)) & mask(n)
    }

    #[inline]
    pub fn skip(&mut self, n: u32) {
        self.bit_pos += n as usize;
    }

    pub fn bits_consumed(&self) -> usize {
        self.bit_pos
    }

    pub fn bytes_consumed(&self) -> usize {
        self.bit_pos.div_ceil(8)
    }
}

/// Backward bit reader. Reads past the beginning of the stream yield zero bits and make
/// [`ReverseBitReader::overflowed`] true (FSE uses this to detect the end of a stream).
#[derive(Debug, Clone)]
pub struct ReverseBitReader<'a> {
    data: &'a [u8],
    /// Number of unread bits; negative after over-reading.
    pos: isize,
}

impl<'a> ReverseBitReader<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self> {
        let last = *data
            .last()
            .ok_or(CoreError::Corrupted("empty reverse bitstream"))?;
        if last == 0 {
            return Err(CoreError::Corrupted("reverse bitstream missing end marker"));
        }
        let padding = last.leading_zeros() as isize + 1;
        Ok(Self {
            data,
            pos: data.len() as isize * 8 - padding,
        })
    }

    /// Return the next `n <= 56` bits (most recently written first) without consuming.
    #[inline]
    pub fn peek(&self, n: u32) -> u64 {
        debug_assert!(n <= 56);
        if n == 0 || self.pos <= 0 {
            return 0;
        }
        let start = self.pos - n as isize;
        if start >= 0 {
            let start = start as usize;
            (load_le_u64(self.data, start / 8) >> (start % 8)) & mask(n)
        } else {
            // Only `pos` real bits remain; the rest are implicit zeros below bit 0.
            (load_le_u64(self.data, 0) & mask(self.pos as u32)) << (-start) as u32
        }
    }

    #[inline]
    pub fn read(&mut self, n: u32) -> u64 {
        let v = self.peek(n);
        self.pos -= n as isize;
        v
    }

    #[inline]
    pub fn consume(&mut self, n: u32) {
        self.pos -= n as isize;
    }

    /// Unread bits; negative after over-reading.
    pub fn remaining(&self) -> isize {
        self.pos
    }

    pub fn overflowed(&self) -> bool {
        self.pos < 0
    }

    pub fn is_finished(&self) -> bool {
        self.pos == 0
    }
}

/// Forward LSB-first bit writer.
#[derive(Debug, Default, Clone)]
pub struct BitWriter {
    out: Vec<u8>,
    acc: u64,
    nbits: u32,
}

impl BitWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            out: Vec::with_capacity(cap),
            acc: 0,
            nbits: 0,
        }
    }

    /// Append the low `n <= 56` bits of `value`.
    #[inline]
    pub fn add_bits(&mut self, value: u64, n: u32) {
        debug_assert!(n <= 56);
        if n == 0 {
            return;
        }
        self.acc |= (value & mask(n)) << self.nbits;
        self.nbits += n;
        while self.nbits >= 8 {
            self.out.push(self.acc as u8);
            self.acc >>= 8;
            self.nbits -= 8;
        }
    }

    pub fn bit_len(&self) -> usize {
        self.out.len() * 8 + self.nbits as usize
    }

    /// Flush the partial byte (zero padded) and return the bytes.
    pub fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            self.out.push(self.acc as u8);
        }
        self.out
    }

    /// Append the `1` end marker required by backward-read streams, then flush.
    pub fn finish_reverse(mut self) -> Vec<u8> {
        self.add_bits(1, 1);
        self.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_roundtrip_odd_widths() {
        let fields = [
            (5u64, 3u32),
            (0xAB, 8),
            (0x1F, 5),
            (1, 1),
            (0x3FFF, 14),
            (0, 2),
        ];
        let mut w = BitWriter::new();
        for &(v, n) in &fields {
            w.add_bits(v, n);
        }
        let bytes = w.finish();
        let mut r = BitReader::new(&bytes);
        for &(v, n) in &fields {
            assert_eq!(r.read(n), v);
        }
    }

    #[test]
    fn reverse_reads_last_written_first() {
        let fields = [
            (5u64, 3u32),
            (0xAB, 8),
            (0x1F, 5),
            (1, 1),
            (0x3FFF, 14),
            (0x123456, 24),
        ];
        let mut w = BitWriter::new();
        for &(v, n) in &fields {
            w.add_bits(v, n);
        }
        let bytes = w.finish_reverse();
        let mut r = ReverseBitReader::new(&bytes).unwrap();
        for &(v, n) in fields.iter().rev() {
            assert_eq!(r.read(n), v);
        }
        assert!(r.is_finished());
        assert_eq!(r.read(3), 0);
        assert!(r.overflowed());
    }

    #[test]
    fn reverse_rejects_missing_marker() {
        assert!(ReverseBitReader::new(&[]).is_err());
        assert!(ReverseBitReader::new(&[0x12, 0x00]).is_err());
    }

    #[test]
    fn reverse_peek_crossing_start_pads_zeros() {
        // Single byte 0b0000_0101: marker at bit 2, payload bits = 0b01.
        let r = ReverseBitReader::new(&[0b0000_0101]).unwrap();
        assert_eq!(r.remaining(), 2);
        assert_eq!(r.peek(4), 0b0100);
    }
}
