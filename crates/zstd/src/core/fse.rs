//! Finite State Entropy (tANS) tables, table descriptions and the two-state stream used
//! for Huffman weights (RFC 8878 §4.1).
//!
//! The encoder side is a port of `FSE_buildCTable_wksp`, `FSE_writeNCount` and
//! `FSE_compress_usingCTable` from `vendor/zstd/lib/compress/fse_compress.c`; the decoder
//! side follows the RFC table-building algorithm (identical to `FSE_buildDTable`).

use super::bitstream::{BitReader, BitWriter, ReverseBitReader};
use super::{CoreError, Result};

/// Predefined literal-length distribution (RFC 8878 §3.1.1.3.2.2.1), accuracy log 6.
pub const LL_DEFAULT_NORM: [i16; 36] = [
    4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1,
];
pub const LL_DEFAULT_LOG: u32 = 6;
/// Predefined match-length distribution, accuracy log 6.
pub const ML_DEFAULT_NORM: [i16; 53] = [
    1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
];
pub const ML_DEFAULT_LOG: u32 = 6;
/// Predefined offset-code distribution, accuracy log 5.
pub const OF_DEFAULT_NORM: [i16; 29] = [
    1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1,
];
pub const OF_DEFAULT_LOG: u32 = 5;

#[inline]
pub(crate) fn highbit(v: u32) -> u32 {
    debug_assert!(v > 0);
    31 - v.leading_zeros()
}

/// Spread symbols over the state table (RFC 8878 §4.1.1). Returns the symbol of each cell.
fn spread_symbols(norm: &[i16], log: u32) -> Result<Vec<u8>> {
    let size = 1usize << log;
    let mut table = vec![0u8; size];
    let mut high = size - 1;
    for (s, &n) in norm.iter().enumerate() {
        if n == -1 {
            table[high] = s as u8;
            high = high.wrapping_sub(1);
        }
    }
    let step = (size >> 1) + (size >> 3) + 3;
    let mask = size - 1;
    let mut pos = 0usize;
    for (s, &n) in norm.iter().enumerate() {
        for _ in 0..n.max(0) {
            table[pos] = s as u8;
            pos = (pos + step) & mask;
            while pos > high {
                pos = (pos + step) & mask;
            }
        }
    }
    if pos != 0 {
        return Err(CoreError::Corrupted("FSE distribution does not fill table"));
    }
    Ok(table)
}

fn check_norm(norm: &[i16], log: u32) -> Result<()> {
    if norm.is_empty() || norm.len() > 256 {
        return Err(CoreError::Corrupted("FSE alphabet size"));
    }
    let mut total: i64 = 0;
    for &n in norm {
        if n < -1 {
            return Err(CoreError::Corrupted("FSE negative probability"));
        }
        total += if n == -1 { 1 } else { i64::from(n) };
    }
    if total != 1i64 << log {
        return Err(CoreError::Corrupted(
            "FSE probabilities do not sum to table size",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Table description (normalized counts)
// ---------------------------------------------------------------------------------------

/// Parse an FSE table description. Returns `(normalized counts, accuracy log, bytes used)`.
pub fn read_ncount(data: &[u8], max_symbol: usize, max_log: u32) -> Result<(Vec<i16>, u32, usize)> {
    if data.is_empty() {
        return Err(CoreError::Truncated("FSE table description"));
    }
    let mut r = BitReader::new(data);
    let log = r.read(4) as u32 + 5;
    if log > max_log {
        return Err(CoreError::Corrupted("FSE accuracy log too large"));
    }
    let mut remaining: i32 = (1 << log) + 1;
    let mut threshold: i32 = 1 << log;
    let mut nb_bits = log + 1;
    let mut norm: Vec<i16> = Vec::with_capacity(max_symbol + 1);
    let mut previous0 = false;

    while remaining > 1 && norm.len() <= max_symbol {
        if previous0 {
            loop {
                let repeat = r.read(2) as usize;
                norm.resize(norm.len() + repeat, 0);
                if repeat != 3 {
                    break;
                }
            }
            if norm.len() > max_symbol {
                return Err(CoreError::Corrupted("FSE zero run exceeds alphabet"));
            }
        }
        let max = (2 * threshold - 1) - remaining;
        let low = r.peek(nb_bits - 1) as i32 & (threshold - 1);
        let mut count = if low < max {
            r.skip(nb_bits - 1);
            low
        } else {
            let mut v = r.peek(nb_bits) as i32 & (2 * threshold - 1);
            if v >= threshold {
                v -= max;
            }
            r.skip(nb_bits);
            v
        };
        count -= 1;
        remaining -= count.abs();
        if remaining < 1 {
            return Err(CoreError::Corrupted("FSE probabilities overflow table"));
        }
        norm.push(count as i16);
        previous0 = count == 0;
        while remaining < threshold {
            nb_bits -= 1;
            threshold >>= 1;
        }
    }
    if remaining != 1 {
        return Err(CoreError::Corrupted("FSE table description incomplete"));
    }
    let used = r.bytes_consumed();
    if used > data.len() {
        return Err(CoreError::Truncated("FSE table description"));
    }
    Ok((norm, log, used))
}

/// Serialize normalized counts (port of `FSE_writeNCount_generic`). The last entry of
/// `norm` must be non-zero.
pub fn write_ncount(norm: &[i16], log: u32) -> Vec<u8> {
    let mut w = BitWriter::new();
    w.add_bits(u64::from(log - 5), 4);
    let size: i32 = 1 << log;
    let mut remaining = size + 1;
    let mut threshold = size;
    let mut nb_bits = log + 1;
    let mut symbol = 0usize;
    let mut previous0 = false;
    while symbol < norm.len() && remaining > 1 {
        if previous0 {
            let mut start = symbol;
            while symbol < norm.len() && norm[symbol] == 0 {
                symbol += 1;
            }
            while symbol >= start + 3 {
                start += 3;
                w.add_bits(3, 2);
            }
            w.add_bits((symbol - start) as u64, 2);
        }
        let mut count = i32::from(norm[symbol]);
        symbol += 1;
        let max = (2 * threshold - 1) - remaining;
        remaining -= count.abs();
        count += 1;
        if count >= threshold {
            count += max;
        }
        let width = if count < max { nb_bits - 1 } else { nb_bits };
        w.add_bits(count as u64, width);
        previous0 = count == 1;
        while remaining < threshold {
            nb_bits -= 1;
            threshold >>= 1;
        }
    }
    debug_assert_eq!(remaining, 1, "invalid normalized distribution");
    w.finish()
}

/// Accuracy log heuristic (port of `FSE_optimalTableLog`).
pub fn optimal_table_log(max_log: u32, src_size: usize, max_symbol: usize) -> u32 {
    let src = src_size.max(2) as u32;
    let max_bits_src = highbit(src - 1).saturating_sub(2);
    let min_bits_src = highbit(src) + 1;
    let min_bits_symbols = highbit(max_symbol.max(1) as u32) + 2;
    let min_bits = min_bits_src.min(min_bits_symbols);
    let mut log = max_log;
    if max_bits_src < log {
        log = max_bits_src;
    }
    if min_bits > log {
        log = min_bits;
    }
    log.clamp(5, max_log)
}

/// Scale `counts` to a distribution summing to `1 << log`; every present symbol gets >= 1.
pub fn normalize(counts: &[u32], log: u32) -> Vec<i16> {
    let size = 1i64 << log;
    let total: u64 = counts.iter().map(|&c| u64::from(c)).sum();
    let last = counts.iter().rposition(|&c| c > 0).unwrap_or(0);
    let mut norm: Vec<i16> = counts[..=last]
        .iter()
        .map(|&c| {
            if c == 0 {
                0
            } else {
                let p = (u64::from(c) * size as u64 + total / 2) / total;
                p.max(1) as i16
            }
        })
        .collect();
    let mut diff = size - norm.iter().map(|&n| i64::from(n)).sum::<i64>();
    if diff > 0 {
        let (best, _) = counts[..=last]
            .iter()
            .enumerate()
            .max_by_key(|&(i, &c)| (c, std::cmp::Reverse(i)))
            .unwrap();
        norm[best] += diff as i16;
    }
    while diff < 0 {
        let (best, _) = norm
            .iter()
            .enumerate()
            .max_by_key(|&(i, &n)| (n, std::cmp::Reverse(i)))
            .unwrap();
        let take = (i64::from(norm[best]) - 1).min(-diff);
        debug_assert!(take > 0, "table too small for alphabet");
        norm[best] -= take as i16;
        diff += take;
    }
    norm
}

// ---------------------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeEntry {
    pub symbol: u8,
    pub nb_bits: u8,
    pub baseline: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeTable {
    pub log: u32,
    pub entries: Vec<DecodeEntry>,
}

impl DecodeTable {
    pub fn build(norm: &[i16], log: u32) -> Result<Self> {
        check_norm(norm, log)?;
        let size = 1u32 << log;
        let cells = spread_symbols(norm, log)?;
        let mut next: Vec<u32> = norm
            .iter()
            .map(|&n| if n == -1 { 1 } else { n.max(0) as u32 })
            .collect();
        let entries = cells
            .iter()
            .map(|&s| {
                let state = next[s as usize];
                next[s as usize] += 1;
                let nb_bits = log - highbit(state);
                DecodeEntry {
                    symbol: s,
                    nb_bits: nb_bits as u8,
                    baseline: ((state << nb_bits) - size) as u16,
                }
            })
            .collect();
        Ok(Self { log, entries })
    }

    /// Table for RLE mode: one state, zero bits.
    pub fn rle(symbol: u8) -> Self {
        Self {
            log: 0,
            entries: vec![DecodeEntry {
                symbol,
                nb_bits: 0,
                baseline: 0,
            }],
        }
    }

    #[inline]
    pub fn init_state(&self, r: &mut ReverseBitReader<'_>) -> usize {
        r.read(self.log) as usize
    }

    #[inline]
    pub fn symbol(&self, state: usize) -> u8 {
        self.entries[state].symbol
    }

    #[inline]
    pub fn update(&self, state: usize, r: &mut ReverseBitReader<'_>) -> usize {
        let e = self.entries[state];
        e.baseline as usize + r.read(u32::from(e.nb_bits)) as usize
    }
}

// ---------------------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default)]
struct SymbolTransform {
    delta_nb_bits: u32,
    delta_find_state: i32,
}

#[derive(Debug, Clone)]
pub struct EncodeTable {
    pub log: u32,
    state_table: Vec<u16>,
    symbol_tt: Vec<SymbolTransform>,
    rle: bool,
}

impl EncodeTable {
    pub fn build(norm: &[i16], log: u32) -> Result<Self> {
        check_norm(norm, log)?;
        let size = 1u32 << log;
        let cells = spread_symbols(norm, log)?;
        let mut cumul = vec![0u32; norm.len() + 1];
        for (s, &n) in norm.iter().enumerate() {
            cumul[s + 1] = cumul[s] + if n == -1 { 1 } else { n.max(0) as u32 };
        }
        let mut state_table = vec![0u16; size as usize];
        for (u, &s) in cells.iter().enumerate() {
            let slot = &mut cumul[s as usize];
            state_table[*slot as usize] = (size + u as u32) as u16;
            *slot += 1;
        }
        let mut symbol_tt = vec![SymbolTransform::default(); norm.len()];
        let mut total: i32 = 0;
        for (s, &n) in norm.iter().enumerate() {
            symbol_tt[s] = match n {
                0 => SymbolTransform {
                    delta_nb_bits: ((log + 1) << 16).wrapping_sub(size),
                    delta_find_state: 0,
                },
                -1 | 1 => {
                    let t = SymbolTransform {
                        delta_nb_bits: (log << 16).wrapping_sub(size),
                        delta_find_state: total - 1,
                    };
                    total += 1;
                    t
                }
                n => {
                    let n = n as u32;
                    let max_bits_out = log - highbit(n - 1);
                    let min_state_plus = n << max_bits_out;
                    let t = SymbolTransform {
                        delta_nb_bits: (max_bits_out << 16).wrapping_sub(min_state_plus),
                        delta_find_state: total - n as i32,
                    };
                    total += n as i32;
                    t
                }
            };
        }
        Ok(Self {
            log,
            state_table,
            symbol_tt,
            rle: false,
        })
    }

    pub fn rle() -> Self {
        Self {
            log: 0,
            state_table: Vec::new(),
            symbol_tt: Vec::new(),
            rle: true,
        }
    }

    /// Initial state for the first encoded (= last decoded) symbol (`FSE_initCState2`).
    #[inline]
    pub fn init_state(&self, symbol: u8) -> u32 {
        if self.rle {
            return 0;
        }
        let tt = self.symbol_tt[symbol as usize];
        let nb_bits_out = (tt.delta_nb_bits.wrapping_add(1 << 15)) >> 16;
        let value = (nb_bits_out << 16).wrapping_sub(tt.delta_nb_bits);
        self.state_table[((value >> nb_bits_out) as i32 + tt.delta_find_state) as usize] as u32
    }

    #[inline]
    pub fn encode(&self, w: &mut BitWriter, state: &mut u32, symbol: u8) {
        if self.rle {
            return;
        }
        let tt = self.symbol_tt[symbol as usize];
        let nb_bits_out = state.wrapping_add(tt.delta_nb_bits) >> 16;
        w.add_bits(u64::from(*state), nb_bits_out);
        *state = u32::from(
            self.state_table[((*state >> nb_bits_out) as i32 + tt.delta_find_state) as usize],
        );
    }

    #[inline]
    pub fn flush(&self, w: &mut BitWriter, state: u32) {
        if !self.rle {
            w.add_bits(u64::from(state), self.log);
        }
    }
}

/// Approximate cost in bits of coding `counts` with distribution `norm`.
pub fn estimate_cost_bits(counts: &[u32], norm: &[i16], log: u32) -> Option<f64> {
    let mut bits = 0f64;
    for (s, &c) in counts.iter().enumerate() {
        if c == 0 {
            continue;
        }
        let p = *norm.get(s)?;
        if p == 0 {
            return None;
        }
        let p = if p == -1 { 1.0 } else { f64::from(p) };
        bits += f64::from(c) * (f64::from(log) - p.log2());
    }
    Some(bits)
}

// ---------------------------------------------------------------------------------------
// Two-state interleaved stream (Huffman weights)
// ---------------------------------------------------------------------------------------

/// Decode an FSE-compressed byte sequence (table description followed by a two-state
/// interleaved bitstream), producing at most `max_out` symbols.
pub fn decompress_interleaved2(data: &[u8], max_log: u32, max_out: usize) -> Result<Vec<u8>> {
    let (norm, log, used) = read_ncount(data, 255, max_log)?;
    let table = DecodeTable::build(&norm, log)?;
    let mut r = ReverseBitReader::new(&data[used..])?;
    let mut s1 = table.init_state(&mut r);
    let mut s2 = table.init_state(&mut r);
    if r.overflowed() {
        return Err(CoreError::Corrupted("FSE stream too short"));
    }
    let mut out = Vec::new();
    loop {
        if out.len() + 2 > max_out {
            return Err(CoreError::Corrupted("FSE stream decodes too many symbols"));
        }
        out.push(table.symbol(s1));
        s1 = table.update(s1, &mut r);
        if r.overflowed() {
            out.push(table.symbol(s2));
            break;
        }
        out.push(table.symbol(s2));
        s2 = table.update(s2, &mut r);
        if r.overflowed() {
            out.push(table.symbol(s1));
            break;
        }
    }
    Ok(out)
}

/// Encode `symbols` (len >= 2) as table description + two-state stream, mirroring
/// `FSE_compress_usingCTable`. Returns `None` when FSE cannot represent the input.
pub fn compress_interleaved2(symbols: &[u8], max_log: u32) -> Option<Vec<u8>> {
    if symbols.len() < 2 {
        return None;
    }
    let mut counts = [0u32; 256];
    for &s in symbols {
        counts[s as usize] += 1;
    }
    let max_symbol = counts.iter().rposition(|&c| c > 0)?;
    if counts.iter().filter(|&&c| c > 0).count() < 2 {
        return None;
    }
    let log = optimal_table_log(max_log, symbols.len(), max_symbol);
    let norm = normalize(&counts[..=max_symbol], log);
    let table = EncodeTable::build(&norm, log).ok()?;
    let mut out = write_ncount(&norm, log);

    let mut w = BitWriter::with_capacity(symbols.len());
    let mut idx = symbols.len();
    let (mut s1, mut s2);
    if symbols.len() % 2 == 1 {
        s1 = table.init_state(symbols[idx - 1]);
        s2 = table.init_state(symbols[idx - 2]);
        table.encode(&mut w, &mut s1, symbols[idx - 3]);
        idx -= 3;
    } else {
        s2 = table.init_state(symbols[idx - 1]);
        s1 = table.init_state(symbols[idx - 2]);
        idx -= 2;
    }
    while idx > 0 {
        table.encode(&mut w, &mut s2, symbols[idx - 1]);
        table.encode(&mut w, &mut s1, symbols[idx - 2]);
        idx -= 2;
    }
    table.flush(&mut w, s2);
    table.flush(&mut w, s1);
    out.extend_from_slice(&w.finish_reverse());
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predefined_tables_are_valid() {
        for (norm, log) in [
            (&LL_DEFAULT_NORM[..], LL_DEFAULT_LOG),
            (&ML_DEFAULT_NORM[..], ML_DEFAULT_LOG),
            (&OF_DEFAULT_NORM[..], OF_DEFAULT_LOG),
        ] {
            let t = DecodeTable::build(norm, log).unwrap();
            assert_eq!(t.entries.len(), 1 << log);
            EncodeTable::build(norm, log).unwrap();
        }
    }

    #[test]
    fn predefined_ll_table_matches_rfc_appendix() {
        // RFC 8878 Appendix A, Literal Length decoding table, first states:
        // state 0: symbol 0, nbBits 4, base 0; state 1: symbol 0, 4, 16;
        // state 2: symbol 1, 5, 32; state 3: symbol 3, 5, 0; "less than 1" symbols
        // 32..=35 occupy states 63..=60 with 6 bits, base 0.
        let t = DecodeTable::build(&LL_DEFAULT_NORM, LL_DEFAULT_LOG).unwrap();
        let e = |i: usize| {
            (
                t.entries[i].symbol,
                t.entries[i].nb_bits,
                t.entries[i].baseline,
            )
        };
        assert_eq!(e(0), (0, 4, 0));
        assert_eq!(e(1), (0, 4, 16));
        assert_eq!(e(2), (1, 5, 32));
        assert_eq!(e(3), (3, 5, 0));
        assert_eq!(e(60), (35, 6, 0));
        assert_eq!(e(63), (32, 6, 0));
    }

    #[test]
    fn ncount_roundtrip() {
        for (norm, log) in [
            (LL_DEFAULT_NORM.to_vec(), LL_DEFAULT_LOG),
            (ML_DEFAULT_NORM.to_vec(), ML_DEFAULT_LOG),
            (OF_DEFAULT_NORM.to_vec(), OF_DEFAULT_LOG),
            (vec![10, 0, 0, 0, 0, 0, 12, 0, 1, 9], 5),
        ] {
            let bytes = write_ncount(&norm, log);
            let (decoded, dlog, used) = read_ncount(&bytes, 255, 9).unwrap();
            assert_eq!((decoded, dlog, used), (norm, log, bytes.len()));
        }
    }

    #[test]
    fn normalize_sums_to_table_size() {
        let counts = [1000u32, 1, 0, 3, 77, 0, 0, 1, 2];
        let norm = normalize(&counts, 6);
        assert_eq!(norm.iter().map(|&n| i32::from(n)).sum::<i32>(), 64);
        assert!(
            counts
                .iter()
                .zip(&norm)
                .all(|(&c, &n)| (c == 0) == (n == 0))
        );
    }

    #[test]
    fn interleaved_roundtrip() {
        let mut seed = 7u32;
        for len in [2usize, 3, 4, 5, 17, 100, 255] {
            let syms: Vec<u8> = (0..len)
                .map(|_| {
                    seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
                    [0u8, 1, 1, 2, 2, 2, 3, 6][(seed >> 16) as usize % 8]
                })
                .collect();
            let Some(enc) = compress_interleaved2(&syms, 6) else {
                continue;
            };
            assert_eq!(
                decompress_interleaved2(&enc, 6, 255).unwrap(),
                syms,
                "len {len}"
            );
        }
    }
}
