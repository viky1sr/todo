//! Block layer (RFC 8878 §3.1.1.2–§3.1.1.4): literals section, sequences section and
//! compressed-block encode/decode.

use super::bitstream::{BitWriter, ReverseBitReader};
use super::fse::{
    self, DecodeTable, EncodeTable, LL_DEFAULT_LOG, LL_DEFAULT_NORM, ML_DEFAULT_LOG,
    ML_DEFAULT_NORM, OF_DEFAULT_LOG, OF_DEFAULT_NORM, highbit,
};
use super::huffman::{self, HuffmanEncoder, HuffmanTable};
use super::lz77::{self, INITIAL_REPS, RawSequence, Sequence};
use super::{BLOCK_SIZE_MAX, CoreError, Result};

pub const LL_BASE: [u32; 36] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64,
    128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
];
pub const LL_BITS: [u8; 36] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16,
];
pub const ML_BASE: [u32; 53] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027,
    2051, 4099, 8195, 16387, 32771, 65539,
];
pub const ML_BITS: [u8; 53] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
];
const LL_MAX_LOG: u32 = 9;
const ML_MAX_LOG: u32 = 9;
const OF_MAX_LOG: u32 = 8;
const OF_MAX_SYMBOL: usize = 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockType {
    Raw = 0,
    Rle = 1,
    Compressed = 2,
}

/// Per-frame decoder state carried between blocks (Huffman/FSE tables for treeless and
/// repeat modes, repeat offsets).
#[derive(Debug, Clone)]
pub struct DecoderState {
    pub huffman: Option<HuffmanTable>,
    pub ll: Option<DecodeTable>,
    pub of: Option<DecodeTable>,
    pub ml: Option<DecodeTable>,
    pub reps: [u32; 3],
}

impl Default for DecoderState {
    fn default() -> Self {
        Self {
            huffman: None,
            ll: None,
            of: None,
            ml: None,
            reps: INITIAL_REPS,
        }
    }
}

fn le_bytes(data: &[u8], n: usize) -> u64 {
    data[..n]
        .iter()
        .rev()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
}

// ---------------------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------------------

/// Decode the literals section. Returns `(literals, bytes consumed)`.
pub fn decode_literals(state: &mut DecoderState, src: &[u8]) -> Result<(Vec<u8>, usize)> {
    let b0 = *src.first().ok_or(CoreError::Truncated("literals header"))?;
    let ty = b0 & 3;
    let size_format = (b0 >> 2) & 3;
    match ty {
        0 | 1 => {
            let (regen, h) = match size_format {
                0 | 2 => (usize::from(b0 >> 3), 1),
                1 => {
                    let b = src
                        .get(..2)
                        .ok_or(CoreError::Truncated("literals header"))?;
                    ((le_bytes(b, 2) >> 4) as usize, 2)
                }
                _ => {
                    let b = src
                        .get(..3)
                        .ok_or(CoreError::Truncated("literals header"))?;
                    ((le_bytes(b, 3) >> 4) as usize, 3)
                }
            };
            if regen > BLOCK_SIZE_MAX {
                return Err(CoreError::Corrupted("literals larger than block"));
            }
            if ty == 0 {
                let lits = src
                    .get(h..h + regen)
                    .ok_or(CoreError::Truncated("raw literals"))?;
                Ok((lits.to_vec(), h + regen))
            } else {
                let b = *src.get(h).ok_or(CoreError::Truncated("RLE literal"))?;
                Ok((vec![b; regen], h + 1))
            }
        }
        _ => {
            let (h, bits, four) = match size_format {
                0 => (3, 10, false),
                1 => (3, 10, true),
                2 => (4, 14, true),
                _ => (5, 18, true),
            };
            let hdr = src
                .get(..h)
                .ok_or(CoreError::Truncated("literals header"))?;
            let v = le_bytes(hdr, h);
            let field = (1u64 << bits) - 1;
            let regen = ((v >> 4) & field) as usize;
            let comp = ((v >> (4 + bits)) & field) as usize;
            if regen > BLOCK_SIZE_MAX {
                return Err(CoreError::Corrupted("literals larger than block"));
            }
            let mut payload = src
                .get(h..h + comp)
                .ok_or(CoreError::Truncated("compressed literals"))?;
            if ty == 2 {
                let (table, used) = huffman::read_table(payload)?;
                payload = &payload[used..];
                state.huffman = Some(table);
            }
            let table = state.huffman.as_ref().ok_or(CoreError::Corrupted(
                "treeless literals without previous table",
            ))?;
            Ok((table.decode_literals(payload, regen, four)?, h + comp))
        }
    }
}

fn build_decode_table(
    mode: u8,
    src: &[u8],
    slot: &mut Option<DecodeTable>,
    default: (&[i16], u32),
    max_symbol: usize,
    max_log: u32,
) -> Result<usize> {
    match mode {
        0 => {
            *slot = Some(DecodeTable::build(default.0, default.1)?);
            Ok(0)
        }
        1 => {
            let s = *src
                .first()
                .ok_or(CoreError::Truncated("RLE table symbol"))?;
            if usize::from(s) > max_symbol {
                return Err(CoreError::Corrupted("RLE symbol out of range"));
            }
            *slot = Some(DecodeTable::rle(s));
            Ok(1)
        }
        2 => {
            let (norm, log, used) = fse::read_ncount(src, max_symbol, max_log)?;
            *slot = Some(DecodeTable::build(&norm, log)?);
            Ok(used)
        }
        _ => {
            if slot.is_none() {
                return Err(CoreError::Corrupted("repeat mode without previous table"));
            }
            Ok(0)
        }
    }
}

/// Decode the sequences section.
pub fn decode_sequences(state: &mut DecoderState, src: &[u8]) -> Result<Vec<Sequence>> {
    let b0 = *src
        .first()
        .ok_or(CoreError::Truncated("sequences header"))?;
    let (count, mut p) = match b0 {
        0 => {
            if src.len() != 1 {
                return Err(CoreError::Corrupted("trailing bytes after empty sequences"));
            }
            return Ok(Vec::new());
        }
        1..=127 => (usize::from(b0), 1),
        128..=254 => {
            let b1 = *src.get(1).ok_or(CoreError::Truncated("sequences header"))?;
            (((usize::from(b0) - 128) << 8) + usize::from(b1), 2)
        }
        255 => {
            let b = src
                .get(1..3)
                .ok_or(CoreError::Truncated("sequences header"))?;
            (usize::from(u16::from_le_bytes([b[0], b[1]])) + 0x7F00, 3)
        }
    };
    let modes = *src.get(p).ok_or(CoreError::Truncated("sequence modes"))?;
    p += 1;
    if modes & 3 != 0 {
        return Err(CoreError::Corrupted("reserved sequence mode bits set"));
    }
    p += build_decode_table(
        modes >> 6,
        &src[p..],
        &mut state.ll,
        (&LL_DEFAULT_NORM, LL_DEFAULT_LOG),
        35,
        LL_MAX_LOG,
    )?;
    p += build_decode_table(
        (modes >> 4) & 3,
        &src[p..],
        &mut state.of,
        (&OF_DEFAULT_NORM, OF_DEFAULT_LOG),
        OF_MAX_SYMBOL,
        OF_MAX_LOG,
    )?;
    p += build_decode_table(
        (modes >> 2) & 3,
        &src[p..],
        &mut state.ml,
        (&ML_DEFAULT_NORM, ML_DEFAULT_LOG),
        52,
        ML_MAX_LOG,
    )?;
    let (ll_t, of_t, ml_t) = match (&state.ll, &state.of, &state.ml) {
        (Some(a), Some(b), Some(c)) => (a, b, c),
        _ => return Err(CoreError::Corrupted("missing sequence tables")),
    };

    let mut r = ReverseBitReader::new(&src[p..])?;
    let mut ll_s = ll_t.init_state(&mut r);
    let mut of_s = of_t.init_state(&mut r);
    let mut ml_s = ml_t.init_state(&mut r);
    let mut seqs = Vec::with_capacity(count);
    for i in 0..count {
        let of_code = u32::from(of_t.symbol(of_s));
        let ml_code = usize::from(ml_t.symbol(ml_s));
        let ll_code = usize::from(ll_t.symbol(ll_s));
        if of_code > OF_MAX_SYMBOL as u32 || ml_code > 52 || ll_code > 35 {
            return Err(CoreError::Corrupted("sequence code out of range"));
        }
        let offset_value = (1u32 << of_code) + r.read(of_code) as u32;
        let match_length = ML_BASE[ml_code] + r.read(u32::from(ML_BITS[ml_code])) as u32;
        let literal_length = LL_BASE[ll_code] + r.read(u32::from(LL_BITS[ll_code])) as u32;
        seqs.push(Sequence {
            literal_length,
            match_length,
            offset_value,
        });
        if i + 1 < count {
            ll_s = ll_t.update(ll_s, &mut r);
            ml_s = ml_t.update(ml_s, &mut r);
            of_s = of_t.update(of_s, &mut r);
        }
        if r.overflowed() {
            return Err(CoreError::Corrupted("sequence bitstream overread"));
        }
    }
    if !r.is_finished() {
        return Err(CoreError::Corrupted(
            "sequence bitstream not fully consumed",
        ));
    }
    Ok(seqs)
}

/// Decode one compressed block, appending to `out`.
pub fn decode_compressed_block(
    state: &mut DecoderState,
    src: &[u8],
    out: &mut Vec<u8>,
    frame_start: usize,
    limit: usize,
) -> Result<()> {
    let before = out.len();
    let (literals, used) = decode_literals(state, src)?;
    let seqs = decode_sequences(state, &src[used..])?;
    lz77::execute_sequences(out, frame_start, &literals, &seqs, &mut state.reps, limit)?;
    if out.len() - before > BLOCK_SIZE_MAX {
        return Err(CoreError::Corrupted(
            "block decompresses beyond maximum size",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------------------

fn write_basic_literals_header(out: &mut Vec<u8>, ty: u8, n: usize) {
    if n < 32 {
        out.push(ty | ((n as u8) << 3));
    } else if n < 4096 {
        let v = u32::from(ty) | (1 << 2) | ((n as u32) << 4);
        out.extend_from_slice(&v.to_le_bytes()[..2]);
    } else {
        let v = u32::from(ty) | (3 << 2) | ((n as u32) << 4);
        out.extend_from_slice(&v.to_le_bytes()[..3]);
    }
}

/// Encode the literals section (raw, RLE or Huffman-compressed).
pub fn encode_literals(literals: &[u8], out: &mut Vec<u8>) {
    let n = literals.len();
    if n > 0 && literals.iter().all(|&b| b == literals[0]) && n > 1 {
        write_basic_literals_header(out, 1, n);
        out.push(literals[0]);
        return;
    }
    let raw_cost = n + if n < 32 {
        1
    } else if n < 4096 {
        2
    } else {
        3
    };
    if n >= 64
        && let Some(enc) = HuffmanEncoder::new(literals)
    {
        let four = n >= 256;
        if let Some(streams) = enc.encode_literals(literals, four) {
            let comp = enc.description.len() + streams.len();
            let largest = n.max(comp);
            let (size_format, h, bits) = match (four, largest) {
                (false, l) if l < 1024 => (0u64, 3usize, 10u32),
                (true, l) if l < 1024 => (1, 3, 10),
                (true, l) if l < 16384 => (2, 4, 14),
                (true, l) if l < 262_144 => (3, 5, 18),
                _ => (u64::MAX, 0, 0),
            };
            if size_format != u64::MAX && h + comp < raw_cost {
                let v =
                    2u64 | (size_format << 2) | ((n as u64) << 4) | ((comp as u64) << (4 + bits));
                out.extend_from_slice(&v.to_le_bytes()[..h]);
                out.extend_from_slice(&enc.description);
                out.extend_from_slice(&streams);
                return;
            }
        }
    }
    write_basic_literals_header(out, 0, n);
    out.extend_from_slice(literals);
}

fn code_for(base: &[u32], value: u32) -> u8 {
    (base.partition_point(|&b| b <= value) - 1) as u8
}

struct ChosenTable {
    mode: u8,
    header: Vec<u8>,
    table: EncodeTable,
}

fn choose_table(codes: &[u8], max_log: u32, default: (&[i16], u32)) -> ChosenTable {
    let mut counts = [0u32; 64];
    for &c in codes {
        counts[c as usize] += 1;
    }
    let max_symbol = counts.iter().rposition(|&c| c > 0).unwrap_or(0);
    if counts.iter().filter(|&&c| c > 0).count() == 1 {
        return ChosenTable {
            mode: 1,
            header: vec![max_symbol as u8],
            table: EncodeTable::rle(),
        };
    }
    let counts = &counts[..=max_symbol];
    let log = fse::optimal_table_log(max_log, codes.len(), max_symbol);
    let norm = fse::normalize(counts, log);
    let header = fse::write_ncount(&norm, log);
    let custom_cost = fse::estimate_cost_bits(counts, &norm, log).unwrap_or(f64::INFINITY)
        + (header.len() * 8) as f64;
    let default_cost = fse::estimate_cost_bits(counts, default.0, default.1);
    if let Some(cost) = default_cost
        && cost <= custom_cost
    {
        return ChosenTable {
            mode: 0,
            header: Vec::new(),
            table: EncodeTable::build(default.0, default.1).expect("predefined table"),
        };
    }
    ChosenTable {
        mode: 2,
        header,
        table: EncodeTable::build(&norm, log).expect("normalized table"),
    }
}

/// Encode the sequences section; `reps` is advanced exactly like the decoder will.
pub fn encode_sequences(seqs: &[RawSequence], reps: &mut [u32; 3], out: &mut Vec<u8>) {
    let n = seqs.len();
    match n {
        0..=127 => out.push(n as u8),
        128..=0x7EFF => out.extend_from_slice(&[((n >> 8) + 0x80) as u8, n as u8]),
        _ => {
            out.push(0xFF);
            out.extend_from_slice(&((n - 0x7F00) as u16).to_le_bytes());
        }
    }
    if n == 0 {
        return;
    }
    let mut ll_codes = Vec::with_capacity(n);
    let mut ml_codes = Vec::with_capacity(n);
    let mut of_codes = Vec::with_capacity(n);
    let mut of_values = Vec::with_capacity(n);
    for s in seqs {
        let ov = lz77::encode_offset(s.offset, s.literal_length, reps);
        let resolved = lz77::resolve_offset(ov, s.literal_length, reps);
        debug_assert_eq!(resolved, Ok(s.offset));
        of_values.push(ov);
        of_codes.push(highbit(ov) as u8);
        ll_codes.push(code_for(&LL_BASE, s.literal_length));
        ml_codes.push(code_for(&ML_BASE, s.match_length));
    }
    let ll = choose_table(&ll_codes, LL_MAX_LOG, (&LL_DEFAULT_NORM, LL_DEFAULT_LOG));
    let of = choose_table(&of_codes, OF_MAX_LOG, (&OF_DEFAULT_NORM, OF_DEFAULT_LOG));
    let ml = choose_table(&ml_codes, ML_MAX_LOG, (&ML_DEFAULT_NORM, ML_DEFAULT_LOG));
    out.push((ll.mode << 6) | (of.mode << 4) | (ml.mode << 2));
    out.extend_from_slice(&ll.header);
    out.extend_from_slice(&of.header);
    out.extend_from_slice(&ml.header);

    let extras = |i: usize, w: &mut BitWriter| {
        let s = &seqs[i];
        let (llc, mlc, ofc) = (ll_codes[i] as usize, ml_codes[i] as usize, of_codes[i]);
        w.add_bits(
            u64::from(s.literal_length - LL_BASE[llc]),
            u32::from(LL_BITS[llc]),
        );
        w.add_bits(
            u64::from(s.match_length - ML_BASE[mlc]),
            u32::from(ML_BITS[mlc]),
        );
        w.add_bits(u64::from(of_values[i] - (1 << ofc)), u32::from(ofc));
    };
    let mut w = BitWriter::with_capacity(n * 4);
    let last = n - 1;
    let mut ml_s = ml.table.init_state(ml_codes[last]);
    let mut of_s = of.table.init_state(of_codes[last]);
    let mut ll_s = ll.table.init_state(ll_codes[last]);
    extras(last, &mut w);
    for i in (0..last).rev() {
        of.table.encode(&mut w, &mut of_s, of_codes[i]);
        ml.table.encode(&mut w, &mut ml_s, ml_codes[i]);
        ll.table.encode(&mut w, &mut ll_s, ll_codes[i]);
        extras(i, &mut w);
    }
    ml.table.flush(&mut w, ml_s);
    of.table.flush(&mut w, of_s);
    ll.table.flush(&mut w, ll_s);
    out.extend_from_slice(&w.finish_reverse());
}

/// Encode a compressed block body (literals + sequences).
pub fn encode_compressed_block(
    literals: &[u8],
    seqs: &[RawSequence],
    reps: &mut [u32; 3],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(literals.len() + seqs.len() * 3 + 16);
    encode_literals(literals, &mut out);
    encode_sequences(seqs, reps, &mut out);
    out
}

/// Write a 3-byte block header.
pub fn write_block_header(out: &mut Vec<u8>, last: bool, ty: BlockType, size: usize) {
    let v = u32::from(last) | ((ty as u32) << 1) | ((size as u32) << 3);
    out.extend_from_slice(&v.to_le_bytes()[..3]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_tables_follow_extra_bits() {
        for i in 16..35 {
            assert_eq!(LL_BASE[i + 1], LL_BASE[i] + (1 << LL_BITS[i]), "LL {i}");
        }
        for i in 32..52 {
            assert_eq!(ML_BASE[i + 1], ML_BASE[i] + (1 << ML_BITS[i]), "ML {i}");
        }
    }

    #[test]
    fn literals_roundtrip_all_modes() {
        let text: Vec<u8> = b"the quick brown fox jumps over the lazy dog ".repeat(40);
        for lits in [
            Vec::new(),
            vec![9u8; 1],
            vec![9u8; 5000],
            (0..31u8).collect(),
            (0..=255u8).cycle().take(4100).collect(),
            text[..100].to_vec(),
            text.clone(),
        ] {
            let mut buf = Vec::new();
            encode_literals(&lits, &mut buf);
            let mut st = DecoderState::default();
            let (dec, used) = decode_literals(&mut st, &buf).unwrap();
            assert_eq!(used, buf.len());
            assert_eq!(dec, lits);
        }
    }

    #[test]
    fn sequences_roundtrip() {
        let seqs: Vec<RawSequence> = (0..500u32)
            .map(|i| RawSequence {
                literal_length: (i * 7) % 40 + u32::from(i % 50 == 0) * 70_000,
                match_length: 4 + (i * 13) % 300,
                offset: 1 + (i * 97) % 5000,
            })
            .collect();
        let mut enc_reps = INITIAL_REPS;
        let mut buf = Vec::new();
        encode_sequences(&seqs, &mut enc_reps, &mut buf);
        let mut st = DecoderState::default();
        let dec = decode_sequences(&mut st, &buf).unwrap();
        let mut dec_reps = INITIAL_REPS;
        for (d, s) in dec.iter().zip(&seqs) {
            assert_eq!(d.literal_length, s.literal_length);
            assert_eq!(d.match_length, s.match_length);
            let off =
                lz77::resolve_offset(d.offset_value, d.literal_length, &mut dec_reps).unwrap();
            assert_eq!(off, s.offset);
        }
        assert_eq!(dec.len(), seqs.len());
        assert_eq!(dec_reps, enc_reps);
    }
}
