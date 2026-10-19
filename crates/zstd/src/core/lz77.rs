//! LZ77 layer: sequence execution (decoder), repeat-offset bookkeeping and a hash-chain
//! match finder (encoder).

use super::{CoreError, Result};

/// Initial repeat offsets for every frame (RFC 8878 §3.1.2.5).
pub const INITIAL_REPS: [u32; 3] = [1, 4, 8];
const MIN_MATCH: usize = 4;

/// A decoded sequence: `offset_value` is the raw `Offset_Value` (repeat code 1..=3 or
/// `offset + 3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sequence {
    pub literal_length: u32,
    pub match_length: u32,
    pub offset_value: u32,
}

/// Encoder-side sequence with the real backward distance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawSequence {
    pub literal_length: u32,
    pub match_length: u32,
    pub offset: u32,
}

/// Resolve an `Offset_Value` into a distance and update the repeat offsets.
pub fn resolve_offset(offset_value: u32, literal_length: u32, reps: &mut [u32; 3]) -> Result<u32> {
    if offset_value == 0 {
        return Err(CoreError::Corrupted("zero offset value"));
    }
    if offset_value > 3 {
        let off = offset_value - 3;
        *reps = [off, reps[0], reps[1]];
        return Ok(off);
    }
    let idx = offset_value - 1 + u32::from(literal_length == 0);
    let off = match idx {
        0 => return Ok(reps[0]),
        1 => reps[1],
        2 => reps[2],
        _ => reps[0].wrapping_sub(1),
    };
    if off == 0 {
        return Err(CoreError::Corrupted("repeat offset resolves to zero"));
    }
    *reps = if idx == 1 {
        [off, reps[0], reps[2]]
    } else {
        [off, reps[0], reps[1]]
    };
    Ok(off)
}

/// Choose the cheapest `Offset_Value` for `offset` given the current repeat offsets.
pub fn encode_offset(offset: u32, literal_length: u32, reps: &[u32; 3]) -> u32 {
    if literal_length > 0 {
        if let Some(i) = reps.iter().position(|&r| r == offset) {
            return i as u32 + 1;
        }
    } else if offset == reps[1] {
        return 1;
    } else if offset == reps[2] {
        return 2;
    } else if reps[0] > 1 && offset == reps[0] - 1 {
        return 3;
    }
    offset + 3
}

/// Execute sequences against `out` (RFC 8878 §3.1.2.5). `frame_start` bounds back
/// references; `limit` bounds total output.
pub fn execute_sequences(
    out: &mut Vec<u8>,
    frame_start: usize,
    literals: &[u8],
    sequences: &[Sequence],
    reps: &mut [u32; 3],
    limit: usize,
) -> Result<()> {
    let mut lit_pos = 0usize;
    for seq in sequences {
        let ll = seq.literal_length as usize;
        let ml = seq.match_length as usize;
        let lit_end = lit_pos
            .checked_add(ll)
            .filter(|&e| e <= literals.len())
            .ok_or(CoreError::Corrupted(
                "literal length exceeds literals section",
            ))?;
        if out.len().saturating_add(ll).saturating_add(ml) > limit {
            return Err(CoreError::OutputLimitExceeded(limit));
        }
        out.extend_from_slice(&literals[lit_pos..lit_end]);
        lit_pos = lit_end;

        let offset = resolve_offset(seq.offset_value, seq.literal_length, reps)? as usize;
        if offset > out.len() - frame_start {
            return Err(CoreError::Corrupted("match offset before frame start"));
        }
        let start = out.len() - offset;
        if offset >= ml {
            out.extend_from_within(start..start + ml);
        } else {
            out.reserve(ml);
            for i in 0..ml {
                let b = out[start + i];
                out.push(b);
            }
        }
    }
    let rest = &literals[lit_pos..];
    if out.len().saturating_add(rest.len()) > limit {
        return Err(CoreError::OutputLimitExceeded(limit));
    }
    out.extend_from_slice(rest);
    Ok(())
}

/// Match-finder parameters derived from the compression level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    pub window_log: u32,
    pub hash_log: u32,
    pub search_depth: u32,
    /// Lazy evaluation steps (0 = greedy).
    pub lazy: u32,
    /// Stop searching once a match this long is found.
    pub nice_len: usize,
}

pub fn params_for_level(level: i32) -> Params {
    let (window_log, hash_log, search_depth, lazy, nice_len) = match level {
        i32::MIN..=1 => (19, 16, 1, 0, 16),
        2 => (20, 17, 4, 0, 24),
        3 => (21, 17, 8, 0, 32),
        4 => (21, 18, 16, 1, 48),
        5..=6 => (22, 18, 32, 1, 64),
        7..=9 => (22, 19, 64, 1, 128),
        10..=15 => (22, 20, 128, 2, 256),
        _ => (23, 20, 256, 2, 4096),
    };
    Params {
        window_log,
        hash_log,
        search_depth,
        lazy,
        nice_len,
    }
}

/// Hash-chain match finder over the whole input; blocks are processed in order and may
/// reference earlier blocks within the window.
pub struct MatchFinder<'a> {
    data: &'a [u8],
    params: Params,
    head: Vec<u32>,
    chain: Vec<u32>,
    chain_mask: usize,
    max_distance: usize,
    next_insert: usize,
    reps: [u32; 3],
}

impl<'a> MatchFinder<'a> {
    pub fn new(data: &'a [u8], params: Params) -> Self {
        let window = 1usize << params.window_log;
        let chain_size = window.min(data.len().max(1).next_power_of_two());
        Self {
            data,
            params,
            head: vec![0; 1 << params.hash_log],
            chain: vec![0; chain_size],
            chain_mask: chain_size - 1,
            max_distance: chain_size - 1,
            next_insert: 0,
            reps: INITIAL_REPS,
        }
    }

    #[inline]
    fn hash(&self, pos: usize) -> usize {
        let v = u32::from_le_bytes(self.data[pos..pos + 4].try_into().unwrap());
        (v.wrapping_mul(2_654_435_761) >> (32 - self.params.hash_log)) as usize
    }

    fn insert_upto(&mut self, target: usize) {
        let end = target.min(self.data.len().saturating_sub(3));
        while self.next_insert < end {
            let pos = self.next_insert;
            let h = self.hash(pos);
            self.chain[pos & self.chain_mask] = self.head[h];
            self.head[h] = pos as u32 + 1;
            self.next_insert += 1;
        }
        self.next_insert = self.next_insert.max(target);
    }

    #[inline]
    fn match_len(&self, older: usize, pos: usize, end: usize) -> usize {
        let d = self.data;
        let max = end - pos;
        let mut n = 0;
        while n + 8 <= max {
            let a = u64::from_le_bytes(d[older + n..older + n + 8].try_into().unwrap());
            let b = u64::from_le_bytes(d[pos + n..pos + n + 8].try_into().unwrap());
            let x = a ^ b;
            if x != 0 {
                return n + (x.trailing_zeros() / 8) as usize;
            }
            n += 8;
        }
        while n < max && d[older + n] == d[pos + n] {
            n += 1;
        }
        n
    }

    /// Best `(length, distance)` at `pos`, or length 0 if nothing >= `MIN_MATCH`.
    fn find_best(&self, pos: usize, end: usize) -> (usize, usize) {
        let mut best = (0usize, 0usize);
        for &r in &self.reps {
            let r = r as usize;
            if r == 0 || r > pos || r > self.max_distance {
                continue;
            }
            let l = self.match_len(pos - r, pos, end);
            if l > best.0 {
                best = (l, r);
            }
        }
        if best.0 >= self.params.nice_len {
            return best;
        }
        let mut cand = self.head[self.hash(pos)] as usize;
        let mut depth = self.params.search_depth;
        while cand != 0 && depth > 0 {
            let c = cand - 1;
            if c >= pos || pos - c > self.max_distance {
                break;
            }
            if pos + best.0 >= end || self.data[c + best.0] == self.data[pos + best.0] {
                let l = self.match_len(c, pos, end);
                if l > best.0 {
                    best = (l, pos - c);
                    if l >= self.params.nice_len {
                        break;
                    }
                }
            }
            let next = self.chain[c & self.chain_mask] as usize;
            if next >= cand {
                break;
            }
            cand = next;
            depth -= 1;
        }
        if best.0 < MIN_MATCH { (0, 0) } else { best }
    }

    /// Produce literals and sequences for `data[start..end]`.
    pub fn find_block(&mut self, start: usize, end: usize) -> (Vec<u8>, Vec<RawSequence>) {
        let mut literals = Vec::new();
        let mut seqs = Vec::new();
        let mut ip = start;
        let mut anchor = start;
        while ip + MIN_MATCH <= end {
            self.insert_upto(ip);
            let (mut len, mut dist) = self.find_best(ip, end);
            if len == 0 {
                ip += 1;
                continue;
            }
            for _ in 0..self.params.lazy {
                if ip + 1 + MIN_MATCH > end {
                    break;
                }
                self.insert_upto(ip + 1);
                let (l2, d2) = self.find_best(ip + 1, end);
                if l2 > len + 1 {
                    ip += 1;
                    len = l2;
                    dist = d2;
                } else {
                    break;
                }
            }
            literals.extend_from_slice(&self.data[anchor..ip]);
            seqs.push(RawSequence {
                literal_length: (ip - anchor) as u32,
                match_length: len as u32,
                offset: dist as u32,
            });
            let d = dist as u32;
            if d != self.reps[0] {
                self.reps = [d, self.reps[0], self.reps[1]];
            }
            ip += len;
            anchor = ip;
        }
        literals.extend_from_slice(&self.data[anchor..end]);
        (literals, seqs)
    }

    /// Skip a block emitted without sequences (raw/RLE) while keeping the history indexed.
    pub fn skip_block(&mut self, end: usize) {
        self.insert_upto(end);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeat_offset_rules() {
        let mut reps = INITIAL_REPS;
        assert_eq!(resolve_offset(1, 5, &mut reps).unwrap(), 1);
        assert_eq!(reps, [1, 4, 8]);
        assert_eq!(resolve_offset(2, 5, &mut reps).unwrap(), 4);
        assert_eq!(reps, [4, 1, 8]);
        assert_eq!(resolve_offset(3, 5, &mut reps).unwrap(), 8);
        assert_eq!(reps, [8, 4, 1]);
        // literal_length == 0 shifts the meaning by one.
        assert_eq!(resolve_offset(1, 0, &mut reps).unwrap(), 4);
        assert_eq!(reps, [4, 8, 1]);
        assert_eq!(resolve_offset(3, 0, &mut reps).unwrap(), 3);
        assert_eq!(reps, [3, 4, 8]);
        assert_eq!(resolve_offset(103, 0, &mut reps).unwrap(), 100);
        assert_eq!(reps, [100, 3, 4]);
    }

    #[test]
    fn encode_offset_inverts_resolve() {
        let mut enc = INITIAL_REPS;
        let mut dec = INITIAL_REPS;
        for &(off, ll) in &[
            (4u32, 3u32),
            (4, 0),
            (8, 0),
            (7, 0),
            (100, 2),
            (100, 1),
            (3, 0),
        ] {
            let v = encode_offset(off, ll, &enc);
            assert_eq!(resolve_offset(v, ll, &mut enc).unwrap(), off);
            assert_eq!(resolve_offset(v, ll, &mut dec).unwrap(), off);
            assert_eq!(enc, dec);
        }
    }

    #[test]
    fn overlapping_match_copy() {
        let mut out = Vec::new();
        let seqs = [Sequence {
            literal_length: 2,
            match_length: 7,
            offset_value: 2 + 3,
        }];
        let mut reps = INITIAL_REPS;
        execute_sequences(&mut out, 0, b"abXY", &seqs, &mut reps, usize::MAX).unwrap();
        assert_eq!(out, b"ababababaXY");
    }

    #[test]
    fn rejects_offset_before_frame() {
        let mut out = b"prev".to_vec();
        let seqs = [Sequence {
            literal_length: 1,
            match_length: 4,
            offset_value: 5 + 3,
        }];
        let mut reps = INITIAL_REPS;
        assert!(execute_sequences(&mut out, 4, b"a", &seqs, &mut reps, usize::MAX).is_err());
    }
}
