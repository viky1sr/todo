//! XXH64 (seed 0 is used by Zstandard's `Content_Checksum`, which stores the low 32 bits).

const P1: u64 = 0x9E37_79B1_85EB_CA87;
const P2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const P3: u64 = 0x1656_67B1_9E37_79F9;
const P4: u64 = 0x85EB_CA77_C2B2_AE63;
const P5: u64 = 0x27D4_EB2F_1656_67C5;

#[inline]
fn read_u64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[..8].try_into().unwrap())
}

#[inline]
fn read_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[..4].try_into().unwrap())
}

#[inline]
fn round(acc: u64, input: u64) -> u64 {
    acc.wrapping_add(input.wrapping_mul(P2))
        .rotate_left(31)
        .wrapping_mul(P1)
}

#[inline]
fn merge_round(acc: u64, val: u64) -> u64 {
    (acc ^ round(0, val)).wrapping_mul(P1).wrapping_add(P4)
}

fn finalize(mut h: u64, mut tail: &[u8]) -> u64 {
    while tail.len() >= 8 {
        h ^= round(0, read_u64(tail));
        h = h.rotate_left(27).wrapping_mul(P1).wrapping_add(P4);
        tail = &tail[8..];
    }
    if tail.len() >= 4 {
        h ^= u64::from(read_u32(tail)).wrapping_mul(P1);
        h = h.rotate_left(23).wrapping_mul(P2).wrapping_add(P3);
        tail = &tail[4..];
    }
    for &b in tail {
        h ^= u64::from(b).wrapping_mul(P5);
        h = h.rotate_left(11).wrapping_mul(P1);
    }
    h ^= h >> 33;
    h = h.wrapping_mul(P2);
    h ^= h >> 29;
    h = h.wrapping_mul(P3);
    h ^ (h >> 32)
}

/// Streaming XXH64 hasher.
#[derive(Debug, Clone)]
pub struct Xxh64 {
    v: [u64; 4],
    seed: u64,
    total_len: u64,
    buf: [u8; 32],
    buf_len: usize,
}

impl Xxh64 {
    pub fn new(seed: u64) -> Self {
        Self {
            v: [
                seed.wrapping_add(P1).wrapping_add(P2),
                seed.wrapping_add(P2),
                seed,
                seed.wrapping_sub(P1),
            ],
            seed,
            total_len: 0,
            buf: [0; 32],
            buf_len: 0,
        }
    }

    fn consume_stripe(v: &mut [u64; 4], stripe: &[u8]) {
        for (i, lane) in v.iter_mut().enumerate() {
            *lane = round(*lane, read_u64(&stripe[i * 8..]));
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        self.total_len += input.len() as u64;
        if self.buf_len > 0 {
            let take = (32 - self.buf_len).min(input.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&input[..take]);
            self.buf_len += take;
            input = &input[take..];
            if self.buf_len < 32 {
                return;
            }
            let stripe = self.buf;
            Self::consume_stripe(&mut self.v, &stripe);
            self.buf_len = 0;
        }
        while input.len() >= 32 {
            Self::consume_stripe(&mut self.v, &input[..32]);
            input = &input[32..];
        }
        self.buf[..input.len()].copy_from_slice(input);
        self.buf_len = input.len();
    }

    pub fn digest(&self) -> u64 {
        let mut h = if self.total_len >= 32 {
            let [v1, v2, v3, v4] = self.v;
            let mut h = v1
                .rotate_left(1)
                .wrapping_add(v2.rotate_left(7))
                .wrapping_add(v3.rotate_left(12))
                .wrapping_add(v4.rotate_left(18));
            for lane in self.v {
                h = merge_round(h, lane);
            }
            h
        } else {
            self.seed.wrapping_add(P5)
        };
        h = h.wrapping_add(self.total_len);
        finalize(h, &self.buf[..self.buf_len])
    }
}

/// One-shot XXH64.
pub fn xxh64(data: &[u8], seed: u64) -> u64 {
    let mut h = Xxh64::new(seed);
    h.update(data);
    h.digest()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        // Reference values from the xxHash project (XXH64, seed 0).
        assert_eq!(xxh64(b"", 0), 0xEF46_DB37_51D8_E999);
        assert_eq!(xxh64(b"abc", 0), 0x44BC_2CF5_AD77_0999);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7 + 3) as u8).collect();
        for split in [0, 1, 5, 31, 32, 33, 64, 999, 1000] {
            let mut h = Xxh64::new(42);
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.digest(), xxh64(&data, 42), "split {split}");
        }
    }
}
