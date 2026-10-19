//! Deterministic, synthetic benchmark datasets (no real data, PII or secrets).
//!
//! Every dataset is a pure function of `(kind, length, seed)`; the benchmark records its
//! SHA-256 so results can be tied to the exact bytes. The classes span the compressibility
//! range relevant to the thesis: the AEAD payload is the *compressed* output, so only
//! poorly compressible inputs produce enough POLYVAL segments for parallelism to matter.

use std::fmt;
use std::str::FromStr;

/// SplitMix64 (Steele, Lea & Flood, 2014): small, fast, reproducible across platforms.
#[derive(Debug, Clone)]
pub struct SplitMix64(pub u64);

impl SplitMix64 {
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `0..n` (`n > 0`; modulo bias is negligible for the small `n` used here).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    pub fn fill(&mut self, out: &mut Vec<u8>, len: usize) {
        let end = out.len() + len;
        while out.len() < end {
            let word = self.next_u64().to_le_bytes();
            let take = (end - out.len()).min(8);
            out.extend_from_slice(&word[..take]);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DatasetKind {
    /// Pseudorandom bytes: incompressible (Zstd output slightly larger than input).
    Random,
    /// Word-based synthetic prose with a skewed word distribution.
    Text,
    /// Newline-delimited JSON records with random identifiers and numbers.
    Json,
    /// Alternating 64 KiB blocks of `Random` and `Text`.
    Mixed,
    /// A 4 KiB random block repeated: extremely compressible.
    Repetitive,
}

impl DatasetKind {
    pub const ALL: [Self; 5] = [
        Self::Random,
        Self::Text,
        Self::Json,
        Self::Mixed,
        Self::Repetitive,
    ];

    pub fn name(&self) -> &'static str {
        match self {
            Self::Random => "random",
            Self::Text => "text",
            Self::Json => "json",
            Self::Mixed => "mixed",
            Self::Repetitive => "repetitive",
        }
    }
}

impl fmt::Display for DatasetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for DatasetKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|k| k.name() == s)
            .ok_or_else(|| format!("unknown dataset '{s}'"))
    }
}

const WORDS: [&str; 48] = [
    "the",
    "of",
    "and",
    "data",
    "block",
    "segment",
    "parallel",
    "hash",
    "field",
    "key",
    "nonce",
    "tag",
    "stream",
    "frame",
    "compress",
    "encrypt",
    "verify",
    "message",
    "length",
    "thread",
    "merge",
    "order",
    "result",
    "value",
    "input",
    "output",
    "state",
    "proof",
    "cipher",
    "counter",
    "memory",
    "buffer",
    "network",
    "storage",
    "object",
    "replica",
    "measure",
    "latency",
    "throughput",
    "sample",
    "trial",
    "median",
    "variance",
    "model",
    "system",
    "design",
    "error",
    "limit",
];

fn text_into(rng: &mut SplitMix64, out: &mut Vec<u8>, len: usize) {
    let end = out.len() + len;
    let mut words_in_sentence = 0;
    while out.len() < end {
        // min of two uniforms skews toward frequent (low-index) words.
        let idx = rng
            .below(WORDS.len() as u64)
            .min(rng.below(WORDS.len() as u64)) as usize;
        let word = WORDS[idx].as_bytes();
        if words_in_sentence == 0 {
            out.push(word[0].to_ascii_uppercase());
            out.extend_from_slice(&word[1..]);
        } else {
            out.extend_from_slice(word);
        }
        words_in_sentence += 1;
        if words_in_sentence > 6 && rng.below(5) == 0 {
            out.extend_from_slice(if rng.below(6) == 0 { b".\n" } else { b". " });
            words_in_sentence = 0;
        } else {
            out.push(b' ');
        }
    }
    out.truncate(end);
}

fn json_into(rng: &mut SplitMix64, out: &mut Vec<u8>, len: usize) {
    const STATUS: [&str; 4] = ["ok", "pending", "failed", "retry"];
    let end = out.len() + len;
    let mut id = 0u64;
    while out.len() < end {
        id += 1;
        let line = format!(
            "{{\"id\":{id},\"user\":\"u{:08x}\",\"ts\":{},\"amount\":{}.{:02},\"status\":\"{}\",\"tags\":[\"t{}\",\"t{}\"]}}\n",
            rng.next_u64() as u32,
            1_700_000_000 + rng.below(100_000_000),
            rng.below(100_000),
            rng.below(100),
            STATUS[rng.below(4) as usize],
            rng.below(32),
            rng.below(32),
        );
        out.extend_from_slice(line.as_bytes());
    }
    out.truncate(end);
}

/// Generate `len` bytes of dataset `kind` from `seed`.
pub fn generate(kind: DatasetKind, len: usize, seed: u64) -> Vec<u8> {
    // Mix the kind into the seed so classes never share a random stream.
    let mut rng = SplitMix64(seed ^ (kind as u64 + 1).wrapping_mul(0xA076_1D64_78BD_642F));
    let mut out = Vec::with_capacity(len + 256);
    match kind {
        DatasetKind::Random => rng.fill(&mut out, len),
        DatasetKind::Text => text_into(&mut rng, &mut out, len),
        DatasetKind::Json => json_into(&mut rng, &mut out, len),
        DatasetKind::Mixed => {
            const BLOCK: usize = 64 * 1024;
            let mut i = 0;
            while out.len() < len {
                let n = BLOCK.min(len - out.len());
                if i % 2 == 0 {
                    rng.fill(&mut out, n);
                } else {
                    text_into(&mut rng, &mut out, n);
                }
                i += 1;
            }
        }
        DatasetKind::Repetitive => {
            let mut block = Vec::with_capacity(4096);
            rng.fill(&mut block, 4096);
            while out.len() < len {
                let n = block.len().min(len - out.len());
                out.extend_from_slice(&block[..n]);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_exact_length_and_distinct() {
        for kind in DatasetKind::ALL {
            for len in [0usize, 1, 4095, 65_537, 300_000] {
                let a = generate(kind, len, 7);
                assert_eq!(a.len(), len, "{:?}", kind);
                assert_eq!(a, generate(kind, len, 7), "{:?}", kind);
            }
            assert_ne!(
                generate(kind, 10_000, 7),
                generate(kind, 10_000, 8),
                "{:?}",
                kind
            );
            assert_eq!(kind.name().parse::<DatasetKind>().unwrap(), kind);
        }
    }

    #[test]
    fn compressibility_ordering() {
        let ratio = |kind| {
            let data = generate(kind, 1 << 20, 1);
            zstd::bulk::compress(&data, 3).unwrap().len() as f64 / data.len() as f64
        };
        let (random, text, repetitive) = (
            ratio(DatasetKind::Random),
            ratio(DatasetKind::Text),
            ratio(DatasetKind::Repetitive),
        );
        assert!(random > 0.99, "random ratio {random}");
        assert!(text < 0.6, "text ratio {text}");
        assert!(repetitive < 0.01, "repetitive ratio {repetitive}");
    }
}
