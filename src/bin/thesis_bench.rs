//! Reproducible thesis benchmark: sequential vs. segment-parallel AES-GCM-SIV over
//! Zstandard-compressed payloads. Writes one JSON object per measured trial (JSONL, the
//! format read by `scripts/summarize_bench.py`) plus a `<out>.meta.json` provenance file.
//!
//! ```text
//! cargo run --release --bin thesis_bench -- --profile quick --out results/quick.jsonl
//! python3 scripts/summarize_bench.py results/quick.jsonl
//! ```
//!
//! Benchmark kinds (see `docs/BENCHMARK_PROTOCOL.md`):
//! * `polyval-only`: POLYVAL over the canonical record `pad16(A)||pad16(C)||len`.
//! * `crypto-only`: AES-GCM-SIV encryption of the frozen compressed payload.
//! * `end-to-end`: single-frame Zstd compress + encrypt + verify/decrypt + decompress;
//!   both arms compress identically, only the AEAD scheduling differs.
//! * `independent-frames`: independent Zstd frames; the sequential arm compresses,
//!   encrypts and decompresses sequentially, the parallel arm parallelises all three.
//!
//! Every trial's output is compared byte-for-byte with a reference computed before
//! timing (and checked once against the upstream `aes-gcm-siv` crate); any mismatch
//! aborts the run. Arm order is randomised per trial with the recorded seed.

use parallel_aes_gcm_siv::datasets::{DatasetKind, SplitMix64, generate};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::hint::black_box;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use todo_crypto::{
    AesGcmSivOutput, CryptoMode, EnvironmentInfo, SegmentPlan, SegmentationPolicy,
    aes_gcm_siv_encrypt_planned, aes_gcm_siv_encrypt_sequential, aes_gcm_siv_encrypt_upstream,
    build_polyval_record, derive_keys, polyval_planned, polyval_sequential,
};
use todo_zstd::{
    CompressionMode, SEALED_STREAM_VERSION, SealedStream, SegmentDescriptor, SegmentationStrategy,
    StreamCryptoPipeline,
};

type AnyResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Fixed, public benchmark key material (never a production secret).
const KEY: [u8; 16] = [0x42; 16];
const NONCE: [u8; 12] = [0x24; 12];
const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    PolyvalOnly,
    CryptoOnly,
    EndToEnd,
    IndependentFrames,
}

impl Kind {
    const ALL: [Self; 4] = [
        Self::PolyvalOnly,
        Self::CryptoOnly,
        Self::EndToEnd,
        Self::IndependentFrames,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::PolyvalOnly => "polyval-only",
            Self::CryptoOnly => "crypto-only",
            Self::EndToEnd => "end-to-end",
            Self::IndependentFrames => "independent-frames",
        }
    }
}

#[derive(Clone, Copy)]
enum SegCfg {
    Adaptive,
    Fixed(usize),
}

impl SegCfg {
    fn label(self) -> String {
        match self {
            Self::Adaptive => "adaptive".into(),
            Self::Fixed(n) => format!("fixed-{n}"),
        }
    }

    fn strategy(self, policy: SegmentationPolicy) -> SegmentationStrategy {
        match self {
            Self::Adaptive => SegmentationStrategy::Adaptive(policy),
            Self::Fixed(n) => SegmentationStrategy::Fixed(n),
        }
    }
}

struct Config {
    out: PathBuf,
    profile: String,
    trials: usize,
    warmup: usize,
    sizes: Vec<usize>,
    datasets: Vec<DatasetKind>,
    threads: Vec<usize>,
    segments: Vec<SegCfg>,
    kinds: Vec<Kind>,
    seed: u64,
    level: i32,
    frame_bytes: usize,
    policy: SegmentationPolicy,
}

const USAGE: &str = "\
Usage: thesis_bench --out FILE.jsonl [options]
  --profile quick|full        defaults below (quick)
  --trials N                  measured paired trials per case (quick 10, full 30)
  --warmup N                  untimed runs per arm before measuring (quick 2, full 3)
  --sizes LIST                original sizes, e.g. 256K,1M,4M
                              (quick 1M,4M; full 256K,1M,4M,16M,64M)
  --datasets LIST             random,text,json,mixed,repetitive (default: all)
  --threads LIST              Rayon threads for the parallel arm, 'max' allowed
                              (quick max; full 1,2,4,8,max)
  --segments LIST             adaptive and/or fixed sizes, e.g. adaptive,64K
                              (quick adaptive; full adaptive,64K)
  --kinds LIST                polyval-only,crypto-only,end-to-end,independent-frames
                              (default: all)
  --seed N                    dataset and arm-order seed (default 20261012)
  --level N                   Zstd level (default 3)
  --frame-bytes SIZE          input bytes per independent frame (default 128K)
  --min-parallel-bytes SIZE   adaptive threshold (default from SegmentationPolicy)
";

fn parse_size(s: &str) -> Result<usize, String> {
    let s = s.trim();
    let (num, mul) = match s.chars().last() {
        Some('K' | 'k') => (&s[..s.len() - 1], KIB),
        Some('M' | 'm') => (&s[..s.len() - 1], MIB),
        Some('G' | 'g') => (&s[..s.len() - 1], 1024 * MIB),
        _ => (s, 1),
    };
    num.parse::<usize>()
        .ok()
        .and_then(|n| n.checked_mul(mul))
        .ok_or_else(|| format!("invalid size '{s}'"))
}

fn parse_list<T>(s: &str, f: impl Fn(&str) -> Result<T, String>) -> Result<Vec<T>, String> {
    s.split(',').filter(|x| !x.is_empty()).map(f).collect()
}

fn max_threads() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get())
}

fn parse_args() -> Result<Config, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{USAGE}");
        std::process::exit(0);
    }
    let mut i = 0;
    while i < args.len() {
        if !args[i].starts_with("--") {
            return Err(format!("unexpected argument '{}'\n{USAGE}", args[i]));
        }
        if args.get(i + 1).is_none_or(|v| v.starts_with("--")) {
            return Err(format!("option {} needs a value\n{USAGE}", args[i]));
        }
        i += 2;
    }
    let get = |name: &str| -> Option<&str> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .map(String::as_str)
    };
    let profile = get("--profile").unwrap_or("quick").to_string();
    let full = match profile.as_str() {
        "quick" => false,
        "full" => true,
        p => return Err(format!("unknown profile '{p}'")),
    };
    let out = PathBuf::from(get("--out").ok_or(format!("--out is required\n{USAGE}"))?);
    let num = |name: &str, default: u64| -> Result<u64, String> {
        get(name).map_or(Ok(default), |v| {
            v.parse().map_err(|_| format!("invalid {name} '{v}'"))
        })
    };
    let trials = (num("--trials", if full { 30 } else { 10 })? as usize).max(1);
    let warmup = num("--warmup", if full { 3 } else { 2 })? as usize;
    let default_sizes = if full { "256K,1M,4M,16M,64M" } else { "1M,4M" };
    let sizes = parse_list(get("--sizes").unwrap_or(default_sizes), parse_size)?;
    let datasets = match get("--datasets") {
        Some(s) => parse_list(s, |x| x.parse())?,
        None => DatasetKind::ALL.to_vec(),
    };
    let default_threads = if full { "1,2,4,8,max" } else { "max" };
    let mut threads = parse_list(get("--threads").unwrap_or(default_threads), |x| {
        if x == "max" {
            return Ok(max_threads());
        }
        x.parse::<usize>()
            .ok()
            .filter(|&n| n > 0)
            .ok_or(format!("invalid thread count '{x}'"))
    })?;
    threads.dedup();
    let default_segments = if full { "adaptive,64K" } else { "adaptive" };
    let segments = parse_list(get("--segments").unwrap_or(default_segments), |x| {
        if x == "adaptive" {
            return Ok(SegCfg::Adaptive);
        }
        let n = parse_size(x)?;
        if n == 0 || n % 16 != 0 {
            return Err(format!(
                "segment size {n} must be a non-zero multiple of 16"
            ));
        }
        Ok(SegCfg::Fixed(n))
    })?;
    let kinds = match get("--kinds") {
        Some(s) => parse_list(s, |x| {
            Kind::ALL
                .into_iter()
                .find(|k| k.name() == x)
                .ok_or(format!("unknown kind '{x}'"))
        })?,
        None => Kind::ALL.to_vec(),
    };
    let mut policy = SegmentationPolicy::DEFAULT;
    if let Some(v) = get("--min-parallel-bytes") {
        policy.min_parallel_bytes = parse_size(v)?;
    }
    let level = i32::try_from(num("--level", 3)?).map_err(|_| "invalid --level".to_string())?;
    Ok(Config {
        out,
        profile,
        trials,
        warmup,
        sizes,
        datasets,
        threads,
        segments,
        kinds,
        seed: num("--seed", 20_261_012)?,
        level,
        frame_bytes: get("--frame-bytes").map_or(Ok(128 * KIB), parse_size)?,
        policy,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn ns(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX).max(1)
}

/// One timed run: wall-clock total plus optional stage breakdown.
struct Sample {
    total_ns: u64,
    stages: Vec<(&'static str, u64)>,
}

fn sample(total: Duration) -> Sample {
    Sample {
        total_ns: ns(total),
        stages: Vec::new(),
    }
}

/// Configuration and plan fields shared by both arms of a case.
struct CaseInfo {
    case_id: String,
    kind: Kind,
    dataset: DatasetKind,
    dataset_sha256: String,
    original_bytes: usize,
    compressed_bytes: usize,
    polyval_bytes: usize,
    zstd_mode: CompressionMode,
    zstd_frames: usize,
    segmentation: String,
    plan: SegmentPlan,
    /// Length the plan was computed for (compressed payload or POLYVAL record).
    plan_bytes: usize,
    threads: usize,
    tag_hex: String,
    ciphertext_sha256: Option<String>,
}

struct RunMeta {
    git_commit: String,
    rustc: String,
}

impl CaseInfo {
    /// `segments`/`segment_bytes` describe the parallel arm's plan; both arms of a pair
    /// carry the same values so `summarize_bench.py` can validate the pairing.
    fn segments_and_size(&self) -> (usize, usize) {
        match self.plan {
            SegmentPlan::Parallel {
                segment_bytes,
                segments,
            } => (segments.max(1), segment_bytes),
            SegmentPlan::Sequential { .. } => (1, self.plan_bytes.next_multiple_of(16).max(16)),
        }
    }

    fn row(
        &self,
        cfg: &Config,
        meta: &RunMeta,
        implementation: &str,
        trial: usize,
        order: &str,
        s: &Sample,
    ) -> Value {
        let (segments, segment_bytes) = self.segments_and_size();
        let parallel = implementation == "parallel";
        let reason = match self.plan {
            SegmentPlan::Sequential { reason } if parallel => {
                serde_json::to_value(reason).unwrap_or(Value::Null)
            }
            _ => Value::Null,
        };
        let mut row = json!({
            "case_id": self.case_id,
            "bench_kind": self.kind.name(),
            "implementation": implementation,
            "trial": trial,
            "order": order,
            "original_bytes": self.original_bytes,
            "compressed_bytes": self.compressed_bytes,
            "polyval_bytes": self.polyval_bytes,
            "segments": segments,
            "segment_bytes": segment_bytes,
            "threads": if parallel { self.threads } else { 1 },
            "total_ns": s.total_ns,
            "tag_hex": self.tag_hex,
            "dataset": self.dataset.name(),
            "dataset_sha256": self.dataset_sha256,
            "zstd_mode": self.zstd_mode.label(),
            "zstd_level": cfg.level,
            "zstd_frames": self.zstd_frames,
            "segmentation": if parallel { self.segmentation.as_str() } else { "sequential" },
            "execution": if parallel { self.plan.label() } else { "sequential" },
            "executed_segments": if parallel {
                self.plan.executed_segments(self.plan_bytes)
            } else {
                1
            },
            "plan_reason": reason,
            "correctness": "PASS",
            "seed": cfg.seed,
            "git_commit": meta.git_commit,
            "rustc": meta.rustc,
        });
        if let Some(obj) = row.as_object_mut() {
            if let Some(h) = &self.ciphertext_sha256 {
                obj.insert("ciphertext_sha256".into(), json!(h));
            }
            for (k, v) in &s.stages {
                obj.insert((*k).into(), json!(v));
            }
        }
        row
    }
}

type Measurement = (usize, &'static str, &'static str, Sample);

/// Run warm-up and `trials` paired measurements with randomised arm order.
fn paired<S, P>(
    cfg: &Config,
    rng: &mut SplitMix64,
    mut seq: S,
    mut par: P,
) -> Result<Vec<Measurement>, String>
where
    S: FnMut() -> Result<Sample, String>,
    P: FnMut() -> Result<Sample, String>,
{
    for _ in 0..cfg.warmup {
        seq()?;
        par()?;
    }
    let mut out = Vec::with_capacity(cfg.trials * 2);
    for trial in 1..=cfg.trials {
        if rng.next_u64() & 1 == 0 {
            out.push((trial, "sequential", "first", seq()?));
            out.push((trial, "parallel", "second", par()?));
        } else {
            out.push((trial, "parallel", "first", par()?));
            out.push((trial, "sequential", "second", seq()?));
        }
    }
    Ok(out)
}

fn check_aead(
    out: &AesGcmSivOutput,
    reference: &AesGcmSivOutput,
    what: &str,
) -> Result<(), String> {
    if out.tag != reference.tag || out.ciphertext != reference.ciphertext {
        return Err(format!(
            "{what}: output differs from reference (correctness FAIL)"
        ));
    }
    Ok(())
}

fn aad_for(segments: Vec<SegmentDescriptor>) -> Vec<u8> {
    SealedStream {
        version: SEALED_STREAM_VERSION,
        crypto_mode: CryptoMode::AesGcmSiv,
        segments,
        ciphertext: Vec::new(),
        tag: vec![0; 16],
        stream_chunk_size: None,
    }
    .associated_data()
}

fn seal_open_sample(
    pipeline: &StreamCryptoPipeline,
    data: &[u8],
    reference: &SealedStream,
) -> Result<Sample, String> {
    let start = Instant::now();
    let (sealed, seal) = pipeline
        .compress_and_encrypt_with_metrics(black_box(data), &KEY, &NONCE)
        .map_err(|e| e.to_string())?;
    let (recovered, open) = pipeline
        .decrypt_and_decompress_with_metrics(&sealed, &KEY, &NONCE)
        .map_err(|e| e.to_string())?;
    let total = start.elapsed();
    if &sealed != reference || recovered != data {
        return Err("end-to-end output or roundtrip differs (correctness FAIL)".into());
    }
    Ok(Sample {
        total_ns: ns(total),
        stages: vec![
            ("compression_ns", ns(seal.compression)),
            ("encrypt_total_ns", ns(seal.encryption)),
            ("decrypt_ns", ns(open.decryption)),
            ("decompression_ns", ns(open.decompression)),
        ],
    })
}

struct CaseInput<'a> {
    kind: Kind,
    dataset: DatasetKind,
    data: &'a [u8],
    dataset_sha256: &'a str,
    threads: usize,
    seg: SegCfg,
}

fn measure_polyval_only(
    cfg: &Config,
    rng: &mut SplitMix64,
    input: &CaseInput,
    base: CaseInfo,
    aad: &[u8],
    stream: &[u8],
) -> AnyResult<(CaseInfo, Vec<Measurement>)> {
    let record = build_polyval_record(aad, stream);
    let h = derive_keys(&KEY, &NONCE)?.auth_key;
    let plan = input.seg.strategy(cfg.policy).plan(record.len())?;
    let reference = polyval_sequential(&h, &record);
    if polyval_planned(&h, &record, &plan)? != reference {
        return Err("POLYVAL parallel != sequential (correctness FAIL)".into());
    }
    let info = CaseInfo {
        polyval_bytes: record.len(),
        plan,
        plan_bytes: record.len(),
        tag_hex: hex(&reference),
        ..base
    };
    let check = |out: [u8; 16], s: Sample| {
        if out == reference {
            Ok(s)
        } else {
            Err("POLYVAL mismatch (correctness FAIL)".to_string())
        }
    };
    let results = paired(
        cfg,
        rng,
        || {
            let t = Instant::now();
            let out = polyval_sequential(black_box(&h), black_box(&record));
            check(out, sample(t.elapsed()))
        },
        || {
            let t = Instant::now();
            let out = polyval_planned(black_box(&h), black_box(&record), &plan)
                .map_err(|e| e.to_string())?;
            check(out, sample(t.elapsed()))
        },
    )?;
    Ok((info, results))
}

fn measure_crypto_only(
    cfg: &Config,
    rng: &mut SplitMix64,
    input: &CaseInput,
    base: CaseInfo,
    aad: &[u8],
    stream: &[u8],
) -> AnyResult<(CaseInfo, Vec<Measurement>)> {
    let plan = input.seg.strategy(cfg.policy).plan(stream.len())?;
    let reference = aes_gcm_siv_encrypt_upstream(&KEY, &NONCE, aad, stream)?;
    check_aead(
        &aes_gcm_siv_encrypt_planned(&KEY, &NONCE, aad, stream, &plan)?,
        &reference,
        "planned vs upstream",
    )?;
    let info = CaseInfo {
        polyval_bytes: aad.len().next_multiple_of(16) + stream.len().next_multiple_of(16) + 16,
        plan,
        plan_bytes: stream.len(),
        tag_hex: hex(&reference.tag),
        ciphertext_sha256: Some(sha256_hex(&reference.ciphertext)),
        ..base
    };
    let results = paired(
        cfg,
        rng,
        || {
            let t = Instant::now();
            let out = aes_gcm_siv_encrypt_sequential(&KEY, &NONCE, aad, black_box(stream))
                .map_err(|e| e.to_string())?;
            let s = sample(t.elapsed());
            check_aead(&out, &reference, "sequential")?;
            Ok(s)
        },
        || {
            let t = Instant::now();
            let out = aes_gcm_siv_encrypt_planned(&KEY, &NONCE, aad, black_box(stream), &plan)
                .map_err(|e| e.to_string())?;
            let s = sample(t.elapsed());
            check_aead(&out, &reference, "parallel")?;
            Ok(s)
        },
    )?;
    Ok((info, results))
}

fn measure_pipeline(
    cfg: &Config,
    rng: &mut SplitMix64,
    input: &CaseInput,
    base: CaseInfo,
) -> AnyResult<(CaseInfo, Vec<Measurement>)> {
    let data = input.data;
    let independent = input.kind == Kind::IndependentFrames;
    let new_pipeline = || -> AnyResult<StreamCryptoPipeline> {
        Ok(if independent {
            StreamCryptoPipeline::new(cfg.frame_bytes, cfg.level, 16)?
                .with_compression_mode(CompressionMode::IndependentFrames)
        } else {
            StreamCryptoPipeline::single_frame(cfg.level)
        })
    };
    let seq_pipe = new_pipeline()?
        .with_frame_parallelism(false)
        .with_segmentation(SegmentationStrategy::Sequential)?;
    let par_pipe = new_pipeline()?
        .with_frame_parallelism(true)
        .with_segmentation(input.seg.strategy(cfg.policy))?;

    let (reference, seal) = seq_pipe.compress_and_encrypt_with_metrics(data, &KEY, &NONCE)?;
    let (par_sealed, par_seal) = par_pipe.compress_and_encrypt_with_metrics(data, &KEY, &NONCE)?;
    if par_sealed != reference {
        return Err("parallel sealed stream != sequential (correctness FAIL)".into());
    }
    let (_, stream) = seq_pipe.compress(data)?;
    let upstream =
        aes_gcm_siv_encrypt_upstream(&KEY, &NONCE, &reference.associated_data(), &stream)?;
    if upstream.tag.as_slice() != reference.tag.as_slice()
        || upstream.ciphertext != reference.ciphertext
    {
        return Err("pipeline output != upstream aes-gcm-siv (correctness FAIL)".into());
    }
    if par_pipe.decrypt_and_decompress(&reference, &KEY, &NONCE)? != data {
        return Err("roundtrip mismatch (correctness FAIL)".into());
    }
    let info = CaseInfo {
        compressed_bytes: seal.compressed_bytes,
        polyval_bytes: seal.aad_bytes.next_multiple_of(16)
            + seal.compressed_bytes.next_multiple_of(16)
            + 16,
        zstd_mode: seal.compression_mode,
        zstd_frames: seal.zstd_frames,
        plan: par_seal.plan,
        plan_bytes: seal.compressed_bytes,
        tag_hex: hex(&reference.tag),
        ciphertext_sha256: Some(sha256_hex(&reference.ciphertext)),
        ..base
    };
    let results = paired(
        cfg,
        rng,
        || seal_open_sample(&seq_pipe, data, &reference),
        || seal_open_sample(&par_pipe, data, &reference),
    )?;
    Ok((info, results))
}

fn run_case(
    cfg: &Config,
    meta: &RunMeta,
    writer: &mut impl Write,
    rng: &mut SplitMix64,
    input: &CaseInput,
) -> AnyResult<String> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(input.threads)
        .build()?;
    let (segments, stream) = StreamCryptoPipeline::single_frame(cfg.level).compress(input.data)?;
    let base = CaseInfo {
        case_id: format!(
            "{}-{}-t{}-{}",
            input.dataset.name(),
            input.data.len(),
            input.threads,
            input.seg.label()
        ),
        kind: input.kind,
        dataset: input.dataset,
        dataset_sha256: input.dataset_sha256.to_string(),
        original_bytes: input.data.len(),
        compressed_bytes: stream.len(),
        polyval_bytes: 0,
        zstd_mode: CompressionMode::SingleFrame,
        zstd_frames: segments.len(),
        segmentation: input.seg.label(),
        plan: SegmentPlan::Sequential {
            reason: todo_crypto::FallbackReason::Forced,
        },
        plan_bytes: stream.len(),
        threads: input.threads,
        tag_hex: String::new(),
        ciphertext_sha256: None,
    };
    let aad = aad_for(segments);

    let (info, results) = pool.install(|| match input.kind {
        Kind::PolyvalOnly => measure_polyval_only(cfg, rng, input, base, &aad, &stream),
        Kind::CryptoOnly => measure_crypto_only(cfg, rng, input, base, &aad, &stream),
        Kind::EndToEnd | Kind::IndependentFrames => measure_pipeline(cfg, rng, input, base),
    })?;

    let mut seq_ns = Vec::new();
    let mut par_ns = Vec::new();
    for (trial, implementation, order, s) in &results {
        if *implementation == "sequential" {
            seq_ns.push(s.total_ns);
        } else {
            par_ns.push(s.total_ns);
        }
        let row = info.row(cfg, meta, implementation, *trial, order, s);
        writeln!(writer, "{row}")?;
    }
    writer.flush()?;
    seq_ns.sort_unstable();
    par_ns.sort_unstable();
    let med = |v: &[u64]| v[v.len() / 2] as f64 / 1e6;
    Ok(format!(
        "{:<36} {:<18} C={:>10} B {:<19} segs={:>4} seq~{:>9.3} ms par~{:>9.3} ms ({:.2}x)",
        info.case_id,
        input.kind.name(),
        info.compressed_bytes,
        info.plan.label(),
        info.plan.executed_segments(info.plan_bytes),
        med(&seq_ns),
        med(&par_ns),
        med(&seq_ns) / med(&par_ns)
    ))
}

fn read_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

fn cpu_model() -> String {
    std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split(':').nth(1))
                .map(|m| m.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".into())
}

fn git(args: &[&str]) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn meta_path(out: &Path) -> PathBuf {
    let mut name = out.file_name().unwrap_or_default().to_os_string();
    name.push(".meta.json");
    out.with_file_name(name)
}

fn main() -> AnyResult<()> {
    let cfg = parse_args()?;
    if cfg!(debug_assertions) {
        eprintln!("WARNING: debug build; measurements are not valid. Use --release.");
    }
    if let Some(dir) = cfg.out.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let env = EnvironmentInfo::detect();
    let git_commit = git(&["rev-parse", "HEAD"]).unwrap_or_else(|| "none".into());
    let git_dirty = git(&["status", "--porcelain"]).map(|s| !s.is_empty());
    let meta = RunMeta {
        git_commit: git_commit.clone(),
        rustc: env.rustc_version.clone(),
    };
    let lock = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock");
    let started = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let mut writer = BufWriter::new(File::create(&cfg.out)?);
    let mut rng = SplitMix64(cfg.seed ^ 0x0BAD_5EED);
    let mut dataset_meta = Vec::new();
    let wall = Instant::now();
    eprintln!(
        "thesis_bench profile={} trials={} warmup={} threads={:?} cpus={} -> {}",
        cfg.profile,
        cfg.trials,
        cfg.warmup,
        cfg.threads,
        env.logical_cpus,
        cfg.out.display()
    );

    for &dataset in &cfg.datasets {
        for &size in &cfg.sizes {
            let data = generate(dataset, size, cfg.seed);
            let digest = sha256_hex(&data);
            let compressed = zstd::bulk::compress(&data, cfg.level)?.len();
            dataset_meta.push(json!({
                "dataset": dataset.name(),
                "original_bytes": size,
                "sha256": digest,
                "single_frame_compressed_bytes": compressed,
                "compression_ratio": size as f64 / compressed.max(1) as f64,
            }));
            for &threads in &cfg.threads {
                for &seg in &cfg.segments {
                    for &kind in &cfg.kinds {
                        let input = CaseInput {
                            kind,
                            dataset,
                            data: &data,
                            dataset_sha256: &digest,
                            threads,
                            seg,
                        };
                        let line = run_case(&cfg, &meta, &mut writer, &mut rng, &input)?;
                        eprintln!("{line}");
                    }
                }
            }
        }
    }

    let meta_json = json!({
        "tool": "thesis_bench",
        "schema": "references/EXPERIMENT_PROTOCOL.md section 5",
        "started_unix": started,
        "wall_seconds": wall.elapsed().as_secs_f64(),
        "argv": std::env::args().collect::<Vec<_>>(),
        "profile": cfg.profile,
        "trials": cfg.trials,
        "warmup": cfg.warmup,
        "seed": cfg.seed,
        "zstd_level": cfg.level,
        "independent_frame_bytes": cfg.frame_bytes,
        "segmentation_policy": cfg.policy,
        "thread_counts": cfg.threads,
        "git_commit": git_commit,
        "git_dirty": git_dirty,
        "cargo_lock_sha256": std::fs::read(&lock).ok().map(|b| sha256_hex(&b)),
        "environment": env,
        "cpu_model": cpu_model(),
        "kernel": read_trimmed("/proc/sys/kernel/osrelease"),
        "cpu0_governor": read_trimmed("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
        "datasets": dataset_meta,
        "key_material": "fixed public benchmark key/nonce; not secret",
    });
    std::fs::write(
        meta_path(&cfg.out),
        serde_json::to_string_pretty(&meta_json)?,
    )?;
    eprintln!(
        "done in {:.1} s; summarize with: python3 scripts/summarize_bench.py {}",
        wall.elapsed().as_secs_f64(),
        cfg.out.display()
    );
    Ok(())
}
