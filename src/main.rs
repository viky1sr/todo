//! Evaluation binary: equivalence checks, pipeline verification, quick measurements,
//! and a REST/IPFS integration smoke test.
//!
//! Run with `cargo run --release` (optionally `RAYON_NUM_THREADS=n`). The timings printed
//! here are single-run indications; use `cargo bench -p todo-crypto` for thesis results.
//!
//! Select the encryption used by the pipeline and integration phases with
//! `--crypto-mode <mode>` (alias `--mode-crypto`, or env `CRYPTO_MODE`); list the modes
//! with `--list-crypto-modes`. Default: `aes-gcm-siv`. Non-AES modes can be sealed as
//! parallel STREAM chunks with `--stream-chunk-size <bytes>` (env `STREAM_CHUNK_SIZE`).

use parallel_aes_gcm_siv::datasets;
use todo_crypto::{
    CryptoMode, DEFAULT_POLYVAL_SEGMENT_SIZE, EnvironmentInfo, assert_aes_gcm_siv_equivalence,
    assert_polyval_equivalence, benchmark_polyval,
};
use todo_rest::{PipelineProcessRequest, RestServiceController};
use todo_zstd::StreamCryptoPipeline;

type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

const USAGE: &str = "Usage: parallel_aes_gcm_siv [--crypto-mode <mode>] [--stream-chunk-size <bytes>] [--list-crypto-modes] [--check-config]";

/// Chunk size used for the STREAM rows of phase [2b].
const DEMO_STREAM_CHUNK: usize = 64 * 1024;

struct CliOptions {
    crypto_mode: CryptoMode,
    stream_chunk_size: Option<usize>,
}

fn print_crypto_modes() {
    println!("Pilihan crypto_mode:");
    for m in CryptoMode::ALL {
        println!(
            "  {:<36} tag {:>2} B | overhead {:>2} B | {}{}",
            m.label(),
            m.tag_len(),
            m.overhead(),
            m.description(),
            if m == CryptoMode::default() {
                " (default)"
            } else {
                ""
            }
        );
    }
}

/// Validate the runtime configuration (env + secret files), print a redacted report that
/// is safe for container logs (Docker, Portainer) and exit: status 1 if invalid.
fn check_config() -> ! {
    let hardening = parallel_aes_gcm_siv::config::harden_process();
    println!("process hardening: {hardening}");
    match parallel_aes_gcm_siv::config::Config::from_env() {
        Ok(config) => {
            print!("{config}");
            std::process::exit(0)
        }
        Err(e) => {
            eprintln!("configuration error: {e}");
            std::process::exit(1)
        }
    }
}

/// `Ok(None)` means: only list the modes and exit.
fn parse_args() -> AnyResult<Option<CliOptions>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut mode = std::env::var("CRYPTO_MODE").ok();
    let mut chunk = std::env::var("STREAM_CHUNK_SIZE").ok();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--list-crypto-modes" => return Ok(None),
            "--check-config" => check_config(),
            "--help" | "-h" => {
                println!("{USAGE}");
                print_crypto_modes();
                return Ok(None);
            }
            "--crypto-mode" | "--mode-crypto" => {
                mode = Some(args.get(i + 1).ok_or(USAGE)?.clone());
                i += 1;
            }
            "--stream-chunk-size" => {
                chunk = Some(args.get(i + 1).ok_or(USAGE)?.clone());
                i += 1;
            }
            other => {
                if let Some(v) = other
                    .strip_prefix("--crypto-mode=")
                    .or_else(|| other.strip_prefix("--mode-crypto="))
                {
                    mode = Some(v.to_string());
                } else if let Some(v) = other.strip_prefix("--stream-chunk-size=") {
                    chunk = Some(v.to_string());
                } else {
                    return Err(format!("unknown argument {other:?}\n{USAGE}").into());
                }
            }
        }
        i += 1;
    }
    let crypto_mode: CryptoMode = mode.map_or(Ok(CryptoMode::default()), |m| m.parse())?;
    let stream_chunk_size = chunk
        .map(|c| c.parse::<usize>())
        .transpose()
        .map_err(|e| format!("invalid --stream-chunk-size: {e}"))?;
    if let Some(size) = stream_chunk_size {
        todo_crypto::crypto_mode::validate_stream_chunk_size(crypto_mode, size)
            .map_err(|e| e.to_string())?;
    }
    Ok(Some(CliOptions {
        crypto_mode,
        stream_chunk_size,
    }))
}

fn main() -> AnyResult<()> {
    let Some(CliOptions {
        crypto_mode,
        stream_chunk_size,
    }) = parse_args()?
    else {
        print_crypto_modes();
        return Ok(());
    };
    let env = EnvironmentInfo::detect();
    println!("== Parallel POLYVAL on Zstandard segments for AES-GCM-SIV (RFC 8452) ==");
    println!(
        "Environment: {} {} | CPUs: {} | Rayon threads: {} | CPU features: [{}] | {} | profile: {}",
        env.os,
        env.arch,
        env.logical_cpus,
        env.rayon_threads,
        env.cpu_features.join(", "),
        env.rustc_version,
        env.build_profile
    );
    if env.build_profile == "debug" {
        println!("WARNING: debug build; use `cargo run --release` for any measurement.");
    }
    println!(
        "crypto_mode: {} ({})",
        crypto_mode.label(),
        crypto_mode.description()
    );
    if let Some(size) = stream_chunk_size {
        println!(
            "STREAM chunking: {size} B per AEAD chunk (index + is_last bound in nonce and AAD)"
        );
    }
    if !crypto_mode.is_authenticated() {
        println!(
            "WARNING: {crypto_mode} is UNAUTHENTICATED: tampering is not detected (baseline only)."
        );
    }
    println!();

    phase_equivalence()?;
    phase_pipeline(crypto_mode, stream_chunk_size)?;
    phase_crypto_modes()?;
    phase_measurements()?;
    phase_integration(crypto_mode, stream_chunk_size)?;

    println!(
        "\nAll checks passed: AES-GCM-SIV identical across sequential, parallel and upstream; every crypto_mode round-trips."
    );
    Ok(())
}

fn pattern(size: usize, mul: usize) -> Vec<u8> {
    (0..size).map(|i| (i * mul % 256) as u8).collect()
}

fn phase_equivalence() -> AnyResult<()> {
    println!("[1] Ekuivalensi tag: POLYVAL sekuensial vs paralel");
    let h_key = [0x4fu8; 16];
    for size in [64 * 1024, 256 * 1024, 1024 * 1024, 8 * 1024 * 1024] {
        let r =
            assert_polyval_equivalence(&h_key, &pattern(size, 37), DEFAULT_POLYVAL_SEGMENT_SIZE)?;
        println!(
            "  {:>8} B | segmen: {:>3} | tag: {} | seq {:>9.1} µs | par {:>9.1} µs | {:.2}x",
            r.data_size_bytes,
            r.num_segments,
            r.parallel_tag_hex,
            r.sequential_latency_micros,
            r.parallel_latency_micros,
            r.speedup_ratio
        );
    }

    let r = assert_aes_gcm_siv_equivalence(
        &[0x3au8; 16],
        &[0x91u8; 12],
        b"Auth Header",
        &pattern(256 * 1024, 19),
        DEFAULT_POLYVAL_SEGMENT_SIZE,
    )?;
    println!(
        "  AES-GCM-SIV 256 KiB | seq = par = upstream: {} | tag {}",
        r.is_bit_identical, r.parallel_tag_hex
    );
    println!();
    Ok(())
}

fn phase_pipeline(mode: CryptoMode, stream_chunk_size: Option<usize>) -> AnyResult<()> {
    match stream_chunk_size {
        Some(size) => println!("[2] Pipeline: Zstd -> {mode} STREAM paralel, chunk AEAD {size} B"),
        None => println!(
            "[2] Pipeline: Zstd -> satu pesan {mode} (segmentasi POLYVAL adaptif untuk AES-GCM-SIV)"
        ),
    }
    let key = [0x3au8; 16];
    let nonce = [0x91u8; 12];
    let repetitive: Vec<u8> = (0..4 * 1024 * 1024)
        .map(|i| if i % 8 == 0 { (i % 256) as u8 } else { 0x42 })
        .collect();
    let mixed = datasets::generate(datasets::DatasetKind::Mixed, 8 * 1024 * 1024, 1);
    let random = datasets::generate(datasets::DatasetKind::Random, 8 * 1024 * 1024, 1);
    let cases: [(&str, &[u8], StreamCryptoPipeline); 4] = [
        (
            "repetitif, 32 frame",
            &repetitive,
            StreamCryptoPipeline::new(128 * 1024, 3, DEFAULT_POLYVAL_SEGMENT_SIZE)?,
        ),
        (
            "repetitif, 1 frame",
            &repetitive,
            StreamCryptoPipeline::single_frame(3),
        ),
        (
            "mixed, 1 frame",
            &mixed,
            StreamCryptoPipeline::single_frame(3),
        ),
        (
            "random, 1 frame",
            &random,
            StreamCryptoPipeline::single_frame(3),
        ),
    ];
    for (label, data, pipeline) in cases {
        let pipeline = pipeline
            .with_crypto_mode(mode)
            .with_stream_chunking(stream_chunk_size)?;
        let r = pipeline.verify_pipeline_with_tag_proof(data, &key, &nonce)?;
        let tag_check = match (&r.aes_gcm_siv_equivalence, r.tamper_rejected) {
            (Some(eq), _) => format!("tag seq=par=upstream: {}", eq.is_bit_identical),
            (None, Some(t)) => format!("tamper ditolak: {t}"),
            (None, None) => "TANPA autentikasi".to_string(),
        };
        println!(
            "  {label:<20} | {:>8} B -> {:>8} B ({:>6.2}%) | {:>2} frame | plan {:<19} | segmen POLYVAL {:>3} @ {:>7} | {tag_check} | roundtrip: {}",
            r.original_size_bytes,
            r.compressed_size_bytes,
            r.compression_ratio_percent,
            r.zstd_frames,
            r.encryption_plan.label(),
            r.num_polyval_segments,
            r.polyval_segment_size
                .map_or_else(|| "-".to_string(), |s| format!("{s} B")),
            r.pipeline_roundtrip_verified,
        );
        println!(
            "  {:<20} | kompresi {:.0} µs | enkripsi {:.0} µs | dekripsi {:.0} µs | dekompresi {:.0} µs | paralel dijalankan: {}",
            "",
            r.compression_time_micros,
            r.encryption_time_micros,
            r.decryption_time_micros,
            r.decompression_time_micros,
            r.parallel_path_exercised
        );
        if r.stream_chunk_size.is_some() {
            println!(
                "  {:<20} | chunk AEAD {} (paralel: {}) | transposisi ditolak: {} | truncation ditolak: {}",
                "",
                r.aead_chunks,
                r.stream_parallel_exercised,
                fmt_check(r.chunk_transposition_rejected),
                fmt_check(r.chunk_truncation_rejected)
            );
        }
    }
    println!(
        "  Catatan: waktu single-run (indikatif). Gunakan `cargo run --release --bin thesis_bench` untuk data tesis."
    );
    println!(
        "  Catatan: panjang hasil kompresi tetap bocor (compression side-channel); segmentasi bukan mitigasi."
    );
    println!();
    Ok(())
}

fn fmt_check(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "ya",
        Some(false) => "TIDAK",
        None => "n/a",
    }
}

fn phase_crypto_modes() -> AnyResult<()> {
    println!("[2b] Perbandingan crypto_mode (mixed 8 MiB, 1 frame Zstd; single-run, indikatif)");
    println!(
        "  {:<36} | {:>12} | {:>9} | {:>8} | {:>11} | {:>11} | {:>5} | {:>11}",
        "crypto_mode",
        "AEAD",
        "terkompr.",
        "overhead",
        "enkripsi µs",
        "dekripsi µs",
        "auth",
        "transposisi"
    );
    let key = [0x3au8; 32];
    let nonce = [0x91u8; 12];
    let data = datasets::generate(datasets::DatasetKind::Mixed, 8 * 1024 * 1024, 1);
    for mode in CryptoMode::ALL {
        let chunkings: &[Option<usize>] = if mode == CryptoMode::AesGcmSiv {
            &[None]
        } else {
            &[None, Some(DEMO_STREAM_CHUNK)]
        };
        for &chunk in chunkings {
            let r = StreamCryptoPipeline::single_frame(3)
                .with_crypto_mode(mode)
                .with_stream_chunking(chunk)?
                .verify_pipeline_with_tag_proof(&data, &key, &nonce)?;
            let framing = match chunk {
                Some(_) => format!("STREAM x{}", r.aead_chunks),
                None => "1 pesan".to_string(),
            };
            println!(
                "  {:<36} | {:>12} | {:>9} | {:>6} B | {:>11.0} | {:>11.0} | {:>5} | {:>11}",
                mode.label(),
                framing,
                r.compressed_size_bytes,
                r.crypto_overhead_bytes,
                r.encryption_time_micros,
                r.decryption_time_micros,
                r.authenticated,
                fmt_check(r.chunk_transposition_rejected)
            );
        }
    }
    println!(
        "  Catatan: STREAM = chunk {} KiB paralel (format v3, indeks + is_last di nonce dan AAD).",
        DEMO_STREAM_CHUNK / 1024
    );
    println!(
        "  Catatan: mode non-AES adalah format berbeda (bukan pembanding tag); gunakan `cargo bench -p todo-crypto --bench crypto_modes_benchmark` untuk data crypto-only."
    );
    println!();
    Ok(())
}

fn phase_measurements() -> AnyResult<()> {
    println!("[3] Pengukuran cepat POLYVAL (indikatif; gunakan `cargo bench` untuk tesis)");
    println!(
        "  {:<10} | {:>12} | {:>12} | {:>11} | {:>11} | {:>7} | {:>6}",
        "Ukuran", "Seq (µs)", "Par (µs)", "Seq MiB/s", "Par MiB/s", "Speedup", "Efis."
    );
    for size in [256 * 1024, 1024 * 1024, 4 * 1024 * 1024, 16 * 1024 * 1024] {
        let r = benchmark_polyval(&pattern(size, 29), DEFAULT_POLYVAL_SEGMENT_SIZE, 5)?;
        if !r.tag_equivalence_passed {
            return Err("benchmark tag mismatch".into());
        }
        println!(
            "  {:<10} | {:>12.1} | {:>12.1} | {:>11.1} | {:>11.1} | {:>6.2}x | {:>6.2}",
            r.payload_size_label,
            r.seq_latency_avg_micros,
            r.par_latency_avg_micros,
            r.seq_throughput_mib_s,
            r.par_throughput_mib_s,
            r.speedup_ratio,
            r.parallel_efficiency
        );
    }
    println!();
    Ok(())
}

fn phase_integration(mode: CryptoMode, stream_chunk_size: Option<usize>) -> AnyResult<()> {
    println!("[4] Integrasi REST + IPFS (mock), crypto_mode {mode}");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let controller = RestServiceController::new();
        let key = vec![0x3au8; 16];
        let nonce = [0x91u8; 12];
        let payload = b"Research sample record for decentralized IPFS pinning".to_vec();

        let processed = controller.process_pipeline(PipelineProcessRequest {
            data: payload.clone(),
            key: key.clone(),
            nonce,
            segment_size: Some(16 * 1024),
            compression_level: Some(3),
            polyval_segment_size: None,
            crypto_mode: Some(mode.label().to_string()),
            stream_chunk_size,
        })?;
        println!(
            "  REST: {} frame, ciphertext {} B",
            processed.total_segments,
            processed.sealed.ciphertext.len()
        );

        let published = controller
            .publish_to_ipfs(todo_rest::DecentralizedPublishRequest {
                stream_id: "thesis-stream-alpha".to_string(),
                data: payload.clone(),
                key: key.clone(),
                nonce,
                crypto_mode: Some(mode.label().to_string()),
                stream_chunk_size,
            })
            .await?;
        println!("  IPFS backend: {}", published.backend_label);
        println!(
            "  IPFS root CID (DAG-JSON manifest): {}",
            published.root_cid
        );
        for (i, link) in published.manifest.blocks().iter().enumerate() {
            println!("  IPFS block #{i}: {} ({} B)", link.cid, link.size);
        }

        let sealed = controller.fetch_from_ipfs(&published.root_cid).await?;
        let recovered = controller.recover_pipeline(todo_rest::PipelineRecoverRequest {
            sealed,
            key,
            nonce,
            crypto_mode: Some(mode.label().to_string()),
        })?;
        if recovered.recovered_data != payload {
            return Err("IPFS roundtrip mismatch".into());
        }
        println!(
            "  IPFS roundtrip: OK ({}; CIDs verified, {})",
            published.backend_label,
            if mode.is_authenticated() {
                "AEAD tag verified"
            } else {
                "NO authentication tag"
            }
        );
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
