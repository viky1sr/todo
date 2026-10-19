//! Differential tests: pure-Rust `todo_zstd::core` vs the reference C libzstd (vendored
//! upstream, linked through the `zstd` crate) and the official `zstd` CLI.

use std::io::Write;
use std::process::Command;

use todo_zstd::core::{self, CoreError};
use todo_zstd::{ZstdSegment, ZstdSegmenter};

const FIXTURE_INPUT: &[u8] = include_bytes!("fixtures/cli_input.bin");

fn xorshift_bytes(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    let text = b"Komposisi paralel POLYVAL pada segmen Zstandard untuk AES-GCM-SIV. ".repeat(3000);
    let mut mixed = Vec::new();
    for i in 0..40u64 {
        mixed.extend_from_slice(&text[..(i as usize * 997) % 5000 + 100]);
        mixed.extend_from_slice(&xorshift_bytes(2000 + (i as usize * 31) % 3000, i + 1));
    }
    let small_alphabet: Vec<u8> = xorshift_bytes(300_000, 9).iter().map(|b| b % 7).collect();
    vec![
        ("empty", Vec::new()),
        ("one", vec![42]),
        ("short", b"abcabcabcabcabcabc".to_vec()),
        ("rle", vec![0xAA; 400_000]),
        ("text", text),
        ("random", xorshift_bytes(300_000, 77)),
        ("mixed", mixed),
        ("small_alphabet", small_alphabet),
        ("fixture", FIXTURE_INPUT.to_vec()),
        ("ramp", (0..1_000_000u32).map(|i| (i / 3) as u8).collect()),
    ]
}

#[test]
fn rust_frames_decode_with_reference_libzstd() {
    for (name, data) in corpus() {
        for level in [1, 3, 5, 9, 19, 22] {
            let frame = core::compress(&data, level).unwrap();
            assert_eq!(&frame[..4], &[0x28, 0xB5, 0x2F, 0xFD], "{name} magic");
            let reference = zstd::stream::decode_all(frame.as_slice())
                .unwrap_or_else(|e| panic!("libzstd rejected {name} level {level}: {e}"));
            assert_eq!(reference, data, "{name} level {level} via libzstd");
            assert_eq!(
                core::decompress(&frame).unwrap(),
                data,
                "{name} level {level} via core"
            );
            assert_eq!(
                core::compress(&data, level).unwrap(),
                frame,
                "{name} deterministic"
            );
        }
    }
}

#[test]
fn reference_libzstd_frames_decode_with_rust() {
    for (name, data) in corpus() {
        for level in [-5, 1, 3, 9, 19] {
            let mut enc = zstd::stream::Encoder::new(Vec::new(), level).unwrap();
            enc.include_checksum(true).unwrap();
            enc.set_pledged_src_size(Some(data.len() as u64)).unwrap();
            enc.write_all(&data).unwrap();
            let frame = enc.finish().unwrap();
            assert_eq!(
                core::decompress(&frame).unwrap(),
                data,
                "{name} level {level} from libzstd"
            );
        }
        // Streaming frame without content size / checksum, plus bulk API.
        let frame = zstd::stream::encode_all(data.as_slice(), 6).unwrap();
        assert_eq!(core::decompress(&frame).unwrap(), data, "{name} stream");
        let frame = zstd::bulk::compress(&data, 22).unwrap();
        assert_eq!(core::decompress(&frame).unwrap(), data, "{name} bulk 22");
    }
}

#[test]
fn official_cli_fixtures_decode() {
    for fixture in [
        &include_bytes!("fixtures/cli_l3_check.zst")[..],
        &include_bytes!("fixtures/cli_l22_nocheck.zst")[..],
        &include_bytes!("fixtures/cli_l1_mt.zst")[..],
    ] {
        assert_eq!(core::decompress(fixture).unwrap(), FIXTURE_INPUT);
    }
}

/// Uses the `zstd` CLI when installed; otherwise reports and returns.
#[test]
fn official_cli_roundtrip_both_directions() {
    if Command::new("zstd").arg("--version").output().is_err() {
        eprintln!("zstd CLI not installed: CLI differential NOT RUN");
        return;
    }
    let dir = std::env::temp_dir().join(format!("todo-zstd-core-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let input = dir.join("in.bin");
    std::fs::write(&input, FIXTURE_INPUT).unwrap();

    for args in [
        &["-1"][..],
        &["-19", "--long=24"],
        &["-3", "-T4", "-B64KiB"],
    ] {
        let out = dir.join("cli.zst");
        let status = Command::new("zstd")
            .args(["-q", "-f", "--check"])
            .args(args)
            .arg(&input)
            .arg("-o")
            .arg(&out)
            .status()
            .unwrap();
        assert!(status.success());
        let frame = std::fs::read(&out).unwrap();
        assert_eq!(core::decompress(&frame).unwrap(), FIXTURE_INPUT, "{args:?}");
    }

    let ours = dir.join("ours.zst");
    std::fs::write(&ours, core::compress(FIXTURE_INPUT, 3).unwrap()).unwrap();
    let decoded = Command::new("zstd")
        .args(["-q", "-d", "-c"])
        .arg(&ours)
        .output()
        .unwrap();
    assert!(decoded.status.success(), "CLI rejected core frame");
    assert_eq!(decoded.stdout, FIXTURE_INPUT);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn zstx_segment_payload_is_standard_frame() {
    let segmenter = ZstdSegmenter::new(64 * 1024, 3);
    let data = FIXTURE_INPUT;
    let segments = segmenter.compress_segments_parallel(data).unwrap();
    assert!(segments.len() > 1);
    assert_eq!(
        segments,
        segmenter.compress_segments_sequential(data).unwrap()
    );
    for seg in &segments {
        let framed = seg.to_bytes();
        assert_eq!(&framed[..4], b"ZSTX");
        assert_eq!(&framed[17..21], &[0x28, 0xB5, 0x2F, 0xFD]);
        let parsed = ZstdSegment::from_bytes(&framed).unwrap();
        let start = seg.segment_id as usize * 64 * 1024;
        let expected = &data[start..start + seg.uncompressed_size];
        assert_eq!(
            zstd::bulk::decompress(&parsed.compressed_data, expected.len()).unwrap(),
            expected
        );
    }
    assert_eq!(
        segmenter.decompress_segments_parallel(&segments).unwrap(),
        data
    );
}

#[test]
fn segment_size_cap_rejects_lying_metadata() {
    let segmenter = ZstdSegmenter::new(4096, 3);
    let mut segments = segmenter
        .compress_segments_sequential(&[7u8; 10_000])
        .unwrap();
    segments[0].uncompressed_size -= 1;
    assert!(segmenter.decompress_segments_parallel(&segments).is_err());
}

#[test]
fn malformed_input_never_panics() {
    let data = corpus().remove(6).1;
    let frame = core::compress(&data[..200_000], 9).unwrap();
    let reference = zstd::bulk::compress(&data[..200_000], 19).unwrap();
    let mut rng = 0x9E37_79B9_7F4A_7C15u64;
    for base in [&frame, &reference] {
        for _ in 0..3000 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let mut m = base.clone();
            let pos = (rng >> 8) as usize % m.len();
            m[pos] ^= 1 << (rng % 8);
            if rng.is_multiple_of(5) {
                m.truncate((rng >> 20) as usize % m.len());
            }
            let r = std::panic::catch_unwind(|| core::decompress_with_limit(&m, 1 << 22));
            assert!(r.is_ok(), "decoder panicked on mutation at byte {pos}");
            if let Ok(Ok(out)) = r {
                // Only possible if the flip hit an unchecked region and checksum still holds.
                assert_eq!(out.len(), 200_000);
            }
        }
    }
    assert!(matches!(
        core::decompress(&[1, 2, 3, 4]),
        Err(CoreError::BadMagic(_))
    ));
    assert!(core::decompress(&[]).is_err());
}
