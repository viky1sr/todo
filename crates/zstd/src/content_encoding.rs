//! Zstandard as an HTTP `Content-Encoding` (RFC 8878 §7.2, RFC 9659) for web responses.
//!
//! Unrelated to the sealed AEAD pipeline: this is transport compression of public page
//! and asset bytes. RFC 9659 requires decoders to support windows up to 8 MiB only, so
//! encoders must not exceed it; levels are therefore limited to 1..=19 (level 19 uses a
//! 2^23 window, ultra levels 20..=22 would exceed it) and the window log is capped.

use std::io::{self, Write};
use zstd::zstd_safe::CParameter;

/// Largest window (log2) a `Content-Encoding: zstd` response may use: 8 MiB.
pub const HTTP_MAX_WINDOW_LOG: u32 = 23;
pub const HTTP_MAX_LEVEL: i32 = 19;

/// One zstd frame with content size and checksum, window ≤ 8 MiB.
pub fn encode_http_zstd(data: &[u8], level: i32) -> io::Result<Vec<u8>> {
    if !(1..=HTTP_MAX_LEVEL).contains(&level) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HTTP zstd level must be 1..=19",
        ));
    }
    let mut enc = zstd::stream::Encoder::new(Vec::with_capacity(data.len() / 2 + 64), level)?;
    enc.set_parameter(CParameter::WindowLog(
        HTTP_MAX_WINDOW_LOG.min(window_log_for(data.len())),
    ))?;
    enc.include_checksum(true)?;
    enc.include_contentsize(true)?;
    enc.set_pledged_src_size(Some(data.len() as u64))?;
    enc.write_all(data)?;
    enc.finish()
}

/// Smallest window covering the input (zstd minimum 2^10), so small bodies get small windows.
fn window_log_for(len: usize) -> u32 {
    let needed = usize::BITS - len.saturating_sub(1).leading_zeros();
    needed.clamp(10, HTTP_MAX_WINDOW_LOG)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn roundtrip_with_browser_window_limit() {
        for len in [0usize, 1, 1000, 70_000, 9 << 20] {
            let data: Vec<u8> = (0..len)
                .map(|i| (i % 251) as u8 ^ (i / 4096) as u8)
                .collect();
            let enc = encode_http_zstd(&data, 19).unwrap();
            // A decoder limited to an 8 MiB window (RFC 9659) must decode it.
            let mut dec = zstd::stream::Decoder::new(&enc[..]).unwrap();
            dec.window_log_max(HTTP_MAX_WINDOW_LOG).unwrap();
            let mut out = Vec::new();
            dec.read_to_end(&mut out).unwrap();
            assert_eq!(out, data, "len {len}");
        }
        assert!(encode_http_zstd(b"x", 20).is_err());
        assert!(encode_http_zstd(b"x", 0).is_err());
    }
}
