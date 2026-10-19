//! Frame layer (RFC 8878 §3.1.1): magic number, frame header, block loop, content
//! checksum, skippable frames.

use super::block::{self, BlockType, DecoderState};
use super::lz77::{self, INITIAL_REPS, MatchFinder};
use super::xxhash::xxh64;
use super::{BLOCK_SIZE_MAX, CoreError, Result, ZSTD_MAGIC};

const SKIPPABLE_MAGIC_MASK: u32 = 0xFFFF_FFF0;
const SKIPPABLE_MAGIC: u32 = 0x184D_2A50;
/// Upper bound on speculative pre-allocation driven by an untrusted content size.
const MAX_PREALLOC: usize = 64 << 20;

/// Parsed frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub window_size: u64,
    pub content_size: Option<u64>,
    pub dictionary_id: u32,
    pub has_checksum: bool,
    pub single_segment: bool,
    /// Header length in bytes, excluding the magic number.
    pub header_len: usize,
}

fn read_le(data: &[u8], n: usize) -> u64 {
    data[..n]
        .iter()
        .rev()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
}

/// Parse a frame header starting right after the magic number.
pub fn parse_frame_header(src: &[u8]) -> Result<FrameHeader> {
    let desc = *src
        .first()
        .ok_or(CoreError::Truncated("frame header descriptor"))?;
    let fcs_flag = desc >> 6;
    let single_segment = desc & 0x20 != 0;
    if desc & 0x08 != 0 {
        return Err(CoreError::BadFrameHeader("reserved bit set"));
    }
    let has_checksum = desc & 0x04 != 0;
    let did_len = [0usize, 1, 2, 4][usize::from(desc & 3)];
    let fcs_len = match fcs_flag {
        0 => usize::from(single_segment),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let wd_len = usize::from(!single_segment);
    let header_len = 1 + wd_len + did_len + fcs_len;
    if src.len() < header_len {
        return Err(CoreError::Truncated("frame header"));
    }
    let mut p = 1;
    let mut window_size = 0u64;
    if !single_segment {
        let wd = src[p];
        let exponent = u64::from(wd >> 3);
        let mantissa = u64::from(wd & 7);
        let window_log = 10 + exponent;
        let base = 1u64 << window_log;
        window_size = base + (base / 8) * mantissa;
        p += 1;
    }
    let dictionary_id = read_le(&src[p..], did_len) as u32;
    p += did_len;
    let content_size = match fcs_len {
        0 => None,
        2 => Some(read_le(&src[p..], 2) + 256),
        n => Some(read_le(&src[p..], n)),
    };
    if single_segment {
        window_size = content_size.unwrap_or(0);
    }
    Ok(FrameHeader {
        window_size,
        content_size,
        dictionary_id,
        has_checksum,
        single_segment,
        header_len,
    })
}

/// Decode a single frame whose magic number has already been consumed. Returns the number
/// of bytes of `src` used.
fn decode_frame(src: &[u8], out: &mut Vec<u8>, limit: usize) -> Result<usize> {
    let header = parse_frame_header(src)?;
    if header.dictionary_id != 0 {
        return Err(CoreError::DictionaryUnsupported(header.dictionary_id));
    }
    let frame_start = out.len();
    if let Some(cs) = header.content_size {
        let room = limit.saturating_sub(out.len());
        if cs > room as u64 {
            return Err(CoreError::OutputLimitExceeded(limit));
        }
        out.reserve((cs as usize).min(MAX_PREALLOC));
    }
    let mut p = header.header_len;
    let mut state = DecoderState::default();
    loop {
        let bh = src
            .get(p..p + 3)
            .ok_or(CoreError::Truncated("block header"))?;
        let bh = read_le(bh, 3) as u32;
        p += 3;
        let last = bh & 1 != 0;
        let ty = (bh >> 1) & 3;
        let size = (bh >> 3) as usize;
        if size > BLOCK_SIZE_MAX {
            return Err(CoreError::Corrupted("block size exceeds maximum"));
        }
        match ty {
            0 => {
                let body = src
                    .get(p..p + size)
                    .ok_or(CoreError::Truncated("raw block"))?;
                if out.len().saturating_add(size) > limit {
                    return Err(CoreError::OutputLimitExceeded(limit));
                }
                out.extend_from_slice(body);
                p += size;
            }
            1 => {
                let b = *src.get(p).ok_or(CoreError::Truncated("RLE block"))?;
                if out.len().saturating_add(size) > limit {
                    return Err(CoreError::OutputLimitExceeded(limit));
                }
                out.resize(out.len() + size, b);
                p += 1;
            }
            2 => {
                let body = src
                    .get(p..p + size)
                    .ok_or(CoreError::Truncated("compressed block"))?;
                block::decode_compressed_block(&mut state, body, out, frame_start, limit)?;
                p += size;
            }
            _ => return Err(CoreError::Corrupted("reserved block type")),
        }
        if last {
            break;
        }
    }
    let produced = (out.len() - frame_start) as u64;
    if let Some(cs) = header.content_size
        && cs != produced
    {
        return Err(CoreError::ContentSizeMismatch {
            declared: cs,
            actual: produced,
        });
    }
    if header.has_checksum {
        let c = src
            .get(p..p + 4)
            .ok_or(CoreError::Truncated("content checksum"))?;
        let expected = read_le(c, 4) as u32;
        let actual = xxh64(&out[frame_start..], 0) as u32;
        if expected != actual {
            return Err(CoreError::ChecksumMismatch { expected, actual });
        }
        p += 4;
    }
    Ok(p)
}

/// Decode every frame in `data` (Zstandard frames are concatenated, skippable frames are
/// ignored).
pub fn decompress_frames(data: &[u8], limit: usize) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(CoreError::Truncated("no frame"));
    }
    let mut out = Vec::new();
    let mut p = 0usize;
    while p < data.len() {
        let magic = data
            .get(p..p + 4)
            .ok_or(CoreError::Truncated("magic number"))?;
        let magic = read_le(magic, 4) as u32;
        p += 4;
        if magic == ZSTD_MAGIC {
            p += decode_frame(&data[p..], &mut out, limit)?;
        } else if magic & SKIPPABLE_MAGIC_MASK == SKIPPABLE_MAGIC {
            let len = data
                .get(p..p + 4)
                .ok_or(CoreError::Truncated("skippable frame size"))?;
            let len = read_le(len, 4) as usize;
            p = p
                .checked_add(4 + len)
                .filter(|&e| e <= data.len())
                .ok_or(CoreError::Truncated("skippable frame"))?;
        } else {
            return Err(CoreError::BadMagic(magic));
        }
    }
    Ok(out)
}

/// Compress `data` into one frame: single-segment when it fits in the window, content
/// size always present, XXH64 checksum always present.
pub fn compress_frame(data: &[u8], level: i32) -> Result<Vec<u8>> {
    if data.len() >= u32::MAX as usize {
        return Err(CoreError::InputTooLarge(data.len()));
    }
    let params = lz77::params_for_level(level);
    let window = 1usize << params.window_log;
    let len = data.len() as u64;
    let single_segment = data.len() <= window;

    let mut out = Vec::with_capacity(data.len() / 2 + 32);
    out.extend_from_slice(&ZSTD_MAGIC.to_le_bytes());
    let fcs_flag: u8 = if single_segment && len < 256 {
        0
    } else if (256..65_536 + 256).contains(&len) {
        1
    } else {
        2
    };
    out.push((fcs_flag << 6) | (u8::from(single_segment) << 5) | 0x04);
    if !single_segment {
        out.push(((params.window_log - 10) as u8) << 3);
    }
    match fcs_flag {
        0 => out.push(len as u8),
        1 => out.extend_from_slice(&((len - 256) as u16).to_le_bytes()),
        _ => out.extend_from_slice(&(len as u32).to_le_bytes()),
    }

    if data.is_empty() {
        block::write_block_header(&mut out, true, BlockType::Raw, 0);
    } else {
        let mut finder = MatchFinder::new(data, params);
        let mut reps = INITIAL_REPS;
        let mut start = 0usize;
        while start < data.len() {
            let end = (start + BLOCK_SIZE_MAX).min(data.len());
            let last = end == data.len();
            let chunk = &data[start..end];
            if chunk.len() > 1 && chunk.iter().all(|&b| b == chunk[0]) {
                block::write_block_header(&mut out, last, BlockType::Rle, chunk.len());
                out.push(chunk[0]);
                finder.skip_block(end);
            } else {
                let (literals, seqs) = finder.find_block(start, end);
                let saved = reps;
                let body = block::encode_compressed_block(&literals, &seqs, &mut reps);
                if body.len() < chunk.len() {
                    block::write_block_header(&mut out, last, BlockType::Compressed, body.len());
                    out.extend_from_slice(&body);
                } else {
                    // Decoder never sees these sequences, so its repeat offsets stay put.
                    reps = saved;
                    block::write_block_header(&mut out, last, BlockType::Raw, chunk.len());
                    out.extend_from_slice(chunk);
                }
            }
            start = end;
        }
    }
    out.extend_from_slice(&(xxh64(data, 0) as u32).to_le_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip_fields() {
        for len in [0usize, 1, 255, 256, 65_791, 65_792, 3_000_000] {
            let data = vec![b'z'; len];
            let frame = compress_frame(&data, 3).unwrap();
            let h = parse_frame_header(&frame[4..]).unwrap();
            assert_eq!(h.content_size, Some(len as u64), "len {len}");
            assert!(h.has_checksum);
            assert_eq!(decompress_frames(&frame, usize::MAX).unwrap(), data);
        }
    }

    #[test]
    fn skippable_and_concatenated_frames() {
        let mut stream = compress_frame(b"hello ", 1).unwrap();
        stream.extend_from_slice(&0x184D_2A5Au32.to_le_bytes());
        stream.extend_from_slice(&3u32.to_le_bytes());
        stream.extend_from_slice(b"xyz");
        stream.extend_from_slice(&compress_frame(b"world", 1).unwrap());
        assert_eq!(
            decompress_frames(&stream, usize::MAX).unwrap(),
            b"hello world"
        );
    }

    #[test]
    fn rejects_checksum_tamper_and_limit() {
        let data = b"some data some data some data some data".repeat(50);
        let mut frame = compress_frame(&data, 3).unwrap();
        assert!(matches!(
            decompress_frames(&frame, 100),
            Err(CoreError::OutputLimitExceeded(100))
        ));
        let n = frame.len();
        frame[n - 1] ^= 0x01;
        assert!(matches!(
            decompress_frames(&frame, usize::MAX),
            Err(CoreError::ChecksumMismatch { .. })
        ));
    }
}
