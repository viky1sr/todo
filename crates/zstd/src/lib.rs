//! `todo-zstd`: single-frame and independent-frame Zstandard compression (RFC 8878) and
//! the compress-then-encrypt pipeline built on `todo-crypto`, with a selectable
//! [`CryptoMode`] (`crypto_mode`).
//!
//! [`core`] is a pure-Rust RFC 8878 codec; [`ZstdSegmenter`] uses it to produce the
//! standard Zstandard frame carried inside each `ZSTX` [`ZstdSegment`].

pub mod compressor;
pub mod content_encoding;
pub mod core;
pub mod pipeline;
pub mod segment;

pub use compressor::{DEFAULT_COMPRESSION_LEVEL, DEFAULT_SEGMENT_SIZE, ZstdSegmenter};
pub use pipeline::{
    CompressionMode, OpenMetrics, PipelineError, PipelineVerificationReport, SEALED_STREAM_MAGIC,
    SEALED_STREAM_VERSION, SEALED_STREAM_VERSION_MULTI_MODE, SEALED_STREAM_VERSION_STREAM,
    SealMetrics, SealedStream, SegmentDescriptor, SegmentationStrategy, StreamCryptoPipeline,
    sealed_stream_version,
};
pub use segment::{SEGMENT_MAGIC, ZstdError, ZstdSegment};
pub use todo_crypto::CryptoMode;
