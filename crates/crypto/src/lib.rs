//! `todo-crypto`: sequential and segment-parallel execution of standard AES-GCM-SIV
//! (RFC 8452) and POLYVAL.
//!
//! No new cryptography is defined here. The parallel code paths only reorder the
//! computation of standard POLYVAL (using its algebraic structure over GF(2^128)).
//! The primary thesis mode keeps CTR sequential so POLYVAL speedup can be isolated; a
//! fully parallel CTR control/optimized mode is retained separately. Outputs are verified
//! to be bit-identical to the
//! sequential reference, the RFC 8452 test vectors, and the upstream `aes-gcm-siv` crate.
//!
//! Modules:
//! - [`polyval_seq`] / [`polyval_par`]: sequential and segment-parallel POLYVAL.
//! - [`aes_gcm_siv_par`]: AES-GCM-SIV with both execution strategies.
//! - [`adaptive`]: per-message choice between sequential and parallel execution.
//! - [`oracle`]: upstream `aes-gcm-siv` used as a reference oracle.
//! - [`tag_equivalence`]: equivalence checks with timing reports.
//! - [`benchmark`]: simple wall-clock measurements (use `cargo bench` for criterion).

pub mod adaptive;
pub mod aes_gcm_siv_par;
pub mod benchmark;
pub mod error;
mod gf128;
pub mod oracle;
pub mod polyval_par;
pub mod polyval_seq;
pub mod tag_equivalence;

pub use adaptive::{
    FallbackReason, SegmentPlan, SegmentationPolicy, aes_gcm_siv_decrypt_adaptive,
    aes_gcm_siv_decrypt_planned, aes_gcm_siv_encrypt_adaptive, aes_gcm_siv_encrypt_planned,
    plan_for_current_pool, plan_segments, polyval_planned,
};
pub use aes_gcm_siv_par::{
    A_MAX, AesGcmSivOutput, DerivedKeys, P_MAX, aes_gcm_siv_decrypt_ctr_parallel,
    aes_gcm_siv_decrypt_parallel, aes_gcm_siv_decrypt_polyval_parallel,
    aes_gcm_siv_decrypt_sequential, aes_gcm_siv_encrypt_ctr_parallel,
    aes_gcm_siv_encrypt_parallel, aes_gcm_siv_encrypt_polyval_parallel,
    aes_gcm_siv_encrypt_sequential, build_polyval_record, derive_keys,
};
pub use benchmark::{BenchmarkResult, EnvironmentInfo, benchmark_polyval, run_standard_suite};
pub use error::CryptoError;
pub use oracle::{aes_gcm_siv_decrypt_upstream, aes_gcm_siv_encrypt_upstream};
pub use polyval_par::{
    DEFAULT_POLYVAL_SEGMENT_SIZE, POLYVAL_BLOCK_SIZE, polyval_parallel,
    polyval_parallel_linear_reduce, segment_count, validate_segment_size,
};
pub use polyval_seq::polyval_sequential;
pub use tag_equivalence::{
    TagEquivalenceReport, assert_aes_gcm_siv_equivalence, assert_polyval_equivalence,
};
