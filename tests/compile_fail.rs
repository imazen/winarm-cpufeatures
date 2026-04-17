//! Compile-fail tests for the `detected!` macro's registry-feature guard.
//!
//! Because trybuild adds significant CI cost, these tests are marked `ignore`
//! by default — run with `cargo test -- --ignored compile_fail`. The cases
//! below double as documentation: each block intentionally fails to compile.
//!
//! ```compile_fail
//! // "rdm" is DetectionMethod::Registry; the fast macro must reject it.
//! let _ = winarm_cpufeatures::detected!("rdm");
//! ```
//!
//! ```compile_fail
//! // "bf16" is also Registry-only.
//! let _ = winarm_cpufeatures::detected!("bf16");
//! ```
//!
//! ```compile_fail
//! // Unknown feature name fails for either macro.
//! let _ = winarm_cpufeatures::detected_full!("not_a_feature");
//! ```
