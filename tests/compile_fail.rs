//! Compile-fail documentation for the `detected!` macro's registry guard
//! and the catch-all "unknown feature name" arm.
//!
//! Each block below is an example of code that intentionally fails to
//! compile. They are pure documentation (rustdoc does not collect
//! doctests from integration test files).
//!
//! ```compile_fail
//! // "paca" is DetectionMethod::Registry; the fast macro rejects it.
//! let _ = winarm_cpufeatures::detected!("paca");
//! ```
//!
//! ```compile_fail
//! // "bti" is also Registry-only.
//! let _ = winarm_cpufeatures::detected!("bti");
//! ```
//!
//! ```compile_fail
//! // Unknown feature name fails for either macro via the catch-all
//! // `compile_error!` arm.
//! let _ = winarm_cpufeatures::detected_full!("not_a_feature");
//! ```
