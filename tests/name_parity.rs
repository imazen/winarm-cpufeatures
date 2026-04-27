//! Cross-platform name-parity test.
//!
//! Both `is_aarch64_feature_detected_fast!` and `is_aarch64_feature_detected_full!`
//! must accept every documented feature name on every supported target.
//! The CI matrix (windows-11-arm, ubuntu-24.04-arm, macos-14, plus the
//! non-aarch64 runners) catches any drift between the cfg-gated dispatch
//! paths.
//!
//! If a name in `features.rs` is renamed without a corresponding macro
//! arm update, or if the Windows-aarch64 enum dispatch falls out of sync
//! with the std-passthrough on Linux/macOS, this test fails to compile
//! on the affected platform.

#![allow(unused_imports)]

use winarm_cpufeatures::{is_aarch64_feature_detected_fast, is_aarch64_feature_detected_full};

/// Per-target list of feature names that compile through both winarm
/// macros. Calls `$cb!(name)` once per name.
///
/// - **Windows aarch64**: all 73 names (cache-based dispatch handles
///   stable + unstable identically).
/// - **non-Windows aarch64**: 41 stable names (the macros passthrough
///   to std, which on stable Rust rejects the 32 unstable names).
/// - **non-aarch64**: all 73 names (single `:literal` arm accepts
///   everything, returns `false`).
macro_rules! for_every_supported_name {
    ($cb:ident) => {
        // Stable names — compile on every target.
        $cb!("asimd");
        $cb!("fp");
        $cb!("fp16");
        $cb!("fhm");
        $cb!("fcma");
        $cb!("bf16");
        $cb!("i8mm");
        $cb!("jsconv");
        $cb!("frintts");
        $cb!("rdm");
        $cb!("dotprod");
        $cb!("aes");
        $cb!("pmull");
        $cb!("sha2");
        $cb!("sha3");
        $cb!("sm4");
        $cb!("crc");
        $cb!("lse");
        $cb!("lse2");
        $cb!("rcpc");
        $cb!("rcpc2");
        $cb!("paca");
        $cb!("pacg");
        $cb!("bti");
        $cb!("dpb");
        $cb!("dpb2");
        $cb!("mte");
        $cb!("dit");
        $cb!("sb");
        $cb!("ssbs");
        $cb!("flagm");
        $cb!("rand");
        $cb!("tme");
        $cb!("sve");
        $cb!("sve2");
        $cb!("sve2-aes");
        $cb!("sve2-bitperm");
        $cb!("sve2-sha3");
        $cb!("sve2-sm4");
        $cb!("f32mm");
        $cb!("f64mm");
        // Unstable-on-stable-Rust names — only on targets where they
        // compile through our macros without a user-side feature gate.
        // On non-Windows aarch64 they passthrough to std which errors
        // on stable; skip them there.
        for_every_unstable_name_when_supported!($cb);
    };
}

#[cfg(any(target_os = "windows", not(target_arch = "aarch64")))]
macro_rules! for_every_unstable_name_when_supported {
    ($cb:ident) => {
        $cb!("lse128");
        $cb!("rcpc3");
        $cb!("pauth-lr");
        $cb!("mops");
        $cb!("flagm2");
        $cb!("ecv");
        $cb!("cssc");
        $cb!("wfxt");
        $cb!("hbc");
        $cb!("lut");
        $cb!("faminmax");
        $cb!("fp8");
        $cb!("fp8dot2");
        $cb!("fp8dot4");
        $cb!("fp8fma");
        $cb!("fpmr");
        $cb!("sve2p1");
        $cb!("sve-b16b16");
        $cb!("sme");
        $cb!("sme2");
        $cb!("sme2p1");
        $cb!("sme-b16b16");
        $cb!("sme-f16f16");
        $cb!("sme-f64f64");
        $cb!("sme-f8f16");
        $cb!("sme-f8f32");
        $cb!("sme-fa64");
        $cb!("sme-i16i64");
        $cb!("sme-lutv2");
        $cb!("ssve-fp8dot2");
        $cb!("ssve-fp8dot4");
        $cb!("ssve-fp8fma");
    };
}

#[cfg(all(target_arch = "aarch64", not(target_os = "windows")))]
macro_rules! for_every_unstable_name_when_supported {
    ($cb:ident) => {
        // Skipped: 32 unstable-on-stable-Rust names would error here
        // because our macro passes through to std, which rejects them
        // without `#![feature(stdarch_aarch64_feature_detection)]`.
    };
}

/// Same shape as [`for_every_supported_name`] but only the 41 names that
/// `std::arch::is_aarch64_feature_detected!` accepts on stable Rust
/// 1.85. Used for tests that compare against std's macro directly —
/// the unstable-on-stable names would error on stable rustc.
macro_rules! for_every_stable_std_name {
    ($cb:ident) => {
        $cb!("asimd");
        $cb!("fp");
        $cb!("fp16");
        $cb!("fhm");
        $cb!("fcma");
        $cb!("bf16");
        $cb!("i8mm");
        $cb!("jsconv");
        $cb!("frintts");
        $cb!("rdm");
        $cb!("dotprod");
        $cb!("aes");
        $cb!("pmull");
        $cb!("sha2");
        $cb!("sha3");
        $cb!("sm4");
        $cb!("crc");
        $cb!("lse");
        $cb!("lse2");
        $cb!("rcpc");
        $cb!("rcpc2");
        $cb!("paca");
        $cb!("pacg");
        $cb!("bti");
        $cb!("dpb");
        $cb!("dpb2");
        $cb!("mte");
        $cb!("dit");
        $cb!("sb");
        $cb!("ssbs");
        $cb!("flagm");
        $cb!("rand");
        $cb!("tme");
        $cb!("sve");
        $cb!("sve2");
        $cb!("sve2-aes");
        $cb!("sve2-bitperm");
        $cb!("sve2-sha3");
        $cb!("sve2-sm4");
        $cb!("f32mm");
        $cb!("f64mm");
    };
}

#[test]
fn fast_accepts_all() {
    macro_rules! probe {
        ($n:tt) => {
            let _ = is_aarch64_feature_detected_fast!($n);
        };
    }
    for_every_supported_name!(probe);
}

#[test]
fn full_accepts_all() {
    macro_rules! probe {
        ($n:tt) => {
            let _ = is_aarch64_feature_detected_full!($n);
        };
    }
    for_every_supported_name!(probe);
}

/// On non-Windows targets there's no registry layer, so fast and full
/// must produce identical answers for every name. (On Windows aarch64
/// they legitimately diverge for Registry-classified names when the
/// `registry` Cargo feature is on.)
#[cfg(not(all(target_os = "windows", target_arch = "aarch64")))]
#[test]
fn fast_and_full_agree_on_non_windows() {
    macro_rules! check {
        ($n:tt) => {
            assert_eq!(
                is_aarch64_feature_detected_fast!($n),
                is_aarch64_feature_detected_full!($n),
                "fast/full disagree for `{}` — should be identical on this target",
                $n,
            );
        };
    }
    for_every_supported_name!(check);
}

/// On Windows aarch64, winarm's detection must be a *strict superset*
/// of std's: any feature std reports present, winarm must also report
/// present. Holds today (we wire more PF_ARM_* than std does on
/// Windows) and continues to hold once
/// [rust-lang/rust#155856](https://github.com/rust-lang/rust/pull/155856)
/// lands stable Windows-aarch64 IPFP coverage in std (we and std then
/// agree on the names that PR adds, and we still cover more via
/// registry decoding).
///
/// If this test ever fails, it means std grew Windows IPFP coverage
/// for a feature we don't track — winarm needs an enum entry and
/// macro arm for that name.
#[cfg(all(target_os = "windows", target_arch = "aarch64"))]
#[test]
fn winarm_is_superset_of_std_on_windows() {
    macro_rules! check {
        ($n:tt) => {
            if std::arch::is_aarch64_feature_detected!($n) {
                assert!(
                    is_aarch64_feature_detected_full!($n),
                    "std reports `{}` present on this Windows ARM64 host but winarm doesn't",
                    $n,
                );
            }
        };
    }
    for_every_stable_std_name!(check);
}

/// On non-aarch64 targets every name returns `false`. Catches any
/// future regression where a stub arm accidentally returns `true`.
#[cfg(not(target_arch = "aarch64"))]
#[test]
fn non_aarch64_always_false() {
    macro_rules! check {
        ($n:tt) => {
            assert!(
                !is_aarch64_feature_detected_fast!($n),
                "expected `{}` to be false on non-aarch64",
                $n,
            );
            assert!(
                !is_aarch64_feature_detected_full!($n),
                "expected `{}` to be false on non-aarch64 (full)",
                $n,
            );
        };
    }
    for_every_supported_name!(check);
}
