//! Smoke tests that compile and run on every supported target.
//!
//! Internal coherence checks (fast/full cache agreement, detection-method
//! routing) live in `src/cache.rs`'s `#[cfg(test)] mod` because they need
//! `pub(crate)` items. This file holds public-API-only assertions.

use winarm_cpufeatures::{is_aarch64_feature_detected, is_aarch64_feature_detected_full};

#[test]
fn fast_macro_compiles_for_ipfp_features() {
    // All these features have DetectionMethod::Ipfp; the fast macro accepts them.
    let _ = is_aarch64_feature_detected!("asimd");
    let _ = is_aarch64_feature_detected!("fp");
    let _ = is_aarch64_feature_detected!("aes");
    let _ = is_aarch64_feature_detected!("crc");
    let _ = is_aarch64_feature_detected!("lse");
    let _ = is_aarch64_feature_detected!("dotprod");
    let _ = is_aarch64_feature_detected!("jsconv");
    let _ = is_aarch64_feature_detected!("rcpc");
    let _ = is_aarch64_feature_detected!("sve");
    let _ = is_aarch64_feature_detected!("sve2");
    let _ = is_aarch64_feature_detected!("sve2p1");
}

#[test]
fn full_macro_compiles_for_all_features() {
    // is_aarch64_feature_detected_full! accepts every known name regardless of detection method.
    let _ = is_aarch64_feature_detected_full!("rdm");
    let _ = is_aarch64_feature_detected_full!("bf16");
    let _ = is_aarch64_feature_detected_full!("i8mm");
    let _ = is_aarch64_feature_detected_full!("sve");
    let _ = is_aarch64_feature_detected_full!("sme");
    let _ = is_aarch64_feature_detected_full!("paca");
    let _ = is_aarch64_feature_detected_full!("dpb2");
    let _ = is_aarch64_feature_detected_full!("flagm2");
    let _ = is_aarch64_feature_detected_full!("frintts");
}

#[cfg(not(target_arch = "aarch64"))]
#[test]
fn non_aarch64_targets_detect_nothing() {
    use winarm_cpufeatures::{Feature, Features};
    let snap = Features::current();
    let count = Feature::all().filter(|f| snap.has(*f)).count();
    assert_eq!(count, 0, "non-aarch64 targets must not claim any features");
}

#[cfg(all(target_arch = "aarch64", not(target_os = "windows")))]
#[test]
fn non_windows_aarch64_matches_stdarch() {
    // Every stable stdarch name must agree with our detection.
    macro_rules! check {
        ($($name:tt),* $(,)?) => {
            $(
                assert_eq!(
                    is_aarch64_feature_detected_full!($name),
                    std::arch::is_aarch64_feature_detected!($name),
                    concat!("mismatch for feature `", $name, "`")
                );
            )*
        };
    }
    // All 37 stable stdarch feature names that share the same spelling
    // between is_aarch64_feature_detected_full! and is_aarch64_feature_detected!.
    // SVE2 sub-features are excluded: stdarch uses dashes (e.g. "sve2-aes")
    // while this crate uses underscores (e.g. "sve2-aes").
    check!(
        "asimd", "fp", "fp16", "fhm", "fcma", "bf16", "i8mm", "jsconv", "frintts", "rdm",
        "dotprod", "aes", "pmull", "sha2", "sha3", "sm4", "crc", "lse", "lse2", "rcpc", "rcpc2",
        "paca", "pacg", "bti", "dpb", "dpb2", "mte", "dit", "sb", "ssbs", "flagm", "rand", "tme",
        "sve", "sve2", "f32mm", "f64mm",
    );
}
