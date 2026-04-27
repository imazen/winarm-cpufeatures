//! Smoke tests that compile and run on every supported target.
//!
//! Internal coherence checks (fast/full cache agreement, detection-method
//! routing) live in `src/cache.rs`'s `#[cfg(test)] mod` because they need
//! `pub(crate)` items. This file holds public-API-only assertions.

use winarm_cpufeatures::{Feature, Features, is_aarch64_feature_detected_fast};

#[test]
fn fast_macro_compiles_for_ipfp_features() {
    // All these features have DetectionMethod::Ipfp; the fast macro accepts them.
    // Names limited to the 41 stable stdarch names so the test compiles on
    // non-Windows aarch64 stable Rust (where the macro is a passthrough to std).
    let _ = is_aarch64_feature_detected_fast!("asimd");
    let _ = is_aarch64_feature_detected_fast!("fp");
    let _ = is_aarch64_feature_detected_fast!("aes");
    let _ = is_aarch64_feature_detected_fast!("crc");
    let _ = is_aarch64_feature_detected_fast!("lse");
    let _ = is_aarch64_feature_detected_fast!("dotprod");
    let _ = is_aarch64_feature_detected_fast!("jsconv");
    let _ = is_aarch64_feature_detected_fast!("rcpc");
    let _ = is_aarch64_feature_detected_fast!("sve");
    let _ = is_aarch64_feature_detected_fast!("sve2");
}

/// Unstable-on-stable-Rust names compile through the macro on Windows
/// aarch64 (cache-based dispatch) and on non-aarch64 (always-`false`
/// stub). On non-Windows aarch64 the macro is a pure passthrough to
/// std, which gates these behind nightly + a feature flag — skip there.
#[cfg(any(
    all(target_arch = "aarch64", target_os = "windows"),
    not(target_arch = "aarch64"),
))]
#[test]
fn fast_macro_compiles_for_unstable_names() {
    let _ = is_aarch64_feature_detected_fast!("sve2p1");
    let _ = is_aarch64_feature_detected_fast!("sve-b16b16");
    let _ = is_aarch64_feature_detected_fast!("sme");
    let _ = is_aarch64_feature_detected_fast!("sme2");
    let _ = is_aarch64_feature_detected_fast!("sme-fa64");
    let _ = is_aarch64_feature_detected_fast!("flagm2");
    let _ = is_aarch64_feature_detected_fast!("mops");
    let _ = is_aarch64_feature_detected_fast!("pauth-lr");
    let _ = is_aarch64_feature_detected_fast!("lse128");
    let _ = is_aarch64_feature_detected_fast!("rcpc3");
}

#[test]
fn full_snapshot_covers_all_features() {
    // Features::current_full() exposes every known name via .has(), regardless of detection method.
    let cpu = Features::current_full();
    let _ = cpu.has(Feature::Rdm);
    let _ = cpu.has(Feature::Bf16);
    let _ = cpu.has(Feature::I8mm);
    let _ = cpu.has(Feature::Sve);
    let _ = cpu.has(Feature::Sme);
    let _ = cpu.has(Feature::Paca);
    let _ = cpu.has(Feature::Dpb2);
    let _ = cpu.has(Feature::FlagM2);
    let _ = cpu.has(Feature::FrintTs);
}

#[cfg(not(target_arch = "aarch64"))]
#[test]
fn non_aarch64_targets_detect_nothing() {
    let snap = Features::current();
    let count = Feature::all().filter(|f| snap.has(*f)).count();
    assert_eq!(count, 0, "non-aarch64 targets must not claim any features");
}

#[cfg(all(target_arch = "aarch64", not(target_os = "windows")))]
#[test]
fn non_windows_aarch64_matches_stdarch() {
    // Every stable stdarch name must agree with our snapshot. Names are
    // checked through the `Features::current_full` snapshot via `Feature`
    // variants, since the macro path is a pure passthrough on this target.
    let cpu = Features::current_full();
    macro_rules! check {
        ($(($variant:ident, $name:tt)),* $(,)?) => {
            $(
                assert_eq!(
                    cpu.has(Feature::$variant),
                    std::arch::is_aarch64_feature_detected!($name),
                    concat!("mismatch for feature `", $name, "`")
                );
            )*
        };
    }
    // All stable stdarch feature names that share the same spelling
    // between this crate and stdarch.
    check!(
        (Asimd, "asimd"),
        (Fp, "fp"),
        (Fp16, "fp16"),
        (Fhm, "fhm"),
        (Fcma, "fcma"),
        (Bf16, "bf16"),
        (I8mm, "i8mm"),
        (JsConv, "jsconv"),
        (FrintTs, "frintts"),
        (Rdm, "rdm"),
        (Dotprod, "dotprod"),
        (Aes, "aes"),
        (Pmull, "pmull"),
        (Sha2, "sha2"),
        (Sha3, "sha3"),
        (Sm4, "sm4"),
        (Crc, "crc"),
        (Lse, "lse"),
        (Lse2, "lse2"),
        (Rcpc, "rcpc"),
        (Rcpc2, "rcpc2"),
        (Paca, "paca"),
        (Pacg, "pacg"),
        (Bti, "bti"),
        (Dpb, "dpb"),
        (Dpb2, "dpb2"),
        (Mte, "mte"),
        (Dit, "dit"),
        (Sb, "sb"),
        (Ssbs, "ssbs"),
        (FlagM, "flagm"),
        (Rand, "rand"),
        (Tme, "tme"),
        (Sve, "sve"),
        (Sve2, "sve2"),
        (F32mm, "f32mm"),
        (F64mm, "f64mm"),
    );
}
