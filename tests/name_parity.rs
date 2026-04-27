//! Cross-platform name-parity test.
//!
//! Calls `is_aarch64_feature_detected!` and `is_aarch64_feature_detected_full!`
//! on every documented feature name. Compiles on every supported target;
//! the CI matrix (windows-11-arm, ubuntu-24.04-arm, macos-14, plus the
//! non-aarch64 runners) catches any drift between the cfg-gated dispatch
//! paths.
//!
//! If a name is renamed in `features.rs` but a corresponding macro arm
//! isn't updated — or if the per-target dispatch in `cache::is_detected`
//! falls out of sync — this test fails to compile on the affected
//! platform.

use winarm_cpufeatures::{is_aarch64_feature_detected, is_aarch64_feature_detected_full};

/// `is_aarch64_feature_detected!` accepts every Ipfp/Both name.
/// Registry-classified names (which raise a `compile_error!` in the
/// fast macro) are excluded — they're covered by `full_accepts_all`.
#[test]
fn fast_accepts_ipfp_and_both() {
    let _ = is_aarch64_feature_detected!("asimd");
    let _ = is_aarch64_feature_detected!("fp");
    let _ = is_aarch64_feature_detected!("fp16");
    let _ = is_aarch64_feature_detected!("bf16");
    let _ = is_aarch64_feature_detected!("i8mm");
    let _ = is_aarch64_feature_detected!("jsconv");
    let _ = is_aarch64_feature_detected!("rdm");
    let _ = is_aarch64_feature_detected!("dotprod");
    let _ = is_aarch64_feature_detected!("aes");
    let _ = is_aarch64_feature_detected!("pmull");
    let _ = is_aarch64_feature_detected!("sha2");
    let _ = is_aarch64_feature_detected!("sha3");
    let _ = is_aarch64_feature_detected!("crc");
    let _ = is_aarch64_feature_detected!("lse");
    let _ = is_aarch64_feature_detected!("lse2");
    let _ = is_aarch64_feature_detected!("rcpc");
    let _ = is_aarch64_feature_detected!("sve");
    let _ = is_aarch64_feature_detected!("sve2");
    let _ = is_aarch64_feature_detected!("sve2p1");
    let _ = is_aarch64_feature_detected!("sve2-aes");
    let _ = is_aarch64_feature_detected!("sve2-bitperm");
    let _ = is_aarch64_feature_detected!("sve2-sha3");
    let _ = is_aarch64_feature_detected!("sve2-sm4");
    let _ = is_aarch64_feature_detected!("sve-b16b16");
    let _ = is_aarch64_feature_detected!("f32mm");
    let _ = is_aarch64_feature_detected!("f64mm");
    let _ = is_aarch64_feature_detected!("sme");
    let _ = is_aarch64_feature_detected!("sme2");
    let _ = is_aarch64_feature_detected!("sme2p1");
    let _ = is_aarch64_feature_detected!("sme-b16b16");
    let _ = is_aarch64_feature_detected!("sme-f16f16");
    let _ = is_aarch64_feature_detected!("sme-f64f64");
    let _ = is_aarch64_feature_detected!("sme-f8f16");
    let _ = is_aarch64_feature_detected!("sme-f8f32");
    let _ = is_aarch64_feature_detected!("sme-fa64");
    let _ = is_aarch64_feature_detected!("sme-i16i64");
    let _ = is_aarch64_feature_detected!("sme-lutv2");
    let _ = is_aarch64_feature_detected!("ssve-fp8dot2");
    let _ = is_aarch64_feature_detected!("ssve-fp8dot4");
    let _ = is_aarch64_feature_detected!("ssve-fp8fma");
}

/// `is_aarch64_feature_detected_full!` accepts every name regardless of
/// detection method — including the 33 Registry-classified names.
#[test]
fn full_accepts_all() {
    let _ = is_aarch64_feature_detected_full!("asimd");
    let _ = is_aarch64_feature_detected_full!("fp");
    let _ = is_aarch64_feature_detected_full!("fp16");
    let _ = is_aarch64_feature_detected_full!("fhm");
    let _ = is_aarch64_feature_detected_full!("fcma");
    let _ = is_aarch64_feature_detected_full!("bf16");
    let _ = is_aarch64_feature_detected_full!("i8mm");
    let _ = is_aarch64_feature_detected_full!("jsconv");
    let _ = is_aarch64_feature_detected_full!("frintts");
    let _ = is_aarch64_feature_detected_full!("rdm");
    let _ = is_aarch64_feature_detected_full!("dotprod");
    let _ = is_aarch64_feature_detected_full!("aes");
    let _ = is_aarch64_feature_detected_full!("pmull");
    let _ = is_aarch64_feature_detected_full!("sha2");
    let _ = is_aarch64_feature_detected_full!("sha3");
    let _ = is_aarch64_feature_detected_full!("sm4");
    let _ = is_aarch64_feature_detected_full!("crc");
    let _ = is_aarch64_feature_detected_full!("lse");
    let _ = is_aarch64_feature_detected_full!("lse2");
    let _ = is_aarch64_feature_detected_full!("lse128");
    let _ = is_aarch64_feature_detected_full!("rcpc");
    let _ = is_aarch64_feature_detected_full!("rcpc2");
    let _ = is_aarch64_feature_detected_full!("rcpc3");
    let _ = is_aarch64_feature_detected_full!("paca");
    let _ = is_aarch64_feature_detected_full!("pacg");
    let _ = is_aarch64_feature_detected_full!("pauth-lr");
    let _ = is_aarch64_feature_detected_full!("bti");
    let _ = is_aarch64_feature_detected_full!("dpb");
    let _ = is_aarch64_feature_detected_full!("dpb2");
    let _ = is_aarch64_feature_detected_full!("mte");
    let _ = is_aarch64_feature_detected_full!("mops");
    let _ = is_aarch64_feature_detected_full!("dit");
    let _ = is_aarch64_feature_detected_full!("sb");
    let _ = is_aarch64_feature_detected_full!("ssbs");
    let _ = is_aarch64_feature_detected_full!("flagm");
    let _ = is_aarch64_feature_detected_full!("flagm2");
    let _ = is_aarch64_feature_detected_full!("rand");
    let _ = is_aarch64_feature_detected_full!("tme");
    let _ = is_aarch64_feature_detected_full!("ecv");
    let _ = is_aarch64_feature_detected_full!("cssc");
    let _ = is_aarch64_feature_detected_full!("wfxt");
    let _ = is_aarch64_feature_detected_full!("hbc");
    let _ = is_aarch64_feature_detected_full!("lut");
    let _ = is_aarch64_feature_detected_full!("faminmax");
    let _ = is_aarch64_feature_detected_full!("fp8");
    let _ = is_aarch64_feature_detected_full!("fp8dot2");
    let _ = is_aarch64_feature_detected_full!("fp8dot4");
    let _ = is_aarch64_feature_detected_full!("fp8fma");
    let _ = is_aarch64_feature_detected_full!("fpmr");
    let _ = is_aarch64_feature_detected_full!("sve");
    let _ = is_aarch64_feature_detected_full!("sve2");
    let _ = is_aarch64_feature_detected_full!("sve2p1");
    let _ = is_aarch64_feature_detected_full!("sve2-aes");
    let _ = is_aarch64_feature_detected_full!("sve2-bitperm");
    let _ = is_aarch64_feature_detected_full!("sve2-sha3");
    let _ = is_aarch64_feature_detected_full!("sve2-sm4");
    let _ = is_aarch64_feature_detected_full!("sve-b16b16");
    let _ = is_aarch64_feature_detected_full!("f32mm");
    let _ = is_aarch64_feature_detected_full!("f64mm");
    let _ = is_aarch64_feature_detected_full!("sme");
    let _ = is_aarch64_feature_detected_full!("sme2");
    let _ = is_aarch64_feature_detected_full!("sme2p1");
    let _ = is_aarch64_feature_detected_full!("sme-b16b16");
    let _ = is_aarch64_feature_detected_full!("sme-f16f16");
    let _ = is_aarch64_feature_detected_full!("sme-f64f64");
    let _ = is_aarch64_feature_detected_full!("sme-f8f16");
    let _ = is_aarch64_feature_detected_full!("sme-f8f32");
    let _ = is_aarch64_feature_detected_full!("sme-fa64");
    let _ = is_aarch64_feature_detected_full!("sme-i16i64");
    let _ = is_aarch64_feature_detected_full!("sme-lutv2");
    let _ = is_aarch64_feature_detected_full!("ssve-fp8dot2");
    let _ = is_aarch64_feature_detected_full!("ssve-fp8dot4");
    let _ = is_aarch64_feature_detected_full!("ssve-fp8fma");
}
