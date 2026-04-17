//! Known-hardware feature-set assertions.
//!
//! These tests pin the expected feature set for specific CPUs so that a
//! regression in this crate's detection path is caught when run on real
//! hardware. All three are `#[ignore]`d by default; enable explicitly:
//!
//! ```shell
//! cargo test --ignored neoverse_n2      # GH windows-11-arm / ubuntu-24.04-arm
//! cargo test --ignored neoverse_v2      # Graviton 4, NVIDIA Grace
//! cargo test --ignored snapdragon_x     # Snapdragon X Elite / X Plus (Oryon)
//! ```
//!
//! The Neoverse N2 test also runs unattended in CI on the matching GH
//! runners — that's where the registry-backed detection path gets its
//! real validation.

#![cfg(target_arch = "aarch64")]

use winarm_cpufeatures::detected_full;

/// Neoverse N2 (Armv9.0-A) as shipped in Azure Cobalt 100, Graviton 3, and
/// GitHub's `windows-11-arm` / `ubuntu-24.04-arm` hosted runners.
///
/// Feature expectations derived from the actual CI run 24479154394 captured
/// against both runners.
#[test]
#[ignore = "requires Neoverse N2 / Cobalt 100 — `cargo test --ignored neoverse_n2`"]
fn neoverse_n2() {
    // ── Must be present ─────────────────────────────────────────────────
    for f in [
        "asimd",
        "fp",
        "crc",
        "aes",
        "pmull",
        "sha2",
        "sha3",
        "sm4",
        "lse",
        "lse2",
        "rcpc",
        "rcpc2",
        "rdm",
        "dotprod",
        "jsconv",
        "fp16",
        "fhm",
        "fcma",
        "bf16",
        "i8mm",
        "frintts",
        "paca",
        "pacg",
        "dpb",
        "dpb2",
        "flagm",
        "sve",
        "sve2",
        "sve2_bitperm",
        "sve2_sha3",
        "sve2_sm4",
    ] {
        assert!(
            dispatch(f),
            "Neoverse N2 must have feature `{f}` but detected_full said no"
        );
    }

    // ── Must be absent ──────────────────────────────────────────────────
    // N2 deliberately does not implement these; if we claim them, something
    // in the detection path is false-positive.
    for f in [
        "sve2_aes",
        "sve_b16b16",
        "f32mm",
        "f64mm",
        "sme",
        "sme2",
        "mte",
        "bti",
        "rcpc3",
        "lse128",
        "rand",
    ] {
        assert!(
            !dispatch(f),
            "Neoverse N2 must NOT have feature `{f}` but detected_full said yes"
        );
    }
}

/// Neoverse V2 (Armv9.0-A + extra SVE2 options) as shipped in AWS Graviton 4
/// and NVIDIA Grace. Adds the SVE2-AES / PMULL128 / B16B16 variants the N2
/// omits; 128-bit SVE vector length.
#[test]
#[ignore = "requires Neoverse V2 — `cargo test --ignored neoverse_v2`"]
fn neoverse_v2() {
    // Superset of N2's positives, plus:
    for f in [
        "asimd",
        "fp",
        "crc",
        "aes",
        "pmull",
        "sha2",
        "sha3",
        "sm4",
        "lse",
        "rcpc",
        "rcpc2",
        "rdm",
        "dotprod",
        "jsconv",
        "fp16",
        "fhm",
        "fcma",
        "bf16",
        "i8mm",
        "frintts",
        "paca",
        "pacg",
        "dpb",
        "dpb2",
        "flagm",
        "sve",
        "sve2",
        "sve2_bitperm",
        "sve2_sha3",
        "sve2_sm4",
        // V2-only additions:
        "sve2_aes",
    ] {
        assert!(
            dispatch(f),
            "Neoverse V2 must have feature `{f}` but detected_full said no"
        );
    }

    // Still no SME on V2 (that's V3+).
    for f in ["sme", "sme2", "sme2p1", "mte"] {
        assert!(
            !dispatch(f),
            "Neoverse V2 must NOT have feature `{f}` but detected_full said yes"
        );
    }
}

/// Snapdragon X Elite / X Plus (Qualcomm Oryon cores, ARMv8.7-A).
///
/// Oryon explicitly skips the SVE family and MTE; it leans into a rich
/// AdvSIMD / atomic / memory-ordering feature set. This is the platform
/// where Windows-ARM laptops live, so the registry-backed detection path
/// pays off most here.
#[test]
#[ignore = "requires Snapdragon X (Oryon) — `cargo test --ignored snapdragon_x`"]
fn snapdragon_x() {
    for f in [
        "asimd", "fp", "crc", "aes", "pmull", "sha2", "sha3", "sm4", "lse", "lse2", "rcpc",
        "rcpc2", "rdm", "dotprod", "jsconv", "fp16", "fhm", "fcma", "bf16", "i8mm", "frintts",
        "paca", "pacg", "dpb", "dpb2", "flagm", "flagm2", "mops", "wfxt", "rand",
    ] {
        assert!(
            dispatch(f),
            "Snapdragon X (Oryon) must have feature `{f}` but detected_full said no"
        );
    }

    // Oryon explicitly omits SVE and MTE.
    for f in ["sve", "sve2", "sme", "mte"] {
        assert!(
            !dispatch(f),
            "Snapdragon X (Oryon) must NOT have feature `{f}` but detected_full said yes"
        );
    }
}

/// detected_full! takes a literal, but these tests iterate over `&str`. Route
/// each name through a match so the macro sees a literal at each site.
fn dispatch(name: &str) -> bool {
    match name {
        "asimd" => detected_full!("asimd"),
        "fp" => detected_full!("fp"),
        "fp16" => detected_full!("fp16"),
        "fhm" => detected_full!("fhm"),
        "fcma" => detected_full!("fcma"),
        "bf16" => detected_full!("bf16"),
        "i8mm" => detected_full!("i8mm"),
        "jsconv" => detected_full!("jsconv"),
        "frintts" => detected_full!("frintts"),
        "rdm" => detected_full!("rdm"),
        "dotprod" => detected_full!("dotprod"),
        "aes" => detected_full!("aes"),
        "pmull" => detected_full!("pmull"),
        "sha2" => detected_full!("sha2"),
        "sha3" => detected_full!("sha3"),
        "sm4" => detected_full!("sm4"),
        "crc" => detected_full!("crc"),
        "lse" => detected_full!("lse"),
        "lse2" => detected_full!("lse2"),
        "lse128" => detected_full!("lse128"),
        "rcpc" => detected_full!("rcpc"),
        "rcpc2" => detected_full!("rcpc2"),
        "rcpc3" => detected_full!("rcpc3"),
        "paca" => detected_full!("paca"),
        "pacg" => detected_full!("pacg"),
        "bti" => detected_full!("bti"),
        "dpb" => detected_full!("dpb"),
        "dpb2" => detected_full!("dpb2"),
        "mte" => detected_full!("mte"),
        "mops" => detected_full!("mops"),
        "flagm" => detected_full!("flagm"),
        "flagm2" => detected_full!("flagm2"),
        "rand" => detected_full!("rand"),
        "wfxt" => detected_full!("wfxt"),
        "sve" => detected_full!("sve"),
        "sve2" => detected_full!("sve2"),
        "sve2p1" => detected_full!("sve2p1"),
        "sve2_aes" => detected_full!("sve2_aes"),
        "sve2_bitperm" => detected_full!("sve2_bitperm"),
        "sve2_sha3" => detected_full!("sve2_sha3"),
        "sve2_sm4" => detected_full!("sve2_sm4"),
        "sve_b16b16" => detected_full!("sve_b16b16"),
        "f32mm" => detected_full!("f32mm"),
        "f64mm" => detected_full!("f64mm"),
        "sme" => detected_full!("sme"),
        "sme2" => detected_full!("sme2"),
        "sme2p1" => detected_full!("sme2p1"),
        other => panic!("unhandled feature in hardware_assertions dispatch: {other}"),
    }
}
