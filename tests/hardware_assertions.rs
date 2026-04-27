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

use winarm_cpufeatures::{Feature, Features, set_registry_enabled};

/// Authorise the registry detection layer once per test process.
///
/// Without this, the `registry` Cargo feature is compiled in but the
/// runtime gate stays off — and `Features::current_full()` returns
/// IPFP-only answers, causing every registry-only feature (sm4, paca,
/// dpb*, flagm*, dit, sb, ssbs, rand, …) to read `false`. Each ignored
/// hardware test calls this at entry. Idempotent; uses `Once` to avoid
/// repeated cache invalidation under parallel execution.
fn setup() -> Features {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| set_registry_enabled(true));
    Features::current_full()
}

/// Look up a feature by stdarch name. Panics on unknown names so a typo
/// in the expected-list arrays surfaces immediately.
fn lookup(name: &str) -> Feature {
    Feature::all()
        .find(|f| f.name() == name)
        .unwrap_or_else(|| panic!("unhandled feature in hardware_assertions: {name}"))
}

/// Neoverse N2 (Armv9.0-A) as shipped in Azure Cobalt 100, Graviton 3, and
/// GitHub's `windows-11-arm` / `ubuntu-24.04-arm` hosted runners.
///
/// Feature expectations derived from the actual CI run 24479154394 captured
/// against both runners.
#[test]
#[ignore = "requires Neoverse N2 / Cobalt 100 — `cargo test --ignored neoverse_n2`"]
fn neoverse_n2() {
    let cpu = setup();
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
        "sve2-bitperm",
        "sve2-sha3",
        "sve2-sm4",
    ] {
        assert!(
            cpu.has(lookup(f)),
            "Neoverse N2 must have feature `{f}` but Features::current_full said no"
        );
    }

    // ── Must be absent ──────────────────────────────────────────────────
    // N2 deliberately does not implement these; if we claim them, something
    // in the detection path is false-positive.
    for f in [
        "sve2-aes",
        "sve-b16b16",
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
            !cpu.has(lookup(f)),
            "Neoverse N2 must NOT have feature `{f}` but Features::current_full said yes"
        );
    }
}

/// Neoverse V2 (Armv9.0-A + extra SVE2 options) as shipped in AWS Graviton 4
/// and NVIDIA Grace. Adds the SVE2-AES / PMULL128 / B16B16 variants the N2
/// omits; 128-bit SVE vector length.
#[test]
#[ignore = "requires Neoverse V2 — `cargo test --ignored neoverse_v2`"]
fn neoverse_v2() {
    let cpu = setup();
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
        "sve2-bitperm",
        "sve2-sha3",
        "sve2-sm4",
        // V2-only additions:
        "sve2-aes",
    ] {
        assert!(
            cpu.has(lookup(f)),
            "Neoverse V2 must have feature `{f}` but Features::current_full said no"
        );
    }

    // Still no SME on V2 (that's V3+).
    for f in ["sme", "sme2", "sme2p1", "mte"] {
        assert!(
            !cpu.has(lookup(f)),
            "Neoverse V2 must NOT have feature `{f}` but Features::current_full said yes"
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
    let cpu = setup();
    // FEAT_MOPS and FEAT_WFxT are optional in ARMv8.7 (only mandated at v8.8);
    // Oryon does not implement them — verified on a Yoga Slim 7x (X1E, MIDR
    // impl=0x51 var=0x2 part=0x001) where ID_AA64ISAR2_EL1 reports MOPS=0,
    // WFxT=0 and `/proc/cpuinfo` lists neither.
    for f in [
        "asimd", "fp", "crc", "aes", "pmull", "sha2", "sha3", "sm4", "lse", "lse2", "rcpc",
        "rcpc2", "rdm", "dotprod", "jsconv", "fp16", "fhm", "fcma", "bf16", "i8mm", "frintts",
        "paca", "pacg", "dpb", "dpb2", "flagm", "flagm2", "rand", "sb", "ssbs",
    ] {
        assert!(
            cpu.has(lookup(f)),
            "Snapdragon X (Oryon) must have feature `{f}` but Features::current_full said no"
        );
    }

    // Oryon explicitly omits SVE and MTE.
    for f in ["sve", "sve2", "sme", "mte"] {
        assert!(
            !cpu.has(lookup(f)),
            "Snapdragon X (Oryon) must NOT have feature `{f}` but Features::current_full said yes"
        );
    }
}

/// Qualcomm SC8280XP (8cx Gen 3 / Nuvia Phoenix, ARMv8.4-A) as found in
/// Lenovo ThinkPad X13s and dev kits running Linux (WSL2 or native).
///
/// Implements a rich AdvSIMD + crypto feature set but no SVE/SME. Notable:
/// has flagm2, frint, sha512 (per /proc/cpuinfo) but Rust stdarch only exposes
/// flagm2/frintts/sb/ssbs on nightly — so those are nightly-only assertions.
///
/// Feature expectations derived from /proc/cpuinfo on WSL2:
///   fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid
///   asimdrdm jscvt fcma lrcpc dcpop sha3 sm3 sm4 asimddp sha512 asimdfhm
///   uscat ilrcpc flagm ssbs sb paca pacg dcpodp flagm2 frint i8mm bf16
///   rng afp rpres
#[test]
#[ignore = "requires Qualcomm SC8280XP — `cargo test --ignored sc8280xp`"]
fn sc8280xp() {
    let cpu = setup();
    // ── Must be present (stable stdarch names) ──────────────────────────
    for f in [
        "asimd", "fp", "crc", "aes", "pmull", "sha2", "sha3", "sm4", "lse", "lse2", "rcpc",
        "rcpc2", "rdm", "dotprod", "jsconv", "fp16", "fhm", "fcma", "bf16", "i8mm", "frintts",
        "paca", "pacg", "dpb", "dpb2", "flagm", "rand", "sb", "ssbs",
    ] {
        assert!(
            cpu.has(lookup(f)),
            "SC8280XP must have feature `{f}` but Features::current_full said no"
        );
    }

    // ── Must be absent ──────────────────────────────────────────────────
    for f in [
        "sve", "sve2", "sme", "sme2", "mte", "bti", "lse128", "rcpc3", "mops", "wfxt",
    ] {
        assert!(
            !cpu.has(lookup(f)),
            "SC8280XP must NOT have feature `{f}` but Features::current_full said yes"
        );
    }
}
