//! `IsProcessorFeaturePresent` probes — the cheap detection backend.
//!
//! Wires every `PF_ARM_*` constant defined in Windows SDK 10.0.26100.0
//! (Win11 24H2) `winnt.h`. Plus one architecturally-derived feature
//! (`rdm`) — Microsoft has never defined a `PF_ARM_RDM_*` constant, so
//! we infer it from the `PF_ARM_V81_ATOMIC` / `PF_ARM_V82_DP` markers
//! using the rule from ARM ARM K.a §D17.2.91. This is the same inference
//! .NET 10 ships in production (`dotnet/runtime#109493`, merged 2025-01,
//! shipped at `src/native/minipal/cpufeatures.c` lines 549-563).
//!
//! ## References
//!
//! - Windows SDK 10.0.26100.0 `winnt.h` — local install at
//!   `C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/um/winnt.h:14202-14272`.
//! - Microsoft Learn: <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocessorfeaturepresent>
//! - .NET 10 GA (`v10.0.0`, commit `60629d14`):
//!   <https://github.com/dotnet/runtime/blob/60629d14374c56f1cb51819049ad1fa529307f8d/src/native/minipal/cpufeatures.c#L531-L582>

use crate::cache::Features;
use crate::features::Feature;

use windows_sys::Win32::System::Threading::IsProcessorFeaturePresent;

// PF_ARM_* numeric values verbatim from winnt.h (Windows SDK 26100).
// Comments mark the SDK series each batch first appeared in.

// ── ARMv8.0 baseline (SDK 17134 / Win10 RS4) ────────────────────────────
const PF_ARM_VFP_32_REGISTERS_AVAILABLE: u32 = 18;
const PF_ARM_NEON_INSTRUCTIONS_AVAILABLE: u32 = 19;
const PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE: u32 = 30;
const PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE: u32 = 31;
// ── ARMv8.1 atomics (SDK 17763 / Win10 RS5) ─────────────────────────────
const PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE: u32 = 34;
// ── ARMv8.2/8.3 (SDK 19041 / Win10 20H1) ────────────────────────────────
const PF_ARM_V82_DP_INSTRUCTIONS_AVAILABLE: u32 = 43;
const PF_ARM_V83_JSCVT_INSTRUCTIONS_AVAILABLE: u32 = 44;
const PF_ARM_V83_LRCPC_INSTRUCTIONS_AVAILABLE: u32 = 45;
// ── SVE family (SDK 26100 / Win11 24H2) ─────────────────────────────────
const PF_ARM_SVE_INSTRUCTIONS_AVAILABLE: u32 = 46;
const PF_ARM_SVE2_INSTRUCTIONS_AVAILABLE: u32 = 47;
const PF_ARM_SVE2_1_INSTRUCTIONS_AVAILABLE: u32 = 48;
const PF_ARM_SVE_AES_INSTRUCTIONS_AVAILABLE: u32 = 49;
const PF_ARM_SVE_PMULL128_INSTRUCTIONS_AVAILABLE: u32 = 50;
const PF_ARM_SVE_BITPERM_INSTRUCTIONS_AVAILABLE: u32 = 51;
// 52 PF_ARM_SVE_BF16 / 53 PF_ARM_SVE_EBF16 — SVE-form BF16; stdarch
//    `bf16` semantics are AdvSIMD form (PF_ARM_V86_BF16, #68).
const PF_ARM_SVE_B16B16_INSTRUCTIONS_AVAILABLE: u32 = 54;
const PF_ARM_SVE_SHA3_INSTRUCTIONS_AVAILABLE: u32 = 55;
const PF_ARM_SVE_SM4_INSTRUCTIONS_AVAILABLE: u32 = 56;
// 57 PF_ARM_SVE_I8MM — SVE-form; AdvSIMD i8mm is V82_I8MM (#66).
const PF_ARM_SVE_F32MM_INSTRUCTIONS_AVAILABLE: u32 = 58;
const PF_ARM_SVE_F64MM_INSTRUCTIONS_AVAILABLE: u32 = 59;
// ── AdvSIMD additions + SME (SDK 26100 / Win11 24H2) ────────────────────
const PF_ARM_LSE2_AVAILABLE: u32 = 62;
const PF_ARM_SHA3_INSTRUCTIONS_AVAILABLE: u32 = 64;
const PF_ARM_SHA512_INSTRUCTIONS_AVAILABLE: u32 = 65;
const PF_ARM_V82_I8MM_INSTRUCTIONS_AVAILABLE: u32 = 66;
const PF_ARM_V82_FP16_INSTRUCTIONS_AVAILABLE: u32 = 67;
const PF_ARM_V86_BF16_INSTRUCTIONS_AVAILABLE: u32 = 68;
// 69 PF_ARM_V86_EBF16 — no stdarch name today.
const PF_ARM_SME_INSTRUCTIONS_AVAILABLE: u32 = 70;
const PF_ARM_SME2_INSTRUCTIONS_AVAILABLE: u32 = 71;
const PF_ARM_SME2_1_INSTRUCTIONS_AVAILABLE: u32 = 72;
// 73..=77 SME2_2 / SME_AES / SME_SBITPERM / SME_SF8MM4 / SME_SF8MM8 —
//         no stdarch feature names yet.
const PF_ARM_SME_SF8DP2_INSTRUCTIONS_AVAILABLE: u32 = 78;
const PF_ARM_SME_SF8DP4_INSTRUCTIONS_AVAILABLE: u32 = 79;
const PF_ARM_SME_SF8FMA_INSTRUCTIONS_AVAILABLE: u32 = 80;
const PF_ARM_SME_F8F32_INSTRUCTIONS_AVAILABLE: u32 = 81;
const PF_ARM_SME_F8F16_INSTRUCTIONS_AVAILABLE: u32 = 82;
const PF_ARM_SME_F16F16_INSTRUCTIONS_AVAILABLE: u32 = 83;
const PF_ARM_SME_B16B16_INSTRUCTIONS_AVAILABLE: u32 = 84;
const PF_ARM_SME_F64F64_INSTRUCTIONS_AVAILABLE: u32 = 85;
const PF_ARM_SME_I16I64_INSTRUCTIONS_AVAILABLE: u32 = 86;
#[allow(non_upper_case_globals)] // matches winnt.h spelling exactly
const PF_ARM_SME_LUTv2_INSTRUCTIONS_AVAILABLE: u32 = 87;
const PF_ARM_SME_FA64_INSTRUCTIONS_AVAILABLE: u32 = 88;

/// Safe wrapper around `IsProcessorFeaturePresent`. The only FFI call site.
#[expect(unsafe_code, reason = "single Win32 FFI entry point")]
#[inline]
fn present(feature: u32) -> bool {
    // SAFETY: IsProcessorFeaturePresent takes a DWORD by value, returns
    // a BOOL. No pointers, no out-parameters, no reentrancy. Pure call.
    unsafe { IsProcessorFeaturePresent(feature) != 0 }
}

/// Fill `f` with every feature IPFP can directly (or by sound architectural
/// inference) confirm.
pub(crate) fn fill(f: &mut Features) {
    // ── Baseline ────────────────────────────────────────────────────────
    if present(PF_ARM_VFP_32_REGISTERS_AVAILABLE) {
        *f = f.with(Feature::Fp);
    }
    if present(PF_ARM_NEON_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::Asimd);
    }
    if present(PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::Crc);
    }
    // PF_ARM_V8_CRYPTO covers AES + SHA1/SHA2 + PMULL together.
    if present(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) {
        *f = f
            .with(Feature::Aes)
            .with(Feature::Pmull)
            .with(Feature::Sha2);
    }

    // ── Atomics & memory ordering ───────────────────────────────────────
    let lse = present(PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE);
    if lse {
        *f = f.with(Feature::Lse);
    }
    if present(PF_ARM_LSE2_AVAILABLE) {
        *f = f.with(Feature::Lse2);
    }
    if present(PF_ARM_V83_LRCPC_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::Rcpc);
    }

    // ── ARMv8.2+ AdvSIMD ───────────────────────────────────────────────
    let dotprod = present(PF_ARM_V82_DP_INSTRUCTIONS_AVAILABLE);
    if dotprod {
        *f = f.with(Feature::Dotprod);
    }
    if present(PF_ARM_V83_JSCVT_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::JsConv);
    }
    if present(PF_ARM_V82_FP16_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::Fp16);
    }
    if present(PF_ARM_V82_I8MM_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::I8mm);
    }
    if present(PF_ARM_V86_BF16_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::Bf16);
    }
    // stdarch `sha3` is documented as "FEAT_SHA512 & FEAT_SHA3" — both
    // must be present. Microsoft exposes them as two separate flags.
    if present(PF_ARM_SHA3_INSTRUCTIONS_AVAILABLE) && present(PF_ARM_SHA512_INSTRUCTIONS_AVAILABLE)
    {
        *f = f.with(Feature::Sha3);
    }

    // ── SVE family ──────────────────────────────────────────────────────
    if present(PF_ARM_SVE_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::Sve);
    }
    if present(PF_ARM_SVE2_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::Sve2);
    }
    if present(PF_ARM_SVE2_1_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::Sve2p1);
    }
    // sve2-aes per ARM ARM = SVE_AES + SVE_PMULL128 together.
    if present(PF_ARM_SVE_AES_INSTRUCTIONS_AVAILABLE)
        && present(PF_ARM_SVE_PMULL128_INSTRUCTIONS_AVAILABLE)
    {
        *f = f.with(Feature::Sve2Aes);
    }
    if present(PF_ARM_SVE_BITPERM_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::Sve2Bitperm);
    }
    if present(PF_ARM_SVE_B16B16_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::SveB16b16);
    }
    if present(PF_ARM_SVE_SHA3_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::Sve2Sha3);
    }
    if present(PF_ARM_SVE_SM4_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::Sve2Sm4);
    }
    if present(PF_ARM_SVE_F32MM_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::F32mm);
    }
    if present(PF_ARM_SVE_F64MM_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::F64mm);
    }

    // ── SME family ──────────────────────────────────────────────────────
    if present(PF_ARM_SME_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::Sme);
    }
    if present(PF_ARM_SME2_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::Sme2);
    }
    if present(PF_ARM_SME2_1_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::Sme2p1);
    }
    if present(PF_ARM_SME_B16B16_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::SmeB16b16);
    }
    if present(PF_ARM_SME_F16F16_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::SmeF16f16);
    }
    if present(PF_ARM_SME_F64F64_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::SmeF64f64);
    }
    if present(PF_ARM_SME_F8F16_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::SmeF8f16);
    }
    if present(PF_ARM_SME_F8F32_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::SmeF8f32);
    }
    if present(PF_ARM_SME_FA64_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::SmeFa64);
    }
    if present(PF_ARM_SME_I16I64_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::SmeI16i64);
    }
    if present(PF_ARM_SME_LUTv2_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::SmeLutv2);
    }
    // SF8 = streaming-SVE-mode FP8.
    if present(PF_ARM_SME_SF8DP2_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::SsveFp8Dot2);
    }
    if present(PF_ARM_SME_SF8DP4_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::SsveFp8Dot4);
    }
    if present(PF_ARM_SME_SF8FMA_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::SsveFp8Fma);
    }

    // ── FEAT_RDM via architectural inference ────────────────────────────
    // Microsoft has never defined a PF_ARM_RDM_* constant. Confirmed by
    // dotnet/runtime#74778 (2022) — Windows has no plans to expose it.
    // Resolved in dotnet/runtime#109493 (merged 2025-01, shipped in
    // .NET 10 GA at src/native/minipal/cpufeatures.c lines 549-563)
    // by exactly this inference:
    //
    //   ARM ARM K.a §D17.2.91 — "In an ARMv8.1 implementation, if
    //   FEAT_AdvSIMD is implemented, FEAT_RDM is implemented."
    //
    // Both FEAT_DotProd (v8.2-A) and FEAT_LSE (v8.1-A) imply v8.1-A
    // baseline, and FEAT_AdvSIMD is universally present on every
    // Windows-on-ARM SKU. Either marker confirms RDM.
    if dotprod || lse {
        *f = f.with(Feature::Rdm);
    }
}
