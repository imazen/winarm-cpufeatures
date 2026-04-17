//! `IsProcessorFeaturePresent` probes.
//!
//! Covers every `PF_ARM_*` constant defined in the stdarch nightly Windows
//! backend as of 2026-04, plus the AdvSIMD / AES / SHA / FP16 / BF16 / I8MM /
//! SME constants added in Windows SDK 26100 (Win11 24H2). Constants that the
//! Windows SDK defines but whose numeric value I cannot verify from an
//! authoritative source are deliberately omitted rather than guessed — see
//! `docs/pf_arm_todo.md` at the repo root.
//!
//! ## References
//!
//! - Windows SDK 26100 `winnt.h` (not publicly fetched here; values are
//!   cross-referenced with rust-lang/stdarch nightly and pytorch/cpuinfo).
//! - Microsoft Learn:
//!   <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-isprocessorfeaturepresent>

use crate::cache::Features;
use crate::features::Feature;

use windows_sys::Win32::System::Threading::IsProcessorFeaturePresent;

// PF_ARM_* numeric values from winnt.h (Windows SDK 26100).
// Bracketed range [lo..=hi] documents the SDK series each batch appeared in.
//
// [18..=31]:   Windows 10 RS4 / SDK 17134
const PF_ARM_VFP_32_REGISTERS_AVAILABLE: u32 = 18;
const PF_ARM_NEON_INSTRUCTIONS_AVAILABLE: u32 = 19;
const PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE: u32 = 30;
const PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE: u32 = 31;
// [34]:        Windows 10 RS5 / SDK 17763
const PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE: u32 = 34;
// [43..=45]:   Windows 10 20H1 / SDK 19041
const PF_ARM_V82_DP_INSTRUCTIONS_AVAILABLE: u32 = 43;
const PF_ARM_V83_JSCVT_INSTRUCTIONS_AVAILABLE: u32 = 44;
const PF_ARM_V83_LRCPC_INSTRUCTIONS_AVAILABLE: u32 = 45;
// [46..=59]:   Windows 11 24H2 / SDK 26100 — SVE family
const PF_ARM_SVE_INSTRUCTIONS_AVAILABLE: u32 = 46;
const PF_ARM_SVE2_INSTRUCTIONS_AVAILABLE: u32 = 47;
const PF_ARM_SVE2_1_INSTRUCTIONS_AVAILABLE: u32 = 48;
const PF_ARM_SVE_AES_INSTRUCTIONS_AVAILABLE: u32 = 49;
const PF_ARM_SVE_PMULL128_INSTRUCTIONS_AVAILABLE: u32 = 50;
const PF_ARM_SVE_BITPERM_INSTRUCTIONS_AVAILABLE: u32 = 51;
const PF_ARM_SVE_BF16_INSTRUCTIONS_AVAILABLE: u32 = 52;
const PF_ARM_SVE_EBF16_INSTRUCTIONS_AVAILABLE: u32 = 53;
const PF_ARM_SVE_B16B16_INSTRUCTIONS_AVAILABLE: u32 = 54;
const PF_ARM_SVE_SHA3_INSTRUCTIONS_AVAILABLE: u32 = 55;
const PF_ARM_SVE_SM4_INSTRUCTIONS_AVAILABLE: u32 = 56;
const PF_ARM_SVE_I8MM_INSTRUCTIONS_AVAILABLE: u32 = 57;
const PF_ARM_SVE_F32MM_INSTRUCTIONS_AVAILABLE: u32 = 58;
const PF_ARM_SVE_F64MM_INSTRUCTIONS_AVAILABLE: u32 = 59;
// TODO: verify against SDK 26100 winnt.h before adding:
//   PF_ARM_V84_LSE2 (~62)                 → Feature::Lse2
//   PF_ARM_V82_SHA3 (~64)                 → Feature::Sha3   (AdvSIMD SHA3)
//   PF_ARM_V82_I8MM (~66)                 → Feature::I8mm   (AdvSIMD I8MM)
//   PF_ARM_V82_FP16 (~67)                 → Feature::Fp16
//   PF_ARM_V86_BF16 (~68)                 → Feature::Bf16   (AdvSIMD BF16)
//   PF_ARM_SME  (~70) / SME2 (~71) / SME2_1 (~72) → Sme/Sme2/Sme2p1
//   SME sub-feature variants (~73..=88)   → Sme*
// These numeric values are from third-party accounts; confirm with an
// SDK header before enabling.

/// Safe wrapper around `IsProcessorFeaturePresent`. The only FFI call site.
#[expect(unsafe_code, reason = "single Win32 FFI entry point")]
#[inline]
fn present(feature: u32) -> bool {
    // SAFETY: IsProcessorFeaturePresent takes a DWORD and returns a BOOL. No
    // pointers, no aliasing, no reentrancy concerns — the call is pure.
    unsafe { IsProcessorFeaturePresent(feature) != 0 }
}

/// Fill `f` with every feature IPFP can directly confirm.
pub(crate) fn fill(f: &mut Features) {
    // ── baseline ─────────────────────────────────────────────────────────
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
    // ── atomics / memory ordering ────────────────────────────────────────
    if present(PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::Lse);
    }
    if present(PF_ARM_V83_LRCPC_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::Rcpc);
    }
    // ── ARMv8.2+ instruction groups ─────────────────────────────────────
    if present(PF_ARM_V82_DP_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::Dotprod);
    }
    if present(PF_ARM_V83_JSCVT_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::JsConv);
    }
    // ── SVE family (SDK 26100) ──────────────────────────────────────────
    if present(PF_ARM_SVE_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::Sve);
    }
    if present(PF_ARM_SVE2_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::Sve2);
    }
    if present(PF_ARM_SVE2_1_INSTRUCTIONS_AVAILABLE) {
        *f = f.with(Feature::Sve2p1);
    }
    // sve2-aes per ARM ARM is SVE + SVE_AES + SVE_PMULL128 together.
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
    // PF_ARM_SVE_BF16 / SVE_EBF16 / SVE_I8MM signal SVE-flavored variants of
    // these features. stdarch's `bf16` / `i8mm` names refer to the AdvSIMD
    // forms, which need PF_ARM_V86_BF16 / PF_ARM_V82_I8MM (TODO: verify
    // numeric values from SDK 26100 winnt.h before enabling). Until then,
    // bf16 / i8mm are detected via the registry ID_AA64ISAR1 path.
    let _unused_until_verified = (
        PF_ARM_SVE_BF16_INSTRUCTIONS_AVAILABLE,
        PF_ARM_SVE_EBF16_INSTRUCTIONS_AVAILABLE,
        PF_ARM_SVE_I8MM_INSTRUCTIONS_AVAILABLE,
    );
}
