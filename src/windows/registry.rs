//! Registry-based AArch64 ID register reader.
//!
//! Windows on ARM caches selected `ID_AA64*_EL1` system registers into the
//! registry at boot, under
//! `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0\CP <hex>`. Each
//! value is `REG_QWORD` (64-bit) and corresponds to a specific EL1 ID
//! register. This is undocumented-but-stable since Windows 10 1709 and is
//! the approach used by LLVM, pytorch/cpuinfo, and Microsoft's ONNX Runtime.
//!
//! Key mappings (cross-referenced with pytorch/cpuinfo and tringi's
//! `win32-arm64-arch-check`):
//!
//! | CP key      | System register       | Purpose                             |
//! |-------------|-----------------------|-------------------------------------|
//! | `CP 4000`   | MIDR_EL1              | implementer/variant/part/revision   |
//! | `CP 4020`   | ID_AA64PFR0_EL1       | FP/AdvSIMD support                  |
//! | `CP 4021`   | ID_AA64PFR1_EL1       | BTI / MTE / SSBS                    |
//! | `CP 4028`   | ID_AA64DFR0_EL1       | debug features                      |
//! | `CP 4030`   | ID_AA64ISAR0_EL1      | RDM / AES / SHA / DP / etc.         |
//! | `CP 4031`   | ID_AA64ISAR1_EL1      | JSCVT / FCMA / LRCPC / DPB / etc.   |
//! | `CP 4032`   | ID_AA64ISAR2_EL1      | RCPC3 / CSSC / etc.                 |
//! | `CP 4038`   | ID_AA64MMFR0_EL1      | memory model features               |
//! | `CP 4039`   | ID_AA64MMFR1_EL1      | memory model features               |
//! | `CP 403A`   | ID_AA64MMFR2_EL1      | memory model features               |
//! | `CP 403B`   | ID_AA64MMFR3_EL1      | memory model features               |

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, RRF_RT_REG_QWORD, RegCloseKey, RegGetValueW, RegOpenKeyExW,
};

use crate::cache::Features;
use crate::features::Feature;

const CPU0_SUBKEY: &str = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0";

/// Raw AArch64 ID register snapshot read from the registry. Values are `None`
/// when the corresponding `CP <hex>` entry is absent or wrong-typed, which
/// happens on older Windows builds.
#[derive(Default, Debug, Copy, Clone)]
pub struct IdRegisters {
    pub midr_el1: Option<u64>,
    pub aa64pfr0: Option<u64>,
    pub aa64pfr1: Option<u64>,
    pub aa64isar0: Option<u64>,
    pub aa64isar1: Option<u64>,
    pub aa64isar2: Option<u64>,
    pub aa64mmfr0: Option<u64>,
    pub aa64mmfr1: Option<u64>,
    pub aa64mmfr2: Option<u64>,
    pub aa64mmfr3: Option<u64>,
}

impl IdRegisters {
    /// Read every known CP key in one pass. Opens the CentralProcessor\0 key
    /// once and issues one `RegGetValueW` per register.
    pub fn read() -> Self {
        let Some(hk) = open_cpu0() else {
            return Self::default();
        };
        let mut r = Self::default();
        r.midr_el1 = read_qword(hk, "CP 4000");
        r.aa64pfr0 = read_qword(hk, "CP 4020");
        r.aa64pfr1 = read_qword(hk, "CP 4021");
        r.aa64isar0 = read_qword(hk, "CP 4030");
        r.aa64isar1 = read_qword(hk, "CP 4031");
        r.aa64isar2 = read_qword(hk, "CP 4032");
        r.aa64mmfr0 = read_qword(hk, "CP 4038");
        r.aa64mmfr1 = read_qword(hk, "CP 4039");
        r.aa64mmfr2 = read_qword(hk, "CP 403A");
        r.aa64mmfr3 = read_qword(hk, "CP 403B");
        close(hk);
        r
    }
}

/// Decode ID registers into feature bits and OR them into `f`.
///
/// Only features the IPFP path cannot reach are set here — features that IPFP
/// already confirms are skipped to keep each bit single-sourced and reduce the
/// blast radius if one source is wrong on a given SKU.
pub(crate) fn fill(f: &mut Features) {
    let r = IdRegisters::read();
    if let Some(isar0) = r.aa64isar0 {
        isar0_decode(isar0, f);
    }
    if let Some(isar1) = r.aa64isar1 {
        isar1_decode(isar1, f);
    }
    if let Some(isar2) = r.aa64isar2 {
        isar2_decode(isar2, f);
    }
    if let Some(pfr0) = r.aa64pfr0 {
        pfr0_decode(pfr0, f);
    }
    if let Some(pfr1) = r.aa64pfr1 {
        pfr1_decode(pfr1, f);
    }
}

/// ID_AA64ISAR0_EL1 field layout (ARM ARM D19.2.60).
fn isar0_decode(isar0: u64, f: &mut Features) {
    // RDM       bits 31:28 — values ≥ 0b0001 indicate FEAT_RDM.
    if field(isar0, 28, 4) >= 1 {
        *f = f.with(Feature::Rdm);
    }
    // SHA1/SHA2 already confirmed by IPFP PF_ARM_V8_CRYPTO.
    // SHA3 (AdvSIMD) bits 35:32 — not reachable via IPFP today.
    if field(isar0, 32, 4) >= 1 {
        *f = f.with(Feature::Sha3);
    }
    // SM4 bits 43:40.
    if field(isar0, 40, 4) >= 1 {
        *f = f.with(Feature::Sm4);
    }
    // TS (FlagM/FlagM2) bits 55:52.
    let ts = field(isar0, 52, 4);
    if ts >= 1 {
        *f = f.with(Feature::FlagM);
    }
    if ts >= 2 {
        *f = f.with(Feature::FlagM2);
    }
    // RNDR bits 63:60.
    if field(isar0, 60, 4) >= 1 {
        *f = f.with(Feature::Rand);
    }
    // TLB operations, atomic loads, etc. are in this register but not
    // currently surfaced as stdarch feature names.
}

/// ID_AA64ISAR1_EL1 field layout (ARM ARM D19.2.61).
fn isar1_decode(isar1: u64, f: &mut Features) {
    // DPB bits 3:0 — 0b0001 = DPB, 0b0010 = DPB + DPB2.
    let dpb = field(isar1, 0, 4);
    if dpb >= 1 {
        *f = f.with(Feature::Dpb);
    }
    if dpb >= 2 {
        *f = f.with(Feature::Dpb2);
    }
    // APA (PAC using QARMA5) bits 7:4; API (PAC using implementation-defined
    // algorithm) bits 11:8. Either ≥1 implies FEAT_PAuth (paca+pacg).
    if field(isar1, 4, 4) >= 1 || field(isar1, 8, 4) >= 1 {
        *f = f.with(Feature::Paca).with(Feature::Pacg);
    }
    // JSCVT bits 15:12 already via IPFP.
    // FCMA bits 19:16 — not reachable via IPFP.
    if field(isar1, 16, 4) >= 1 {
        *f = f.with(Feature::Fcma);
    }
    // LRCPC bits 23:20 — ≥1 = FEAT_LRCPC, ≥2 = FEAT_LRCPC2.
    let lrcpc = field(isar1, 20, 4);
    if lrcpc >= 2 {
        *f = f.with(Feature::Rcpc2);
    }
    // GPA/GPI (generic PAC) bits 27:24 / 31:28 — already covered by pacg above.
    // FRINTTS bits 35:32.
    if field(isar1, 32, 4) >= 1 {
        *f = f.with(Feature::FrintTs);
    }
    // SB bits 39:36.
    if field(isar1, 36, 4) >= 1 {
        *f = f.with(Feature::Sb);
    }
    // SPECRES bits 43:40 — no stdarch feature name.
    // BF16 bits 47:44 — also not reachable via IPFP today.
    if field(isar1, 44, 4) >= 1 {
        *f = f.with(Feature::Bf16);
    }
    // I8MM bits 55:52 — also not reachable via IPFP today.
    if field(isar1, 52, 4) >= 1 {
        *f = f.with(Feature::I8mm);
    }
    // DGH bits 51:48 — no stdarch feature.
    // LS64, XS, BC, LSP — fields exist but no stdarch feature names today.
}

/// ID_AA64ISAR2_EL1 field layout (ARM ARM).
fn isar2_decode(isar2: u64, f: &mut Features) {
    // RPRES bits 3:0 — no stdarch feature name.
    // WFxT bits 7:4.
    if field(isar2, 4, 4) >= 1 {
        *f = f.with(Feature::WfxT);
    }
    // MOPS bits 19:16.
    if field(isar2, 16, 4) >= 1 {
        *f = f.with(Feature::Mops);
    }
    // BC (BC instruction, FEAT_HBC) bits 23:20.
    if field(isar2, 20, 4) >= 1 {
        *f = f.with(Feature::Hbc);
    }
    // CSSC bits 55:52.
    if field(isar2, 52, 4) >= 1 {
        *f = f.with(Feature::Cssc);
    }
    // RPRFM bits 51:48 — no stdarch feature.
}

fn pfr0_decode(pfr0: u64, f: &mut Features) {
    // FP bits 19:16 — 0b0000 = FP present, 0b0001 = FP+half-precision.
    // AdvSIMD bits 23:20 — same encoding.
    let advsimd = field(pfr0, 20, 4);
    if advsimd == 1 {
        // FP16 half-precision AdvSIMD.
        *f = f.with(Feature::Fp16);
        // FHM is a separate bit in ISAR0 historically; older registers
        // conflated it. Conservatively gate on ISAR0's FHM field below if added.
    }
    // SVE bits 35:32 already covered by IPFP PF_ARM_SVE.
    // DIT bits 51:48.
    if field(pfr0, 48, 4) >= 1 {
        *f = f.with(Feature::Dit);
    }
}

fn pfr1_decode(pfr1: u64, f: &mut Features) {
    // BT (BTI) bits 3:0.
    if field(pfr1, 0, 4) >= 1 {
        *f = f.with(Feature::Bti);
    }
    // SSBS bits 7:4.
    if field(pfr1, 4, 4) >= 1 {
        *f = f.with(Feature::Ssbs);
    }
    // MTE bits 11:8.
    if field(pfr1, 8, 4) >= 1 {
        *f = f.with(Feature::Mte);
    }
    // SME bits 27:24.
    if field(pfr1, 24, 4) >= 1 {
        *f = f.with(Feature::Sme);
    }
}

#[inline]
const fn field(reg: u64, shift: u32, bits: u32) -> u64 {
    (reg >> shift) & ((1u64 << bits) - 1)
}

// ── FFI wrappers ─────────────────────────────────────────────────────────

#[expect(unsafe_code, reason = "Win32 registry FFI entry points")]
fn open_cpu0() -> Option<HKEY> {
    let wide = wide_null(CPU0_SUBKEY);
    let mut hk: HKEY = core::ptr::null_mut();
    // SAFETY: wide is null-terminated; &mut hk is a valid out parameter.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            wide.as_ptr(),
            0,
            KEY_READ,
            &mut hk as *mut _,
        )
    };
    if status == ERROR_SUCCESS {
        Some(hk)
    } else {
        None
    }
}

#[expect(unsafe_code, reason = "Win32 registry FFI entry points")]
fn read_qword(hk: HKEY, value: &str) -> Option<u64> {
    let wide = wide_null(value);
    let mut data: u64 = 0;
    let mut cb: u32 = core::mem::size_of::<u64>() as u32;
    // SAFETY: wide is null-terminated; data and cb are valid out parameters
    // whose sizes match RRF_RT_REG_QWORD expectations.
    let status = unsafe {
        RegGetValueW(
            hk,
            core::ptr::null(),
            wide.as_ptr(),
            RRF_RT_REG_QWORD,
            core::ptr::null_mut(),
            &mut data as *mut u64 as *mut _,
            &mut cb as *mut u32,
        )
    };
    (status == ERROR_SUCCESS).then_some(data)
}

#[expect(unsafe_code, reason = "Win32 registry FFI entry points")]
fn close(hk: HKEY) {
    // SAFETY: hk came from a successful RegOpenKeyExW; close is idempotent.
    let _ = unsafe { RegCloseKey(hk) };
}

fn wide_null(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}
