//! Minimal Win32 FFI declarations.
//!
//! We declare the four function entry points and four constants this
//! crate uses ourselves to avoid the `windows-sys` dependency, which
//! dominates clean-build time on Windows aarch64 (~3s) and brings
//! hundreds of MB of unused source. Signatures match the published
//! Win32 SDK headers (`winnt.h`, `winreg.h`).
//!
//! API stability: `IsProcessorFeaturePresent` has shipped since Windows
//! Vista (2006); the registry trio since Windows 2000. Win32 ABIs are
//! decade-stable; no realistic risk of FFI drift.

#![allow(unsafe_code)]

/// Opaque registry-key handle. Win32 represents `HKEY` as a
/// pointer-sized integer; `*mut c_void` matches windows-sys's
/// representation and the `winreg.h` typedef.
#[cfg(feature = "registry")]
#[allow(
    clippy::upper_case_acronyms,
    reason = "matches the Win32 `HKEY` typedef name verbatim"
)]
pub(crate) type HKEY = *mut core::ffi::c_void;

/// Predefined `HKEY_LOCAL_MACHINE` per `winreg.h`:
/// `(HKEY)(ULONG_PTR)((LONG)0x80000002)` — the constant is sign-extended
/// from a 32-bit signed integer to the pointer width before being
/// reinterpreted as a handle.
#[cfg(feature = "registry")]
pub(crate) const HKEY_LOCAL_MACHINE: HKEY =
    0x8000_0002_u32 as i32 as isize as *mut core::ffi::c_void;

/// `KEY_READ = STANDARD_RIGHTS_READ | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY`,
/// from `winnt.h`.
#[cfg(feature = "registry")]
pub(crate) const KEY_READ: u32 = 0x2_0019;

/// `RegGetValueW` flag restricting the call to `REG_QWORD` data, from
/// `winreg.h`.
#[cfg(feature = "registry")]
pub(crate) const RRF_RT_REG_QWORD: u32 = 0x0000_0040;

/// `ERROR_SUCCESS` — `0`, the standard Win32 success status.
#[cfg(feature = "registry")]
pub(crate) const ERROR_SUCCESS: u32 = 0;

#[link(name = "kernel32")]
unsafe extern "system" {
    /// Probes a `PF_*` processor-feature flag (see `winnt.h`). Returns
    /// nonzero when the feature is supported. Marked `safe` because
    /// the call has no caller-side safety contract — it simply reads
    /// process-global state.
    pub(crate) safe fn IsProcessorFeaturePresent(ProcessorFeature: u32) -> i32;
}

#[cfg(feature = "registry")]
#[link(name = "advapi32")]
unsafe extern "system" {
    pub(crate) fn RegOpenKeyExW(
        hKey: HKEY,
        lpSubKey: *const u16,
        ulOptions: u32,
        samDesired: u32,
        phkResult: *mut HKEY,
    ) -> u32;

    pub(crate) fn RegGetValueW(
        hkey: HKEY,
        lpSubKey: *const u16,
        lpValue: *const u16,
        dwFlags: u32,
        pdwType: *mut u32,
        pvData: *mut core::ffi::c_void,
        pcbData: *mut u32,
    ) -> u32;

    pub(crate) fn RegCloseKey(hKey: HKEY) -> u32;
}
