//! Windows-on-ARM64 detection backend.
//!
//! Two layers, the second behind a Cargo feature flag:
//!
//! 1. **Always-on (`ipfp`):** every `PF_ARM_*` constant defined in
//!    Windows SDK 10.0.26100.0 (Win11 24H2) `winnt.h`, plus the
//!    DP/LSE→RDM architectural inference (matches what .NET 10 ships
//!    in `dotnet/runtime` v10.0.0 `cpufeatures.c:549-563`).
//!
//! 2. **Opt-in (`registry`):** `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0\CP <hex>`
//!    reads decoding the cached `ID_AA64*_EL1` system-register snapshots.
//!    Covers ~30 stdarch feature names Microsoft has never exposed via
//!    IPFP. Adds one `RegOpenKeyExW` + a handful of `RegGetValueW` calls
//!    on first probe.

#![cfg(all(target_os = "windows", target_arch = "aarch64"))]

mod ipfp;
#[cfg(feature = "registry")]
mod registry;

pub(crate) use ipfp::fill as fill_ipfp;
#[cfg(feature = "registry")]
pub(crate) use registry::fill as fill_registry;
