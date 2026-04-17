//! Windows-on-ARM64 detection backend.
//!
//! Layered strategy:
//! 1. `IsProcessorFeaturePresent` with every `PF_ARM_*` constant through
//!    Windows SDK 26100 (Windows 11 24H2).
//! 2. Registry `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0\CP <hex>`
//!    reads, which expose cached `ID_AA64ISARx_EL1` / `ID_AA64PFRx_EL1` /
//!    `ID_AA64MMFRx_EL1` values populated by the kernel at boot.
//! 3. Platform baseline fallback: Windows 11 on ARM mandates ARMv8.1-A,
//!    guaranteeing FEAT_RDM when the OS version is ≥ 10.0.22000.

#![cfg(all(target_os = "windows", target_arch = "aarch64"))]

mod ipfp;
mod registry;

pub(crate) use ipfp::fill as fill_ipfp;
pub(crate) use registry::fill as fill_registry;
