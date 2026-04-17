# Changelog

## [Unreleased]

### Added
- Initial crate scaffold: `Features`, `Feature` enum, `detected!` macro
- Windows-on-ARM detection backend:
  - `IsProcessorFeaturePresent` probes for all `PF_ARM_*` constants in Windows SDK 26100 (Win11 24H2)
  - Registry `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0\CP <hex>` reader for AArch64 ID-register snapshots
  - MIDR_EL1 parsing with implementer/variant/part/revision decode
- Non-Windows platforms: all detection delegates to `std::arch::is_aarch64_feature_detected!`
