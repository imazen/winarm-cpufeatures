# Changelog

## [0.2.0] — 2026-04-25

### Added

- Wire every `PF_ARM_*` constant defined in Windows SDK 10.0.26100.0
  (`winnt.h:14202-14272`). New IPFP-detectable features: `lse2`, `sha3`,
  `fp16`, `bf16`, `i8mm`, `f32mm`, `f64mm`, `sme`, `sme2`, `sme2p1`,
  `sme_b16b16`, `sme_f16f16`, `sme_f64f64`, `sme_f8f16`, `sme_f8f32`,
  `sme_fa64`, `sme_i16i64`, `sme_lutv2`, `ssve_fp8dot2`, `ssve_fp8dot4`,
  `ssve_fp8fma`. (~20 features moved from `Registry`-only to `Both`/`Ipfp`.)
- DP/LSE → RDM architectural inference. Microsoft has never defined a
  `PF_ARM_RDM_*` constant; we follow the rule from ARM ARM K.a §D17.2.91
  and `dotnet/runtime#109493` (shipped in .NET 10 GA at
  `src/native/minipal/cpufeatures.c:549-563`). Result: `detected!("rdm")`
  now works without the registry layer.
- New Cargo feature `registry` (off by default). Enables the
  `HKLM\…\CentralProcessor\0\CP <hex>` ID-register decoder for the ~30
  stdarch feature names IPFP cannot reach. Same shape as before, just
  opt-in.
- **Double opt-in for the registry layer**: even when the Cargo feature
  is enabled (whether by your own crate or any transitive dep — Cargo
  features union across the dependency graph), the registry is *not
  consulted* until `set_registry_enabled(true)` is called. The registry
  FFI is linked but stays dormant. Defense in depth against transitive
  feature enablement.
- New public functions: `set_registry_enabled(bool)` and
  `is_registry_enabled() -> bool`. Both are no-ops on builds without the
  `registry` feature, kept for API stability.
- Documentation: `contrib/std_detect_patch/` contains a draft
  `library/std_detect/src/detect/os/windows/aarch64.rs` replacement plus
  a `dotnet10_arm_detection_reference.md` source-pinned to .NET 10 GA
  (`v10.0.0`, commit `60629d14`) showing the reference implementation.

### Changed

- **Default features no longer include the registry pass.** Migration:
  add `features = ["registry"]` to your `Cargo.toml` if you depend on any
  of the registry-only feature names being detected. Without it,
  `detected_full!` returns the same answers as `detected!`.
- `Cargo.toml` description now reflects the IPFP-first design.
- `Feature::Rdm`, `Feature::Sha3`, `Feature::Fp16`, `Feature::Bf16`,
  `Feature::I8mm`, `Feature::Lse2`, `Feature::Sme` reclassified
  `DetectionMethod::Registry` → `DetectionMethod::Both`. Sme2/Sme2p1/all
  `Sme*` and `SsveFp8*` reclassified to `DetectionMethod::Ipfp`.

### Fixed

- `#![cfg_attr(winarm_rustc_nightly, feature(stdarch_aarch64_feature_detection))]`
  is now also gated on `target_arch = "aarch64"`, so the crate builds on
  nightly toolchains targeting non-aarch64 hosts (the previous predicate
  triggered `unknown feature 'stdarch_aarch64_feature_detection'` errors
  on x86_64 nightly).

## [0.1.0] — initial release

### Added
- Initial crate scaffold: `Features`, `Feature` enum, `detected!` macro
- Windows-on-ARM detection backend:
  - `IsProcessorFeaturePresent` probes for the `PF_ARM_*` constants known
    at the time
  - Registry `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0\CP <hex>`
    reader for AArch64 ID-register snapshots
  - MIDR_EL1 parsing with implementer/variant/part/revision decode
- Non-Windows platforms: all detection delegates to
  `std::arch::is_aarch64_feature_detected!`
