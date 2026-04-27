# Changelog

## [0.1.0] — 2026-04-26

Initial release.

### What this crate does

Drop-in `detected!` / `detected_full!` macros that fill the
Windows-on-ARM gap in `std::arch::is_aarch64_feature_detected!`.

### Detection layers

- **IPFP layer (always on).** Wires every `PF_ARM_*` constant defined in
  Windows SDK 10.0.26100.0 (`winnt.h:14202-14272`). Covers the SVE/SME
  family added in Windows 11 24H2.
- **DP/LSE → RDM architectural inference.** Microsoft has never defined a
  `PF_ARM_RDM_*` constant; we follow ARM ARM K.a §D17.2.91 and
  `dotnet/runtime#109493` (shipped in .NET 10 GA at
  `src/native/minipal/cpufeatures.c:549-563`).
- **Registry layer (opt-in, double-gated).** Behind the `registry` Cargo
  feature *and* a runtime `set_registry_enabled(true)` call. Reads the
  `HKLM\…\CentralProcessor\0\CP <hex>` `ID_AA64*_EL1` snapshots Windows
  publishes — covers ~30 stdarch feature names IPFP cannot reach.
  Defense-in-depth against transitive Cargo-feature unification.
- **MIDR_EL1 parsing** with implementer/variant/part/revision decode.

### Compile-time design

- `detected!` / `detected_full!` use direct `macro_rules!` arm dispatch.
  Each call site expands to a single function call — no const-eval, no
  per-site string-compare lookup.
- No build script. Nightly opt-in for the 32 unstable stdarch feature
  names is via the explicit `nightly-stdarch` Cargo feature; users on
  stable get the 41 stable names without paying for build-script overhead.

### Cargo features

- `registry` — link the `HKLM\…\CentralProcessor\0\CP <hex>` registry
  decoder. Off by default. Even when enabled, the registry path is *not
  consulted* until `set_registry_enabled(true)` is called.
- `nightly-stdarch` — opt into
  `#![feature(stdarch_aarch64_feature_detection)]` so non-Windows aarch64
  targets can detect the 32 unstable stdarch names. Requires nightly rustc.
- `nightly-sve` — enable the SVE execution test (`tests/sve_execution.rs`).

### Public API

- `detected!(name)` / `detected_full!(name)` macros.
- `Features` / `Feature` / `DetectionMethod` / `FEATURE_COUNT`.
- `is_detected(Feature) -> bool`, `is_detected_full(Feature) -> bool`.
- `set_registry_enabled(bool)`, `is_registry_enabled() -> bool` (no-ops
  on builds without the `registry` feature).
- Non-Windows platforms: detection delegates to
  `std::arch::is_aarch64_feature_detected!`.
