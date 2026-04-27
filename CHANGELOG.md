# Changelog

## [0.1.0] — 2026-04-26

Initial release.

### Drop-in for `std::arch::is_aarch64_feature_detected!`

This crate ships an `is_aarch64_feature_detected!` macro with the *same
name*, *same dashed feature spelling*, and *same call shape* as std's,
namespaced by crate path. Migration from std is a one-line import swap.

```diff
-use std::arch::is_aarch64_feature_detected;
+use winarm_cpufeatures::is_aarch64_feature_detected;
```

Names use stdarch's dashed convention exactly: `sve2-aes`, `sme-fa64`,
`pauth-lr`, `ssve-fp8dot2`, etc. Code is portable: same source compiles
on Windows ARM64, Linux ARM64, macOS ARM64, and (with always-`false`
results) non-aarch64 hosts.

### Detection layers

- **IPFP layer (always on, Windows ARM64).** Wires every `PF_ARM_*`
  constant defined in Windows SDK 10.0.26100.0 (`winnt.h:14202-14272`),
  covering the SVE/SME family added in Windows 11 24H2.
- **DP/LSE → RDM architectural inference (Windows ARM64).** Microsoft
  has never defined a `PF_ARM_RDM_*` constant; we follow ARM ARM K.a
  §D17.2.91 and `dotnet/runtime#109493` (shipped in .NET 10 GA at
  `src/native/minipal/cpufeatures.c:549-563`).
- **Registry layer (opt-in, double-gated).** Behind the `registry` Cargo
  feature *and* a runtime `set_registry_enabled(true)` call. Reads the
  `HKLM\…\CentralProcessor\0\CP <hex>` `ID_AA64*_EL1` snapshots Windows
  publishes — covers ~30 stdarch feature names IPFP cannot reach.
  Defense-in-depth against transitive Cargo-feature unification.
- **Std passthrough (non-Windows aarch64).** Macros expand directly to
  `std::arch::is_aarch64_feature_detected!`. No added cache layer; std's
  internal HWCAP cache amortizes.
- **No-op stub (non-aarch64).** Every name returns `false`. Lets
  cross-platform code use one spelling.

### Compile-time design

- Macros use direct `macro_rules!` arm dispatch. Each call site expands
  to one function call (Windows aarch64) or one std-macro invocation
  (non-Windows aarch64) — no const-eval, no per-site string-compare,
  no `panic!`-based assertions. Compile-time cost matches calling
  `std::arch::is_aarch64_feature_detected!` directly.
- No build script. Nightly opt-in for the 32 unstable stdarch feature
  names is via an explicit `nightly-stdarch` Cargo feature; stable
  users get the 41 stable names without build-script overhead.

### Cargo features

- `registry` — link the `HKLM\…\CentralProcessor\0\CP <hex>` registry
  decoder. Off by default. Even when enabled, the registry path is
  *not consulted* until `set_registry_enabled(true)` is called.
- `nightly-stdarch` — opt into
  `#![feature(stdarch_aarch64_feature_detection)]` so non-Windows
  aarch64 targets can detect the 32 unstable stdarch names. Requires
  nightly rustc.
- `nightly-sve` — enable the SVE execution test
  (`tests/sve_execution.rs`).

### Public API (docs-visible)

- `is_aarch64_feature_detected!(name)` — fast detection.
- `is_aarch64_feature_detected_full!(name)` — full detection (Windows
  aarch64 with `registry` adds registry-decoded features).
- `Features` snapshot struct: `EMPTY`, `current()`, `current_full()`,
  `has(Feature)`, `iter()`.
- `Feature` enum (73 variants), with `name()` and `all()`.
- `set_registry_enabled(bool)`.
