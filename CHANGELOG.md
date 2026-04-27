# Changelog

All notable changes to this project are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-04-27

Initial release.

### Drop-in for `std::arch::is_aarch64_feature_detected!`

This crate ships an `is_aarch64_feature_detected_fast!` macro with the *same
name*, *same dashed feature spelling*, and *same call shape* as std's,
namespaced by crate path. Migration from std is a one-line import swap.

```diff
-use std::arch::is_aarch64_feature_detected;
+use winarm_cpufeatures::is_aarch64_feature_detected_fast;
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
- **Registry layer (opt-in via Cargo feature).** Behind the `registry`
  Cargo feature, which links the `HKLM\…\CentralProcessor\0\CP <hex>`
  `ID_AA64*_EL1` decoder. When that feature is on, the registry is
  consulted by default — sandboxed callers can opt out with
  `set_registry_enabled(false)`. Covers ~30 stdarch feature names IPFP
  cannot reach.
- **Zero deps.** Win32 entry points (`IsProcessorFeaturePresent`, plus
  `RegOpenKeyExW` / `RegGetValueW` / `RegCloseKey` under `registry`)
  are declared inline in `src/windows/sys.rs` instead of pulling in
  `windows-sys`. Saves ~1.5s of clean-build time on Windows aarch64
  and keeps the dependency graph trivial to audit.
- **Std passthrough (non-Windows aarch64).** Macros expand directly to
  `std::arch::is_aarch64_feature_detected!`. No added cache layer; std's
  internal HWCAP cache amortizes. Future stdarch additions Just Work
  without any winarm-cpufeatures update.
- **Always-false stub (non-aarch64).** Every documented name returns
  `false`. Lets cross-platform code use one spelling. Unknown names
  produce a `compile_error!` so typos surface on any host.

### Compile-time design

- Macros use direct `macro_rules!` arm dispatch. Each call site expands
  to one function call (Windows aarch64) or one std-macro invocation
  (non-Windows aarch64) — no const-eval, no per-site string-compare,
  no `panic!`-based assertions. Compile-time cost matches calling
  `std::arch::is_aarch64_feature_detected!` directly.
- No build script.

### Cargo features

- `registry` — link the `HKLM\…\CentralProcessor\0\CP <hex>` registry
  decoder. Off by default. When enabled, the registry path is
  consulted by default at runtime; suppress with
  `set_registry_enabled(false)` for sandboxed processes.
- `nightly-sve` — enable the SVE execution test
  (`tests/sve_execution.rs`). Test-only.

### Windows-aarch64-first scope

This crate exists to fill the Windows-on-ARM gap. On non-Windows
aarch64 we passthrough to `std::arch::is_aarch64_feature_detected!`
unmodified — std handles those targets correctly already, and unstable
feature names (the 32 names std gates behind
`#![feature(stdarch_aarch64_feature_detection)]`) require the user's
own nightly + feature gate, same as calling std directly. Drop-in
import works for stable feature names; for unstable names on
non-Windows aarch64, use std with its own gate.

On Windows aarch64 we own the dispatch: cache-based detection covers
the full 73 names (regardless of rustc channel), filling in what
Microsoft's `IsProcessorFeaturePresent` and the upcoming
[rust-lang/rust#155856](https://github.com/rust-lang/rust/pull/155856)
can't yet reach. A `winarm_is_superset_of_std_on_windows` test
asserts that whenever std reports a feature present, winarm also
reports it — the invariant holds today and continues to hold after
that PR lands stable.

### Public API (docs-visible)

- `is_aarch64_feature_detected_fast!(name)` — fast (IPFP-only)
  single-feature check; matches std's behavior on Windows.
- `Features::current_full()` — full snapshot. On Windows aarch64 with
  `registry`, includes registry-decoded features that IPFP can't see.
  One snapshot, then any number of `.has(Feature::*)` bit tests —
  better codegen for multi-feature checks.
- `Features` snapshot struct: `EMPTY`, `current()`, `current_full()`,
  `has(Feature)`, `iter()`.
- `Feature` enum (73 variants), with `name()` and `all()`.
- `set_registry_enabled(bool)`.
