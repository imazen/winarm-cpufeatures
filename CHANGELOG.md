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
- **Registry layer (opt-in via Cargo feature).** Behind the `registry`
  Cargo feature, which links the `HKLM\…\CentralProcessor\0\CP <hex>`
  `ID_AA64*_EL1` decoder. When that feature is on, the registry is
  consulted by default — sandboxed callers can opt out with
  `set_registry_enabled(false)`. Covers ~30 stdarch feature names IPFP
  cannot reach.
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
- No build script. Nightly opt-in for the 32 unstable stdarch feature
  names is via an explicit `nightly-stdarch` Cargo feature; stable
  users get the 41 stable names without build-script overhead.

### Cargo features

- `registry` — link the `HKLM\…\CentralProcessor\0\CP <hex>` registry
  decoder. Off by default. When enabled, the registry path is
  consulted by default at runtime; suppress with
  `set_registry_enabled(false)` for sandboxed processes.
- `nightly-stdarch` — opt into
  `#![feature(stdarch_aarch64_feature_detection)]` so non-Windows
  aarch64 targets can detect the 32 unstable stdarch names. Requires
  nightly rustc.
- `nightly-sve` — enable the SVE execution test
  (`tests/sve_execution.rs`).

### Relationship to upstream std

The macros do not reject names std accepts. On non-Windows aarch64,
both `is_aarch64_feature_detected!` and `is_aarch64_feature_detected_full!`
are a single-arm `:tt` passthrough to `std::arch::is_aarch64_feature_detected!` —
std validates names and dispatches. New stdarch additions (e.g. via
[rust-lang/rust#155856](https://github.com/rust-lang/rust/pull/155856),
which adds Windows IPFP coverage for `fp16`/`bf16`/`i8mm`/`lse2`/
`sha3`/`f32mm`/`f64mm`/`rdm`) are picked up automatically without any
winarm-cpufeatures update.

A `winarm_is_superset_of_std_on_windows` test in `tests/name_parity.rs`
asserts the invariant: any feature std reports present on Windows
ARM64, winarm must also report present. Holds today and continues to
hold once that PR lands stable.

### Public API (docs-visible)

- `is_aarch64_feature_detected!(name)` — fast detection.
- `is_aarch64_feature_detected_full!(name)` — full detection (Windows
  aarch64 with `registry` adds registry-decoded features).
- `Features` snapshot struct: `EMPTY`, `current()`, `current_full()`,
  `has(Feature)`, `iter()`.
- `Feature` enum (73 variants), with `name()` and `all()`.
- `set_registry_enabled(bool)`.
