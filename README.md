# winarm-cpufeatures ![CI](https://img.shields.io/github/actions/workflow/status/imazen/winarm-cpufeatures/ci.yml?style=flat-square&label=CI) ![crates.io](https://img.shields.io/crates/v/winarm-cpufeatures?style=flat-square) [![lib.rs](https://img.shields.io/crates/v/winarm-cpufeatures?style=flat-square&label=lib.rs&color=blue)](https://lib.rs/crates/winarm-cpufeatures) ![docs.rs](https://img.shields.io/docsrs/winarm-cpufeatures?style=flat-square) ![license](https://img.shields.io/crates/l/winarm-cpufeatures?style=flat-square)

AArch64 CPU feature detection that fills the Windows-on-ARM gap in `std::arch::is_aarch64_feature_detected!`.

## The gap

On Windows aarch64, Rust's `is_aarch64_feature_detected!` is a thin wrapper around `IsProcessorFeaturePresent`. As of stable Rust 1.85 it only wires ~10 features. On Windows ARM hardware these all report `false` despite being physically present:

```
rdm, fp16, fhm, fcma, bf16, i8mm, frintts, sha3, sha512, sm4,
rcpc2, rcpc3, paca, pacg, flagm, flagm2, dpb, dpb2, lse2, lse128,
sve, sve2, sve2-aes, sve2-bitperm, sve2-sha3, sve2-sm4, sve2p1,
sve-b16b16, sme, sme2, sme2p1, ...
```

[rust-lang/rust#155856](https://github.com/rust-lang/rust/pull/155856) closes 8 of those. The remaining ~25 (the registry-decoded ones — `paca`, `bti`, `dpb`, `flagm`, `mte`, `mops`, the FP8 family, etc.) are why this crate exists.

## What this crate does

- **On Windows aarch64**: detects all 73 stdarch feature names, including the 32 std flags as nightly-only, on **stable Rust** without any feature gate. Probes every `PF_ARM_*` constant in Windows SDK 26100, derives RDM via the same DP/LSE inference .NET 10 uses, and (with `--features registry`) decodes the `HKLM\…\CentralProcessor\0\CP <hex>` `ID_AA64*_EL1` snapshots Windows publishes — same undocumented-but-stable approach LLVM, pytorch/cpuinfo, and Microsoft's own ONNX Runtime use.
- **On non-Windows aarch64**: macros are a pure passthrough to `std::arch::is_aarch64_feature_detected!`. Std handles those targets correctly already; we add nothing. Stable feature names work; the 32 unstable names need the user's own nightly + `#![feature(stdarch_aarch64_feature_detection)]`, same as if you used std directly.
- **On non-aarch64**: every documented name returns `false`. Lets cross-platform code use one spelling.

## Drop-in for std

Same name, same dashed feature spelling (`sve2-aes`, `sme-fa64`, `pauth-lr`, …), same call shape:

```diff
-use std::arch::is_aarch64_feature_detected;
+use winarm_cpufeatures::is_aarch64_feature_detected;
```

Every existing call site stays unchanged.

```rust
use winarm_cpufeatures::is_aarch64_feature_detected;

if is_aarch64_feature_detected!("rdm") { /* vqrdmlahq_s16 etc. */ }
if is_aarch64_feature_detected!("bf16") { /* bfdot */ }
if is_aarch64_feature_detected!("sve")  { /* SVE kernel */ }
```

Or the struct-style API for batched checks:

```rust
use winarm_cpufeatures::{Features, Feature};

let f = Features::current();
if f.has(Feature::Bf16) && f.has(Feature::I8mm) {
    // Armv8.6 dot-product path
}
```

## Two macros

| Macro | What it reads on Windows aarch64 |
|---|---|
| `is_aarch64_feature_detected!` | IPFP-only cache. Names IPFP can't see (`paca`, `bti`, `dpb`, `flagm`, `mte`, `fhm`, `fcma`, `frintts`, `sm4`, …) silently return `false`, matching std's behavior. |
| `is_aarch64_feature_detected_full!` | IPFP + registry cache (when `--features registry` is on). Covers the ~25 names IPFP can't reach. |

On non-Windows aarch64 and non-aarch64 the two macros behave identically.

## Cargo features

- `registry` — links the `HKLM\…\CentralProcessor\0\CP <hex>` registry decoder. Off by default. When enabled, the registry path is consulted automatically; sandboxed processes can opt out with `set_registry_enabled(false)`.
- `nightly-sve` — enables `tests/sve_execution.rs` (verifies SVE detection against actually executing an SVE instruction). Test-only; requires nightly rustc.

## Compile-time cost

Calling our macro is the same cost as calling std's. Measured at 0.16s for 480 invocations on aarch64-pc-windows-msvc — identical to `std::arch::is_aarch64_feature_detected!` within noise. See `contrib/compile-bench/`.

## MSRV

Rust 1.85.

## License

Dual-licensed under MIT or Apache-2.0.
