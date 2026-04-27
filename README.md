# winarm-cpufeatures ![CI](https://img.shields.io/github/actions/workflow/status/imazen/winarm-cpufeatures/ci.yml?style=flat-square&label=CI) ![crates.io](https://img.shields.io/crates/v/winarm-cpufeatures?style=flat-square) [![lib.rs](https://img.shields.io/crates/v/winarm-cpufeatures?style=flat-square&label=lib.rs&color=blue)](https://lib.rs/crates/winarm-cpufeatures) ![docs.rs](https://img.shields.io/docsrs/winarm-cpufeatures?style=flat-square) ![license](https://img.shields.io/crates/l/winarm-cpufeatures?style=flat-square)

AArch64 CPU feature detection that fills the Windows-on-ARM gap in `std::arch::is_aarch64_feature_detected!`.

## The problem

Rust's `is_aarch64_feature_detected!` on Windows ARM64 is a thin wrapper around `IsProcessorFeaturePresent`. Microsoft only exposes ~17 `PF_ARM_*` constants, so on **1.85**, the Windows backend probes exactly 10 features out of the 73 the macro accepts. On Windows-on-ARM Neoverse N2 hardware (same silicon as Linux ARM CI runners), these all report `false` despite being physically present:

```
rdm, fp16, fhm, fcma, bf16, i8mm, frintts, sha3, sha512, sm4,
rcpc2, rcpc3, paca, pacg, flagm, flagm2, dpb, dpb2, lse2, lse128,
sve, sve2, sve2-aes, sve2-bitperm, sve2-sha3, sve2-sm4, sve2p1,
sve-b16b16, sme, sme2, sme2p1, ...
```

## What this crate does

Ships a drop-in `is_aarch64_feature_detected!` macro — same name, same dashed feature spelling, same call shape as std's. Detection strategy:

1. **`IsProcessorFeaturePresent`** using every `PF_ARM_*` constant through Windows SDK 26100 — covers the ~30 features Microsoft does expose, including the SVE/SME family added in Windows 11 24H2.
2. **Registry `CP <hex>` parsing** (opt-in via the `registry` Cargo feature; on by default at runtime when that feature is enabled, suppressible with `set_registry_enabled(false)`) — reads `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0\CP 4030` etc., the AArch64 `ID_AA64*_EL1` snapshots Windows publishes. Same undocumented-but-stable approach used by LLVM, pytorch/cpuinfo, and Microsoft's own ONNX Runtime.
3. **DP/LSE → RDM architectural inference** — Windows-on-ARM mandates ARMv8.1-A, which guarantees FEAT_RDM; matches what .NET 10 ships (`dotnet/runtime#109493`).

On non-Windows aarch64 targets, `is_aarch64_feature_detected!` expands directly to `std::arch::is_aarch64_feature_detected!` — no added cache layer, no overhead, no rejected-name footgun. Future stdarch additions Just Work without crate updates. On non-aarch64 targets the macro returns `false` for any known aarch64 feature name (whereas std's macro doesn't compile there at all), so cross-platform code can use one spelling everywhere.

### Relationship to upstream std

[rust-lang/rust#155856](https://github.com/rust-lang/rust/pull/155856) ("std_detect: support detecting more features on aarch64 Windows") wires 8 of the names this crate already covers (`fp16`, `bf16`, `i8mm`, `lse2`, `sha3`, `f32mm`, `f64mm`, plus the same DP/LSE→RDM inference for `rdm`) into std itself. Once that lands stable, std and this crate agree on those names on Windows. This crate's remaining value-add is the registry-decoded layer covering the ~25 names Microsoft has never exposed via `IsProcessorFeaturePresent` — `paca`, `pacg`, `bti`, `dpb`, `dpb2`, `mte`, `mops`, `flagm`, `flagm2`, `dit`, `sb`, `ssbs`, `rand`, `cssc`, `wfxt`, `hbc`, `lut`, `faminmax`, `rcpc2`, `rcpc3`, `pauth-lr`, `lse128`, `sm4`, `fhm`, `fcma`, `frintts`, plus the FP8 family.

## Usage

```rust
use winarm_cpufeatures::is_aarch64_feature_detected;

if is_aarch64_feature_detected!("rdm") {
    // safe to use vqrdmlahq_s16 etc.
}

if is_aarch64_feature_detected!("bf16") {
    // safe to use bfdot
}
```

Migrating from `std::arch::is_aarch64_feature_detected!` is a one-line change:

```diff
-use std::arch::is_aarch64_feature_detected;
+use winarm_cpufeatures::is_aarch64_feature_detected;
```

Every existing call site stays the same. Feature names match std's spelling exactly (dashes, not underscores: `sve2-aes`, `sme-fa64`, `pauth-lr`, …).

Or the struct-style API for batched checks:

```rust
use winarm_cpufeatures::{Features, Feature};

let f = Features::current();
if f.has(Feature::Bf16) && f.has(Feature::I8mm) {
    // Armv8.6 dot-product path
}
```

## MSRV

Rust 1.85.

## License

Dual-licensed under MIT or Apache-2.0.
