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

Ships a drop-in `detected!` macro that returns the correct answer on Windows. Detection strategy:

1. **`IsProcessorFeaturePresent`** using all `PF_ARM_*` constants through SDK 26100 — covers the ~30 features Microsoft does expose (including the SVE/SME family added in Windows 11 24H2).
2. **Registry `CP <hex>` parsing** — reads `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0\CP 4030` etc., which are cached AArch64 ID register snapshots (`ID_AA64ISAR0/1/2_EL1`, `ID_AA64PFR0/1_EL1`, `ID_AA64MMFR0/1/2/3_EL1`). Same undocumented-but-stable approach used by LLVM, pytorch/cpuinfo, and Microsoft's own ONNX Runtime.
3. **Platform baseline override** for `rdm` — Windows 11 on ARM mandates ARMv8.1-A, which guarantees FEAT_RDM.

On non-Windows platforms, `detected!` delegates directly to `std::arch::is_aarch64_feature_detected!` — no added logic, no overhead.

## Usage

```rust
use winarm_cpufeatures::detected;

if detected!("rdm") {
    // safe to use vqrdmlahq_s16 etc.
}

if detected!("bf16") {
    // safe to use bfdot
}
```

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
