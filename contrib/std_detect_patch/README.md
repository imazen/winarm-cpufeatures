# Local std_detect patch — Windows AArch64

Drop-in replacement for the file rust nightly ships at:

```
library/std_detect/src/detect/os/windows/aarch64.rs
```

Result: `std::arch::is_aarch64_feature_detected!(...)` returns the correct
answer on Windows-on-ARM for the ~50 feature names IPFP currently misses
(rdm, fp16, fhm, fcma, bf16, i8mm, paca/pacg, frintts, dpb/dpb2, flagm/flagm2,
sha3, sm4, mte, bti, ssbs, dit, sb, lse2, rcpc2, rcpc3, rand, mops, hbc, cssc,
wfxt, sme, …) — using the same registry-cached `ID_AA64*_EL1` snapshots
LLVM (PR #151596), pytorch/cpuinfo, and ONNX Runtime already use.

## Design constraints

- **No regex.** Each `CP <hex>` value name (`"CP 4030"`, `"CP 4031"`, …) is
  read by exact name with `RegGetValueW(RRF_RT_REG_QWORD)`. No enumeration,
  no string matching.
- **No OS version checks.** The CP keys have been kernel-populated since
  Windows 10 1709 on every Windows-on-ARM SKU. Missing entries silently
  contribute zero feature bits — behaviour degrades gracefully back to the
  IPFP-only answer on hypothetical builds where the kernel skips them.
- **No `extern crate` additions.** All Win32 types/constants are declared
  inline, mirroring how the existing `aarch64.rs` already handles
  `IsProcessorFeaturePresent`. `std_detect` continues to depend on nothing
  beyond `core` + `alloc`.
- **No allocation.** Wide-string buffers are stack arrays sized at
  compile-time (`[u16; 16]` for value names, `[u16; 48]` for the subkey).
- **All `unsafe` is at FFI boundaries** with explicit `// SAFETY:` comments
  covering pointer validity, ownership of out-parameters, and the
  `RRF_RT_REG_QWORD` size invariant.
- **Heterogeneous big.LITTLE:** reads `CentralProcessor\0`, matching what
  `IsProcessorFeaturePresent` already reports (boot CPU). Windows-on-ARM
  scheduling guarantees every core supports the architectural baseline of
  CPU 0, so the answer is at-least-correct system-wide.

## Comparison to upstream LLVM precedent

LLVM's `llvm/lib/TargetParser/Host.cpp` Windows-AArch64 path
([PR #151596](https://github.com/llvm/llvm-project/pull/151596), merged Aug
2025) takes the same approach: open `CentralProcessor\0`, read named CP
values directly, decode the ID-register fields. The only divergence: LLVM
also enumerates `CentralProcessor\1..N` to pick a "primary" core for
heterogeneous packages. We don't — IPFP doesn't either, so this preserves
existing semantics; if upstream wants big.LITTLE primary-selection later,
it can layer on top of this.

## How to apply

### Option A — quick local override (one nightly toolchain)

```bash
TOOLCHAIN=$(rustc +nightly --print sysroot)
TARGET="$TOOLCHAIN/lib/rustlib/src/rust/library/std_detect/src/detect/os/windows/aarch64.rs"
cp "$TARGET" "$TARGET.orig"   # back up
cp aarch64.rs "$TARGET"
```

Then build with `-Z build-std=std,panic_abort`:

```bash
cargo +nightly build -Z build-std=std,panic_abort \
    --target aarch64-pc-windows-msvc
```

(You need `rustup component add rust-src --toolchain nightly` first if you
don't already have the source tree.)

### Option B — clone rust-lang/rust and apply

1. `git clone https://github.com/rust-lang/rust && cd rust`
2. Replace `library/std_detect/src/detect/os/windows/aarch64.rs` with
   `aarch64.rs` from this directory.
3. `./x.py build library/std --target aarch64-pc-windows-msvc`
4. `rustup toolchain link patched build/host/stage1`

### Option C — submit upstream

This is what should ultimately happen. The patch is structured to make a
PR straightforward: it's a single file replacement, alloc-free, no new
dependencies, and the existing IPFP probes are preserved verbatim. Open
issue: rust-lang/rust#127764 (the parent tracking issue for
`stdarch_aarch64_feature_detection`).

## Local type-check sandbox

`_check/` is a tiny no-ship helper crate that mocks the
`crate::detect::cache::Initializer` + `Feature` API and `#[path]`-includes
`aarch64.rs`. Build it to confirm the patch type-checks against the
expected std_detect surface:

```bash
cargo build --target aarch64-pc-windows-msvc \
    --manifest-path _check/Cargo.toml
cargo clippy --target aarch64-pc-windows-msvc \
    --manifest-path _check/Cargo.toml -- -D warnings
```

Both pass clean today on rustc 1.92.0-nightly with target
`aarch64-pc-windows-msvc`.

## What's left for a real upstream PR

- **Cross-validate field decoding** against running hardware. The
  `winarm-cpufeatures` crate tests that exercise the same decode logic on
  Neoverse N2 / V2 / Snapdragon X (`tests/hardware_assertions.rs`) should
  be ported into a `library/std_detect/tests/aarch64-windows.rs` harness
  and CI'd on the GitHub `windows-11-arm` runner.
- **arm64ec target.** The dispatch table already routes both `aarch64` and
  `arm64ec` Windows targets to this file. The IPFP path works on arm64ec;
  the registry path does too (same kernel, same CP keys). No additional
  cfg gates needed.
- **Add the SDK-26100 PF_ARM constants Microsoft has not yet published
  numeric values for** (PF_ARM_SME / SME2 / SME2_1, PF_ARM_V86_BF16,
  PF_ARM_V82_I8MM, PF_ARM_V84_LSE2, PF_ARM_V82_FP16). These would let us
  drop the corresponding registry decodes once verified against an
  authoritative `winnt.h`. Until then, the registry path is the only
  reliable source for those names.
