> **Part of [Kvant](https://github.com/shamsuarov/kvant-crypto-core).** Open source, in
> part so the cryptography can be audited independently. Licensed under the
> Apache License 2.0 — see [LICENSE](LICENSE).

# kvant-mls — M1 FFI spike (OpenMLS + libcrux, X-Wing 0x004D)

**Spike goal (NOT integration):** prove OpenMLS + libcrux cross-compiles & runs on Android ARM,
measure REAL Commit/Welcome bytes + latency **on-device**, and demonstrate **KSE1 storage-at-rest**.
This is the entry gate before the M2 membership work.

## Boundary (the rule)
OpenMLS/libcrux owns **ALL** MLS crypto — HPKE, the **X-Wing KEM**, TreeKEM, key schedule,
signatures, AEAD. This crate + the Kotlin/JS layers do **ZERO** KEM/crypto operations; they only
orchestrate the spike and marshal opaque bytes. The only crypto *we* do is the **KSE1 at-rest
envelope** that protects OpenMLS's on-disk secrets (ratchet tree + group context = group secrets).
`crypto-core/xwing.js` (M0) was throwaway feasibility recon — discarded, never shipped, never wired.

## Build flow
1. **Toolchain** (once): `rustup` + `rustup target add aarch64-linux-android x86_64-linux-android` +
   `cargo install cargo-ndk uniffi-bindgen` + `ANDROID_NDK_HOME`.
2. **Host build first** — `cargo build --release` from this dir. This resolves deps and is where you
   **confirm the pinned OpenMLS release exposes the X-Wing ciphersuite (0x004D)** and fix any API
   drift in `Cargo.toml`/`src/lib.rs` (the versions there are best-effort; commit `Cargo.lock` once
   it resolves). Send build errors back for correction.
3. **Cross-compile + bindings** — `scripts/build-mls-aar.ps1`: cargo-ndk → `app/src/main/jniLibs/{arm64-v8a,x86_64}/libkvant_mls.so`, uniffi Kotlin bindings → source set, and installs `KvantMlsModule.kt`.
4. **Register + build APK** — add `KvantMlsModule(reactContext)` to `ScreenSecurityPackage.kt`, build a **separate spike APK** (keep it OUT of the 53c7fea+L1 retest).
5. **Measure on-device** — Diagnostics screen → **MLS spike** → runs the sweep (N = 2,16,128,512,1000;
   product cap 500, headroom to 1000) on the Zenfone 9 + S10+; reports Commit/Welcome bytes + latency
   (libcrux-on-device, not JS extrapolation) and the KSE1 at-rest round-trip.

## Files
- `Cargo.toml` — pinned deps (verify/adjust at first build).
- `src/lib.rs` — uniffi surface: `mls_ciphersuite_info()`, `mls_measure(n, dir, kek)`; KSE1 seal/open;
  the OpenMLS flow is laid out as commented pseudocode to fill against the real 0.6 API.
- `scripts/build-mls-aar.ps1` — cross-compile + bindgen + install module.
- `android/KvantMlsModule.kt` — RN bridge template (installed into the source set by the script).
- JS: `app-rn/src/mlsSpike.ts` + the Diagnostics "MLS spike" button (no-op until the .aar exists).

## Design notes carried into M2 (not this spike)
- Group cap **500** + protocol-version live in a **signed `GroupContext` extension** (authenticated
  state, not a client flag) — like protocol-version.
- StorageProvider: per-value encrypted provider (KSE1) with a **stable Keystore KEK**
  (`com.kvant.mlskek`), added to the emergency-wipe (Bug-1) clear path. (Spike uses a per-call KEK.)
- FFI is the historical bug zone → M2 adds adversarial tests (malformed Welcome/Commit → fail-closed).
- M5 Sender-Keys→MLS migration = the critical downgrade surface (one-way, authenticated, no fallback).
