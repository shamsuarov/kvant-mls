# kvant-mls fuzzing — Tier-1 (deserialize-only)

The cheapest, highest-bug-density surface: drive the **raw deserializers** on arbitrary bytes and prove
the invariant

> any malformed / truncated / oversized input → a typed `MlsError` / `tls_codec` error / `None`,
> **never** a panic, abort, OOB, or UB.

Each target runs the parser **outside** the Contract-1 `catch_unwind` guard so a panic/UB/OOB reaches the
sanitizer instead of being swallowed into a typed error (the guard's panic→typed-error conversion is
proven separately by the unit tests `guard_converts_panic_to_typed_error` / `…passes_ok_and_err…`).

## Targets

| target              | what it deserializes                          | covers |
|---------------------|-----------------------------------------------|--------|
| `decode_identity`   | our identity parser (`as_validate::decode_identity`), bounded + exact-consumption | account-id ∥ device-cert wire; no-amplification; canonical/round-trip oracle |
| `mls_message_in`    | `MlsMessageIn::tls_deserialize_exact`          | **Welcome / Commit / Application / GroupInfo** (all arrive as an MlsMessageIn body) — historical MLS/HPKE/codec bugs |
| `key_package_in`    | `KeyPackageIn::tls_deserialize_exact`          | the Add path: a peer KeyPackage on the wire |

Tier-2 (stateful: feed bytes into `process_message` over a valid group fixture) is a **separate** crate,
added after Tier-1 reaches its exit criteria.

## Where it runs — WSL, not Windows

cargo-fuzz / libFuzzer need `-Zsanitizer` (nightly) and a Unix sanitizer runtime; the Windows MSVC
toolchain can't, and **MSAN is Linux-only**. Use the WSL2 Ubuntu box. No sudo/apt is required — ASAN's
runtime ships inside rustc-nightly and libFuzzer builds from `libfuzzer-sys` with the already-present g++.

```bash
# from Windows, enter the fuzz dir inside WSL:
wsl -d Ubuntu
cd /mnt/c/Users/<you>/kvant/app-rn/android/kvant-mls/fuzz

./bootstrap-wsl.sh         # one-time: rustup + nightly + rust-src + cargo-fuzz  (no sudo)
./run.sh mls_message_in    # ~25s ASAN smoke run, seeded from corpus/
./run.sh decode_identity
./run.sh key_package_in
```

## Sanitizers (honest mapping)

Rust has **no standalone UBSAN** like C. The auditor's "ASAN+UBSAN primary" maps to:

- **ASAN** — `-Zsanitizer=address` (cargo-fuzz default). Memory safety: OOB, use-after-free, etc.
- **UB-equivalent** — `overflow-checks = true` + `debug-assertions = true` (baked into
  `Cargo.toml [profile.release]`): integer-overflow and internal `debug_assert!`s become crashes instead
  of silent wraps/no-ops. This is the practical UBSAN substitute for Rust.

- **MSAN (targeted, later — NOT in the smoke run)** — `-Zsanitizer=memory`. The auditor's guidance:
  run MSAN **only** on a **portable / no-asm libcrux build** (the AVX2 asm trips MSAN false-positives),
  matched to the device code-path by the on-device KAT. Tier-1 deserialize never executes libcrux, so
  MSAN is viable here once a portable build is wired:
  ```bash
  # portable libcrux (disable AVX2) + MSAN; build std too (-Zbuild-std handled by cargo-fuzz)
  RUSTFLAGS="-C target-feature=-avx2,-avx,-sse4.2" \
    cargo +nightly fuzz run --sanitizer memory mls_message_in -- -max_total_time=25
  ```

## No-amplification

A `0xFFFFFFFF` length-prefix on a short buffer must fail closed **without** pre-allocating ~4 GiB. Proven
as a unit test (`no_amplification_oversized_length_prefix_returns_none`) and seeded as `b_oversized_len.bin`
in every corpus. The bounded reader validates `end > len` before it slices/allocates.

## Seed corpus

`corpus/<target>/` holds **real** valid wire bytes (the mutation set — identity, commit, welcome,
app-message, KeyPackage, produced by the real libcrux X-Wing stack) **plus** manual boundary cases
(empty, magic-only, oversized length-prefix, all-ones). Regenerate with:

```powershell
# on the Windows host (host build is green):
cargo test -p kvant-mls emit_fuzz_seeds -- --ignored --nocapture
```

## Exit criteria (the long campaign — run separately)

- **Coverage plateau**: ~24h with no new edges (`cov: …` in libFuzzer stats stops growing).
- **Crash-free**: 48h on the FINAL build, or a `≥1e9` execs floor — whichever is reached.
- **Re-run after EVERY fix** (a fix changes the reachable state space).

Long run (per target), unbounded, detached:
```bash
tmux new -s fuzz-mls
./run.sh mls_message_in 0      # max_total_time=0 → runs until stopped
# Ctrl-b d to detach; crashes land in artifacts/<target>/crash-*
```
