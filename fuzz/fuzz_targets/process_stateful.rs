#![no_main]
//! Tier-2 / Target A — STATEFUL: a (libFuzzer-mutated) VALID MLS message into process_message on a live
//! group. Unlike Tier-1 (raw bytes → parser, libcrux never runs), this DECRYPTS: HPKE + ChaCha20Poly1305
//! + ML-KEM decap + Ed25519 — exactly the libcrux paths the Route-2 bump fixed. Seeded with two valid
//! templates (a Commit + an Application message at bob's epoch-1); libFuzzer mutates them toward the
//! semi-valid inputs that reach deep into the crypto.
//!
//! Per-iteration isolation: a FRESH bob is rebuilt from a frozen fixture blob each run (process_message
//! mutates state), so the same input always drives the same path → a crash reproduces.
//!
//! Invariants (driven OUTSIDE the Contract-1 guard so a crash reaches ASAN):
//!   1. NO-PANIC / NO-UB — any input → Ok/Err, never a panic/OOB/overflow (overflow-checks + debug-assert
//!      are baked into the fuzz release profile).
//!   2. FAIL-CLOSED (auditor Q4) — on Err, bob's full group_state fingerprint is byte-identical
//!      before/after: a rejected message must NEVER advance membership state.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    kvant_mls::fuzz_api::process_stateful(data);
});
