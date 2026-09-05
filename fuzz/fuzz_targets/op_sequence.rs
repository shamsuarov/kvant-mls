#![no_main]
//! Tier-2 / Target B — STATEFUL op-sequence: the fuzz input is a tiny PROGRAM over three real X-Wing
//! members (alice/bob/carol). Each byte selects an operation (app send/recv, add carol, remove carol,
//! consistency probe). State is rebuilt from scratch per input, so iterations are naturally isolated.
//!
//! Exercises libcrux end to end (every op = real MLS crypto — costlier than Target A, run with fewer
//! workers). Hunts logical/state bugs that a single-message target can't reach:
//!   • CONSISTENCY — after both parties apply a commit, member sets + epochs must agree (no divergence).
//!   • PCS — once carol is removed, she must NEVER decrypt a new-epoch message.
//! Any invariant break is an assert → a crash for libFuzzer to minimize.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    kvant_mls::fuzz_api::op_sequence(data);
});
