#![no_main]
//! Tier-1 / target 1 — our OWN identity parser `decode_identity` (bounded reader, exact-consumption).
//! First and cheapest target, highest bug density (the auditor's ordering). Driven OUTSIDE the Contract-1
//! `guard` (catch_unwind) via `fuzz_api::fuzz_decode_identity`, so any panic / OOB / overflow reaches the
//! sanitizer instead of being swallowed into a typed MlsError.
//!
//! Invariants checked (see lib.rs::fuzz_api):
//!   - NO-PANIC: every byte string returns None or Some, never panics / OOBs (oversized length-prefix
//!     fails closed without ~4 GiB allocation — the no-amplification property).
//!   - CANONICAL: any accepted input re-encodes to itself (no ambiguous parse).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    kvant_mls::fuzz_api::fuzz_decode_identity(data);
});
