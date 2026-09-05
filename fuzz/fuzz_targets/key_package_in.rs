#![no_main]
//! Tier-1 / target 3 — the Add path: a peer's KeyPackage as it arrives on the wire.
//!
//! `KeyPackageIn` is the UNVERIFIED parsed form (signature / capability / leaf validation happens later,
//! in as_validate); the deserialization itself is the attack surface here — leaf-node extensions, the
//! credential, the HPKE init key, and the signature are all length-prefixed sub-structures with their own
//! historical codec edge cases.
//!
//! Invariant: any malformed / truncated / oversized input → a typed `tls_codec` error, NEVER a panic /
//! abort / OOB / UB.
use libfuzzer_sys::fuzz_target;
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;

fuzz_target!(|data: &[u8]| {
    let _ = KeyPackageIn::tls_deserialize_exact(data);
});
