#![no_main]
//! Tier-1 / target 2 — OpenMLS WIRE deserialization of an incoming MLS message.
//!
//! A Welcome, a Commit (PublicMessage), an Application message (PrivateMessage), and a GroupInfo all
//! arrive on the wire as an `MlsMessageIn` body — so this single target covers the Welcome wire-decode the
//! auditor listed. Historical MLS / HPKE / codec bugs live exactly in this deserialization. Pure parse:
//! stateless, no crypto provider, no group fixture (that's Tier-2).
//!
//! Invariant: any malformed / truncated / oversized input → a typed `tls_codec` error, NEVER a panic /
//! abort / OOB / UB. The exact-consumption variant (`tls_deserialize_exact`) also rejects trailing bytes,
//! matching the production dispatch path (dispatch.rs).
use libfuzzer_sys::fuzz_target;
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;

fuzz_target!(|data: &[u8]| {
    let _ = MlsMessageIn::tls_deserialize_exact(data);
});
