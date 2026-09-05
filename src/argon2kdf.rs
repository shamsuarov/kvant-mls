//! argon2kdf.rs — audit A-5: NATIVE Argon2id for the app-lock passcode verifier (app-rn/src/pinkdf.js).
//!
//! WHY HERE. pinkdf.js has had Argon2id (RFC 9106) fully wired since the forensic-hardening pass, but
//! OFF: the pure-JS @noble implementation runs on Hermes (no JIT) at ~13 s per login, which is why
//! PBKDF2 already went native. This crate is the app's existing Rust→Kotlin bridge (uniffi + cargo-ndk),
//! so a native Argon2id rides on the same .so with no new build pipeline. It is a SEPARATE module from
//! the frozen MLS/messaging crypto in this crate: nothing here touches MlsClient, KSE1 or the
//! ciphersuite code — it shares only the library file and the FFI scaffolding.
//!
//! CONTRACT (interop): output MUST be byte-identical to @noble/hashes argon2id(password, salt,
//! {m, t, p, dkLen}) — Argon2id, version 0x13, no secret, no associated data — so a record made by
//! the JS fallback (Node tests, a build without this .so) verifies natively and vice versa. Pinned
//! by the host test below (vector produced with @noble on the same params) and by the RFC 9106 §5.3
//! reference vector for the algorithm itself.
//!
//! The app-lock passcode gates the app-lock ONLY (the data key lives in the AndroidKeyStore); this
//! KDF hardens the stored VERIFIER against offline brute force after extraction (memory-hard ⇒ no
//! cheap GPU/ASIC parallelism), it is not a data-encryption key.

use argon2::{Algorithm, Argon2, Params, Version};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum Argon2Error {
    #[error("argon2 params rejected: {0}")]
    Params(String),
    #[error("argon2 derivation failed: {0}")]
    Hash(String),
}

/// Argon2id(password UTF-8, salt, m_kib, t, p) → dk_len bytes. Bounds are the argon2 crate's own
/// (m ≥ 8·p KiB, t ≥ 1, 1 ≤ p ≤ 2^24, 4 ≤ dk_len). Cost policy (floors) lives in pinkdf.js.
#[uniffi::export]
pub fn argon2id_derive(
    password: String,
    salt: Vec<u8>,
    m_kib: u32,
    t: u32,
    p: u32,
    dk_len: u32,
) -> Result<Vec<u8>, Argon2Error> {
    let params = Params::new(m_kib, t, p, Some(dk_len as usize))
        .map_err(|e| Argon2Error::Params(e.to_string()))?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; dk_len as usize];
    a.hash_password_into(password.as_bytes(), &salt, &mut out)
        .map_err(|e| Argon2Error::Hash(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

    /// RFC 9106 §5.3 Argon2id reference vector — but that vector uses secret + associated data, which
    /// the app-lock path (and @noble's default) never sets. So the algorithm KAT is done with the
    /// crate's own secret/ad-capable API, proving the crate is a conformant Argon2id; the interop
    /// vector below proves OUR export matches @noble on the app's parameters.
    #[test]
    fn rfc9106_argon2id_reference_vector() {
        let mut b = argon2::ParamsBuilder::new();
        b.m_cost(32).t_cost(3).p_cost(4).output_len(32);
        b.data(argon2::AssociatedData::new(&[0x04u8; 12]).unwrap());
        let params = b.build().unwrap();
        let a = Argon2::new_with_secret(&[0x03u8; 8], Algorithm::Argon2id, Version::V0x13, params).unwrap();
        let mut out = [0u8; 32];
        a.hash_password_into(&[0x01u8; 32], &[0x02u8; 16], &mut out).unwrap();
        assert_eq!(hex(&out), "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
    }

    /// Interop vector: @noble/hashes argon2id("1234", salt=00112233445566778899aabbccddeeff, m=12288,
    /// t=3, p=1, dkLen=32) — generated on the host with the exact pinkdf.js parameters. Any drift here
    /// means native and JS records stop verifying each other.
    #[test]
    fn matches_noble_on_pinkdf_params() {
        let salt: Vec<u8> = (0..16).map(|i| (i * 0x11) as u8).collect();
        let out = argon2id_derive("1234".into(), salt, 12288, 3, 1, 32).unwrap();
        // @noble/hashes 1.x: argon2id(utf8("1234"), salt, {m:12288,t:3,p:1,dkLen:32}) — regenerate with
        //   node -e "const{argon2id}=require('@noble/hashes/argon2.js');..." (see app-rn/src/pinkdf.js)
        assert_eq!(hex(&out), "fe3ad1dae901328ee8afe917aeba5dfc8c4dfba398da6af4e68d38d13b67963c");
    }

    #[test]
    fn rejects_bad_params() {
        assert!(argon2id_derive("x".into(), vec![0; 16], 0, 3, 1, 32).is_err());
        assert!(argon2id_derive("x".into(), vec![0; 16], 12288, 0, 1, 32).is_err());
    }
}
