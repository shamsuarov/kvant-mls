// devicecert.rs — M2 trust root. BYTE-EXACT Rust port of crypto-core/devicecert.js (the C3-LINKED
// device-certificate chain). The auditor's B1.2 is explicit: REUSE verifyDeviceBundle, do NOT invent
// a new MLS-specific credential format. So the MLS AS-callback (as_validate.rs) sources the device
// sign key from the MLS leaf and runs EXACTLY this verification — the same gate that protects 1:1.
//
// Trust chain:  account Ed25519  --(device cert)-->  device Ed25519 (== the MLS leaf signature_key).
// A malicious server (A2) cannot mint a cert under the account key, so a ghost device/leaf it injects
// fails here and is never admitted to the group.
//
// Canonical signed payloads are mirrored field-for-field, big-endian, bytes(x) = u32(len)||x, with the
// SAME domain-separation strings — so a cert produced by the JS primary verifies here and vice-versa.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

pub const CERT_VERSION: u32 = 1;
pub const DEVICE_ID_LEN: usize = 16;
const DOMAIN_CERT: &[u8] = b"kvant/devicecert/v1";
const DOMAIN_REVOKE: &[u8] = b"kvant/devicecert/revoke/v1";

// ----------------------------- canonical writer ------------------------------
// Matches the JS Writer: u32/u64 big-endian; bytes(x) = u32(len) || x; raw = append.
struct W(Vec<u8>);
impl W {
    fn new() -> Self { W(Vec::new()) }
    fn u32(mut self, n: u32) -> Self { self.0.extend_from_slice(&n.to_be_bytes()); self }
    fn u64(mut self, n: u64) -> Self { self.0.extend_from_slice(&n.to_be_bytes()); self }
    fn bytes(mut self, b: &[u8]) -> Self { self = self.u32(b.len() as u32); self.0.extend_from_slice(b); self }
    fn raw(mut self, b: &[u8]) -> Self { self.0.extend_from_slice(b); self }
    fn out(self) -> Vec<u8> { self.0 }
}

// constant-time-ish byte compare (mirrors JS eq()).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut d = 0u8;
    for i in 0..a.len() { d |= a[i] ^ b[i]; }
    d == 0
}

/// Stable 16-byte device fingerprint = first 16 bytes of SHA-256(device sign pubkey).
/// Deterministic from the key → a cert's deviceId is tamper-evident (swap the key, id no longer matches).
pub fn device_fingerprint(device_pub: &[u8]) -> Vec<u8> {
    let h = Sha256::digest(device_pub);
    h[..DEVICE_ID_LEN].to_vec()
}

// ----------------------------- types -----------------------------------------

#[derive(Clone, Debug)]
pub struct DeviceCert {
    pub version: u32,
    pub device_id: Vec<u8>,
    pub device_public_key: Vec<u8>,   // Ed25519, 32 bytes; == the MLS leaf signature_key
    pub account_public_key: Vec<u8>,  // Ed25519, 32 bytes; the account identity that signed
    pub created_at: u64,
    pub expires_at: u64,              // 0 = no expiry
    pub signature: Vec<u8>,           // Ed25519 over cert_payload, 64 bytes
}

#[derive(Clone, Debug)]
pub struct Revocation {
    pub version: u32,
    pub device_id: Vec<u8>,
    pub account_public_key: Vec<u8>,
    pub revoked_at: u64,
    pub signature: Vec<u8>,
}

/// Typed, fail-closed rejection reasons (mirrors verifyDeviceCertReason's `reason` strings).
#[derive(Debug, PartialEq, Eq)]
pub enum CertReject {
    Structure,         // wrong key/sig lengths — not a well-formed cert
    Version,           // unsupported version
    DeviceIdLen,       // deviceId length != 16
    DeviceIdMismatch,  // deviceId != fingerprint(devicePublicKey)  OR bundle key != certified key
    AccountMismatch,   // cert account != the pinned account (or empty pin)
    BadSignature,      // account signature does not verify
    Expired,           // now > expiresAt
    Revoked,           // a valid revocation for this deviceId exists
}

fn cert_payload(c: &DeviceCert) -> Vec<u8> {
    W::new()
        .raw(DOMAIN_CERT)
        .u32(c.version)
        .bytes(&c.device_id)
        .bytes(&c.device_public_key)
        .bytes(&c.account_public_key)
        .u64(c.created_at)
        .u64(c.expires_at)
        .out()
}

fn revoke_payload(r: &Revocation) -> Vec<u8> {
    W::new()
        .raw(DOMAIN_REVOKE)
        .u32(r.version)
        .bytes(&r.device_id)
        .bytes(&r.account_public_key)
        .u64(r.revoked_at)
        .out()
}

fn ed_verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let vk_bytes: [u8; 32] = match pubkey.try_into() { Ok(x) => x, Err(_) => return false };
    let vk = match VerifyingKey::from_bytes(&vk_bytes) { Ok(x) => x, Err(_) => return false };
    let sig = match Signature::from_slice(sig) { Ok(x) => x, Err(_) => return false };
    // verify_strict = RFC 8032 canonical (rejects non-canonical / small-order) — matches @noble strict.
    vk.verify_strict(msg, &sig).is_ok()
}

// ----------------------------- verification ----------------------------------

/// Port of verifyDeviceCertReason. `account` = pin (None skips the pin check, as in JS opts.account).
/// `now` = ms clock for TTL (None skips). `revocations` = known revocations to screen against.
pub fn verify_device_cert(
    c: &DeviceCert,
    account: Option<&[u8]>,
    now: Option<u64>,
    revocations: &[Revocation],
) -> Result<(), CertReject> {
    // structural: keys/sig must be the right widths or nothing below is meaningful.
    if c.device_public_key.len() != 32 || c.account_public_key.len() != 32 || c.signature.len() != 64 {
        return Err(CertReject::Structure);
    }
    if c.version != CERT_VERSION { return Err(CertReject::Version); }
    if c.device_id.len() != DEVICE_ID_LEN { return Err(CertReject::DeviceIdLen); }
    // Binding: deviceId MUST be the fingerprint of devicePublicKey (no key swap).
    if !ct_eq(&c.device_id, &device_fingerprint(&c.device_public_key)) {
        return Err(CertReject::DeviceIdMismatch);
    }
    // Account pinning: reject a valid cert for a DIFFERENT (attacker) account.
    if let Some(acc) = account {
        if !ct_eq(&c.account_public_key, acc) { return Err(CertReject::AccountMismatch); }
    }
    // The signature must verify under the account key claimed in the cert.
    if !ed_verify(&c.account_public_key, &cert_payload(c), &c.signature) {
        return Err(CertReject::BadSignature);
    }
    // TTL.
    if let Some(n) = now {
        if c.expires_at > 0 && n > c.expires_at { return Err(CertReject::Expired); }
    }
    // Revocation: any VALID revocation (signed by the same account) for this deviceId kills it.
    for r in revocations {
        if ct_eq(&r.device_id, &c.device_id)
            && ct_eq(&r.account_public_key, &c.account_public_key)
            && verify_revocation(r, None)
        {
            return Err(CertReject::Revoked);
        }
    }
    Ok(())
}

/// Port of verifyRevocation.
pub fn verify_revocation(r: &Revocation, account: Option<&[u8]>) -> bool {
    if r.version != CERT_VERSION { return false; }
    if r.account_public_key.len() != 32 || r.signature.len() != 64 { return false; }
    if let Some(a) = account {
        if !ct_eq(&r.account_public_key, a) { return false; }
    }
    ed_verify(&r.account_public_key, &revoke_payload(r), &r.signature)
}

/// Port of verifyDeviceBundle (C2 ghost-device gate). The cert must be valid AND issued by EXACTLY
/// the pinned account, AND the key we'd adopt (here: the MLS leaf signature_key) must be the device
/// key the cert certifies — the server cannot pair a genuine cert with a different (its own) key.
pub fn verify_device_bundle(
    cert: &DeviceCert,
    account_key: &[u8],
    device_sign_key: &[u8],
    now: Option<u64>,
    revocations: &[Revocation],
) -> Result<(), CertReject> {
    if account_key.is_empty() { return Err(CertReject::AccountMismatch); }
    verify_device_cert(cert, Some(account_key), now, revocations)?;
    if !ct_eq(&cert.device_public_key, device_sign_key) {
        return Err(CertReject::DeviceIdMismatch); // bundle/leaf key is not the certified device key
    }
    Ok(())
}

/// Release-callable genuine-cert minting, used ONLY by the on-device M2 self-check (Diagnostics). The
/// account SigningKey signs the SAME canonical `cert_payload` this module verifies. Minting requires the
/// account PRIVATE key, so it grants no capability a malicious server (which never has it) could abuse.
pub fn mint_cert(
    account: &ed25519_dalek::SigningKey,
    device_pub: &[u8],
    created_at: u64,
    expires_at: u64,
) -> DeviceCert {
    use ed25519_dalek::Signer;
    let mut c = DeviceCert {
        version: CERT_VERSION,
        device_id: device_fingerprint(device_pub),
        device_public_key: device_pub.to_vec(),
        account_public_key: account.verifying_key().to_bytes().to_vec(),
        created_at,
        expires_at,
        signature: vec![0u8; 64],
    };
    c.signature = account.sign(&cert_payload(&c)).to_bytes().to_vec();
    c
}

// ----------------------------- cross-module test kit -------------------------
// Genuine cert/revocation minting, reused by as_validate's harness (so it signs the SAME canonical
// payloads this module verifies — no payload duplication).
#[cfg(test)]
pub(crate) mod testkit {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    pub fn sk(seed: u8) -> SigningKey { SigningKey::from_bytes(&[seed; 32]) }
    pub fn pubk(s: &SigningKey) -> Vec<u8> { s.verifying_key().to_bytes().to_vec() }

    pub fn mint(account: &SigningKey, device_pub: &[u8], created_at: u64, expires_at: u64) -> DeviceCert {
        let mut c = DeviceCert {
            version: CERT_VERSION,
            device_id: device_fingerprint(device_pub),
            device_public_key: device_pub.to_vec(),
            account_public_key: pubk(account),
            created_at,
            expires_at,
            signature: vec![0u8; 64],
        };
        c.signature = account.sign(&cert_payload(&c)).to_bytes().to_vec();
        c
    }

    pub fn mint_revocation(account: &SigningKey, device_id: &[u8], revoked_at: u64) -> Revocation {
        let mut r = Revocation {
            version: CERT_VERSION,
            device_id: device_id.to_vec(),
            account_public_key: pubk(account),
            revoked_at,
            signature: vec![0u8; 64],
        };
        r.signature = account.sign(&revoke_payload(&r)).to_bytes().to_vec();
        r
    }
}

// ----------------------------- ghost-member harness --------------------------
// The central membership risk: a malicious server (A2) trying to admit a GHOST device/leaf. Each test
// asserts the gate FAILS CLOSED. These mirror the JS devicegate/c3linked suites against the Rust port.
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sk(seed: u8) -> SigningKey { SigningKey::from_bytes(&[seed; 32]) }
    fn pubk(s: &SigningKey) -> Vec<u8> { s.verifying_key().to_bytes().to_vec() }

    // Mint a genuine cert exactly as createDeviceCert would (account signs the canonical payload).
    fn mint(account: &SigningKey, device: &SigningKey, created_at: u64, expires_at: u64) -> DeviceCert {
        let device_public_key = pubk(device);
        let mut c = DeviceCert {
            version: CERT_VERSION,
            device_id: device_fingerprint(&device_public_key),
            device_public_key,
            account_public_key: pubk(account),
            created_at,
            expires_at,
            signature: vec![0u8; 64],
        };
        c.signature = account.sign(&cert_payload(&c)).to_bytes().to_vec();
        c
    }

    #[test]
    fn genuine_cert_and_bundle_pass() {
        let acc = sk(1); let dev = sk(2);
        let cert = mint(&acc, &dev, 1000, 0);
        // verify_device_cert under the right pin
        assert!(verify_device_cert(&cert, Some(&pubk(&acc)), Some(2000), &[]).is_ok());
        // verify_device_bundle when the adopted (leaf) key IS the certified device key
        assert!(verify_device_bundle(&cert, &pubk(&acc), &pubk(&dev), Some(2000), &[]).is_ok());
    }

    #[test]
    fn ghost_forged_signature_rejected() {
        // A2 fabricates a cert it didn't get the account to sign.
        let acc = sk(1); let dev = sk(2);
        let mut cert = mint(&acc, &dev, 1000, 0);
        cert.signature[0] ^= 0xFF; // tamper
        assert_eq!(verify_device_cert(&cert, Some(&pubk(&acc)), None, &[]), Err(CertReject::BadSignature));
    }

    #[test]
    fn ghost_wrong_account_rejected() {
        // Valid cert, but for the ATTACKER's account — must fail the pin to the victim's account.
        let attacker = sk(9); let dev = sk(2); let victim = sk(1);
        let cert = mint(&attacker, &dev, 1000, 0);
        assert_eq!(verify_device_cert(&cert, Some(&pubk(&victim)), None, &[]), Err(CertReject::AccountMismatch));
    }

    #[test]
    fn ghost_key_swap_rejected() {
        // deviceId no longer matches devicePublicKey after a key swap.
        let acc = sk(1); let dev = sk(2); let other = sk(3);
        let mut cert = mint(&acc, &dev, 1000, 0);
        cert.device_public_key = pubk(&other); // swap the key, keep the old id+sig
        assert_eq!(verify_device_cert(&cert, Some(&pubk(&acc)), None, &[]), Err(CertReject::DeviceIdMismatch));
    }

    #[test]
    fn bundle_key_not_certified_rejected() {
        // Genuine cert, but A2 pairs it with a DIFFERENT leaf signature_key (its own).
        let acc = sk(1); let dev = sk(2); let attacker_leaf = sk(7);
        let cert = mint(&acc, &dev, 1000, 0);
        assert_eq!(
            verify_device_bundle(&cert, &pubk(&acc), &pubk(&attacker_leaf), None, &[]),
            Err(CertReject::DeviceIdMismatch)
        );
    }

    #[test]
    fn expired_cert_rejected() {
        let acc = sk(1); let dev = sk(2);
        let cert = mint(&acc, &dev, 1000, 1500); // expires at 1500
        assert_eq!(verify_device_cert(&cert, Some(&pubk(&acc)), Some(2000), &[]), Err(CertReject::Expired));
        assert!(verify_device_cert(&cert, Some(&pubk(&acc)), Some(1200), &[]).is_ok()); // still valid
    }

    #[test]
    fn revoked_device_rejected() {
        let acc = sk(1); let dev = sk(2);
        let cert = mint(&acc, &dev, 1000, 0);
        // account signs a revocation for this deviceId
        let mut rev = Revocation {
            version: CERT_VERSION,
            device_id: cert.device_id.clone(),
            account_public_key: pubk(&acc),
            revoked_at: 1800,
            signature: vec![0u8; 64],
        };
        rev.signature = acc.sign(&revoke_payload(&rev)).to_bytes().to_vec();
        assert!(verify_revocation(&rev, Some(&pubk(&acc))));
        assert_eq!(verify_device_cert(&cert, Some(&pubk(&acc)), None, &[rev]), Err(CertReject::Revoked));
    }

    #[test]
    fn revocation_forged_by_third_party_ignored() {
        // A non-account party cannot revoke (their revocation doesn't verify under the account key).
        let acc = sk(1); let dev = sk(2); let third = sk(5);
        let cert = mint(&acc, &dev, 1000, 0);
        let mut rev = Revocation {
            version: CERT_VERSION,
            device_id: cert.device_id.clone(),
            account_public_key: pubk(&acc), // claims to be the account...
            revoked_at: 1800,
            signature: vec![0u8; 64],
        };
        rev.signature = third.sign(&revoke_payload(&rev)).to_bytes().to_vec(); // ...but THIRD party signed
        assert!(!verify_revocation(&rev, Some(&pubk(&acc))));
        // so the genuine cert is still accepted
        assert!(verify_device_cert(&cert, Some(&pubk(&acc)), None, &[rev]).is_ok());
    }

    #[test]
    fn empty_account_pin_fails_closed() {
        let acc = sk(1); let dev = sk(2);
        let cert = mint(&acc, &dev, 1000, 0);
        assert_eq!(verify_device_bundle(&cert, &[], &pubk(&dev), None, &[]), Err(CertReject::AccountMismatch));
    }
}
