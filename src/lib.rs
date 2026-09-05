// kvant-mls — M1 FFI SPIKE (OpenMLS 0.8.1 + libcrux, X-Wing ciphersuite 0x004D). Goal: prove
// OpenMLS+libcrux runs on Android ARM, measure REAL Commit/Welcome bytes + latency on-device, and
// demonstrate KSE1 storage-at-rest. NOT membership integration (M2). All MLS crypto is OpenMLS/
// libcrux; our code does ZERO KEM ops (only the KSE1 at-rest envelope over OpenMLS's on-disk state).
//
// ⚠️ Written against the OpenMLS 0.8 API WITHOUT a compiler here. Spots marked `VERIFY 0.8` are the
// likely-to-need-adjustment calls (provider construction, exact method/serialize signatures). First
// host `cargo build` will pinpoint them — send errors and I'll drive it to a clean compile.

uniffi::setup_scaffolding!();

// M2.0 substrate. Pure modules (no FFI surface yet — exercised by host `cargo test`):
//   devicecert — C3-LINKED trust root (byte-exact port; the ghost-member gate).
//   policy     — version/capability floor + B2.4 internal-downgrade guard.
//   as_validate — AS-callback: leaf↔TOFU/device-cert validation on ALL leaf paths.
//   dispatch    — the process_message glue that invokes the validators fail-closed on EVERY branch.
//   storage    — encrypting StorageProvider (Contract-2): KSE1-seal every write + keyspace counters.
mod devicecert;
mod policy;
mod as_validate;
mod dispatch;
mod storage;
//   client      — M3: the app-facing MlsClient bridge (uniffi Object) wrapping the verified spike.
mod client;
// A-5: native Argon2id for the APP-LOCK verifier (pinkdf.js). Separate from the MLS crypto above —
// shares only the .so + uniffi scaffolding; no MLS/KSE1 logic is touched by it.
mod argon2kdf;

// SANCTIONED VISIBILITY-ONLY re-export (Windows/Tauri port, этап 2): expose the EXISTING MlsClient API — the
// very same items already `#[uniffi::export]`ed to Kotlin/Swift — so a native Rust host (the wry/Tauri desktop
// backend) can link kvant-mls as an rlib and drive groups directly, instead of going through UniFFI bindings.
// This changes NO logic and adds NO surface beyond what UniFFI already exports; it only makes the private
// `client`/`devicecert`/`as_validate` items reachable by a Rust dependency (the .aar/UniFFI build is unaffected).
pub use crate::client::{MlsClient, AddResult, IncomingResult, IncomingKind, MemberAccountKey, MemberDevice};
pub use crate::devicecert::{mint_cert, device_fingerprint, DeviceCert};
pub use crate::as_validate::encode_identity;
// V-09 (KV-07-002), та же санкционированная видимость и ровно по той же причине: десктопный хост
// заворачивает мастер-ключ вторым фактором (KEK = HKDF(Argon2id(пароль) ‖ TPM-half)) и обязан
// считать Argon2id ТЕМ ЖЕ кодом, чей побайтовый паритет с @noble/hashes уже закреплён тестом
// (argon2kdf.rs). Альтернатива — второй argon2 в хосте, то есть вторая реализация одного примитива:
// расходятся именно копии. Логика не меняется, поверхности сверх уже экспортированного в UniFFI
// не добавляется — только достижимость из Rust-зависимости.
pub use crate::argon2kdf::{argon2id_derive, Argon2Error};

use std::time::Instant;

// VERIFY 0.8: exact import paths.
use openmls::prelude::*;
use openmls::credentials::BasicCredential;                           // 0.8: BasicCredential is in core
use openmls::prelude::tls_codec::{Serialize as _, Deserialize as _}; // tls_(de)serialize
use openmls_basic_credential::SignatureKeyPair;                      // 0.8: signer is out of core
use openmls_libcrux_crypto::Provider as LibcruxProvider;             // VERIFY: provider type name
use openmls_traits::OpenMlsProvider;

// The X-Wing ciphersuite — libcrux-only, experimental, code-point 0x004D. VERIFY 0.8: exact name.
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

// ----------------------------- KSE1 at-rest envelope -------------------------
// Same format/AEAD as the app's session-at-rest (C5): "KSE1" | nonce(12) | ChaCha20-Poly1305 ct.
// The 32-byte KEK comes from the Android Keystore (Kotlin) and is NEVER persisted here. AAD binds
// the blob to its label (group id). Protects OpenMLS's on-disk secrets (ratchet tree + group ctx).
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, ChaCha20Poly1305, Nonce};
const KSE1_MAGIC: &[u8; 4] = b"KSE1";

pub(crate) fn kse1_seal(kek: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, MlsError> {
    let cipher = ChaCha20Poly1305::new_from_slice(kek).map_err(|_| MlsError::BadKek)?;
    let mut nonce = [0u8; 12];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    let ct = cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| MlsError::AtRest)?;
    let mut out = Vec::with_capacity(16 + ct.len());
    out.extend_from_slice(KSE1_MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}
pub(crate) fn kse1_open(kek: &[u8], blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, MlsError> {
    if blob.len() < 4 + 12 + 16 || &blob[0..4] != KSE1_MAGIC { return Err(MlsError::AtRest); }
    let cipher = ChaCha20Poly1305::new_from_slice(kek).map_err(|_| MlsError::BadKek)?;
    cipher.decrypt(Nonce::from_slice(&blob[4..16]), Payload { msg: &blob[16..], aad })
        .map_err(|_| MlsError::AtRest)
}

// ----------------------------- uniffi surface --------------------------------

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MlsError {
    #[error("bad KEK (must be 32 bytes)")] BadKek,
    #[error("at-rest seal/open failed")] AtRest,
    #[error("MLS op failed: {0}")] Mls(String),
}
// Map any OpenMLS/tls_codec error → MlsError::Mls (used via `.map_err(mls)?` — no blanket From,
// which would violate coherence).
fn mls<E: std::fmt::Debug>(e: E) -> MlsError { MlsError::Mls(format!("{e:?}")) }

// CONTRACT 1 (FFI fail-closed + panic boundary): wrap OpenMLS calls that process UNTRUSTED input
// (Welcome/Commit/Proposal from a peer = A2's surface in M2) in catch_unwind → convert any panic
// into a TYPED MlsError, never an unwind across the FFI. uniffi already catch_unwinds at the export
// boundary (→ generic InternalException), but this converts a panic to a clean fail-closed typed
// error AT the call site. Pairs with panic="unwind" (Cargo.toml) so catch_unwind actually catches.
fn guard<T>(label: &str, f: impl FnOnce() -> Result<T, MlsError>) -> Result<T, MlsError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => Err(MlsError::Mls(format!("panic caught in {label} (fail-closed)"))),
    }
}

// ----------------------------- fuzzing surface (Tier-1) ----------------------
// Off by default (feature = "fuzzing"); never compiled into the production cdylib. Exposes the RAW
// deserialize parsers the auditor flagged so libFuzzer/ASAN/UBSAN can drive them on arbitrary bytes —
// DELIBERATELY OUTSIDE the Contract-1 `guard` (catch_unwind), so a panic/UB/OOB surfaces to the sanitizer
// instead of being converted to a typed error. The OpenMLS wire targets (MlsMessageIn/KeyPackageIn) live
// directly in the fuzz crate (they need only `openmls` + `tls_codec`); this module exposes only our own
// parser, `decode_identity`, which is otherwise private to the crate.
#[cfg(feature = "fuzzing")]
pub mod fuzz_api {
    use crate::as_validate::{decode_identity, encode_identity};

    /// Tier-1 invariant for our identity parser, plus an ambiguity oracle:
    ///   (a) NO-PANIC: any input — malformed, truncated, oversized length-prefix — returns None, never
    ///       panics / OOBs (the bounded reader `R` must hold for every byte string).
    ///   (b) CANONICAL: any input it ACCEPTS is canonical — re-encoding the decoded value reproduces the
    ///       exact input. Exact-consumption + explicit u32 length-prefixes mean no two byte strings may
    ///       decode to the same value; a round-trip mismatch would be a parser-ambiguity finding.
    /// A panic here, or a failed assert, is a real crash for libFuzzer to minimize and report.
    pub fn fuzz_decode_identity(data: &[u8]) {
        if let Some((account_id, cert)) = decode_identity(data) {
            let reencoded = encode_identity(&account_id, &cert);
            assert!(
                reencoded == data,
                "decode_identity accepted a NON-canonical encoding (ambiguous parse) — len {}",
                data.len()
            );
        }
    }

    // Tier-2 (stateful) re-exports. The bodies live in client::fuzz (they need MlsClient internals);
    // this only surfaces them to the fuzz crate. `process_stateful`/`op_sequence` drive the VERIFIED
    // spike over a valid fixture, `emit_seeds_a` writes the Target-A seed corpus.
    pub use crate::client::fuzz::{emit_seeds_a, op_sequence, process_stateful};
}

#[derive(uniffi::Record)]
pub struct MlsMeasure {
    pub n: u32, pub ciphersuite: String,
    pub key_package_bytes: u32, pub commit_bytes: u32, pub welcome_bytes: u32, pub app_msg_bytes: u32,
    pub create_ms: f64, pub add_commit_ms: f64, pub welcome_ms: f64,
    pub process_ms: f64, pub encrypt_ms: f64, pub decrypt_ms: f64,
    pub at_rest_ok: bool,
}

/// Confirm at runtime that X-Wing (0x004D) is the ciphersuite — belt to the source grep.
#[uniffi::export]
pub fn mls_ciphersuite_info() -> String {
    format!("{:?} = 0x{:04X}", CIPHERSUITE, u16::from(CIPHERSUITE))
}

fn ms(t: Instant) -> f64 { t.elapsed().as_secs_f64() * 1000.0 }

// VERIFY 0.8: provider construction (crypto+rand+storage). The spike uses a fresh provider per call.
fn provider() -> LibcruxProvider { LibcruxProvider::default() }

// VERIFY 0.8: credential + signature keypair creation/storage.
fn member(p: &LibcruxProvider, name: &str) -> Result<(SignatureKeyPair, CredentialWithKey), MlsError> {
    let credential = BasicCredential::new(name.as_bytes().to_vec());
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).map_err(mls)?;
    signer.store(p.storage()).map_err(mls)?;
    // Build the credential BEFORE moving `signer` into the tuple — SignatureKeyPair isn't Clone
    // (Clone is behind the "clonable" feature), so we read its public key here, no clone.
    let cwk = CredentialWithKey { credential: credential.into(), signature_key: signer.to_public_vec().into() };
    Ok((signer, cwk))
}

/// Build a group, add N members in one Commit, process Welcome on a 2nd instance, round-trip an app
/// message, and KSE1-seal the serialized group state to `storage_dir`. Real on-device sizes + times.
#[uniffi::export]
pub fn mls_measure(n: u32, storage_dir: String, kek: Vec<u8>) -> Result<MlsMeasure, MlsError> {
    if kek.len() != 32 { return Err(MlsError::BadKek); }
    let p = provider();
    let (signer, creator) = member(&p, "creator")?;

    // VERIFY 0.8: create-config builder sets the ciphersuite directly (CryptoConfig removed, #1548).
    let cfg = MlsGroupCreateConfig::builder().ciphersuite(CIPHERSUITE).build();
    let t = Instant::now();
    let mut group = MlsGroup::new(&p, &signer, &cfg, creator).map_err(mls)?;
    let create_ms = ms(t);

    // N member KeyPackages (each its own provider/identity). VERIFY 0.8: KeyPackage::builder().build(...)
    let mut kps: Vec<KeyPackage> = Vec::with_capacity(n as usize);
    let mut joiners: Vec<(LibcruxProvider, SignatureKeyPair)> = Vec::new();
    for i in 0..n {
        let jp = provider();
        let (jsigner, jcred) = member(&jp, &format!("m{i}"))?;
        let bundle = KeyPackage::builder().build(CIPHERSUITE, &jp, &jsigner, jcred).map_err(mls)?;
        kps.push(bundle.key_package().clone()); // VERIFY 0.8: bundle → key_package()
        joiners.push((jp, jsigner));
    }
    let key_package_bytes = kps.first()
        .and_then(|k| k.tls_serialize_detached().ok()).map(|b| b.len()).unwrap_or(0) as u32;

    // Add all members in ONE Commit. VERIFY 0.8: returns (commit, welcome, group_info).
    let t = Instant::now();
    let (commit, welcome, _gi) = group.add_members(&p, &signer, &kps).map_err(mls)?;
    let add_commit_ms = ms(t);
    group.merge_pending_commit(&p).map_err(mls)?;
    let commit_bytes = commit.tls_serialize_detached().map_err(mls)?.len() as u32;
    let t = Instant::now();
    let welcome_bytes = welcome.tls_serialize_detached().map_err(mls)?.len() as u32;
    let welcome_ms = ms(t);

    // Process the Welcome on the FIRST joiner → real join/process cost. into_welcome() is
    // test-gated in 0.8, so extract the Welcome via the ungated body() (Welcome is Clone).
    let (jp, _js) = &joiners[0];
    let welcome_obj = match welcome.body() {
        MlsMessageBodyOut::Welcome(w) => w.clone(),
        _ => return Err(MlsError::Mls("add_members did not return a Welcome".into())),
    };
    // CONTRACT 1: the join/process path consumes peer-supplied messages → run under the panic guard
    // (fail-closed). In M2 this same guard wraps EVERY untrusted Welcome/Commit/Proposal handler.
    let t = Instant::now();
    let staged = guard("StagedWelcome::new_from_welcome",
        || StagedWelcome::new_from_welcome(jp, cfg.join_config(), welcome_obj, None).map_err(mls))?;
    let mut joined = guard("into_group", || staged.into_group(jp).map_err(mls))?;
    let process_ms = ms(t);

    // App message round-trip, the production wire path: encrypt → serialize → deserialize as
    // MlsMessageIn → try_into_protocol_message (ungated) → process.
    let t = Instant::now();
    let app = group.create_message(&p, &signer, b"ping").map_err(mls)?;
    let encrypt_ms = ms(t);
    let app_bytes = app.tls_serialize_detached().map_err(mls)?;
    let app_msg_bytes = app_bytes.len() as u32;
    let t = Instant::now();
    let app_in = MlsMessageIn::tls_deserialize_exact(&app_bytes).map_err(mls)?;
    let proto = app_in.try_into_protocol_message().map_err(mls)?;
    let _processed = guard("process_message", || joined.process_message(jp, proto).map_err(mls))?; // CONTRACT 1
    let decrypt_ms = ms(t);

    // Storage-at-rest self-check (M1 KSE1 AEAD round-trip). NOTE (M2 Contract-2 DELIVERED): the real
    // "no-plaintext-on-disk by construction" is now `storage::KseStorageProvider` — it KSE1-seals EVERY
    // StorageProvider value before it touches the backing store (per-write, not a whole-state export),
    // with structural per-keyspace write counters. This block remains only as a standalone KSE1 envelope
    // self-check; the production at-rest path is the encrypting StorageProvider, not a post-hoc seal here.
    let gid = group.group_id().as_slice().to_vec();
    let state_bytes: Vec<u8> = b"<<KSE1 AEAD self-check; real at-rest = storage::KseStorageProvider>>".to_vec();
    let _ = &storage_dir; // (persist `sealed` to storage_dir/group.kse1 once the real export is wired)
    let sealed = kse1_seal(&kek, &state_bytes, &gid)?;
    let at_rest_ok = kse1_open(&kek, &sealed, &gid)? == state_bytes && &sealed[0..4] == KSE1_MAGIC;

    Ok(MlsMeasure {
        n, ciphersuite: mls_ciphersuite_info(),
        key_package_bytes, commit_bytes, welcome_bytes, app_msg_bytes,
        create_ms, add_commit_ms, welcome_ms, process_ms, encrypt_ms, decrypt_ms, at_rest_ok,
    })
}

// ----------------------------- KAT (portable-path correctness) ----------------
// aarch64 runs a DIFFERENT libcrux code path (portable/NEON) than the AVX2 CI/audits. Compile
// proved it builds; this proves the portable ML-KEM-768 is CORRECT on-device: deterministic keygen,
// encaps/decaps round-trip, AND the pk/ss hashes match the values pinned from the x86/AVX2 host
// (a mismatch = the portable path diverged — historical ML-KEM edge bugs live exactly here).
#[derive(uniffi::Record)]
pub struct MlsKat {
    pub deterministic: bool,
    pub roundtrip: bool,
    pub pk_sha256: String,
    pub ss_sha256: String,
    pub pinned_ok: bool, // pk+ss hashes equal the host(AVX2) reference → portable path correct
}

// host(AVX2)-pinned reference for seed=[7;64], coins=[9;32] (captured on x86 via `cargo test`).
// The device (portable/NEON path) must reproduce these exactly, or the portable ML-KEM diverged.
const PIN_PK_SHA256: &str = "c12e9e39db6758fc2ba63a638785b04f8efe3d7df23ba09803b4e39ba2fbc707";
const PIN_SS_SHA256: &str = "78dbb52f99672a2fee9001f5b7f0e91917551c7eb2137ca220058cc4918f9322";

fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().iter().map(|x| format!("{x:02x}")).collect()
}

#[uniffi::export]
pub fn mls_kat() -> MlsKat {
    use libcrux_ml_kem::mlkem768;
    let seed = [7u8; 64];
    let kp = mlkem768::generate_key_pair(seed);
    let kp2 = mlkem768::generate_key_pair(seed);
    let deterministic = kp.pk() == kp2.pk();
    let coins = [9u8; 32];
    let (ct, ss_enc) = mlkem768::encapsulate(kp.public_key(), coins);
    let ss_dec = mlkem768::decapsulate(kp.private_key(), &ct);
    let roundtrip = ss_enc.as_ref() == ss_dec.as_ref();
    let pk_sha256 = sha256_hex(kp.pk());
    let ss_sha256 = sha256_hex(ss_enc.as_ref());
    let pinned_ok = pk_sha256 == PIN_PK_SHA256 && ss_sha256 == PIN_SS_SHA256;
    MlsKat { deterministic, roundtrip, pk_sha256, ss_sha256, pinned_ok }
}

// ----------------------------- M2 on-device self-check ------------------------
// Exercises the M2 substrate on the REAL device (the last unverified thing after the ed25519-dalek +
// serde_json deps landed): the ghost-defense AS-callback (validate_leaf), Contract-2 encrypting storage,
// and re-confirms the M1 KAT is byte-identical. Diagnostics "MLS spike" surfaces the booleans.
#[derive(uniffi::Record)]
pub struct MlsM2SelfCheck {
    pub ghost_genuine_pass: bool,     // validate_leaf ACCEPTS a genuine cert-verified leaf
    pub ghost_forged_reject: bool,    // validate_leaf REJECTS an attacker-signed (ghost) leaf — fail-closed
    pub contract2_no_plaintext: bool, // encrypting storage holds only KSE1 ciphertext (no plaintext at rest)
    pub contract2_roundtrip: bool,    // seal→open recovers the exact bytes
    pub kat_pinned_ok: bool,          // M1 ML-KEM KAT pk/ss byte-identical AFTER the M2 deps
    pub all_ok: bool,                 // conjunction of all the above
}

#[uniffi::export]
pub fn mls_m2_selfcheck() -> MlsM2SelfCheck {
    use crate::as_validate::{encode_identity, validate_leaf, TrustStore};
    use crate::devicecert::mint_cert;
    use ed25519_dalek::SigningKey;

    // ---- ghost-defense: validate_leaf on a genuine vs an attacker-signed (ghost) leaf ----
    let account = SigningKey::from_bytes(&[1u8; 32]);
    let device = SigningKey::from_bytes(&[2u8; 32]);
    let attacker = SigningKey::from_bytes(&[9u8; 32]);
    let device_pub = device.verifying_key().to_bytes().to_vec();
    let account_pub = account.verifying_key().to_bytes().to_vec();
    let mut ts = TrustStore::new();
    ts.pin(b"alice", &account_pub); // TOFU-pin alice → her real account key

    let genuine_cert = mint_cert(&account, &device_pub, 1000, 0);
    let genuine_cred: Credential = BasicCredential::new(encode_identity(b"alice", &genuine_cert)).into();
    let ghost_genuine_pass = validate_leaf(&genuine_cred, &device_pub, &ts).is_ok();

    // A2 forges: attacker signs a cert for the same device, claiming alice. Pin is alice's REAL key → reject.
    let forged_cert = mint_cert(&attacker, &device_pub, 1000, 0);
    let forged_cred: Credential = BasicCredential::new(encode_identity(b"alice", &forged_cert)).into();
    let ghost_forged_reject = validate_leaf(&forged_cred, &device_pub, &ts).is_err();

    // ---- Contract-2: encrypting storage seals every value (no plaintext at rest) + round-trips ----
    let prov = storage::KseStorageProvider::new([0x42u8; 32]);
    let (contract2_no_plaintext, contract2_roundtrip) = prov.selfcheck_contract2();

    // ---- M1 KAT unchanged after the M2 deps ----
    let kat_pinned_ok = mls_kat().pinned_ok;

    let all_ok = ghost_genuine_pass
        && ghost_forged_reject
        && contract2_no_plaintext
        && contract2_roundtrip
        && kat_pinned_ok;
    MlsM2SelfCheck {
        ghost_genuine_pass,
        ghost_forged_reject,
        contract2_no_plaintext,
        contract2_roundtrip,
        kat_pinned_ok,
        all_ok,
    }
}

/// Build the MLS credential identity blob from the app's device-cert fields — the SINGLE SOURCE OF TRUTH
/// for the KMI1 byte format (JS must not reimplement it; it calls this). Reuses `as_validate::encode_identity`
/// so what the app produces is exactly what `decode_identity` / the fuzzed parser accepts. `account_id` =
/// the canonical nick bytes; the cert fields come from crypto-core/devicecert.js.
#[uniffi::export]
pub fn mls_encode_identity(
    account_id: Vec<u8>,
    cert_version: u32,
    device_id: Vec<u8>,
    device_public_key: Vec<u8>,
    account_public_key: Vec<u8>,
    created_at: u64,
    expires_at: u64,
    signature: Vec<u8>,
) -> Vec<u8> {
    let cert = crate::devicecert::DeviceCert {
        version: cert_version,
        device_id,
        device_public_key,
        account_public_key,
        created_at,
        expires_at,
        signature,
    };
    crate::as_validate::encode_identity(&account_id, &cert)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mls_encode_identity_roundtrips() {
        // the FFI encoder must produce a blob the (fuzzed) decoder accepts, field-for-field.
        let blob = super::mls_encode_identity(b"alice".to_vec(), 1, vec![7u8; 16], vec![2u8; 32], vec![3u8; 32], 100, 200, vec![9u8; 64]);
        let (aid, cert) = crate::as_validate::decode_identity(&blob).expect("decodes");
        assert_eq!(aid, b"alice");
        assert_eq!(cert.version, 1);
        assert_eq!(cert.device_public_key, vec![2u8; 32]);
        assert_eq!(cert.account_public_key, vec![3u8; 32]);
        assert_eq!(cert.signature, vec![9u8; 64]);
    }

    #[test]
    fn print_kat() {
        let k = super::mls_kat();
        println!("KAT_PK_SHA256={}", k.pk_sha256);
        println!("KAT_SS_SHA256={}", k.ss_sha256);
        assert!(k.deterministic, "keygen not deterministic");
        assert!(k.roundtrip, "encaps/decaps round-trip failed");
    }

    // Contract-1 unit invariant, proven SEPARATELY from the fuzz no-panic invariant: the `guard` CONVERTS a
    // panic into a typed, fail-closed MlsError (never an unwind across the FFI). The fuzz targets prove the
    // parsers DON'T panic on raw input; this proves that IF something deeper ever does, the boundary still
    // fails closed. Two distinct invariants, tested independently (auditor).
    #[test]
    fn guard_converts_panic_to_typed_error() {
        // a closure that panics deep inside an OpenMLS-style call
        let r: Result<(), MlsError> = guard("unit-panic", || panic!("simulated codec panic"));
        match r {
            Err(MlsError::Mls(msg)) => {
                assert!(msg.contains("panic caught in unit-panic"), "typed, labelled, fail-closed: {msg}");
            }
            other => panic!("guard must convert a panic to MlsError::Mls, got {other:?}"),
        }
    }

    #[test]
    fn guard_passes_ok_and_err_through_unchanged() {
        // the guard is transparent on the non-panicking paths
        assert!(matches!(guard("ok", || Ok::<u8, MlsError>(7)), Ok(7)));
        assert!(matches!(guard("err", || Err::<u8, MlsError>(MlsError::BadKek)), Err(MlsError::BadKek)));
    }

    // No-amplification invariant for our parser, locked as a unit test (also a fuzz seed). A 0xFFFFFFFF
    // length-prefix on a short buffer must FAIL CLOSED (None) WITHOUT pre-allocating ~4 GiB — the bounded
    // reader validates `end > len` before it ever slices/allocates. Mirrors the libFuzzer OOM guard.
    #[test]
    fn no_amplification_oversized_length_prefix_returns_none() {
        let mut b = Vec::new();
        b.extend_from_slice(b"KMI1"); // == IDENTITY_MAGIC, so the parser proceeds to the length-prefix
        b.extend_from_slice(&u32::to_be_bytes(0xFFFF_FFFF)); // account_id length = 4 GiB, buffer has 0 bytes left
        assert!(crate::as_validate::decode_identity(&b).is_none(), "oversized length-prefix must fail closed, no OOM");
    }

    // Host-side proof the on-device M2 self-check passes (the device run re-confirms it on real ARM +
    // the ARM-specific KAT). If this ever fails on host, the device run would too.
    #[test]
    fn m2_selfcheck_all_ok_on_host() {
        let r = super::mls_m2_selfcheck();
        assert!(r.ghost_genuine_pass, "genuine leaf must validate");
        assert!(r.ghost_forged_reject, "forged/ghost leaf must fail closed");
        assert!(r.contract2_no_plaintext, "no plaintext at rest");
        assert!(r.contract2_roundtrip, "seal/open round-trips");
        assert!(r.kat_pinned_ok, "M1 KAT preserved after M2 deps");
        assert!(r.all_ok);
    }
}
