// storage harness — Contract-2 (no plaintext at rest) + the keyspace security boundary measured
// structurally (per-keyspace counters), over REAL OpenMLS groups backed by KseProvider.

use super::*;
use crate::as_validate::tests::integration::{group_config, kvant_caps, CS};
use crate::as_validate::{encode_identity, TrustStore};
use crate::devicecert::testkit::{mint, pubk, sk};
use crate::dispatch::{dispatch_group_message, DispatchReject, Disposition};
use ed25519_dalek::SigningKey;
use openmls::group::StagedWelcome;
use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;

fn kek() -> [u8; 32] {
    [0x42u8; 32]
}
fn kse() -> KseProvider {
    KseProvider::new(kek()).unwrap()
}
fn wire(m: &MlsMessageOut) -> Vec<u8> {
    m.tls_serialize_detached().unwrap()
}

fn party(p: &KseProvider, cert_signer: &SigningKey, account_id: &[u8]) -> (SignatureKeyPair, CredentialWithKey) {
    let signer = SignatureKeyPair::new(CS.signature_algorithm()).unwrap();
    signer.store(p.storage()).unwrap();
    let device_pub = signer.to_public_vec();
    let cert = mint(cert_signer, &device_pub, 1000, 0);
    let credential: Credential = BasicCredential::new(encode_identity(account_id, &cert)).into();
    let cwk = CredentialWithKey { credential, signature_key: signer.to_public_vec().into() };
    (signer, cwk)
}

fn key_package(p: &KseProvider, signer: &SignatureKeyPair, cwk: CredentialWithKey) -> KeyPackage {
    KeyPackage::builder()
        .leaf_node_capabilities(kvant_caps())
        .build(CS, p, signer, cwk)
        .unwrap()
        .key_package()
        .clone()
}

// alice + bob, both backed by KseProvider; bob's receiver group's storage is the encrypting one.
fn kse_two_member() -> (KseProvider, MlsGroup, SignatureKeyPair, KseProvider, MlsGroup, TrustStore) {
    let alice_acc = sk(1);
    let bob_acc = sk(2);
    let mut ts = TrustStore::new();
    ts.pin(b"alice", &pubk(&alice_acc));
    ts.pin(b"bob", &pubk(&bob_acc));

    let ap = kse();
    let (asig, acwk) = party(&ap, &alice_acc, b"alice");
    let cfg = group_config();
    let mut agroup = MlsGroup::new(&ap, &asig, &cfg, acwk).unwrap();

    let bp = kse();
    let (bsig, bcwk) = party(&bp, &bob_acc, b"bob");
    let bkp = key_package(&bp, &bsig, bcwk);
    let (_c, welcome, _g) = agroup.add_members(&ap, &asig, &[bkp]).unwrap();
    agroup.merge_pending_commit(&ap).unwrap();

    let w = match welcome.body() {
        MlsMessageBodyOut::Welcome(w) => w.clone(),
        _ => panic!("no welcome"),
    };
    let tree = agroup.export_ratchet_tree();
    let bgroup = StagedWelcome::new_from_welcome(&bp, cfg.join_config(), w, Some(tree.into()))
        .unwrap()
        .into_group(&bp)
        .unwrap();
    (ap, agroup, asig, bp, bgroup, ts)
}

// Seed-corpus emitter for the Tier-1 fuzz targets (fuzz/corpus/<target>/). #[ignore] so normal `cargo
// test` skips it; run explicitly to (re)generate seeds:
//     cargo test -p kvant-mls emit_fuzz_seeds -- --ignored --nocapture
// Emits REAL valid wire bytes (the mutation set: identity / commit / welcome / app-message / KeyPackage,
// produced by the actual libcrux X-Wing stack on the host) PLUS the manual boundary cases the auditor
// listed (empty, magic-only, oversized 0xFFFFFFFF length-prefix = the no-amplification probe, all-ones).
#[test]
#[ignore = "seed emitter — run explicitly with --ignored to (re)populate fuzz/corpus"]
fn emit_fuzz_seeds() {
    use std::fs;
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/fuzz/corpus");
    let put = |sub: &str, name: &str, bytes: &[u8]| {
        let d = format!("{root}/{sub}");
        fs::create_dir_all(&d).unwrap();
        fs::write(format!("{d}/{name}"), bytes).unwrap();
    };

    // ---- identity parser seed (valid, canonical) ----
    let alice_acc = sk(1);
    let asigner = SignatureKeyPair::new(CS.signature_algorithm()).unwrap();
    let cert = mint(&alice_acc, &asigner.to_public_vec(), 1000, 0);
    put("decode_identity", "valid_identity.bin", &encode_identity(b"alice", &cert));

    // ---- a real 2-member group: capture the wire forms ----
    let bob_acc = sk(2);
    let ap = kse();
    let (asig, acwk) = party(&ap, &alice_acc, b"alice");
    let cfg = group_config();
    let mut agroup = MlsGroup::new(&ap, &asig, &cfg, acwk).unwrap();

    let bp = kse();
    let (bsig, bcwk) = party(&bp, &bob_acc, b"bob");
    let bkp = key_package(&bp, &bsig, bcwk);
    put("key_package_in", "bob_keypackage.bin", &bkp.tls_serialize_detached().unwrap());

    let (commit, welcome, _g) = agroup.add_members(&ap, &asig, &[bkp]).unwrap();
    put("mls_message_in", "add_commit.bin", &wire(&commit));
    put("mls_message_in", "welcome.bin", &wire(&welcome));
    agroup.merge_pending_commit(&ap).unwrap();
    let app = agroup.create_message(&ap, &asig, b"ping").unwrap();
    put("mls_message_in", "app_message.bin", &wire(&app));

    // ---- manual boundary seeds ----
    let oversized = |prefix: &[u8]| {
        let mut v = prefix.to_vec();
        v.extend_from_slice(&u32::to_be_bytes(0xFFFF_FFFF)); // 4 GiB length/count, buffer ends here
        v
    };
    put("decode_identity", "b_empty.bin", b"");
    put("decode_identity", "b_magic_only.bin", b"KMI1");
    put("decode_identity", "b_oversized_len.bin", &oversized(b"KMI1"));
    put("mls_message_in", "b_empty.bin", b"");
    put("mls_message_in", "b_oversized_len.bin", &oversized(b""));
    put("mls_message_in", "b_ones.bin", &[0xFFu8; 64]);
    put("key_package_in", "b_empty.bin", b"");
    put("key_package_in", "b_oversized_len.bin", &oversized(b""));
    put("key_package_in", "b_ones.bin", &[0xFFu8; 64]);

    println!("[seeds] wrote real + boundary corpus under {root}");
}

#[test]
fn contract2_no_plaintext_at_rest() {
    let (ap, _ag, _as, bp, bgroup, _ts) = kse_two_member();
    assert_eq!(bgroup.members().count(), 2);
    // Every value in BOTH backing stores is a KSE1 envelope — no plaintext at rest (A4 dump sees ciphertext).
    assert!(ap.storage().all_values_sealed(), "alice store fully sealed");
    assert!(bp.storage().all_values_sealed(), "bob store fully sealed");
}

#[test]
fn reject_freezes_membership_keyspace_including_interim_transcript() {
    let (ap, mut agroup, asig, bp, mut bgroup, ts) = kse_two_member();
    // forged ghost claiming alice (attacker-signed cert)
    let attacker = sk(9);
    let cp = kse();
    let (csig, ccwk) = party(&cp, &attacker, b"alice");
    let ckp = key_package(&cp, &csig, ccwk);
    let (commit, _w, _g) = agroup.add_members(&ap, &asig, &[ckp]).unwrap();
    agroup.merge_pending_commit(&ap).unwrap();

    let frozen_before = bp.storage().counters.frozen_writes();
    let interim_before = bp.storage().counters.interim_transcript_writes();
    let secret_before = bp.storage().counters.secret_ratchet_writes();

    let r = dispatch_group_message(&mut bgroup, &bp, &wire(&commit), &ts, None);
    assert!(matches!(r, Err(DispatchReject::Commit(_))), "forged commit rejected");

    // SECURITY BOUNDARY: zero FROZEN-keyspace writes on the reject path...
    assert_eq!(bp.storage().counters.frozen_writes(), frozen_before, "0 membership/config/proposal writes on reject");
    // ...including the literal interim-transcript hash, observed natively (no test-utils needed).
    assert_eq!(
        bp.storage().counters.interim_transcript_writes(),
        interim_before,
        "0 interim-transcript writes on reject (literal transcript frozen)"
    );
    // FS ratchet writes (secret-tree) are ALLOWED to advance here — they may only grow, never roll back.
    assert!(
        bp.storage().counters.secret_ratchet_writes() >= secret_before,
        "secret-tree/ratchet keyspace is free to advance for forward secrecy"
    );
}

#[test]
fn keyspace_boundary_is_classified() {
    // The security boundary itself, machine-checked: exactly Membership/Config/ProposalStore are frozen.
    assert!(Keyspace::Membership.frozen_on_reject());
    assert!(Keyspace::Config.frozen_on_reject());
    assert!(Keyspace::ProposalStore.frozen_on_reject());
    assert!(!Keyspace::SecretRatchet.frozen_on_reject());
    assert!(!Keyspace::KeyMaterial.frozen_on_reject());
}

#[test]
fn genuine_commit_advances_membership_keyspace() {
    let (ap, mut agroup, asig, bp, mut bgroup, mut ts) = kse_two_member();
    let carol = sk(3);
    ts.pin(b"carol", &pubk(&carol));
    let cp = kse();
    let (csig, ccwk) = party(&cp, &carol, b"carol");
    let ckp = key_package(&cp, &csig, ccwk);
    let (commit, _w, _g) = agroup.add_members(&ap, &asig, &[ckp]).unwrap();
    agroup.merge_pending_commit(&ap).unwrap();

    let frozen_before = bp.storage().counters.frozen_writes();
    let r = dispatch_group_message(&mut bgroup, &bp, &wire(&commit), &ts, None).unwrap();
    assert_eq!(r, Disposition::CommitMerged);
    assert!(
        bp.storage().counters.frozen_writes() > frozen_before,
        "a genuine merge DOES advance the membership keyspace (positive control)"
    );
    // and the store is still entirely sealed after the merge
    assert!(bp.storage().all_values_sealed());
}

#[test]
fn atomicity_rolls_back_only_frozen_preserving_fs_ratchet() {
    // 🔴 The subtle FS point: rollback must touch ONLY the FROZEN keyspace. A whole-store rollback would
    // resurrect FS-forgotten ratchet keys = a forward-secrecy hole. This proves membership rolls back
    // while the SECRET-RATCHET (FREE) keyspace is left advanced.
    let (ap, mut agroup, asig, bp, mut bgroup, mut ts) = kse_two_member();

    // bob's FROZEN snapshot (membership) BEFORE a genuine merge
    let frozen0 = bp.storage().snapshot_frozen();

    // alice adds carol (genuine); bob dispatches → merges, writing BOTH membership (FROZEN) and ratchet (FREE)
    let carol = sk(3);
    ts.pin(b"carol", &pubk(&carol));
    let cp = kse();
    let (csig, ccwk) = party(&cp, &carol, b"carol");
    let ckp = key_package(&cp, &csig, ccwk);
    let (commit, _w, _g) = agroup.add_members(&ap, &asig, &[ckp]).unwrap();
    agroup.merge_pending_commit(&ap).unwrap();
    dispatch_group_message(&mut bgroup, &bp, &wire(&commit), &ts, None).unwrap();
    assert_ne!(bp.storage().snapshot_frozen(), frozen0, "merge changed bob's membership");

    let (_frozen_before, free_before) = bp.storage().frozen_free_counts();
    let secret_writes_before_restore = bp.storage().counters.secret_ratchet_writes();

    // restore ONLY frozen
    bp.storage().restore_frozen(frozen0.clone());

    // membership rolled back exactly...
    assert_eq!(bp.storage().snapshot_frozen(), frozen0, "membership keyspace restored to the snapshot");
    // ...but the FREE (ratchet/secret) keyspace is byte-untouched: same count, not resurrected, not dropped.
    let (_frozen_after, free_after) = bp.storage().frozen_free_counts();
    assert_eq!(free_after, free_before, "FS/ratchet keyspace untouched by the rollback (forward secrecy preserved)");
    // restore performs no writes through the counters either — no FS regression.
    assert_eq!(bp.storage().counters.secret_ratchet_writes(), secret_writes_before_restore);
    // store remains fully sealed (Contract-2 intact after rollback)
    assert!(bp.storage().all_values_sealed());
}
