// as_validate harness. Part 1 (this file): UNIT-level — validate_leaf / decode_identity over real
// OpenMLS Credential values, no full groups. Part 2 (integration, real OpenMLS groups + staged
// commits + welcomes) is added once the core compiles green.

use super::*;
use crate::devicecert::testkit::{mint, mint_revocation, pubk, sk};
use crate::devicecert::{CertReject, DeviceCert};
use openmls::prelude::BasicCredential;

fn cred(account_id: &[u8], cert: &DeviceCert) -> Credential {
    BasicCredential::new(encode_identity(account_id, cert)).into()
}

#[test]
fn genuine_leaf_passes() {
    let acc = sk(1);
    let dev = sk(2);
    let dpub = pubk(&dev); // stands in for the MLS leaf signature_key
    let cert = mint(&acc, &dpub, 1000, 0);
    let mut ts = TrustStore::new();
    ts.pin(b"alice", &pubk(&acc));
    ts.set_now(2000);
    let c = cred(b"alice", &cert);
    assert!(validate_leaf(&c, &dpub, &ts).is_ok());
}

#[test]
fn unknown_account_fails_closed() {
    let acc = sk(1);
    let dev = sk(2);
    let dpub = pubk(&dev);
    let cert = mint(&acc, &dpub, 1000, 0);
    let ts = TrustStore::new(); // nothing pinned
    let c = cred(b"alice", &cert);
    assert_eq!(validate_leaf(&c, &dpub, &ts), Err(LeafReject::UnknownAccount));
}

#[test]
fn forged_account_rejected() {
    // Cert minted by the ATTACKER account, but the credential claims to be alice and alice is pinned
    // to her real key → verify_device_bundle's account pin mismatch.
    let alice = sk(1);
    let attacker = sk(9);
    let dev = sk(2);
    let dpub = pubk(&dev);
    let cert = mint(&attacker, &dpub, 1000, 0);
    let mut ts = TrustStore::new();
    ts.pin(b"alice", &pubk(&alice));
    let c = cred(b"alice", &cert);
    assert_eq!(validate_leaf(&c, &dpub, &ts), Err(LeafReject::Cert(CertReject::AccountMismatch)));
}

#[test]
fn leaf_key_not_certified_rejected() {
    // Genuine cert for dev, but the MLS leaf signature_key presented is a DIFFERENT key (A2's own).
    let acc = sk(1);
    let dev = sk(2);
    let attacker_leaf = sk(7);
    let cert = mint(&acc, &pubk(&dev), 1000, 0);
    let mut ts = TrustStore::new();
    ts.pin(b"alice", &pubk(&acc));
    let c = cred(b"alice", &cert);
    assert_eq!(
        validate_leaf(&c, &pubk(&attacker_leaf), &ts),
        Err(LeafReject::Cert(CertReject::DeviceIdMismatch))
    );
}

#[test]
fn revoked_device_rejected() {
    let acc = sk(1);
    let dev = sk(2);
    let dpub = pubk(&dev);
    let cert = mint(&acc, &dpub, 1000, 0);
    let mut ts = TrustStore::new();
    ts.pin(b"alice", &pubk(&acc));
    ts.revoke(mint_revocation(&acc, &cert.device_id, 1500));
    let c = cred(b"alice", &cert);
    assert_eq!(validate_leaf(&c, &dpub, &ts), Err(LeafReject::Cert(CertReject::Revoked)));
}

#[test]
fn malformed_identity_fails_closed() {
    let mut ts = TrustStore::new();
    ts.pin(b"alice", &pubk(&sk(1)));
    // Not a KMI1 blob at all.
    let c: Credential = BasicCredential::new(vec![1, 2, 3, 4, 5]).into();
    assert_eq!(validate_leaf(&c, &[0u8; 32], &ts), Err(LeafReject::IdentityDecode));
}

#[test]
fn identity_roundtrip_and_trailing_bytes_rejected() {
    let acc = sk(1);
    let dev = sk(2);
    let cert = mint(&acc, &pubk(&dev), 7, 9);
    let enc = encode_identity(b"alice#dev1", &cert);
    let (id, dec) = decode_identity(&enc).expect("roundtrip");
    assert_eq!(id, b"alice#dev1");
    assert_eq!(dec.device_public_key, cert.device_public_key);
    assert_eq!(dec.signature, cert.signature);
    // trailing byte → exact-consumption check rejects it (no smuggling).
    let mut padded = enc.clone();
    padded.push(0x00);
    assert!(decode_identity(&padded).is_none());
    // truncated → bounded reader returns None, never panics.
    assert!(decode_identity(&enc[..enc.len() - 1]).is_none());
}

// ============================================================================
// Part 2 — INTEGRATION harness over REAL OpenMLS groups (libcrux provider, X-Wing).
// Builds genuine groups and crafts the adversarial scenarios the auditor named, asserting fail-closed
// AND the no-state-mutation invariant (rejected commit → epoch byte-identical).
// ============================================================================
pub(crate) mod integration {
    use super::super::*; // as_validate items
    use crate::devicecert::testkit::{mint, pubk, sk};
    use ed25519_dalek::SigningKey;
    use openmls::prelude::*;
    use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_libcrux_crypto::Provider as LibcruxProvider;
    use openmls_traits::OpenMlsProvider;

    use crate::policy::floor_required_capabilities;

    pub(crate) const CS: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

    pub(crate) fn provider() -> LibcruxProvider { LibcruxProvider::default() }

    // Every Kvant leaf must advertise support for the device-cert floor capabilities, or OpenMLS
    // rejects it against the group's required_capabilities.
    pub(crate) fn kvant_caps() -> Capabilities {
        Capabilities::new(
            None,
            Some(&[CS]),
            Some(&[crate::policy::KVANT_DEVCERT_EXT]),
            None,
            Some(&[CredentialType::Basic]),
        )
    }

    // A Kvant party: a fresh MLS signer whose leaf key is certified by `account` (genuine) or by
    // `cert_signer` (forged when cert_signer != account). `account_id` is what the credential claims.
    pub(crate) fn party(
        p: &LibcruxProvider,
        cert_signer: &SigningKey,
        account_id: &[u8],
    ) -> (SignatureKeyPair, CredentialWithKey) {
        let signer = SignatureKeyPair::new(CS.signature_algorithm()).unwrap();
        signer.store(p.storage()).unwrap();
        let device_pub = signer.to_public_vec();
        let cert = mint(cert_signer, &device_pub, 1000, 0);
        let identity = encode_identity(account_id, &cert);
        let credential: Credential = BasicCredential::new(identity).into();
        let cwk = CredentialWithKey { credential, signature_key: signer.to_public_vec().into() };
        (signer, cwk)
    }

    pub(crate) fn group_config() -> MlsGroupCreateConfig {
        let gce = Extensions::single(Extension::RequiredCapabilities(floor_required_capabilities()))
            .expect("gc extensions");
        MlsGroupCreateConfig::builder()
            .ciphersuite(CS)
            .capabilities(kvant_caps())
            .with_group_context_extensions(gce)
            .build()
    }

    pub(crate) fn key_package(p: &LibcruxProvider, signer: &SignatureKeyPair, cwk: CredentialWithKey) -> KeyPackage {
        KeyPackage::builder()
            .leaf_node_capabilities(kvant_caps())
            .build(CS, p, signer, cwk)
            .expect("kp build")
            .key_package()
            .clone()
    }

    // Extract a StagedCommit on the RECEIVER side (the real AS-callback path) by processing `commit`.
    fn process_to_staged(
        p: &LibcruxProvider,
        group: &mut MlsGroup,
        commit: MlsMessageOut,
    ) -> StagedCommit {
        let bytes = commit.tls_serialize_detached().unwrap();
        let msg_in = MlsMessageIn::tls_deserialize_exact(&bytes).unwrap();
        let proto = msg_in.try_into_protocol_message().unwrap();
        let processed = group.process_message(p, proto).expect("process");
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(sc) => *sc,
            _ => panic!("expected a StagedCommit"),
        }
    }

    // alice creates a group and adds bob; bob joins. Returns the two providers/groups, alice's + bob's
    // signers, and the trust store.
    pub(crate) fn two_member_group() -> (
        LibcruxProvider, MlsGroup, SignatureKeyPair, LibcruxProvider, MlsGroup, SignatureKeyPair, TrustStore,
    ) {
        let alice_acc = sk(1);
        let bob_acc = sk(2);
        let mut ts = TrustStore::new();
        ts.pin(b"alice", &pubk(&alice_acc));
        ts.pin(b"bob", &pubk(&bob_acc));

        let ap = provider();
        let (asig, acwk) = party(&ap, &alice_acc, b"alice");
        let cfg = group_config();
        let mut agroup = MlsGroup::new(&ap, &asig, &cfg, acwk).expect("create");

        let bp = provider();
        let (bsig, bcwk) = party(&bp, &bob_acc, b"bob");
        let bkp = key_package(&bp, &bsig, bcwk);

        let (_commit, welcome, _gi) = agroup.add_members(&ap, &asig, &[bkp]).expect("add bob");
        agroup.merge_pending_commit(&ap).expect("merge");

        // bob joins via the welcome — and validates the whole tree first (B1.3).
        let welcome_obj = match welcome.body() {
            MlsMessageBodyOut::Welcome(w) => w.clone(),
            _ => panic!("no welcome"),
        };
        let tree = agroup.export_ratchet_tree();
        let staged = StagedWelcome::new_from_welcome(&bp, cfg.join_config(), welcome_obj, Some(tree.into()))
            .expect("staged");
        walk_welcome_tree(&staged, &ts).expect("genuine tree validates");
        let bgroup = staged.into_group(&bp).expect("join");

        (ap, agroup, asig, bp, bgroup, bsig, ts)
    }

    // alice adds `newcomer` and returns the commit bob will process. `cert_signer`/`account_id`
    // control whether the newcomer is genuine or forged (ghost).
    fn alice_adds(
        ap: &LibcruxProvider,
        agroup: &mut MlsGroup,
        asig: &SignatureKeyPair,
        cert_signer: &SigningKey,
        account_id: &[u8],
    ) -> MlsMessageOut {
        let np = provider();
        let (nsig, ncwk) = party(&np, cert_signer, account_id);
        let nkp = key_package(&np, &nsig, ncwk);
        let (commit, _welcome, _gi) = agroup.add_members(ap, asig, &[nkp]).expect("add");
        agroup.merge_pending_commit(ap).unwrap();
        commit
    }

    #[test]
    fn genuine_add_passes_via_process_message() {
        let (ap, mut agroup, asig, bp, mut bgroup, _bsig, mut ts) = two_member_group();
        let carol_acc = sk(3);
        ts.pin(b"carol", &pubk(&carol_acc));
        let commit = alice_adds(&ap, &mut agroup, &asig, &carol_acc, b"carol");
        // bob (receiver) AS-validates the real StagedCommit from process_message.
        let sc = process_to_staged(&bp, &mut bgroup, commit);
        assert!(walk_staged_commit(&sc, &ts).is_ok());
    }

    #[test]
    fn forged_add_rejected_and_no_state_mutation() {
        let (ap, mut agroup, asig, bp, mut bgroup, _bsig, ts) = two_member_group();
        // A malicious committer adds a GHOST claiming to be alice, but the cert is signed by an
        // attacker account (sk(9)), not alice's pinned key.
        let attacker = sk(9);
        let commit = alice_adds(&ap, &mut agroup, &asig, &attacker, b"alice");
        let epoch_before = bgroup.epoch();
        let sc = process_to_staged(&bp, &mut bgroup, commit);
        assert_eq!(
            walk_staged_commit(&sc, &ts),
            Err(CommitReject::Leaf(LeafReject::Cert(crate::devicecert::CertReject::AccountMismatch)))
        );
        // no-state-mutation: bob never merged the rejected commit → epoch byte-identical.
        assert_eq!(bgroup.epoch(), epoch_before);
    }

    #[test]
    fn ghost_add_unknown_account_rejected() {
        let (ap, mut agroup, asig, bp, mut bgroup, _bsig, ts) = two_member_group();
        // Newcomer claims an account that was never TOFU-pinned → fail closed.
        let mallory = sk(8);
        let commit = alice_adds(&ap, &mut agroup, &asig, &mallory, b"mallory");
        let sc = process_to_staged(&bp, &mut bgroup, commit);
        assert_eq!(
            walk_staged_commit(&sc, &ts),
            Err(CommitReject::Leaf(LeafReject::UnknownAccount))
        );
    }

    #[test]
    fn welcome_whole_tree_ghost_detected() {
        // alice's group already contains bob; alice now adds a GHOST (forged cert) and then invites a
        // fresh member dave. dave's Welcome carries the WHOLE tree incl. the ghost. dave must detect it
        // by walking the tree — even though the leaf that added HIM (alice) is fine.
        let alice_acc = sk(1);
        let bob_acc = sk(2);
        let attacker = sk(9);
        let mut ts = TrustStore::new();
        ts.pin(b"alice", &pubk(&alice_acc));
        ts.pin(b"bob", &pubk(&bob_acc));
        ts.pin(b"dave", &pubk(&sk(4)));

        let ap = provider();
        let (asig, acwk) = party(&ap, &alice_acc, b"alice");
        let cfg = group_config();
        let mut agroup = MlsGroup::new(&ap, &asig, &cfg, acwk).unwrap();

        // add genuine bob
        let bp = provider();
        let (bsig, bcwk) = party(&bp, &bob_acc, b"bob");
        let bkp = key_package(&bp, &bsig, bcwk);
        let (_c, _w, _g) = agroup.add_members(&ap, &asig, &[bkp]).unwrap();
        agroup.merge_pending_commit(&ap).unwrap();

        // add a GHOST (claims alice, cert by attacker)
        let gp = provider();
        let (gsig, gcwk) = party(&gp, &attacker, b"alice");
        let gkp = key_package(&gp, &gsig, gcwk);
        let (_c2, _w2, _g2) = agroup.add_members(&ap, &asig, &[gkp]).unwrap();
        agroup.merge_pending_commit(&ap).unwrap();

        // now invite dave; his Welcome carries the whole (poisoned) tree.
        let dp = provider();
        let (dsig, dcwk) = party(&dp, &sk(4), b"dave");
        let dkp = key_package(&dp, &dsig, dcwk);
        let (_c3, welcome, _g3) = agroup.add_members(&ap, &asig, &[dkp]).unwrap();
        agroup.merge_pending_commit(&ap).unwrap();

        let welcome_obj = match welcome.body() {
            MlsMessageBodyOut::Welcome(w) => w.clone(),
            _ => panic!("no welcome"),
        };
        let tree = agroup.export_ratchet_tree();
        let staged = StagedWelcome::new_from_welcome(&dp, cfg.join_config(), welcome_obj, Some(tree.into())).unwrap();
        // B1.3: walking the whole tree detects the ghost leaf → reject, do NOT into_group.
        assert_eq!(walk_welcome_tree(&staged, &ts), Err(LeafReject::Cert(crate::devicecert::CertReject::AccountMismatch)));
    }

    // A self-update that ROTATES bob's signature key + credential onto a new key. The commit is signed
    // by the OLD signer; the new key/credential ride in NewSignerBundle (MLS requires this). `cert_signer`
    // genuine (bob's pinned account) or forged (attacker) → controls whether the new leaf binds.
    fn bob_self_update(
        bp: &LibcruxProvider,
        bgroup: &mut MlsGroup,
        old_signer: &SignatureKeyPair,
        cert_signer: &SigningKey,
    ) -> MlsMessageOut {
        let bsig2 = SignatureKeyPair::new(CS.signature_algorithm()).unwrap();
        bsig2.store(bp.storage()).unwrap();
        let dpub2 = bsig2.to_public_vec();
        let cert = mint(cert_signer, &dpub2, 1000, 0);
        let cwk2 = CredentialWithKey {
            credential: BasicCredential::new(encode_identity(b"bob", &cert)).into(),
            signature_key: dpub2.into(),
        };
        let new_signer = NewSignerBundle { signer: &bsig2, credential_with_key: cwk2 };
        // capabilities (incl. the device-cert floor) ride in leaf params; credential rides in the bundle.
        let params = LeafNodeParameters::builder().with_capabilities(kvant_caps()).build();
        bgroup
            .self_update_with_new_signer(bp, old_signer, new_signer, params)
            .expect("self update")
            .into_commit()
    }

    #[test]
    fn forged_self_update_via_path_rejected() {
        // bob (or A2 as bob) rotates his leaf onto a new key whose cert is forged (attacker-signed).
        // This is a PATH update, not an Update proposal — caught only by update_path_leaf_node().
        let (ap, mut agroup, _asig, bp, mut bgroup, bsig, ts) = two_member_group();
        let attacker = sk(9);
        let commit = bob_self_update(&bp, &mut bgroup, &bsig, &attacker);
        let epoch_before = agroup.epoch();
        let sc = process_to_staged(&ap, &mut agroup, commit);
        assert_eq!(
            walk_staged_commit(&sc, &ts),
            Err(CommitReject::Leaf(LeafReject::Cert(crate::devicecert::CertReject::AccountMismatch)))
        );
        assert_eq!(agroup.epoch(), epoch_before);
    }

    #[test]
    fn genuine_self_update_via_path_passes() {
        // Positive control: bob rotates onto a new key WITH a genuine cert from his pinned account —
        // legitimate key rotation must NOT be blocked.
        let (ap, mut agroup, _asig, bp, mut bgroup, bsig, ts) = two_member_group();
        let bob_acc = sk(2); // the account two_member_group pinned for bob
        let commit = bob_self_update(&bp, &mut bgroup, &bsig, &bob_acc);
        let sc = process_to_staged(&ap, &mut agroup, commit);
        assert!(walk_staged_commit(&sc, &ts).is_ok());
    }

    #[test]
    fn downgrade_commit_rejected_b2_4() {
        // alice commits a GroupContextExtensions proposal that LOWERS required_capabilities (drops the
        // device-cert floor). bob processes it and must reject (B2.4 internal downgrade).
        let (ap, mut agroup, asig, bp, mut bgroup, _bsig, ts) = two_member_group();
        // a downgraded required_capabilities: no required extensions, no required credentials.
        let downgraded = RequiredCapabilitiesExtension::new(&[], &[], &[]);
        let new_gce = Extensions::single(Extension::RequiredCapabilities(downgraded)).unwrap();
        let (commit, _welcome, _gi) = agroup
            .update_group_context_extensions(&ap, new_gce, &asig)
            .expect("gce commit");
        agroup.merge_pending_commit(&ap).unwrap();
        let epoch_before = bgroup.epoch();
        let sc = process_to_staged(&bp, &mut bgroup, commit);
        assert!(matches!(walk_staged_commit(&sc, &ts), Err(CommitReject::Downgrade(_))));
        assert_eq!(bgroup.epoch(), epoch_before);
    }

    #[test]
    fn standalone_forged_add_proposal_rejected() {
        // The standalone-proposal / external-join path: a forged Add can arrive as a ProposalMessage
        // (not inside a Commit). validate_queued_proposal must reject it via the same leaf validator.
        let (ap, mut agroup, asig, bp, mut bgroup, _bsig, ts) = two_member_group();
        let attacker = sk(9);
        let np = provider();
        let (nsig, ncwk) = party(&np, &attacker, b"alice"); // ghost claiming alice, forged cert
        let nkp = key_package(&np, &nsig, ncwk);
        let (proposal, _ref) = agroup.propose_add_member(&ap, &asig, &nkp).expect("propose");
        let bytes = proposal.tls_serialize_detached().unwrap();
        let proto = MlsMessageIn::tls_deserialize_exact(&bytes)
            .unwrap()
            .try_into_protocol_message()
            .unwrap();
        match bgroup.process_message(&bp, proto).expect("process").into_content() {
            ProcessedMessageContent::ProposalMessage(qp) => assert_eq!(
                validate_queued_proposal(qp.proposal(), &ts),
                Err(CommitReject::Leaf(LeafReject::Cert(crate::devicecert::CertReject::AccountMismatch)))
            ),
            _ => panic!("expected a ProposalMessage"),
        }
    }
}
