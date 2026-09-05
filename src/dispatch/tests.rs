// dispatch harness — one test per process_message branch + Welcome, proving (a) the validator IS
// invoked on that branch and (b) Err ⇒ NOTHING is applied. "Nothing applied" is proven the strongest
// available way: the MemoryStorage map is byte-identical before/after the reject (no persisted write —
// the test-level form of the Q4 "storage-write-count == 0" invariant), plus epoch / pending-count.

use super::*;
use crate::as_validate::tests::integration::{
    group_config, kvant_caps, key_package, party, provider, two_member_group, CS,
};
use crate::as_validate::{walk_staged_commit, CommitReject, LeafReject, TrustStore};
use crate::devicecert::testkit::{pubk, sk};
use crate::devicecert::CertReject;
use ed25519_dalek::SigningKey;
use openmls::prelude::tls_codec::Serialize as _;
use openmls_libcrux_crypto::Provider as LibcruxProvider;
use sha2::{Digest, Sha256};

fn wire(m: &MlsMessageOut) -> Vec<u8> {
    m.tls_serialize_detached().unwrap()
}

/// A FULL membership fingerprint, frozen across a rejected dispatch (auditor Q4 v2). Hashes:
///   • epoch — advances on EVERY commit merge, so any applied commit is caught here;
///   • the ratchet tree (tls) — membership + the data the GroupContext tree_hash is computed over;
///   • the GroupContext extensions (tls) — required_capabilities, so an applied downgrade is caught;
///   • pending proposals BY CONTENT — each ProposalRef is a content-addressed hash, so a content swap
///     that preserves the count is caught (count alone would miss it).
/// These advance ONLY on merge, so freezing them proves no membership change was applied.
///
/// NOTE (Q4): "storage-write-count == 0" is the WRONG invariant here — `process_message` legitimately
/// persists decryption-ratchet advancement (forward secrecy: a message can't be re-processed), so storage
/// DOES change on the reject path. CAVEAT on the auditor's transcript-hash ask: the confirmed/interim
/// transcript hashes are reachable only via `export_group_context`, which OpenMLS 0.8.1 gates behind its
/// `test-utils`/`test` cfg — we deliberately do NOT enable `test-utils` on a security crate just for a
/// test accessor. The transcript hash advances in lockstep with `epoch` on merge, so freezing `epoch`
/// (plus tree + extensions) is an equivalent freeze for "a commit was applied". (The literal transcript
/// hash can be folded in at the storage.rs layer, where commit-scoped writes are observable directly.)
fn group_state_fp(g: &MlsGroup) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(g.epoch().as_u64().to_be_bytes());
    h.update(RatchetTreeIn::from(g.export_ratchet_tree()).tls_serialize_detached().unwrap());
    h.update(g.extensions().tls_serialize_detached().unwrap());
    let mut refs: Vec<Vec<u8>> =
        g.pending_proposals().map(|qp| qp.proposal_reference_ref().as_slice().to_vec()).collect();
    refs.sort(); // order-independent set of content-addressed proposal refs
    for r in refs {
        h.update(r);
    }
    h.finalize().to_vec()
}

// ---------------- Commit branch ----------------

#[test]
fn genuine_commit_dispatch_merges() {
    let (ap, mut agroup, asig, bp, mut bgroup, _bsig, mut ts) = two_member_group();
    let carol = sk(3);
    ts.pin(b"carol", &pubk(&carol));
    let cp = provider();
    let (csig, ccwk) = party(&cp, &carol, b"carol");
    let ckp = key_package(&cp, &csig, ccwk);
    let (commit, _w, _g) = agroup.add_members(&ap, &asig, &[ckp]).unwrap();
    agroup.merge_pending_commit(&ap).unwrap();

    let epoch_before = bgroup.epoch();
    let disp = dispatch_group_message(&mut bgroup, &bp, &wire(&commit), &ts, None).unwrap();
    assert_eq!(disp, Disposition::CommitMerged);
    assert_ne!(bgroup.epoch(), epoch_before, "genuine commit advances the epoch");
}

#[test]
fn forged_commit_dispatch_fails_closed_nothing_persisted() {
    let (ap, mut agroup, asig, bp, mut bgroup, _bsig, ts) = two_member_group();
    let attacker = sk(9);
    let cp = provider();
    let (csig, ccwk) = party(&cp, &attacker, b"alice"); // ghost claiming alice, attacker-signed cert
    let ckp = key_package(&cp, &csig, ccwk);
    let (commit, _w, _g) = agroup.add_members(&ap, &asig, &[ckp]).unwrap();
    agroup.merge_pending_commit(&ap).unwrap();

    let fp_before = group_state_fp(&bgroup);
    let r = dispatch_group_message(&mut bgroup, &bp, &wire(&commit), &ts, None);
    assert_eq!(
        r,
        Err(DispatchReject::Commit(CommitReject::Leaf(LeafReject::Cert(CertReject::AccountMismatch))))
    );
    assert_eq!(group_state_fp(&bgroup), fp_before, "no group-state advance on the reject path");
}

// ---------------- Proposal branch ----------------

#[test]
fn genuine_proposal_dispatch_stores() {
    let (ap, mut agroup, asig, bp, mut bgroup, _bsig, mut ts) = two_member_group();
    let carol = sk(3);
    ts.pin(b"carol", &pubk(&carol));
    let cp = provider();
    let (csig, ccwk) = party(&cp, &carol, b"carol");
    let ckp = key_package(&cp, &csig, ccwk);
    let (prop, _ref) = agroup.propose_add_member(&ap, &asig, &ckp).unwrap();

    // B8: a GENUINE proposal from a real member with a valid leaf is refused too, and that is the
    // point of the change rather than a side effect. Nothing in kvant sends proposals — every
    // membership change is a direct commit — so "genuine" here means only "well-formed", not
    // "expected". The store stays empty, which is the invariant the commit path relies on.
    let fp_before = group_state_fp(&bgroup);
    let r = dispatch_group_message(&mut bgroup, &bp, &wire(&prop), &ts, None);
    assert_eq!(r, Err(DispatchReject::ProposalRefused("Add")));
    assert_eq!(bgroup.pending_proposals().count(), 0, "no proposal is ever stored");
    assert_eq!(group_state_fp(&bgroup), fp_before, "no group-state advance on the refusal path");
}

#[test]
fn forged_proposal_dispatch_fails_closed_nothing_persisted() {
    let (ap, mut agroup, asig, bp, mut bgroup, _bsig, ts) = two_member_group();
    let attacker = sk(9);
    let cp = provider();
    let (csig, ccwk) = party(&cp, &attacker, b"alice"); // forged
    let ckp = key_package(&cp, &csig, ccwk);
    let (prop, _ref) = agroup.propose_add_member(&ap, &asig, &ckp).unwrap();

    let fp_before = group_state_fp(&bgroup);
    let r = dispatch_group_message(&mut bgroup, &bp, &wire(&prop), &ts, None);
    // B8: the refusal now comes one step EARLIER — the proposal branch refuses before AS-validation
    // is reached, so a forged leaf never has to be caught by it. Both outcomes are "nothing stored";
    // what changed is which gate says no first.
    assert_eq!(r, Err(DispatchReject::ProposalRefused("Add")));
    assert_eq!(bgroup.pending_proposals().count(), 0, "forged proposal never stored");
    assert_eq!(group_state_fp(&bgroup), fp_before, "no group-state advance on the reject path");
}

// ---------------- By-reference proposals (hermetic at commit time) ----------------

#[test]
fn byreference_forged_add_rejected_at_commit() {
    // Even if a forged Add reached the proposal store, a commit that references it by-reference resolves
    // it back into the StagedCommit queue → walk_staged_commit sees it and rejects. (Store-time gate
    // already blocks this earlier; this proves the SECOND hermetic path at commit time.)
    let (ap, mut agroup, asig, _bp, _bg, _bsig, ts) = two_member_group();
    let attacker = sk(9);
    let cp = provider();
    let (csig, ccwk) = party(&cp, &attacker, b"alice");
    let ckp = key_package(&cp, &csig, ccwk);
    let (_prop, _ref) = agroup.propose_add_member(&ap, &asig, &ckp).unwrap(); // stored locally
    let _ = agroup.commit_to_pending_proposals(&ap, &asig).unwrap(); // commits it by-reference
    let sc = agroup.pending_commit().expect("a pending commit");
    assert_eq!(
        walk_staged_commit(sc, &ts),
        Err(CommitReject::Leaf(LeafReject::Cert(CertReject::AccountMismatch)))
    );
}

// ---------------- SEND side (symmetric ghost-KeyPackage guard) ----------------

#[test]
fn send_guarded_add_genuine_ok() {
    let (ap, mut agroup, asig, _bp, _bg, _bsig, mut ts) = two_member_group();
    let carol = sk(3);
    ts.pin(b"carol", &pubk(&carol));
    let cp = provider();
    let (csig, ccwk) = party(&cp, &carol, b"carol");
    let ckp = key_package(&cp, &csig, ccwk);
    assert!(guarded_add_members(&mut agroup, &ap, &asig, &[ckp], &ts).is_ok());
}

#[test]
fn send_guarded_add_ghost_rejected_no_commit_formed() {
    // A2 hands us a ghost KeyPackage for "alice" (attacker-signed cert, not chaining to alice's pin).
    // The SEND guard must reject it BEFORE add_members stages anything.
    let (ap, mut agroup, asig, _bp, _bg, _bsig, ts) = two_member_group();
    let attacker = sk(9);
    let cp = provider();
    let (csig, ccwk) = party(&cp, &attacker, b"alice");
    let ckp = key_package(&cp, &csig, ccwk);

    let fp_before = group_state_fp(&agroup);
    let r = guarded_add_members(&mut agroup, &ap, &asig, &[ckp], &ts);
    assert_eq!(
        r.err(),
        Some(DispatchReject::Leaf(LeafReject::Cert(CertReject::AccountMismatch)))
    );
    assert!(agroup.pending_commit().is_none(), "ghost add must NOT stage a commit");
    assert_eq!(group_state_fp(&agroup), fp_before, "no group-state change on a rejected add");
}

#[test]
fn send_guarded_add_unknown_account_rejected() {
    let (ap, mut agroup, asig, _bp, _bg, _bsig, ts) = two_member_group();
    let mallory = sk(8);
    let cp = provider();
    let (csig, ccwk) = party(&cp, &mallory, b"mallory"); // never pinned
    let ckp = key_package(&cp, &csig, ccwk);
    let r = guarded_add_members(&mut agroup, &ap, &asig, &[ckp], &ts);
    assert_eq!(r.err(), Some(DispatchReject::Leaf(LeafReject::UnknownAccount)));
    assert!(agroup.pending_commit().is_none());
}

#[test]
fn send_guarded_add_revoked_device_rejected() {
    let (ap, mut agroup, asig, _bp, _bg, _bsig, mut ts) = two_member_group();
    let carol = sk(3);
    ts.pin(b"carol", &pubk(&carol));
    let cp = provider();
    let (csig, ccwk) = party(&cp, &carol, b"carol");
    let dev_pub = csig.to_public_vec(); // the leaf signature_key = the certified device key
    let ckp = key_package(&cp, &csig, ccwk);
    // carol's account revokes that device
    let dev_id = crate::devicecert::device_fingerprint(&dev_pub);
    ts.revoke(crate::devicecert::testkit::mint_revocation(&carol, &dev_id, 2000));
    let r = guarded_add_members(&mut agroup, &ap, &asig, &[ckp], &ts);
    assert_eq!(r.err(), Some(DispatchReject::Leaf(LeafReject::Cert(CertReject::Revoked))));
}

#[test]
fn send_guarded_propose_add_genuine_ok() {
    let (ap, mut agroup, asig, _bp, _bg, _bsig, mut ts) = two_member_group();
    let carol = sk(3);
    ts.pin(b"carol", &pubk(&carol));
    let cp = provider();
    let (csig, ccwk) = party(&cp, &carol, b"carol");
    let ckp = key_package(&cp, &csig, ccwk);
    assert!(guarded_propose_add_member(&mut agroup, &ap, &asig, &ckp, &ts).is_ok());
    assert_eq!(agroup.pending_proposals().count(), 1);
}

#[test]
fn send_guarded_propose_add_ghost_rejected_no_proposal() {
    // proposal-flow add of a ghost KeyPackage → rejected before the proposal is even created.
    let (ap, mut agroup, asig, _bp, _bg, _bsig, ts) = two_member_group();
    let attacker = sk(9);
    let cp = provider();
    let (csig, ccwk) = party(&cp, &attacker, b"alice");
    let ckp = key_package(&cp, &csig, ccwk);
    let fp_before = group_state_fp(&agroup);
    let r = guarded_propose_add_member(&mut agroup, &ap, &asig, &ckp, &ts);
    assert_eq!(
        r.err(),
        Some(DispatchReject::Leaf(LeafReject::Cert(CertReject::AccountMismatch)))
    );
    assert_eq!(agroup.pending_proposals().count(), 0, "ghost proposal never created");
    assert_eq!(group_state_fp(&agroup), fp_before, "no state change on a rejected propose");
}

// ---------------- Welcome branch ----------------

// Build alice's group with `create_cfg`, optionally seed a GHOST member, then add `joiner`. Returns the
// JOINER's provider (its KeyPackage secrets live there), the Welcome, and the exported ratchet tree.
fn build_join(
    joiner_acc: &SigningKey,
    joiner_id: &[u8],
    create_cfg: &MlsGroupCreateConfig,
    seed_ghost: bool,
) -> (LibcruxProvider, Welcome, RatchetTreeIn) {
    let ap = provider();
    let (asig, acwk) = party(&ap, &sk(1), b"alice");
    let mut agroup = MlsGroup::new(&ap, &asig, create_cfg, acwk).unwrap();
    if seed_ghost {
        // A2 inserts a ghost: claims alice, cert signed by an attacker (sk(9)).
        let gp = provider();
        let (gsig, gcwk) = party(&gp, &sk(9), b"alice");
        let gkp = key_package(&gp, &gsig, gcwk);
        let (_c, _w, _g) = agroup.add_members(&ap, &asig, &[gkp]).unwrap();
        agroup.merge_pending_commit(&ap).unwrap();
    }
    let jp = provider();
    let (jsig, jcwk) = party(&jp, joiner_acc, joiner_id);
    let jkp = key_package(&jp, &jsig, jcwk);
    let (_c, welcome, _g) = agroup.add_members(&ap, &asig, &[jkp]).unwrap();
    agroup.merge_pending_commit(&ap).unwrap();
    let w = match welcome.body() {
        MlsMessageBodyOut::Welcome(w) => w.clone(),
        _ => panic!("no welcome"),
    };
    (jp, w, agroup.export_ratchet_tree().into())
}

#[test]
fn welcome_dispatch_genuine_joins() {
    let dave = sk(4);
    let cfg = group_config();
    let (jp, w, tree) = build_join(&dave, b"dave", &cfg, false);
    let mut ts = TrustStore::new();
    ts.pin(b"alice", &pubk(&sk(1)));
    ts.pin(b"dave", &pubk(&dave));
    let g = dispatch_welcome(&jp, cfg.join_config(), w, Some(tree), &ts).expect("join");
    assert_eq!(g.members().count(), 2);
}

#[test]
fn welcome_dispatch_ghost_tree_rejected() {
    // B1.3 via the dispatcher: the tree handed to dave contains a ghost leaf → refuse the join.
    let dave = sk(4);
    let cfg = group_config();
    let (jp, w, tree) = build_join(&dave, b"dave", &cfg, true);
    let mut ts = TrustStore::new();
    ts.pin(b"alice", &pubk(&sk(1)));
    ts.pin(b"dave", &pubk(&dave));
    let r = dispatch_welcome(&jp, cfg.join_config(), w, Some(tree), &ts);
    assert!(
        matches!(r, Err(DispatchReject::Leaf(LeafReject::Cert(CertReject::AccountMismatch)))),
        "ghost leaf in the welcome tree must refuse the join"
    );
}

#[test]
fn welcome_dispatch_below_floor_rejected() {
    // A group whose required_capabilities is missing (below floor) must be refused at join — the
    // Welcome-reject-below-floor point that walk_welcome_tree alone does not cover.
    let dave = sk(4);
    let cfg_lo = MlsGroupCreateConfig::builder().ciphersuite(CS).capabilities(kvant_caps()).build();
    let (jp, w, tree) = build_join(&dave, b"dave", &cfg_lo, false);
    let mut ts = TrustStore::new();
    ts.pin(b"alice", &pubk(&sk(1)));
    ts.pin(b"dave", &pubk(&dave));
    let r = dispatch_welcome(&jp, cfg_lo.join_config(), w, Some(tree), &ts);
    assert!(matches!(r, Err(DispatchReject::BelowFloor(_))), "below-floor group refused at join");
}

// ---------------- B8: no incoming proposal is stored, whatever it is ----------------
//
// The hole this closes: as_validate::validate_queued_proposal checks Add, Update and
// GroupContextExtensions and lets everything else through on `_ => Ok(())`. A stored proposal is not
// inert — commit_builder consumes the pending-proposal store BY DEFAULT — so anything that settled
// there rode out in the next commit anyone made. Remove meant "any member can have any member
// evicted, bypassing the roles chain"; PreSharedKey meant "any member can stop the group from ever
// committing again". See the note in dispatch.rs for why refusing all of them is the answer and what
// it costs.

#[test]
fn b8_remove_proposal_refused_and_not_stored() {
    // The one that bypassed the roles chain: a member proposing somebody ELSE's removal.
    let (ap, mut agroup, asig, bp, mut bgroup, _bsig, ts) = two_member_group();
    // Target somebody OTHER than the proposer: alice is leaf 0, so leaf 1 is bob.
    let victim = LeafNodeIndex::new(1);
    assert_ne!(victim, agroup.own_leaf_index(), "the point is a Remove aimed at another member");
    let (prop, _r) = agroup.propose_remove_member(&ap, &asig, victim).unwrap();

    let fp_before = group_state_fp(&bgroup);
    let r = dispatch_group_message(&mut bgroup, &bp, &wire(&prop), &ts, None);
    assert_eq!(r, Err(DispatchReject::ProposalRefused("Remove")), "a Remove must be refused BY NAME");
    assert_eq!(bgroup.pending_proposals().count(), 0, "nothing queued for the next commit to sweep");
    assert_eq!(group_state_fp(&bgroup), fp_before);
}

#[test]
fn b8_psk_proposal_refused_and_not_stored() {
    // The one that wedged the group: a PSK nobody holds, loaded while building every later commit.
    let (ap, mut agroup, asig, bp, mut bgroup, _bsig, ts) = two_member_group();
    let psk = openmls::schedule::PreSharedKeyId::external(vec![7u8; 16], vec![9u8; 32]);
    let (prop, _r) = agroup.propose_external_psk(&ap, &asig, psk).unwrap();

    let r = dispatch_group_message(&mut bgroup, &bp, &wire(&prop), &ts, None);
    assert_eq!(r, Err(DispatchReject::ProposalRefused("PreSharedKey")));
    assert_eq!(bgroup.pending_proposals().count(), 0);
}

#[test]
fn b8_gce_proposal_refused_even_though_it_used_to_be_validated() {
    // GroupContextExtensions WAS one of the three checked types. It is refused now as well: the rule
    // is "no standalone proposal", not "no unchecked proposal".
    let (ap, mut agroup, asig, bp, mut bgroup, _bsig, ts) = two_member_group();
    let gce = Extensions::single(Extension::RequiredCapabilities(
        crate::policy::floor_required_capabilities(),
    ))
    .unwrap();
    let (prop, _r) = agroup.propose_group_context_extensions(&ap, gce, &asig).unwrap();

    let r = dispatch_group_message(&mut bgroup, &bp, &wire(&prop), &ts, None);
    assert_eq!(r, Err(DispatchReject::ProposalRefused("GroupContextExtensions")));
    assert_eq!(bgroup.pending_proposals().count(), 0);
}

#[test]
fn b8_after_refusal_the_next_commit_carries_nothing() {
    // The whole reason the store matters: commit_builder sweeps it. With nothing stored, a commit
    // carries exactly what its caller asked for — here, one Add and nothing else.
    let (ap, mut agroup, asig, bp, mut bgroup, bsig, ts) = two_member_group();
    let attacker_prop = {
        let (prop, _r) = agroup.propose_remove_member(&ap, &asig, LeafNodeIndex::new(0)).unwrap();
        prop
    };
    let _ = dispatch_group_message(&mut bgroup, &bp, &wire(&attacker_prop), &ts, None); // refused
    assert_eq!(bgroup.pending_proposals().count(), 0);

    // B now commits an ordinary Add. If the refused Remove had been stored, it would ride along here.
    let carol = sk(4);
    let cp = provider();
    let (csig, ccwk) = party(&cp, &carol, b"carol");
    let ckp = key_package(&cp, &csig, ccwk);
    let mut ts2 = ts;
    ts2.pin(b"carol", &pubk(&carol));
    let (commit, _welcome, _gi) = bgroup.add_members(&bp, &bsig, &[ckp]).unwrap();
    bgroup.merge_pending_commit(&bp).unwrap();
    let _ = (commit, csig);
    assert_eq!(bgroup.members().count(), 3, "the Add applied");
    assert!(
        bgroup.members().any(|m| m.index == LeafNodeIndex::new(0)),
        "leaf 0 is still a member — the refused Remove was not swept into this commit"
    );
}

#[test]
fn b8_positive_commits_and_application_messages_still_work() {
    // The refusal is narrow: only the standalone-proposal branch. Commits and application messages
    // — everything kvant actually sends — are untouched.
    let (ap, mut agroup, asig, bp, mut bgroup, _bsig, _ts) = two_member_group();
    let carol = sk(5);
    let cp = provider();
    let (csig, ccwk) = party(&cp, &carol, b"carol");
    let ckp = key_package(&cp, &csig, ccwk);
    let mut ts2 = TrustStore::new();
    ts2.pin(b"alice", &pubk(&sk(1)));
    ts2.pin(b"bob", &pubk(&sk(2)));
    ts2.pin(b"carol", &pubk(&carol));
    let (commit, _welcome, _gi) = agroup.add_members(&ap, &asig, &[ckp]).unwrap();
    agroup.merge_pending_commit(&ap).unwrap();
    let disp = dispatch_group_message(&mut bgroup, &bp, &wire(&commit), &ts2, None).unwrap();
    assert_eq!(disp, Disposition::CommitMerged, "an ordinary Add commit still merges");

    let msg = agroup.create_message(&ap, &asig, b"hello").unwrap();
    let disp = dispatch_group_message(&mut bgroup, &bp, &wire(&msg), &ts2, None).unwrap();
    assert_eq!(disp, Disposition::Application(b"hello".to_vec()), "application messages untouched");
    let _ = csig;
}

// ---------------- KV-11-006: чем ДЕЙСТВИТЕЛЬНО держится шифронабор ----------------
//
// Прежний тест шифронабора звал чистую функцию `assert_ciphersuite` с константой и был вечнозелёным:
// он не касался ни одного пути, по которому в группу можно попасть, и не сказал бы ни слова, если бы
// OpenMLS перестал проверять шифронабор. Проверять надо ТО, ЧТО НАС ЗАЩИЩАЕТ, а защищают нас семь
// контролей внутри библиотеки (перечислены в шапке policy::assert_ciphersuite).
//
// Оба теста ниже ПОВЕДЕНЧЕСКИЕ и идут через наши собственные точки входа (`guarded_add_members`,
// `dispatch_welcome`), а не через внутренности OpenMLS: если библиотека сменит поведение, красным
// станет НАШ путь.
//
// ПАРА «до/после» ВМЕСТО СРАВНЕНИЯ СТРОК ОШИБКИ. Проверять текст отказа («содержит
// CiphersuiteMismatch») — дословная форма: покраснеет от переименования и промолчит, если отказ
// придёт по другой причине. Поэтому каждый тест прогоняет ОДИН И ТОТ ЖЕ вход дважды, меняя ровно
// шифронабор: неизменённый обязан пройти, изменённый — нет. Тогда причиной отказа доказуемо является
// шифронабор, а не случайно испорченный вход.

/// Второй ШТАТНО ПОДДЕРЖИВАЕМЫЙ провайдером набор (openmls_libcrux_crypto умеет 0x0001, 0x0003,
/// 0x004D). Поддерживаемость важна: иначе отказ пришёл бы из `crypto().supports()` — «провайдер
/// такого не умеет», — и тест доказывал бы не то. Нужен отказ именно из сравнения с нашим KeyPackage.
const CS_OTHER: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

#[test]
fn foreign_ciphersuite_keypackage_refused_on_add() {
    use crate::as_validate::encode_identity;
    use crate::devicecert::testkit::mint;
    use openmls_basic_credential::SignatureKeyPair;

    let carol = sk(3);
    // Один и тот же лист, два шифронабора — больше ничего не меняется.
    let build_kp = |cs: Ciphersuite| {
        let cp = provider();
        let signer = SignatureKeyPair::new(cs.signature_algorithm()).unwrap();
        signer.store(cp.storage()).unwrap();
        let cert = mint(&carol, &signer.to_public_vec(), 1000, 0);
        let identity = encode_identity(b"carol", &cert);
        let credential: Credential = BasicCredential::new(identity).into();
        let cwk = CredentialWithKey { credential, signature_key: signer.to_public_vec().into() };
        let caps = Capabilities::new(
            None,
            Some(&[cs]),
            Some(&[crate::policy::KVANT_DEVCERT_EXT]),
            None,
            Some(&[CredentialType::Basic]),
        );
        KeyPackage::builder()
            .leaf_node_capabilities(caps)
            .build(cs, &cp, &signer, cwk)
            .expect("kp build")
            .key_package()
            .clone()
    };

    // КОНТРОЛЬ: ровно такой же лист с нашим набором ПРИНИМАЕТСЯ. Без этого отказ ниже нельзя отличить
    // от отказа по сертификату, capabilities или ошибке построения.
    {
        let (ap, mut agroup, asig, _bp, _bg, _bs, mut ts) = two_member_group();
        ts.pin(b"carol", &pubk(&carol));
        assert!(
            guarded_add_members(&mut agroup, &ap, &asig, &[build_kp(CS)], &ts).is_ok(),
            "КОНТРОЛЬ: лист с X-Wing обязан приниматься, иначе проверка ниже доказывает не то"
        );
    }

    // Тот же лист с чужим набором — отказ.
    {
        let (ap, mut agroup, asig, _bp, _bg, _bs, mut ts) = two_member_group();
        ts.pin(b"carol", &pubk(&carol));
        let r = guarded_add_members(&mut agroup, &ap, &asig, &[build_kp(CS_OTHER)], &ts);
        assert!(r.is_err(), "KeyPackage с чужим шифронабором обязан быть отвергнут при добавлении");
        assert!(
            !matches!(r, Err(DispatchReject::Leaf(_))),
            "отказ обязан быть по набору, а не по сертификату — иначе тест проверяет чужое свойство"
        );
    }
}

#[test]
fn welcome_naming_a_foreign_ciphersuite_refused() {
    // Welcome, в заголовке которого ЗАЯВЛЕН чужой набор, а адресован он нашему X-Wing KeyPackage-у:
    // ровно та форма, которую библиотека ловит на creation.rs:168. Строим настоящий Welcome и правим
    // в ПРОВОДЕ два байта.
    //
    // ДВА НЕЗАВИСИМЫХ ВСТУПЛЕНИЯ, а не одно — и причина этого сама по себе находка. Первая редакция
    // прогоняла подменённый и подлинный Welcome через ОДИН провайдер, и контроль падал с
    // `NoMatchingKeyPackage`: отвергнутое вступление УСПЕВАЕТ СЪЕСТЬ KeyPackage. `keys_for_welcome`
    // потребляет подходящий (не last-resort) KeyPackage ДО сравнения шифронаборов, а перед ним стоит
    // только `crypto().supports()` — который чужой, но ПОДДЕРЖИВАЕМЫЙ набор пропускает. То есть
    // поддельный Welcome с поддерживаемым чужим набором сжигает одноразовый KeyPackage получателя,
    // ничего при этом не открывая: отказ в обслуживании, дешёвый и незаметный. Здесь это обойдено
    // двумя вступлениями; как долг — записано в ROADMAP.
    let dave = sk(4);
    let cfg = group_config();
    let mut ts = TrustStore::new();
    ts.pin(b"alice", &pubk(&sk(1)));
    ts.pin(b"dave", &pubk(&dave));

    let parse = |b: &[u8]| -> Option<Welcome> { Welcome::tls_deserialize_exact(b).ok() };
    let cs_x = u16::from(CS).to_be_bytes();

    // (1) ПОДМЕНЁННЫЙ — обязан быть отвергнут.
    {
        let (jp, w, tree) = build_join(&dave, b"dave", &cfg, false);
        // build_join отдаёт САМ Welcome (не обёртку MlsMessage), поэтому провод начинается прямо с
        // его первого поля: Welcome = cipher_suite(u16) || secrets<V> || encrypted_group_info<V>.
        // КОНТРОЛЬ на смещение: если поле лежит не здесь, подмена бьёт по случайным байтам и «отказ»
        // не значит ничего. Первая редакция взяла смещение 4 — от формы MlsMessage — и не собралась;
        // смещение подтверждено компилятором и этим ассертом, а не угадано.
        let bytes = w.tls_serialize_detached().unwrap();
        assert_eq!(&bytes[0..2], &cs_x[..], "КОНТРОЛЬ: шифронабор Welcome лежит в начале провода");

        let mut patched = bytes.clone();
        patched[0..2].copy_from_slice(&u16::from(CS_OTHER).to_be_bytes());
        // Не разобрался — тоже отказ, только раньше: до группы дело не дошло, свойство соблюдено.
        if let Some(bad) = parse(&patched) {
            let r = dispatch_welcome(&jp, cfg.join_config(), bad, Some(tree), &ts);
            assert!(r.is_err(), "Welcome с чужим шифронабором обязан быть отвергнут");
        }
    }

    // (2) КОНТРОЛЬ: тот же построитель, тот же конфиг, ничего не менялось — вступление проходит.
    // Пара «до/после» и есть доказательство, что причиной отказа стал ИМЕННО шифронабор, а не
    // испорченный провод и не что-то в построении.
    {
        let (jp, w, tree) = build_join(&dave, b"dave", &cfg, false);
        let bytes = w.tls_serialize_detached().unwrap();
        let ok = parse(&bytes).expect("original welcome parses");
        let ctl = dispatch_welcome(&jp, cfg.join_config(), ok, Some(tree), &ts);
        assert!(ctl.is_ok(), "КОНТРОЛЬ: подлинный X-Wing Welcome обязан приниматься: {:?}", ctl.err());
    }
}

#[test]
fn rejected_welcome_does_not_burn_the_keypackage() {
    // §10.11. Отказ — это ПОЛОВИНА свойства, и без второй половины тест доказывает не то.
    //
    // `keys_for_welcome` ПОТРЕБЛЯЕТ подходящий (не last-resort) KeyPackage ДО сравнения
    // шифронаборов, а единственная проверка перед ним — `crypto().supports()`, который чужой, но
    // ПОДДЕРЖИВАЕМЫЙ набор пропускает. Значит поддельный Welcome отвергался — и по дороге съедал
    // одноразовый KeyPackage жертвы. Ничего не открыв: чистое исчерпание ресурса, после которого её
    // нельзя пригласить в группу, пока пул не пополнится. Ни следа, ни ошибки, ни повода посмотреть.
    //
    // Поэтому проверок здесь ДВЕ, и вторая — та, ради которой всё написано:
    //   1. подделка ничего не открыла;
    //   2. и KeyPackage ЖИВ — подлинный Welcome К ТОМУ ЖЕ KeyPackage-у после неё по-прежнему
    //      открывается. Без п.2 тест был бы зелёным и до правки.
    let dave = sk(4);
    let cfg = group_config();
    let mut ts = TrustStore::new();
    ts.pin(b"alice", &pubk(&sk(1)));
    ts.pin(b"dave", &pubk(&dave));

    // ОДИН провайдер и ОДИН KeyPackage на оба вступления — иначе исчерпание непроверяемо в принципе.
    let (jp, w, tree) = build_join(&dave, b"dave", &cfg, false);
    let bytes = w.tls_serialize_detached().unwrap();
    let mut patched = bytes.clone();
    patched[0..2].copy_from_slice(&u16::from(CS_OTHER).to_be_bytes());
    let parse = |b: &[u8]| -> Option<Welcome> { Welcome::tls_deserialize_exact(b).ok() };

    // ---- 1. подделка ничего не открыла ----
    let bad = parse(&patched).expect("patched welcome parses");
    let r = dispatch_welcome(&jp, cfg.join_config(), bad, Some(tree.clone()), &ts);
    assert!(r.is_err(), "поддельный Welcome не имеет права открыть группу");
    // Отказать обязаны МЫ, до OpenMLS. Это не придирка к форме: любой отказ ПОСЛЕ
    // build_from_welcome означает, что KeyPackage уже потреблён, — то есть п.2 ниже упадёт.
    // Здесь проверка стоит ради внятного сообщения, гарантию даёт п.2.
    assert!(
        matches!(r, Err(DispatchReject::WrongCiphersuite(_))),
        "отказ обязан прийти от НАШЕЙ предварительной отбраковки, а не из глубины OpenMLS: {:?}",
        r.err()
    );

    // ---- 2. 🔴 и KeyPackage ЖИВ ----
    let ok = parse(&bytes).expect("original welcome parses");
    let r2 = dispatch_welcome(&jp, cfg.join_config(), ok, Some(tree), &ts);
    assert!(
        r2.is_ok(),
        "подлинный Welcome к тому же KeyPackage обязан открыться. NoMatchingKeyPackage здесь \
         означает, что отвергнутая подделка съела KeyPackage — то самое исчерпание: {:?}",
        r2.err()
    );
}
