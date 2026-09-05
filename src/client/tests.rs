// client tests — M3 Phase 1 vertical slice, host-only (like M1/M2 were proven host-first).
// Proves: app-message round-trip over the MlsClient bridge, ghost-defense still fail-closed through the
// wrapper, and the export/import persistence foundation (a restored client continues the group).

use super::*;
use crate::as_validate::encode_identity;
use crate::devicecert::{device_fingerprint, mint_cert};
use crate::devicecert::testkit::mint_revocation;
use ed25519_dalek::SigningKey;

fn kek() -> Vec<u8> {
    vec![0x42u8; 32]
}

// The device_id (cert fingerprint) for a device seed — the per-device leaf identifier remove_device targets.
fn device_id_of(device_seed: u8) -> Vec<u8> {
    device_fingerprint(&SigningKey::from_bytes(&[device_seed; 32]).verifying_key().to_bytes())
}

// Build an MlsClient with a genuine account/device identity. Returns (client, account_id, account_pub)
// so peers can TOFU-pin it. account_seed picks the ACCOUNT key that signs the device cert; a mismatched
// account_seed vs the claimed account_id = a forged (ghost) identity.
fn mk(account_seed: u8, device_seed: u8, account_id: &[u8]) -> (Arc<MlsClient>, Vec<u8>, Vec<u8>) {
    let account = SigningKey::from_bytes(&[account_seed; 32]);
    let device = SigningKey::from_bytes(&[device_seed; 32]);
    let device_priv = device.to_bytes().to_vec();
    let device_pub = device.verifying_key().to_bytes().to_vec();
    let account_pub = account.verifying_key().to_bytes().to_vec();
    let cert = mint_cert(&account, &device_pub, 0, 0); // 0 created / 0 expires = no TTL
    let identity = encode_identity(account_id, &cert);
    let client = MlsClient::new(kek(), device_priv, device_pub, identity).unwrap();
    (client, account_id.to_vec(), account_pub)
}

// alice + bob, cross-pinned, alice owns a group with bob in it. Returns (alice, bob, gid, bob_pins…).
fn two_member_group() -> (Arc<MlsClient>, Arc<MlsClient>, Vec<u8>, (Vec<u8>, Vec<u8>), (Vec<u8>, Vec<u8>)) {
    let (alice, a_id, a_pub) = mk(1, 2, b"alice");
    let (bob, b_id, b_pub) = mk(3, 4, b"bob");
    alice.pin_account(b_id.clone(), b_pub.clone());
    bob.pin_account(a_id.clone(), a_pub.clone());
    let gid = alice.create_group().unwrap();
    let add = alice.add_member(gid.clone(), bob.make_key_package().unwrap()).unwrap();
    let bob_gid = bob.join_from_welcome(add.welcome, add.ratchet_tree).unwrap();
    assert_eq!(bob_gid, gid, "joiner lands in the same group");
    // KV-03-001: роли есть у КАЖДОГО, кто обрабатывает коммиты, — ровно как в приложении, где
    // mlsWiring пере-подаёт цепочку на старте и при каждом изменении. Без этого группа сидит в окне
    // «ролей нет», и стороннее удаление отклоняется (policy::may_remove).
    for c in [&alice, &bob] {
        c.set_group_roles(gid.clone(), b"alice".to_vec(), vec![]);
    }
    (alice, bob, gid, (a_id, a_pub), (b_id, b_pub))
}

#[test]
fn app_message_roundtrip() {
    let (alice, bob, gid, _, _) = two_member_group();
    // alice → bob
    let wire = alice.encrypt_message(gid.clone(), b"hello".to_vec()).unwrap();
    let r = bob.process_incoming(gid.clone(), wire).unwrap();
    assert!(matches!(r.kind, IncomingKind::Application), "kind = application");
    assert_eq!(r.plaintext.as_deref(), Some(&b"hello"[..]), "decrypted plaintext matches");

    // bob → alice (the reverse direction ratchets too)
    let wire2 = bob.encrypt_message(gid.clone(), b"hi back".to_vec()).unwrap();
    let r2 = alice.process_incoming(gid, wire2).unwrap();
    assert_eq!(r2.plaintext.as_deref(), Some(&b"hi back"[..]));
}

#[test]
fn forged_keypackage_rejected() {
    // alice pins "bob" to bob's REAL account key…
    let (alice, _, _) = mk(1, 2, b"alice");
    let bob_account = SigningKey::from_bytes(&[3u8; 32]);
    alice.pin_account(b"bob".to_vec(), bob_account.verifying_key().to_bytes().to_vec());
    let gid = alice.create_group().unwrap();

    // …but A2 hands alice a GHOST KeyPackage: cert signed by an ATTACKER account (seed 9), claiming "bob".
    // guarded_add_members → validate_leafnode → account-pin mismatch → fail-closed, NO commit formed.
    let (ghost, _, _) = mk(9, 4, b"bob");
    let ghost_kp = ghost.make_key_package().unwrap();
    let res = alice.add_member(gid, ghost_kp);
    assert!(res.is_err(), "ghost KeyPackage must be rejected (ghost-defense fail-closed through the wrapper)");
}

#[test]
fn remove_member_pcs_and_no_participation() {
    let (alice, bob, gid, _, (b_id, _)) = two_member_group();
    // messaging works before removal
    let w0 = alice.encrypt_message(gid.clone(), b"before".to_vec()).unwrap();
    assert_eq!(bob.process_incoming(gid.clone(), w0).unwrap().plaintext.as_deref(), Some(&b"before"[..]));

    // alice removes bob → remove commit; bob processes his own removal (learns he's out)
    let remove_commit = alice.remove_member(gid.clone(), b_id).unwrap();
    let _ = bob.process_incoming(gid.clone(), remove_commit);

    // PCS: alice's NEW-epoch message cannot be read by the removed member
    let post = alice.encrypt_message(gid.clone(), b"secret".to_vec()).unwrap();
    assert!(
        bob.process_incoming(gid.clone(), post).is_err(),
        "removed member cannot read post-removal traffic (post-compromise security)"
    );

    // removed member cannot participate: bob can no longer encrypt into the group
    assert!(bob.encrypt_message(gid, b"intrusion".to_vec()).is_err(), "removed member cannot send");
}

fn sorted(mut v: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    v.sort();
    v
}

#[test]
fn late_join_own_device() {
    // LATE-JOIN (Stage A): after a group exists, the PRIMARY adds its OWN new device's leaf → the new
    // device joins POST-HOC and reads; member_account_ids still dedups the account; the existing member
    // (bob) is untouched. This reuses add_member (ghost-checked) — no new FFI needed.
    let (alice, bob, gid, (a_id, a_pub), (b_id, b_pub)) = two_member_group();
    // alice's SECOND device: SAME account (seed 1) → same account_id "alice"; DIFFERENT device (seed 5).
    let (alice_linked, _, _) = mk(1, 5, b"alice");
    alice_linked.pin_account(a_id.clone(), a_pub.clone()); // self-account (whole-tree validation on join)
    alice_linked.pin_account(b_id, b_pub);                 // bob (whole-tree ghost check)

    // PRIMARY adds its OWN new device leaf into the EXISTING group (reuses add_member; own account-cert
    // passes ghost-defense against the self-pin).
    let add = alice.add_member(gid.clone(), alice_linked.make_key_package().unwrap()).unwrap();
    bob.process_incoming(gid.clone(), add.commit).unwrap(); // existing member applies the Add commit

    // 🔴 STOP-1: the new device joins POST-HOC and reads a subsequent message.
    let new_gid = alice_linked.join_from_welcome(add.welcome, add.ratchet_tree).unwrap();
    assert_eq!(new_gid, gid, "late-joined device lands in the same group");

    // 🔴 STOP-2: dedup — member_account_ids = {alice, bob} (alice ONCE despite 2 leaves).
    let both = sorted(vec![b"alice".to_vec(), b"bob".to_vec()]);
    assert_eq!(sorted(alice.member_account_ids(gid.clone()).unwrap()), both, "primary: alice deduped (2 leaves, 1 account)");
    assert_eq!(sorted(alice_linked.member_account_ids(gid.clone()).unwrap()), both, "new device: same deduped view");
    assert_eq!(sorted(bob.member_account_ids(gid.clone()).unwrap()), both, "bob: same deduped view");

    // the late-joined device decrypts a message from the primary (its own leaf ratchet, independent copy).
    let w_new = alice.encrypt_message(gid.clone(), b"welcome device".to_vec()).unwrap();
    assert_eq!(alice_linked.process_incoming(gid.clone(), w_new).unwrap().plaintext.as_deref(), Some(&b"welcome device"[..]), "new device reads");

    // 🔴 STOP-3: the existing member bob is UNTOUCHED — still reads normally after the late-join.
    let w_bob = alice.encrypt_message(gid.clone(), b"still here".to_vec()).unwrap();
    assert_eq!(bob.process_incoming(gid, w_bob).unwrap().plaintext.as_deref(), Some(&b"still here"[..]), "existing member unaffected");
}

#[test]
fn member_list_reflects_add_and_remove() {
    let (alice, bob, gid, _, (b_id, _)) = two_member_group();
    let both = sorted(vec![b"alice".to_vec(), b"bob".to_vec()]);
    // TRUE list from the group tree = {alice, bob} on both sides after the add
    assert_eq!(sorted(alice.member_account_ids(gid.clone()).unwrap()), both, "adder sees both");
    assert_eq!(sorted(bob.member_account_ids(gid.clone()).unwrap()), both, "joiner sees both");
    // remove bob → the true list shrinks to {alice}.
    // Многоадминные гонки: remove_member больше НЕ сливает коммит сам — он остаётся отложенным,
    // пока вызывающий не подтвердит. Поэтому здесь появился merge_pending; без него список бы не
    // изменился, и это ровно то свойство, ради которого правка делалась.
    let _ = alice.remove_member(gid.clone(), b_id).unwrap();
    alice.merge_pending(gid.clone()).unwrap();
    assert_eq!(alice.member_account_ids(gid).unwrap(), vec![b"alice".to_vec()], "removed account drops out");
}

#[test]
fn member_account_keys_attested_by_tree() {
    // The MLS-roles genesis ANCHOR: each member's account Ed25519 pub is read back from the
    // ghost-defense-validated leaf credentials — on BOTH the adder and the WELCOME-joiner (whose
    // whole tree was validated by walk_welcome_tree/B1.3 before the join happened). The returned
    // keys must equal the REAL account verifying keys; a forged key can't reach the tree at all
    // (forged_keypackage_rejected proves that side).
    let (alice, bob, gid, (a_id, a_pub), (b_id, b_pub)) = two_member_group();
    for (who, c) in [("adder", &alice), ("joiner", &bob)] {
        let mut keys = c.member_account_keys(gid.clone()).unwrap();
        keys.sort_by(|x, y| x.account_id.cmp(&y.account_id)); // alice < bob
        assert_eq!(keys.len(), 2, "{who}: two accounts, deduped");
        assert_eq!(keys[0].account_id, a_id, "{who}: alice id");
        assert_eq!(keys[0].account_public_key, a_pub, "{who}: alice account key attested by the tree");
        assert_eq!(keys[1].account_id, b_id, "{who}: bob id");
        assert_eq!(keys[1].account_public_key, b_pub, "{who}: bob account key attested by the tree");
    }
}

#[test]
fn three_party_roster_consistency() {
    // The core roster-sync guarantee: when alice adds carol, the NON-ADDER (bob) learns the real membership
    // by processing the Add COMMIT → member_account_ids() then agrees across ALL THREE clients.
    let (alice, bob, gid, (a_id, a_pub), (b_id, b_pub)) = two_member_group();
    let (carol, c_id, c_pub) = mk(5, 6, b"carol");
    // pins: adder(alice) needs carol; non-adder(bob) needs carol to validate the Add commit's new leaf;
    // carol needs alice+bob because dispatch_welcome walks the WHOLE tree (B1.3 ghost check) on join.
    alice.pin_account(c_id.clone(), c_pub.clone());
    bob.pin_account(c_id.clone(), c_pub.clone());
    carol.pin_account(a_id, a_pub);
    carol.pin_account(b_id, b_pub);

    let add = alice.add_member(gid.clone(), carol.make_key_package().unwrap()).unwrap();
    // NON-ADDER bob auto-learns carol by applying the Add commit (the roster-sync trigger)
    let rb = bob.process_incoming(gid.clone(), add.commit).unwrap();
    assert!(matches!(rb.kind, IncomingKind::CommitMerged), "bob applies the Add commit");
    let carol_gid = carol.join_from_welcome(add.welcome, add.ratchet_tree).unwrap();
    assert_eq!(carol_gid, gid, "carol joins the same group");

    // CONSISTENCY: all three agree on {alice, bob, carol} — bob got there WITHOUT being the adder
    let three = sorted(vec![b"alice".to_vec(), b"bob".to_vec(), b"carol".to_vec()]);
    assert_eq!(sorted(alice.member_account_ids(gid.clone()).unwrap()), three, "alice");
    assert_eq!(sorted(bob.member_account_ids(gid.clone()).unwrap()), three, "bob (auto-synced via Add commit)");
    assert_eq!(sorted(carol.member_account_ids(gid.clone()).unwrap()), three, "carol");

    // remove: alice removes carol → the non-adder bob applies the remove commit, all agree carol is gone
    let rm = alice.remove_member(gid.clone(), c_id).unwrap();
    alice.merge_pending(gid.clone()).unwrap(); // коммит теперь подтверждается явно (см. remove_member)
    let rb2 = bob.process_incoming(gid.clone(), rm).unwrap();
    assert!(matches!(rb2.kind, IncomingKind::CommitMerged), "bob applies the Remove commit");
    let two = sorted(vec![b"alice".to_vec(), b"bob".to_vec()]);
    assert_eq!(sorted(alice.member_account_ids(gid.clone()).unwrap()), two, "alice after remove");
    assert_eq!(sorted(bob.member_account_ids(gid).unwrap()), two, "bob after remove (auto-synced)");
}

/// peek_frame читает эпоху и тип кадра БЕЗ обработки — это то, чем «устаревший коммит» отличается
/// от «подделки» и чем гонка распознаётся до того, как чужой коммит применился.
#[test]
fn peek_frame_reads_epoch_and_kind_without_applying() {
    let (alice, bob, gid, _, (b_id, _)) = two_member_group();
    let e0 = alice.group_epoch(gid.clone()).unwrap();
    let fp0 = alice.group_state_fp(gid.clone()).unwrap();

    let commit = alice.remove_member(gid.clone(), b_id).unwrap();
    let p = alice.peek_frame(commit.clone()).unwrap();
    assert!(p.is_commit && !p.is_application, "коммит опознан как коммит");
    assert_eq!(p.epoch, e0, "и он для ТЕКУЩЕЙ эпохи — то есть ещё применим");
    assert_eq!(p.group_id, gid, "и для этой группы");
    assert_eq!(alice.group_state_fp(gid.clone()).unwrap(), fp0, "🔴 заглядывание НИЧЕГО не изменило");

    // После мержа тот же кадр становится УСТАРЕВШИМ, и это видно тем же способом, без обработки.
    alice.merge_pending(gid.clone()).unwrap();
    let after = alice.peek_frame(commit).unwrap();
    assert!(after.epoch < alice.group_epoch(gid.clone()).unwrap(), "эпоха кадра ниже текущей = устарел");

    // КОНТРОЛЬ: обычное сообщение опознаётся как НЕ коммит — иначе проверка не различала бы ничего.
    let app = bob.encrypt_message(gid.clone(), b"hi".to_vec()).unwrap();
    let pa = bob.peek_frame(app).unwrap();
    assert!(pa.is_application && !pa.is_commit, "КОНТРОЛЬ: application опознан как application");
}

/// МНОГОАДМИННЫЕ ГОНКИ, половина «обнаружение + неоптимистичный мерж».
///
/// Свойство, которого раньше не было: коммит, СОЗДАННЫЙ автором, не двигает его состояние, пока
/// автор явно не подтвердит. Именно это превращает «раскол группы» в «моё действие не применилось»:
/// пока коммит отложен, чужой коммит для той же эпохи ещё применим, и выйти из гонки можно без
/// расхождения эпох.
///
/// Проверяется на ОТПЕЧАТКЕ состояния, а не на списке участников: список — следствие, отпечаток —
/// само состояние (эпоха + дерево + расширения + ссылки на отложенные предложения).
#[test]
fn pending_commit_does_not_move_state_until_merged() {
    let (alice, bob, gid, _, (b_id, _)) = two_member_group();
    let before_fp = alice.group_state_fp(gid.clone()).unwrap();
    let before_epoch = alice.group_epoch(gid.clone()).unwrap();

    // 1. Создали коммит на удаление — и НИЧЕГО не сдвинулось.
    let commit = alice.remove_member(gid.clone(), b_id.clone()).unwrap();
    assert_eq!(alice.group_epoch(gid.clone()).unwrap(), before_epoch, "эпоха не двигается до мержа");
    assert_eq!(alice.group_state_fp(gid.clone()).unwrap(), before_fp, "состояние не двигается до мержа");
    assert!(
        alice.member_account_ids(gid.clone()).unwrap().len() == 2,
        "и список участников тоже: удаление ещё не применено"
    );

    // 2. Отменили — состояние осталось ровно тем же, байт в байт.
    alice.clear_pending(gid.clone()).unwrap();
    assert_eq!(alice.group_epoch(gid.clone()).unwrap(), before_epoch, "clear_pending не двигает эпоху");
    assert_eq!(alice.group_state_fp(gid.clone()).unwrap(), before_fp, "clear_pending возвращает то же состояние");

    // 3. И ровно поэтому ЧУЖОЙ коммит для той же эпохи всё ещё применим — это и есть выход из
    //    гонки без раскола. Боб (у которого своя эпоха не двигалась) делает свой коммит.
    //
    //    KV-03-001 ИЗМЕНИЛ ЗДЕСЬ СЦЕНАРИЙ, и это не косметика. Раньше боб удалял alice — но alice
    //    владелец, а владельца теперь не удаляет никто, кроме него самого. В группе из ДВОИХ любая
    //    симметричная гонка удалений неизбежно целится во владельца, то есть стала невозможной по
    //    построению. Проверяемое свойство (чужой коммит той же эпохи применим после clear_pending)
    //    от вида коммита не зависит, поэтому боб добавляет третьего — операция легальная и обычная.
    let (carol, c_id, c_pub) = mk(5, 6, b"carol");
    alice.pin_account(c_id.clone(), c_pub.clone());
    bob.pin_account(c_id, c_pub);
    let their_commit = bob.add_member(gid.clone(), carol.make_key_package().unwrap()).unwrap().commit;
    bob.merge_pending(gid.clone()).unwrap();
    let r = alice.process_incoming(gid.clone(), their_commit).unwrap();
    assert!(matches!(r.kind, IncomingKind::CommitMerged), "проигравший применяет чужой коммит");
    assert_eq!(
        alice.group_epoch(gid.clone()).unwrap(),
        before_epoch + 1,
        "и только теперь эпоха сдвинулась — на ЧУЖОМ коммите"
    );
    assert_eq!(
        alice.group_state_fp(gid.clone()).unwrap(),
        bob.group_state_fp(gid).unwrap(),
        "🔴 обе стороны в ОДНОМ состоянии — раскола нет"
    );

    // 4. КОНТРОЛЬ: отпечаток вообще умеет различать. Два разных состояния обязаны дать разные байты.
    let (c1, _c2, g2, _, (id2, _)) = two_member_group();
    let fp_before = c1.group_state_fp(g2.clone()).unwrap();
    let _ = c1.remove_member(g2.clone(), id2).unwrap();
    c1.merge_pending(g2.clone()).unwrap();
    assert_ne!(c1.group_state_fp(g2).unwrap(), fp_before, "КОНТРОЛЬ: после мержа отпечаток ДРУГОЙ");
}

// Build a client whose MLS signer (leaf key) DELIBERATELY does not match the cert's certified device
// key: the account certifies `cert_device_seed`, but the MLS signer is `signer_seed` (≠). Models a
// server trying to pair a genuine account-signed cert with a different (its own) leaf key.
fn mk_leaf_swap(account_seed: u8, cert_device_seed: u8, signer_seed: u8, account_id: &[u8]) -> Arc<MlsClient> {
    let account = SigningKey::from_bytes(&[account_seed; 32]);
    let cert_device = SigningKey::from_bytes(&[cert_device_seed; 32]);
    let signer = SigningKey::from_bytes(&[signer_seed; 32]);
    let cert = mint_cert(&account, &cert_device.verifying_key().to_bytes(), 0, 0); // certifies cert_device
    let identity = encode_identity(account_id, &cert);
    // MLS leaf signer uses signer_seed → leaf signature_key != cert.device_public_key (the swap).
    MlsClient::new(kek(), signer.to_bytes().to_vec(), signer.verifying_key().to_bytes().to_vec(), identity).unwrap()
}

#[test]
fn primary_model_dedicated_leaf_attested_and_swap_rejected() {
    // ANCHOR for the production identity path (getMlsIdentity, leaf-key hardening): the PRIMARY device's
    // MLS leaf key is a DEDICATED per-device Ed25519 (device seed) that the ACCOUNT (a DISTINCT account
    // seed) attests via a C3-LINKED device cert — never the account key itself. mk() already builds
    // exactly this separate-key shape (account_seed != device_seed), so this test pins the prod model to
    // the ghost-defense that has always covered it.
    assert_ne!(
        SigningKey::from_bytes(&[1u8; 32]).verifying_key().to_bytes(),
        SigningKey::from_bytes(&[2u8; 32]).verifying_key().to_bytes(),
        "leaf (device) seed is distinct from the account seed — no key reuse"
    );

    // POSITIVE: a genuine separate-leaf identity validates through the FULL ghost-defense (add + join).
    let (alice, a_id, a_pub) = mk(1, 2, b"alice");
    let (bob, b_id, b_pub) = mk(3, 4, b"bob");
    alice.pin_account(b_id, b_pub);
    bob.pin_account(a_id, a_pub);
    let gid = alice.create_group().unwrap();
    let add = alice.add_member(gid.clone(), bob.make_key_package().unwrap()).unwrap();
    assert_eq!(
        bob.join_from_welcome(add.welcome, add.ratchet_tree).unwrap(),
        gid,
        "genuine per-device leaf validates + joins (ghost-defense OK on the separate-key model)"
    );

    // NEGATIVE (leaf-swap, the Rust twin of the JS tamper test): an identity whose MLS signer (leaf key)
    // does NOT match the cert's certified device key → verify_device_bundle rejects on add (fail-closed).
    let mallory = mk_leaf_swap(7, 8, 9, b"mallory"); // account 7 certifies device 8, but signs with 9
    alice.pin_account(b"mallory".to_vec(), SigningKey::from_bytes(&[7u8; 32]).verifying_key().to_bytes().to_vec());
    let res = alice.add_member(gid, mallory.make_key_package().unwrap());
    assert!(
        res.is_err(),
        "leaf signature_key != cert.device_public_key → fail-closed (server can't pair a genuine cert with its own key)"
    );
}

#[test]
fn multidevice_two_leaves_one_account() {
    // MULTIDEVICE core (Stage 1a): two DEVICES of ONE account are two DISTINCT leaves in the SAME tree,
    // sharing one account_id but with different per-device keys/certs. Same account_seed (3) → same account
    // key + account_id "bob"; different device_seed (4 vs 5) → distinct leaf keys, each cert account-signed
    // for "bob". This anchors that the verified spike ALREADY supports multidevice — leaves are independent,
    // ghost-defense validates each, and the roster dedups by account_id.
    let (alice, a_id, a_pub) = mk(1, 2, b"alice");
    let (bob_primary, b_id, b_pub) = mk(3, 4, b"bob"); // account "bob", device A
    let (bob_linked, b_id2, b_pub2) = mk(3, 5, b"bob"); // account "bob", device B (SAME account key)
    assert_eq!(b_id, b_id2, "both devices share the account_id");
    assert_eq!(b_pub, b_pub2, "both devices share the account key (only the device/leaf key differs)");

    // cross-pins: alice pins bob's account; both bob devices pin alice's account
    alice.pin_account(b_id.clone(), b_pub.clone());
    bob_primary.pin_account(a_id.clone(), a_pub.clone());
    bob_linked.pin_account(a_id.clone(), a_pub.clone());

    let gid = alice.create_group().unwrap();
    // Add device A (ghost-defense validates its account-signed leaf) → A joins.
    let add_a = alice.add_member(gid.clone(), bob_primary.make_key_package().unwrap()).unwrap();
    assert_eq!(bob_primary.join_from_welcome(add_a.welcome, add_a.ratchet_tree).unwrap(), gid);
    // Add device B in the next epoch → device A processes B's Add commit; B joins via its own welcome.
    let add_b = alice.add_member(gid.clone(), bob_linked.make_key_package().unwrap()).unwrap();
    let ra = bob_primary.process_incoming(gid.clone(), add_b.commit).unwrap();
    assert!(matches!(ra.kind, IncomingKind::CommitMerged), "device A applies device B's Add commit");
    assert_eq!(bob_linked.join_from_welcome(add_b.welcome, add_b.ratchet_tree).unwrap(), gid);

    // 🔴 STOP-1: member_account_ids DEDUPS two leaves of one account → {alice, bob} (bob ONCE, not twice).
    let want = sorted(vec![b"alice".to_vec(), b"bob".to_vec()]);
    assert_eq!(sorted(alice.member_account_ids(gid.clone()).unwrap()), want, "alice roster: bob once (deduped)");
    assert_eq!(sorted(bob_primary.member_account_ids(gid.clone()).unwrap()), want, "device A roster: bob once");
    assert_eq!(sorted(bob_linked.member_account_ids(gid.clone()).unwrap()), want, "device B roster: bob once");
    // (the TRUE tree has 3 leaves — alice + 2×bob — but the account-level roster is {alice, bob})

    // 🔴 STOP-2: ONE app message from alice is decrypted INDEPENDENTLY by BOTH bob devices (each with its
    // own copy of alice's sender ratchet at this epoch — the transport fan-out delivers a copy to each).
    let wire_a = alice.encrypt_message(gid.clone(), b"hi devices".to_vec()).unwrap();
    let wire_b = alice.encrypt_message(gid.clone(), b"hi devices".to_vec()).unwrap(); // second copy for device B
    assert_eq!(bob_primary.process_incoming(gid.clone(), wire_a).unwrap().plaintext.as_deref(), Some(&b"hi devices"[..]), "device A decrypts");
    assert_eq!(bob_linked.process_incoming(gid.clone(), wire_b).unwrap().plaintext.as_deref(), Some(&b"hi devices"[..]), "device B decrypts");

    // commit-consistency: alice adds carol → BOTH bob devices apply the same commit → all agree on members.
    let (carol, c_id, c_pub) = mk(6, 7, b"carol");
    alice.pin_account(c_id.clone(), c_pub.clone());
    bob_primary.pin_account(c_id.clone(), c_pub.clone());
    bob_linked.pin_account(c_id, c_pub);
    let add_c = alice.add_member(gid.clone(), carol.make_key_package().unwrap()).unwrap();
    bob_primary.process_incoming(gid.clone(), add_c.commit.clone()).unwrap();
    bob_linked.process_incoming(gid.clone(), add_c.commit).unwrap();
    let three = sorted(vec![b"alice".to_vec(), b"bob".to_vec(), b"carol".to_vec()]);
    assert_eq!(sorted(bob_primary.member_account_ids(gid.clone()).unwrap()), three, "device A after carol add");
    assert_eq!(sorted(bob_linked.member_account_ids(gid).unwrap()), three, "device B after carol add (consistent)");
}

#[test]
fn single_use_keypackage_pool_and_last_resort() {
    // SINGLE-USE KP hardening: a pool of DISTINCT one-time KeyPackages (each a fresh init_key) + a
    // reusable last-resort fallback. Proves: (1) the pool members are distinct and each joins ONCE;
    // (2) ghost-defense validates every KP in the pool (same leaf/cert); (3) the last-resort works as a
    // fallback join. (The server pops one per fetch — the "consumed → not served again" replay bound is
    // enforced server-side; here we prove the client-side crypto: distinct init keys, all valid, joinable.)
    let (alice, a_id, a_pub) = mk(1, 2, b"alice");
    let (bob, b_id, b_pub) = mk(3, 4, b"bob");
    alice.pin_account(b_id.clone(), b_pub.clone());
    bob.pin_account(a_id.clone(), a_pub.clone());

    // 🔴 STOP-1 (pool distinct + consumed one-by-one): a pool of 5 one-time KPs are all DIFFERENT bytes
    // (distinct init_keys) → each add consumes a different KP, not one reused KP.
    let pool = bob.make_key_packages(5).unwrap();
    assert_eq!(pool.len(), 5, "pool has 5 KPs");
    let uniq: std::collections::HashSet<&Vec<u8>> = pool.iter().collect();
    assert_eq!(uniq.len(), 5, "all 5 KPs are distinct (fresh init_key each — not a reused KP)");

    // 🔴 STOP-3 (ghost-defense on EVERY pool KP): each parses + validates as a genuine account-certified
    // leaf. A forged pool member would fail here; add_member runs the SAME validate_leafnode gate.
    for (i, kp_wire) in pool.iter().enumerate() {
        let kp_in = KeyPackageIn::tls_deserialize_exact(kp_wire).expect("pool KP parses");
        // the leaf validates against bob's pinned account (ghost-defense) — reuse the crate's validator path
        let gid = alice.create_group().unwrap();
        let add = alice.add_member(gid.clone(), kp_wire.clone());
        assert!(add.is_ok(), "pool KP #{i} passes ghost-defense on add");
        let _ = kp_in; // parsed form (proves well-formed wire)
        // a joiner using THIS specific KP lands in the group (distinct init_key decrypts its own welcome)
        let add = add.unwrap();
        assert_eq!(bob.join_from_welcome(add.welcome, add.ratchet_tree).unwrap(), gid, "join via pool KP #{i}");
    }

    // 🔴 STOP-2 (last-resort fallback): when the pool is exhausted the reusable last-resort KP still joins.
    let (carol, c_id, c_pub) = mk(5, 6, b"carol");
    let (dave, d_id, d_pub) = mk(7, 8, b"dave");
    let (erin, e_id, e_pub) = mk(9, 10, b"erin");
    carol.pin_account(d_id.clone(), d_pub.clone());
    erin.pin_account(d_id, d_pub);
    dave.pin_account(c_id, c_pub);
    dave.pin_account(e_id, e_pub);
    let last_resort = dave.make_last_resort_key_package().unwrap();
    let gid = carol.create_group().unwrap();
    let add = carol.add_member(gid.clone(), last_resort.clone()).unwrap();
    assert_eq!(dave.join_from_welcome(add.welcome, add.ratchet_tree).unwrap(), gid, "last-resort KP joins (fallback works)");
    // last-resort is REUSABLE by design (LastResortExtension): its init secret is NOT consumed on join, so
    // the SAME dave (same provider → still holds the init secret) can join a SECOND group with the same KP.
    let gid2 = erin.create_group().unwrap();
    let add2 = erin.add_member(gid2.clone(), last_resort).unwrap();
    assert_eq!(dave.join_from_welcome(add2.welcome, add2.ratchet_tree).unwrap(), gid2, "last-resort is reusable (bounded fallback)");
    let _ = (a_pub, b_pub);
}

// Build alice + a 2-device bob group (device seeds 4 and 5), all pinned. Returns the clients + ids.
fn alice_bob_two_devices() -> (Arc<MlsClient>, Arc<MlsClient>, Arc<MlsClient>, Vec<u8>) {
    let (alice, a_id, a_pub) = mk(1, 2, b"alice");
    let (bob_primary, b_id, b_pub) = mk(3, 4, b"bob");
    let (bob_linked, _, _) = mk(3, 5, b"bob"); // SAME account, different device (leaf)
    alice.pin_account(b_id, b_pub);
    bob_primary.pin_account(a_id.clone(), a_pub.clone());
    bob_linked.pin_account(a_id, a_pub);
    let gid = alice.create_group().unwrap();
    let add_a = alice.add_member(gid.clone(), bob_primary.make_key_package().unwrap()).unwrap();
    bob_primary.join_from_welcome(add_a.welcome, add_a.ratchet_tree).unwrap();
    let add_b = alice.add_member(gid.clone(), bob_linked.make_key_package().unwrap()).unwrap();
    bob_primary.process_incoming(gid.clone(), add_b.commit).unwrap(); // primary learns of the linked leaf
    bob_linked.join_from_welcome(add_b.welcome, add_b.ratchet_tree).unwrap();
    // KV-03-001: как в приложении — роли у каждого, кто обрабатывает коммиты (mlsWiring).
    for c in [&alice, &bob_primary, &bob_linked] {
        c.set_group_roles(gid.clone(), b"alice".to_vec(), vec![]);
    }
    (alice, bob_primary, bob_linked, gid)
}

#[test]
fn device_removal_pcs() {
    // DEVICE REMOVAL (Stage A): removing ONE device's leaf gives leaf-level PCS — the removed device can't
    // read the new epoch, but the account's OTHER device is untouched. Removing the last device drops the
    // account entirely.
    let (alice, bob_primary, bob_linked, gid) = alice_bob_two_devices();
    let both = sorted(vec![b"alice".to_vec(), b"bob".to_vec()]);
    assert_eq!(sorted(alice.member_account_ids(gid.clone()).unwrap()), both, "before: alice+bob");

    // alice removes bob's LINKED device (device seed 5) → its leaf leaves the tree.
    let commit = alice.remove_device(gid.clone(), b"bob".to_vec(), device_id_of(5)).unwrap();
    // bob_primary applies the remove commit (it stays; only the sibling leaf is gone)
    bob_primary.process_incoming(gid.clone(), commit.clone()).unwrap();
    // bob_linked processes its OWN removal (learns it's out)
    let _ = bob_linked.process_incoming(gid.clone(), commit);

    // 🔴 STOP-2: the account is STILL a member (bob_primary remains) — device removal ≠ account removal.
    assert_eq!(sorted(alice.member_account_ids(gid.clone()).unwrap()), both, "after device remove: bob still present (primary remains)");

    // 🔴 STOP-1: PCS — a NEW-epoch message is READABLE by the surviving device, UNREADABLE by the removed one.
    let post = alice.encrypt_message(gid.clone(), b"post-remove".to_vec()).unwrap();
    let post2 = alice.encrypt_message(gid.clone(), b"post-remove".to_vec()).unwrap();
    assert_eq!(bob_primary.process_incoming(gid.clone(), post).unwrap().plaintext.as_deref(), Some(&b"post-remove"[..]), "surviving device reads");
    assert!(bob_linked.process_incoming(gid.clone(), post2).is_err(), "REMOVED device cannot read the new epoch (leaf-level PCS)");

    // remove the LAST device (primary, seed 4) → the account disappears from the roster.
    let commit2 = alice.remove_device(gid.clone(), b"bob".to_vec(), device_id_of(4)).unwrap();
    let _ = bob_primary.process_incoming(gid.clone(), commit2);
    assert_eq!(alice.member_account_ids(gid).unwrap(), vec![b"alice".to_vec()], "after removing the LAST device, bob is gone");
}

#[test]
fn member_devices_lists_each_leaf() {
    // member_devices returns ONE entry per leaf (device), NOT deduped by account — so the UI can target a
    // specific device for removal. The device_id is cert.device_id (the remove_device target).
    let (alice, bob_primary, _bl, gid) = alice_bob_two_devices();
    let mut devs = alice.member_devices(gid.clone()).unwrap();
    devs.sort_by(|a, b| (a.account_id.clone(), a.device_id.clone()).cmp(&(b.account_id.clone(), b.device_id.clone())));
    // alice (1 device) + bob (2 devices, seeds 4 & 5) = 3 leaves
    assert_eq!(devs.len(), 3, "3 leaves total (alice + 2×bob)");
    let bob_devices: Vec<Vec<u8>> = devs.iter().filter(|d| d.account_id == b"bob").map(|d| d.device_id.clone()).collect();
    assert_eq!(bob_devices.len(), 2, "bob has 2 device entries (not deduped)");
    assert!(bob_devices.contains(&device_id_of(4)) && bob_devices.contains(&device_id_of(5)), "both bob device_ids present");
    // and the device_id member_devices reports is exactly what remove_device targets
    let _ = bob_primary;
    assert!(alice.remove_device(gid, b"bob".to_vec(), device_id_of(4)).is_ok(), "reported device_id is removable");
}

#[test]
fn remove_device_unknown_is_error() {
    let (alice, _bp, _bl, gid) = alice_bob_two_devices();
    // a device_id that isn't in the group (seed 99) → typed error, no state change.
    assert!(alice.remove_device(gid, b"bob".to_vec(), device_id_of(99)).is_err(), "removing a non-member device errors");
}

#[test]
fn revoked_device_not_readmittable() {
    // 🔴 STOP-3: after a device is removed AND its cert revoked (account-signed), ghost-defense refuses to
    // RE-ADD it — add_revocation closes the gap (the TrustStore previously held no revocations, so a revoked
    // device's KP would have passed validate_leaf on a later add).
    let (alice, _bp, bob_linked, gid) = alice_bob_two_devices();
    // remove bob's linked device (seed 5)
    let commit = alice.remove_device(gid.clone(), b"bob".to_vec(), device_id_of(5)).unwrap();
    let _ = bob_linked.process_incoming(gid.clone(), commit);

    // WITHOUT a revocation: alice could re-add the same device's fresh KP (leaf still valid) — the gap.
    let readd_ok = alice.add_member(gid.clone(), bob_linked.make_key_package().unwrap());
    assert!(readd_ok.is_ok(), "without a revocation the removed device is re-addable (the gap this closes)");
    // undo that re-add so the group is clean for the revocation check
    let _ = alice.remove_device(gid.clone(), b"bob".to_vec(), device_id_of(5)).unwrap();

    // The account (seed 3) signs a revocation for the linked device (seed 5); alice registers it.
    let bob_account = SigningKey::from_bytes(&[3u8; 32]);
    let rev = mint_revocation(&bob_account, &device_id_of(5), 0);
    alice.add_revocation(rev.version, rev.device_id.clone(), rev.account_public_key.clone(), rev.revoked_at, rev.signature.clone());

    // Now a re-add of the SAME (revoked) device's KP is REJECTED by ghost-defense (validate_leafnode).
    let readd = alice.add_member(gid, bob_linked.make_key_package().unwrap());
    assert!(readd.is_err(), "a REVOKED device cannot be re-admitted (add_revocation closes the re-add gap)");
}

#[test]
fn export_import_persistence() {
    let (alice, bob, gid, _, (b_id, b_pub)) = two_member_group();

    // alice exports her sealed state (Contract-2 ciphertext) — the persistence foundation.
    let blob = alice.export_state().unwrap();

    // simulate an app RESTART: a fresh alice client (same KEK + device key + identity) re-imports.
    let (alice2, _, _) = mk(1, 2, b"alice");
    alice2.pin_account(b_id, b_pub);
    alice2.import_state(blob).unwrap();

    // the RESTORED client continues the group: encrypt → bob (unchanged) decrypts. Proves state survived.
    let wire = alice2.encrypt_message(gid.clone(), b"after-restart".to_vec()).unwrap();
    let r = bob.process_incoming(gid, wire).unwrap();
    assert_eq!(r.plaintext.as_deref(), Some(&b"after-restart"[..]), "restored client continues the group");
}

#[test]
fn media_filekey_roundtrip() {
    // M3 media: the FILE KEY rides an MLS application message (the app's 0x01+JSON control
    // envelope); the encrypted blob itself never touches MLS (0x02 frames / blob-store).
    // Proves the two properties the JS path relies on: (1) the MLS channel is byte-transparent
    // for a BINARY control envelope (0x01 tag + JSON with key material), and (2) the recovered
    // key actually decrypts a file-layer blob (same AEAD family as the app's file layer).
    use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
    let (alice, bob, gid, _, _) = two_member_group();

    // file layer (sender side): encrypt a "photo" ONCE with a random per-file key.
    let file_key: [u8; 32] = rand::random();
    let photo: Vec<u8> = (0..4096u32).map(|i| (i.wrapping_mul(31) >> 3) as u8).collect();
    let cipher = ChaCha20Poly1305::new_from_slice(&file_key).unwrap();
    let blob = cipher.encrypt(Nonce::from_slice(&[0u8; 12]), photo.as_slice()).unwrap();

    // key envelope: 0x01 || JSON — the shape mlsSendEnvelope produces (fk = key bytes; the JS
    // side base64s them, which is a JSON-encoding detail, not a channel property).
    let env = serde_json::json!({ "t": "media", "k": "photo", "fk": file_key.to_vec(), "size": photo.len() });
    let mut envelope = vec![0x01u8];
    envelope.extend_from_slice(env.to_string().as_bytes());

    // alice → bob over MLS
    let wire = alice.encrypt_message(gid.clone(), envelope.clone()).unwrap();
    let r = bob.process_incoming(gid, wire).unwrap();
    assert!(matches!(r.kind, IncomingKind::Application), "kind = application");
    let got = r.plaintext.expect("application plaintext");
    assert_eq!(got, envelope, "binary control envelope survives byte-for-byte");

    // receiver side: split the tag, parse the JSON, recover the file key, decrypt the blob.
    assert_eq!(got[0], 0x01, "control tag intact");
    let parsed: serde_json::Value = serde_json::from_slice(&got[1..]).unwrap();
    assert_eq!(parsed["t"], "media");
    let recovered: Vec<u8> = parsed["fk"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap() as u8).collect();
    let cipher2 = ChaCha20Poly1305::new_from_slice(&recovered).unwrap();
    let plain = cipher2.decrypt(Nonce::from_slice(&[0u8; 12]), blob.as_slice()).unwrap();
    assert_eq!(plain, photo, "file key delivered over MLS decrypts the blob");
}


#[test]
fn b8_a_proposal_that_settled_before_the_fix_is_cleared_on_load() {
    // B8 — THE TAIL. Refusing new proposals (dispatch.rs) does nothing about one that settled in
    // storage BEFORE the change, and a settled proposal is not inert: commit_builder consumes the
    // pending-proposal store by default, so it would ride out in the next commit and we would believe
    // the hole was closed. Inner::group_mut clears on load; this proves it on a state that HAS one.
    //
    // The proposal is planted the way the old code planted it — store_pending_proposal on the group
    // itself — because no path can produce one any more, which is the whole point.
    let (alice, bob, gid, _, (b_id, b_pub)) = two_member_group();

    let planted = {
        let mut g = alice.inner.lock().unwrap();
        let Inner { provider, signer, groups, .. } = &mut *g;
        let group = groups.get_mut(&gid).expect("alice holds the group");
        // A Remove aimed at somebody else — the case that bypassed the roles chain.
        let (_msg, _r) = group
            .propose_remove_member(&*provider, &*signer, LeafNodeIndex::new(1))
            .expect("propose");
        let n = group.pending_proposals().count();
        assert_eq!(n, 1, "planted a proposal, as the old code would have stored it");
        n
    };
    assert_eq!(planted, 1);

    // Round-trip through the sealed blob: import_state drops the RAM cache, so the next use of the
    // group goes through Inner::group_mut and reloads it from storage — the path that now clears.
    let blob = alice.export_state().unwrap();
    let (alice2, _, _) = mk(1, 2, b"alice");
    alice2.pin_account(b_id, b_pub);
    alice2.import_state(blob).unwrap();

    // Any operation forces the load. members() is a pure read.
    let _ = alice2.member_account_ids(gid.clone()).unwrap();
    {
        let g = alice2.inner.lock().unwrap();
        let group = g.groups.get(&gid).expect("group loaded");
        assert_eq!(
            group.pending_proposals().count(),
            0,
            "a proposal that settled before the fix must not survive the load"
        );
    }

    // And the group still works afterwards: clearing the store is not clearing the group.
    let wire = alice2.encrypt_message(gid.clone(), b"still here".to_vec()).unwrap();
    let r = bob.process_incoming(gid, wire).unwrap();
    assert_eq!(r.plaintext.as_deref(), Some(&b"still here"[..]), "the group survived the clear");
}

/// KV-03-001 — НАЗВАННЫЙ СЦЕНАРИЙ АУДИТА, целиком, через FFI.
///
/// Права на изменение состава проверялись только у ОТПРАВИТЕЛЯ (`mlsRemoveMember` → `mlsRoles.isAdmin`).
/// На приёме `walk_staged_commit` смотрит КЛЮЧИ и не смотрит автора; `remove_proposals()` не
/// вызывался ни разу. Значит любой участник мог закоммитить удаление владельца, и все мержили —
/// личность бралась из тела сообщения, а не из локального состояния (ROOT-1).
///
/// Проверяется, что отвергают ВСЕ, а не только жертва: и владелец, и посторонний участник.
#[test]
fn non_admin_removing_the_owner_is_refused_by_everyone() {
    let (alice, bob, gid, (a_id, a_pub), (b_id, b_pub)) = two_member_group();
    // Третий участник — чтобы проверить не только жертву. carol обычный член, как и bob.
    let (carol, c_id, c_pub) = mk(5, 6, b"carol");
    alice.pin_account(c_id.clone(), c_pub.clone());
    bob.pin_account(c_id, c_pub);
    carol.pin_account(a_id, a_pub);
    carol.pin_account(b_id.clone(), b_pub);
    let add = alice.add_member(gid.clone(), carol.make_key_package().unwrap()).unwrap();
    alice.merge_pending(gid.clone()).unwrap();
    bob.process_incoming(gid.clone(), add.commit).unwrap();
    carol.join_from_welcome(add.welcome, add.ratchet_tree).unwrap();
    carol.set_group_roles(gid.clone(), b"alice".to_vec(), vec![]);

    let a_fp = alice.group_state_fp(gid.clone()).unwrap();
    let c_fp = carol.group_state_fp(gid.clone()).unwrap();

    // bob — не админ — коммитит удаление ВЛАДЕЛЬЦА. Его собственный крейт коммит соберёт: права
    // здесь и не проверялись, в этом вся находка.
    let evil = bob.remove_member(gid.clone(), b"alice".to_vec()).unwrap();

    // 🔴 ЖЕРТВА отвергает.
    let ra = alice.process_incoming(gid.clone(), evil.clone());
    assert!(ra.is_err(), "владелец обязан отвергнуть коммит, снимающий его самого");
    // 🔴 И ПОСТОРОННИЙ тоже — иначе группа расколется на тех, кто применил, и тех, кто нет.
    let rc = carol.process_incoming(gid.clone(), evil);
    assert!(rc.is_err(), "посторонний участник обязан отвергнуть тот же коммит");

    // 🔴 И НИЧЕГО НЕ ПРИМЕНЕНО — отпечаток состояния (эпоха + дерево + расширения + ссылки на
    // отложенные предложения) байт в байт тот же. Отказ, который всё же сдвинул состояние, был бы
    // хуже пропуска: расхождение без единого признака.
    assert_eq!(alice.group_state_fp(gid.clone()).unwrap(), a_fp, "у владельца состояние не сдвинулось");
    assert_eq!(carol.group_state_fp(gid.clone()).unwrap(), c_fp, "у постороннего тоже");
    assert!(
        alice.member_account_ids(gid.clone()).unwrap().contains(&b"alice".to_vec()),
        "владелец на месте"
    );

    // КОНТРОЛЬ, без которого всё выше доказывает лишь «всё отвергается»: ВЛАДЕЛЕЦ удаляет обычного
    // участника — обязано пройти и примениться.
    let good = alice.remove_member(gid.clone(), b_id).unwrap();
    alice.merge_pending(gid.clone()).unwrap();
    let rc2 = carol.process_incoming(gid.clone(), good).unwrap();
    assert!(matches!(rc2.kind, IncomingKind::CommitMerged), "легальное удаление админом применяется");
    assert!(
        !carol.member_account_ids(gid).unwrap().contains(&b"bob".to_vec()),
        "и bob действительно вышел из состава"
    );
}
