// dispatch.rs — the AS-callback DISPATCHER: the process_message glue that routes EVERY branch to its
// validator and FAILS CLOSED (applies merge/store/join ONLY after the validator returns Ok). The
// validators in as_validate.rs are sound in isolation; ghost-protection actually CLOSES here. The bug
// class the auditor flagged ("primary path covered, a secondary path slips through") lives in a
// dispatcher that forgets to call a validator on some branch — so every branch is tested to prove the
// validator is invoked AND that Err ⇒ nothing is applied (no merge, no store, no join, no persisted write).
//
// Branches of MlsGroup::process_message → ProcessedMessageContent (verified in OpenMLS 0.8.1 source):
//   ApplicationMessage          → return plaintext (no membership change).
//   StagedCommitMessage         → walk_staged_commit (Add + Update + commit-PATH + GCE/B2.4),
//                                 incl. an EXTERNAL commit (its committer leaf rides update_path_leaf_node)
//                                 and BY-REFERENCE proposals (resolved into the queue) → merge only on Ok.
//   ProposalMessage             → validate_queued_proposal → store only on Ok (hermetic store-time gate).
//   ExternalJoinProposalMessage → validate_queued_proposal → store only on Ok.
// Welcome (separate entry; not a process_message branch):
//   dispatch_welcome → required_capabilities ≥ floor (Welcome-reject-below-floor) + walk_welcome_tree
//                      (whole tree, B1.3) → into_group only on Ok.

use openmls::ciphersuite::hash_ref::ProposalRef;
use openmls::group::StagedWelcome;
use openmls::messages::group_info::GroupInfo;
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;
use openmls_traits::signatures::Signer;
use openmls_traits::OpenMlsProvider;

use crate::as_validate::{
    decode_identity,
    validate_leafnode, walk_staged_commit, walk_welcome_tree, CommitReject,
    LeafReject, TrustStore,
};
use crate::policy::{assert_ciphersuite, check_no_downgrade, may_remove, DowngradeReject, GroupRoles, MembershipReject, KVANT_DEVCERT_EXT};

#[derive(Debug, PartialEq, Eq)]
pub enum Disposition {
    Application(Vec<u8>),
    CommitMerged,
    // B8: NO LONGER CONSTRUCTED — nothing stores a proposal any more (see the refusal below), so
    // `cargo build` reports this variant as dead. Kept deliberately: it is mapped to
    // IncomingKind::ProposalStored across the FFI and JS still carries that member in its union
    // (mlsGroups.ts, mlsLeave.decideIncoming ignores it). Deleting the variant to quiet the warning
    // would change the FFI enum's shape for a value that costs nothing to keep.
    ProposalStored,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DispatchReject {
    Commit(CommitReject), // a commit/proposal leaf or B2.4 downgrade failed AS-validation
    Leaf(LeafReject),     // a welcome-tree leaf failed AS-validation
    BelowFloor(DowngradeReject), // welcome: the group's required_capabilities < floor
    Process(String),      // OpenMLS rejected the message (incl. UnauthorizedExternalCommitMessage)
    // B8: a standalone proposal arrived. Carries the TYPE, because in the field "we are being fed
    // Remove proposals" and "some other client sends something we do not use" are the same event
    // otherwise, and only one of them is an attack.
    ProposalRefused(&'static str),
    Apply(String),        // a storage error while merging/storing/joining
    Deserialize,          // malformed wire bytes
    // 0.9: our OWN message fanned back by the delivery service (OwnPendingCommit / OwnPrivateMessage).
    // The kvant transport never echoes to self (fan-out excludes the sender) and own commits are merged
    // at SEND time (guarded_add_members → merge), so a pending commit can never be waiting here. If an
    // echo still arrives it is dropped FAIL-CLOSED: no merge, no plaintext surfaced, no state change.
    OwnEcho(&'static str),
    // §10.11: наша ПРЕДВАРИТЕЛЬНАЯ отбраковка Welcome по шифронабору. Отдельным именем, а не общим
    // Process, ровно по той же причине, что и ProposalRefused выше: в поле «нам шлют Welcome с чужим
    // набором» и «OpenMLS что-то не понравилось» — разные события, и только одно из них атака.
    WrongCiphersuite(u16),
    // KV-03-001: автор коммита не имеет права на это изменение состава. Отдельным именем и с
    // ПРИЧИНОЙ внутри — «не админ», «нельзя удалять владельца» и «роли ещё не доехали» это три
    // разных события: первые два атака или ошибка, третье — гонка доставки, которая пройдёт сама.
    MembershipRefused(MembershipReject),
}

/// B8: name the proposal type for the refusal, so a log line separates an attack from noise.
fn proposal_kind(p: &Proposal) -> &'static str {
    match p {
        Proposal::Add(_) => "Add",
        Proposal::Update(_) => "Update",
        Proposal::Remove(_) => "Remove",
        Proposal::PreSharedKey(_) => "PreSharedKey",
        Proposal::ReInit(_) => "ReInit",
        Proposal::ExternalInit(_) => "ExternalInit",
        Proposal::GroupContextExtensions(_) => "GroupContextExtensions",
        Proposal::SelfRemove => "SelfRemove",
        Proposal::Custom(_) => "Custom",
        // Unreachable with the features this crate compiles, and kept anyway: the variants behind
        // extensions-draft (AppDataUpdate, AppEphemeral) would otherwise break the build if the
        // feature were ever enabled, and a new variant must be NAMED here rather than silently
        // becoming "other" in the one log line that says we are under attack.
        #[allow(unreachable_patterns)]
        _ => "Unknown",
    }
}

/// Dispatch an incoming GROUP message (commit / proposal / external-join / application). Fails closed:
/// a commit is merged / a proposal is stored ONLY after its validator returns Ok. On any reject NOTHING
/// is applied — the group epoch and the persisted storage are left untouched.
/// Аккаунт из credential-а (те же байты канонического ника, что в pin_account и в ролях).
fn account_of(cred: &Credential) -> Option<Vec<u8>> {
    let basic = BasicCredential::try_from(cred.clone()).ok()?;
    decode_identity(basic.identity()).map(|(account_id, _cert)| account_id)
}

/// KV-03-001. Для каждого Remove в коммите: чей это лист и можно ли автору его удалить.
///
/// Лист → аккаунт берётся из ТЕКУЩЕГО дерева (до мержа), потому что после мержа удаляемого листа
/// там уже нет. Лист, которого в дереве нет, и лист с нечитаемым credential-ом — отказ: «не смог
/// определить, чьё это» не то же самое, что «ничьё».
fn check_remove_authority(
    group: &MlsGroup,
    sc: &StagedCommit,
    committer: Option<&[u8]>,
    roles: Option<&GroupRoles>,
) -> Result<(), DispatchReject> {
    let mut removes = sc.remove_proposals().peekable();
    if removes.peek().is_none() {
        return Ok(()); // состав не меняется — спрашивать не о чем
    }
    let committer = match committer {
        Some(c) => c,
        // Автор не опознан, а коммит трогает состав. Фейл-клоузд: без имени автора любое правило
        // о правах бессмысленно.
        None => return Err(DispatchReject::MembershipRefused(MembershipReject::NotAdmin)),
    };
    for rem in removes {
        let idx = rem.remove_proposal().removed();
        let removed_account = group
            .members()
            .find(|m| m.index == idx)
            .and_then(|m| account_of(&m.credential));
        let removed_account = match removed_account {
            Some(a) => a,
            None => return Err(DispatchReject::MembershipRefused(MembershipReject::NotAdmin)),
        };
        may_remove(roles, committer, &removed_account).map_err(DispatchReject::MembershipRefused)?;
    }
    Ok(())
}

pub fn dispatch_group_message<P: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &P,
    wire: &[u8],
    ts: &TrustStore,
    roles: Option<&GroupRoles>,
) -> Result<Disposition, DispatchReject> {
    let msg = MlsMessageIn::tls_deserialize_exact(wire).map_err(|_| DispatchReject::Deserialize)?;
    let proto = msg.try_into_protocol_message().map_err(|_| DispatchReject::Deserialize)?;
    let processed = group
        .process_message(provider, proto)
        .map_err(|e| DispatchReject::Process(format!("{e:?}")))?;

    // KV-03-001: аккаунт АВТОРА берётся из credential-а отправителя, который OpenMLS уже сверил с
    // деревом, — не из тела сообщения. Читается ДО into_content(), потому что тот забирает
    // `processed` целиком. None здесь означает «credential не декодируется» — для коммита это
    // отказ ниже, а не молчаливое разрешение.
    let committer = account_of(processed.credential());

    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => {
            Ok(Disposition::Application(app.into_bytes()))
        }
        ProcessedMessageContent::StagedCommitMessage(sc) => {
            // FAIL-CLOSED: validate every leaf path (incl. commit-PATH self/external update, by-reference
            // proposals) + B2.4 downgrade BEFORE merging. On Err we return without merging → no state change.
            walk_staged_commit(&sc, ts).map_err(DispatchReject::Commit)?;
            // KV-03-001 — ПОЛНОМОЧИЯ, а не ключи. walk_staged_commit выше отвечает на вопрос «не
            // появился ли в дереве непривязанный лист»; здесь — на вопрос «а этому автору вообще
            // можно менять состав». Место выбрано не случайно: после process_message (иначе Remove
            // не виден — он в шифрованной части) и ДО merge (иначе изменение уже применено).
            // Отложить решение нельзя: ratchet приёма уже сдвинут и кадр повторно не обработать —
            // поэтому роли обязаны быть резидентны здесь, а не запрашиваться из JS.
            check_remove_authority(group, &sc, committer.as_deref(), roles)?;
            group
                .merge_staged_commit(provider, *sc)
                .map_err(|e| DispatchReject::Apply(format!("{e:?}")))?;
            Ok(Disposition::CommitMerged)
        }
        // B8 — NO INCOMING PROPOSAL IS STORED. Read the note below before "restoring" this.
        //
        // What was here: AS-validate the proposal, then store it. The validation covers Add, Update
        // and GroupContextExtensions; everything else fell into `_ => Ok(())` in
        // as_validate::validate_queued_proposal and was stored unchecked — Remove, PreSharedKey,
        // ReInit, ExternalInit, SelfRemove, Custom. And a stored proposal is not inert: every kvant
        // commit goes through OpenMLS's commit_builder, whose `consume_proposal_store` DEFAULTS TO
        // TRUE (commit_builder.rs:125), so the group's pending proposals ride along in the next
        // commit anybody makes. Two of those six are serious:
        //   * Remove  — any member could queue the removal of any other member, and the next honest
        //               commit would carry it out. That bypasses the whole owner-signed roles chain,
        //               which exists precisely to decide who may remove whom.
        //   * PreSharedKey — queues a PSK we do not hold; every later commit loads PSKs while being
        //               built, so the group stops being able to commit at all. Nobody can add,
        //               remove, or heal.
        //
        // Why refuse ALL of them rather than authorise Remove properly: kvant does not send proposals
        // at all. Every membership change is a direct commit (add_member / remove_member /
        // remove_device); guarded_propose_add_member exists in this file but has no client.rs method
        // and no FFI, so its only callers are this crate's own tests. There is therefore no
        // legitimate sender of a standalone proposal anywhere in the system, and nothing — old
        // clients included — breaks by refusing them. Authorising Remove alone would have closed one
        // of the six doors and left the group-wedging one open.
        //
        // THE PRICE, so the next person does not think this was an oversight: if leave_group (the
        // protocol-level "remove me", which posts a Remove proposal for another member to commit) or
        // by-reference Adds are ever wanted, this decision has to be revisited DELIBERATELY — with
        // an authorisation rule for what may be stored, not by deleting this branch. The analysis is
        // B8.1; the leave path it was weighed against is the signed t:'gleave' envelope.
        ProcessedMessageContent::ProposalMessage(qp)
        | ProcessedMessageContent::ExternalJoinProposalMessage(qp) => {
            Err(DispatchReject::ProposalRefused(proposal_kind(qp.proposal())))
        }
        // 0.9 new variants — both are echoes of OUR OWN traffic, impossible in the kvant flow (fan-out
        // excludes self; own commits merge at send time). FAIL-CLOSED: reject, apply nothing. We
        // deliberately do NOT follow the library hint to merge_pending_commit() here — an implicit merge
        // on the RECEIVE path would bypass the send-time guarded_add_members discipline.
        ProcessedMessageContent::OwnPendingCommit => Err(DispatchReject::OwnEcho(
            "own pending commit fanned back — not merged (kvant merges own commits at send time)",
        )),
        ProcessedMessageContent::OwnPrivateMessage => Err(DispatchReject::OwnEcho(
            "own private message fanned back — dropped, never surfaced as plaintext",
        )),
        // NOTE: ProcessedMessageContent::UnresolvedAppDataCommit exists only behind the openmls
        // `extensions-draft` feature, which this crate deliberately does NOT enable — the variant is
        // not compiled into the enum, so this match stays exhaustive without it. Keep it that way.
    }
}

/// Dispatch an incoming WELCOME (join). Fails closed: validates the group's capability floor AND the
/// WHOLE ratchet tree before joining; on any reject the join does NOT happen (no group is created).
pub fn dispatch_welcome<P: OpenMlsProvider>(
    provider: &P,
    join_config: &MlsGroupJoinConfig,
    welcome: Welcome,
    ratchet_tree: Option<RatchetTreeIn>,
    ts: &TrustStore,
) -> Result<MlsGroup, DispatchReject> {
    // B6.2 — RE-JOINING A GROUP WE WERE EVICTED FROM.
    //
    // new_from_welcome hardcodes replace_old_group=false, so a Welcome for a group we still hold any
    // state for is refused with GroupAlreadyExists — BEFORE the floor check and the tree walk below.
    // After an eviction that state is the dead husk left by merge_staged_commit's self_removed()
    // branch: Inactive, unable to decrypt or encrypt anything (UseAfterEviction), and nothing ever
    // clears it. So an admin who re-adds a member they had removed mints a Welcome that the member
    // cannot act on, and the member stays out of the group forever while appearing to be in it.
    //
    // Replacing state on the strength of an incoming message is a remotely triggered destruction of
    // local data, so it is gated on a LOCALLY decided predicate: the existing group must be INACTIVE.
    //   * inactive ⇒ provably worthless. Every operation on it returns UseAfterEviction, and the
    //     message history lives in the app's own store, not here — there is nothing to lose.
    //   * active ⇒ still refused, exactly as before. Otherwise a Welcome would become a "wipe my group
    //     state" primitive that any sender could aim at a group we are happily in.
    // The group id used for the lookup is UNVERIFIED at this point, which is safe precisely because of
    // that gate: a forged id can only name some other local group, and an active one is not replaced.
    //
    // MlsGroup::delete before the replace, rather than the replace alone: the flag only skips the
    // existence check, so state the new join does not happen to overwrite (old epoch key pairs,
    // message secrets of epochs past) would linger in the sealed store as garbage.
    // §10.11 — ОТБРАКОВКА ДО OpenMLS, и порядок здесь и есть всё содержание правки.
    //
    // `keys_for_welcome` внутри build_from_welcome ПОТРЕБЛЯЕТ подходящий (не last-resort) KeyPackage
    // ДО того, как сравнит шифронаборы, а единственная проверка перед ним — `crypto().supports()`,
    // который чужой, но ПОДДЕРЖИВАЕМЫЙ набор (провайдер умеет 0x0001, 0x0003, 0x004D) пропускает.
    // Значит Welcome с чужим набором отвергался — и по дороге съедал одноразовый KeyPackage жертвы,
    // ничего не открыв. Дешёвое и незаметное исчерпание: пул вычерпывается со скоростью, которую
    // задаёт отправитель, а пополняется со скоростью, которую задаём мы, и после этого жертву просто
    // нельзя пригласить в группу.
    //
    // Чинится тем, что набор виден СРАЗУ: он лежит в первых двух байтах провода Welcome и доступен
    // как `welcome.ciphersuite()` без единого обращения к хранилищу. Отказ здесь не потребляет
    // ничего. Порядок «потребить, потом проверить» остаётся внутри библиотеки — мы просто не даём
    // ей дойти до него.
    assert_ciphersuite(u16::from(welcome.ciphersuite()))
        .map_err(|_| DispatchReject::WrongCiphersuite(u16::from(welcome.ciphersuite())))?;
    let jb = StagedWelcome::build_from_welcome(provider, join_config, welcome)
        .map_err(|e| DispatchReject::Process(format!("{e:?}")))?;
    // PRESENCE comes from the PUBLIC group, ACTIVITY from MlsGroup — and they are not the same
    // question. write_group_state runs only when a commit is merged (processing.rs:475), so a group
    // that was joined and has merged nothing yet has NO group-state key and MlsGroup::load answers
    // None for it. Asking MlsGroup alone would therefore read "no such group" for a perfectly live
    // freshly-joined one and replace it without a murmur — and since OpenMLS's own already-exists
    // check uses that same load, that hole was there before this change too. PublicGroup::load reads
    // the tree, which the join does write, so it is the honest presence probe.
    let gid = jb.processed_welcome().unverified_group_info().group_id().clone();
    let present = PublicGroup::load(provider.storage(), &gid)
        .map_err(|e| DispatchReject::Apply(format!("{e:?}")))?
        .is_some();
    // Absent group-state means "never evicted" ⇒ treat as ALIVE. The fail-safe direction: unsure
    // about a group means keep it, never replace it.
    let evicted = MlsGroup::load(provider.storage(), &gid)
        .map_err(|e| DispatchReject::Apply(format!("{e:?}")))?
        .map(|g| !g.is_active())
        .unwrap_or(false);
    let jb = match (present, evicted) {
        (false, _) => jb,
        (true, true) => {
            let mut old = MlsGroup::load(provider.storage(), &gid)
                .map_err(|e| DispatchReject::Apply(format!("{e:?}")))?
                .ok_or_else(|| DispatchReject::Apply("evicted group vanished between reads".into()))?;
            old.delete(provider.storage())
                .map_err(|e| DispatchReject::Apply(format!("{e:?}")))?;
            jb.replace_old_group()
        }
        // The crate has no logger, so the branches name themselves where they can be READ: this one
        // through a reject string distinct from the library's bare GroupAlreadyExists (so the field can
        // tell OUR gate from OpenMLS's check), and the replace above through the caller, which knows
        // whether it held a dead group before the join.
        (true, false) => return Err(DispatchReject::Process("GroupAlreadyExists: LIVE group — welcome refused, state untouched".into())),
    };
    let jb = match ratchet_tree { Some(t) => jb.with_ratchet_tree(t), None => jb };
    let staged = jb
        .build()
        .map_err(|e| DispatchReject::Process(format!("{e:?}")))?;
    // Welcome-reject-below-floor: the group we are about to join MUST itself require at least the
    // capability floor, or future Adds in it would not be gated by required_capabilities.
    // (Defense-in-depth — validate_leaf below is the always-on ghost enforcement; see policy.rs.)
    match staged.group_context().extensions().required_capabilities() {
        Some(rc) => check_no_downgrade(rc).map_err(DispatchReject::BelowFloor)?,
        None => {
            return Err(DispatchReject::BelowFloor(
                DowngradeReject::MissingRequiredExtension(KVANT_DEVCERT_EXT),
            ))
        }
    }
    // B1.3: validate EVERY member of the tree A2 handed us before trusting it.
    walk_welcome_tree(&staged, ts).map_err(DispatchReject::Leaf)?;
    staged
        .into_group(provider)
        .map_err(|e| DispatchReject::Apply(format!("{e:?}")))
}

// ----------------------------- SEND side (symmetric) -------------------------
// Ghost-defense is SYMMETRIC. The dispatcher above covers RECEIVE (leaves OTHERS introduce). But when
// WE add a member, the KeyPackage came from the untrusted server: if A2 hands us a ghost KeyPackage for
// "alice" (attacker key, not chaining to the pin), add_members would let US add the ghost. So validate
// EVERY added leaf with the SAME validator (validate_leafnode), BEFORE forming the commit — fail-closed
// with no pending state created. This closes the seam between the receive AS-callback and membership ops.

/// `add_members` with the SEND-side AS-guard. Validates each added KeyPackage's leaf against the TOFU
/// pin BEFORE staging the commit; on a ghost KeyPackage it returns Err and NO commit is formed.
pub fn guarded_add_members<P: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &P,
    signer: &impl Signer,
    key_packages: &[KeyPackage],
    ts: &TrustStore,
) -> Result<(MlsMessageOut, MlsMessageOut, Option<GroupInfo>), DispatchReject> {
    for kp in key_packages {
        validate_leafnode(kp.leaf_node(), ts).map_err(DispatchReject::Leaf)?;
    }
    group
        .add_members(provider, signer, key_packages)
        .map_err(|e| DispatchReject::Apply(format!("{e:?}")))
}

/// `propose_add_member` with the SAME SEND-side guard, for completeness. Kvant currently exposes only
/// `guarded_add_members` (the direct commit-flow), so the proposal-flow add is NOT in use. This wrapper
/// closes that path BY CONSTRUCTION: if a future integration adds via propose-then-commit, the
/// server-supplied KeyPackage gets the identical `validate_leafnode` gate BEFORE the proposal is created,
/// so a ghost can never be proposed. (self-update = own key, remove = no new key, external-commit =
/// disabled — those need no guard, per the auditor.)
pub fn guarded_propose_add_member<P: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &P,
    signer: &impl Signer,
    key_package: &KeyPackage,
    ts: &TrustStore,
) -> Result<(MlsMessageOut, ProposalRef), DispatchReject> {
    validate_leafnode(key_package.leaf_node(), ts).map_err(DispatchReject::Leaf)?;
    group
        .propose_add_member(provider, signer, key_package)
        .map_err(|e| DispatchReject::Apply(format!("{e:?}")))
}

#[cfg(test)]
mod tests;
