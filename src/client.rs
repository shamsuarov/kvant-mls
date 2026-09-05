// client.rs — M3 MlsClient: the app-facing MLS bridge (uniffi Object). ORCHESTRATION ONLY — every method
// delegates to a VERIFIED spike function, inheriting its auditor + fuzz verification. It does NOT
// reimplement any security core:
//   add_member        → guarded_add_members   (SEND-side ghost-defense: validate_leafnode before commit)
//   process_incoming  → dispatch_group_message (RECEIVE fail-closed, every branch) under guard() [Contract-1]
//   join_from_welcome → dispatch_welcome        (whole-tree ghost check B1.3 + capability floor)
//   storage           → KseProvider             (Contract-2: no plaintext at rest)
// M3 is a PARALLEL MLS path. Sender-Keys (senderkey.js) and the production 1:1/group/call paths are
// untouched; Sender-Keys→MLS migration is M5, later. State persistence = app-managed sealed blobs
// (export_state/import_state, decision 2b) so a restored client survives an app restart.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;

use crate::as_validate::{decode_identity, TrustStore};
use crate::devicecert::{DeviceCert, Revocation};
use crate::dispatch::{dispatch_group_message, dispatch_welcome, guarded_add_members, DispatchReject, Disposition};
use crate::policy::{assert_ciphersuite, floor_required_capabilities, GroupRoles};
use crate::storage::KseProvider;
use crate::{guard, MlsError};

const CS: Ciphersuite = crate::CIPHERSUITE;

fn m<E: std::fmt::Debug>(e: E) -> MlsError {
    MlsError::Mls(format!("{e:?}"))
}
fn rej(e: DispatchReject) -> MlsError {
    MlsError::Mls(format!("reject: {e:?}"))
}

// Every Kvant leaf advertises the device-cert floor caps (else OpenMLS rejects it vs required_capabilities).
// LastResort is declared as a SUPPORTED extension (not required) so a last-resort KP — which carries the
// LastResortExtension — is accepted on add (else OpenMLS rejects it UnsupportedExtension). This is a
// capability declaration only; it does NOT change the required_capabilities FLOOR (floor_required_capabilities).
fn kvant_caps() -> Capabilities {
    Capabilities::new(
        None,
        Some(&[CS]),
        Some(&[crate::policy::KVANT_DEVCERT_EXT, ExtensionType::LastResort]),
        None,
        Some(&[CredentialType::Basic]),
    )
}
// Group create-config carrying the required_capabilities floor (so Adds are gated + Welcome floor holds).
fn group_config() -> MlsGroupCreateConfig {
    let gce = Extensions::single(Extension::RequiredCapabilities(floor_required_capabilities()))
        .expect("gce");
    MlsGroupCreateConfig::builder()
        .ciphersuite(CS)
        .capabilities(kvant_caps())
        .with_group_context_extensions(gce)
        .build()
}

// Decode the (account_id, device_cert) carried in a member's BasicCredential
// (identity = encode_identity(account_id, cert)).
fn cred_identity(credential: &Credential) -> Option<(Vec<u8>, DeviceCert)> {
    let basic = BasicCredential::try_from(credential.clone()).ok()?;
    decode_identity(basic.identity())
}
fn cred_account_id(credential: &Credential) -> Option<Vec<u8>> {
    cred_identity(credential).map(|(account_id, _cert)| account_id)
}

// ----------------------------- FFI result types ------------------------------

#[derive(uniffi::Record)]
pub struct AddResult {
    pub commit: Vec<u8>,       // MlsMessageOut wire (send to existing members)
    pub welcome: Vec<u8>,      // MlsMessageOut wire (send to the new member)
    pub ratchet_tree: Vec<u8>, // the new member needs the tree to join
}

#[derive(uniffi::Enum)]
pub enum IncomingKind {
    Application,    // an application message → plaintext returned
    CommitMerged,   // a membership commit was applied
    ProposalStored, // a proposal was stored
}

#[derive(uniffi::Record)]
pub struct IncomingResult {
    pub kind: IncomingKind,
    pub plaintext: Option<Vec<u8>>,
}

#[derive(uniffi::Record)]
pub struct MemberAccountKey {
    pub account_id: Vec<u8>,          // canonical-nick bytes (as in member_account_ids)
    pub account_public_key: Vec<u8>,  // the account's Ed25519 pub, ATTESTED by the validated tree leaf
}

#[derive(uniffi::Record)]
pub struct MemberDevice {
    pub account_id: Vec<u8>,  // canonical-nick bytes
    pub device_id: Vec<u8>,   // cert.device_id (fingerprint of the MLS leaf key) — the remove_device target
}

// ----------------------------- the client ------------------------------------

struct Inner {
    provider: KseProvider,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    account_id: Vec<u8>,
    ts: TrustStore,
    // KV-03-001: роли по группам, протолкнутые из JS после проверки owner-signed цепочки. В ПАМЯТИ —
    // как и отзывы в TrustStore, и по той же причине пере-подаются на старте (mlsWiring).
    roles: HashMap<Vec<u8>, GroupRoles>,
    groups: HashMap<Vec<u8>, MlsGroup>, // live handles; repopulated from storage after import
}

#[derive(uniffi::Object)]
pub struct MlsClient {
    inner: Mutex<Inner>, // single lock → MlsClient is Send+Sync for uniffi
}

impl Inner {
    // Get a live group handle: from the cache, else load from the (possibly just-imported) sealed storage.
    fn group_mut(&mut self, gid: &[u8]) -> Result<&mut MlsGroup, MlsError> {
        if !self.groups.contains_key(gid) {
            let group_id = GroupId::from_slice(gid);
            let mut loaded = MlsGroup::load(self.provider.storage(), &group_id)
                .map_err(m)?
                .ok_or_else(|| MlsError::Mls("group not found".into()))?;
            // B8 — THE TAIL. dispatch.rs refuses to store any incoming proposal from now on, but a
            // proposal that settled BEFORE this change is still sitting in storage, and it is not
            // inert: commit_builder consumes the pending-proposal store by default, so it would ride
            // out in the next commit and we would believe the hole was closed. Clearing on load makes
            // the invariant true rather than true-going-forward: the store is empty, and a kvant
            // commit therefore carries exactly what the caller asked for and nothing swept up.
            // Best-effort: a storage error here must not make an otherwise healthy group unusable.
            let _ = loaded.clear_pending_proposals(self.provider.storage());
            // KV-11-006 — ЧЕТВЁРТЫЙ ВХОД, и единственный, где наш ассерт не декоративен. Семь
            // контролей шифронабора внутри OpenMLS (перечислены в шапке assert_ciphersuite) стоят на
            // ВСТУПЛЕНИИ в группу: создание, Welcome, Add. Группа, уже лежащая в хранилище, не
            // проходит ни один из них — она считается доверенной. Здесь это и проверяется.
            assert_ciphersuite(u16::from(loaded.ciphersuite()))
                .map_err(|e| MlsError::Mls(format!("stored group: {e:?}")))?;
            self.groups.insert(gid.to_vec(), loaded);
        }
        Ok(self.groups.get_mut(gid).unwrap())
    }
}

/// ОДНО определение отпечатка состояния членства на всех потребителей: экспорт FFI (group_state_fp),
/// аудиторскую проверку Q4 v2 и фаззинг. Раньше их было два — здесь и в фаззинг-модуле ниже; две
/// копии одного хеша расходятся ровно тогда, когда одну из них поправят, и тогда сторож начинает
/// врать в обе стороны сразу (тот же довод записан в crate-provenance.sh).
///
/// Что входит: эпоха, ratchet tree, расширения GroupContext и отсортированные ссылки на отложенные
/// предложения. Двигается ТОЛЬКО при мерже коммита.  [mls state fingerprint]
fn state_fp(g: &MlsGroup) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(g.epoch().as_u64().to_be_bytes());
    h.update(RatchetTreeIn::from(g.export_ratchet_tree()).tls_serialize_detached().unwrap_or_default());
    h.update(g.extensions().tls_serialize_detached().unwrap_or_default());
    let mut refs: Vec<Vec<u8>> = g.pending_proposals().map(|qp| qp.proposal_reference_ref().as_slice().to_vec()).collect();
    refs.sort();
    for r in refs { h.update(r); }
    h.finalize().to_vec()
}

/// Что видно в кадре БЕЗ обработки (см. peek_frame). Неаутентифицировано by design.
#[derive(uniffi::Record)]
pub struct FramePeek {
    pub epoch: u64,
    pub group_id: Vec<u8>,
    pub is_commit: bool,
    pub is_application: bool,
}

#[uniffi::export]
impl MlsClient {
    /// Build from the app's stable Keystore KEK + this device's EXISTING C3-LINKED identity — the same
    /// device Ed25519 key and account cert as the 1:1 path (decision 4). `identity_blob` =
    /// encode_identity(account_id, device_cert) as the app already produces for the 1:1 credential.
    #[uniffi::constructor]
    pub fn new(
        kek: Vec<u8>,
        device_sign_private: Vec<u8>,
        device_sign_public: Vec<u8>,
        identity_blob: Vec<u8>,
    ) -> Result<Arc<MlsClient>, MlsError> {
        if kek.len() != 32 {
            return Err(MlsError::BadKek);
        }
        let kek: [u8; 32] = kek.try_into().map_err(|_| MlsError::BadKek)?;
        let provider = KseProvider::new(kek).map_err(m)?;

        // Reconstruct the signer from the app's device key (its public MUST be the cert-certified device key).
        let signer = SignatureKeyPair::from_raw(CS.signature_algorithm(), device_sign_private, device_sign_public);
        signer.store(provider.storage()).map_err(m)?;

        let (account_id, cert): (Vec<u8>, DeviceCert) =
            decode_identity(&identity_blob).ok_or_else(|| MlsError::Mls("bad identity blob".into()))?;
        let credential: Credential = BasicCredential::new(identity_blob).into();
        let cwk = CredentialWithKey { credential, signature_key: signer.to_public_vec().into() };

        let mut ts = TrustStore::new();
        // self-pin: our own account → our account key, so our own leaves validate on the receive path.
        ts.pin(&account_id, &cert.account_public_key);

        Ok(Arc::new(MlsClient {
            inner: Mutex::new(Inner { provider, signer, credential: cwk, account_id, ts, roles: HashMap::new(), groups: HashMap::new() }),
        }))
    }

    /// TOFU-pin a peer account (from the app's safety-number flow) so their leaves validate.
    pub fn pin_account(&self, account_id: Vec<u8>, account_pub: Vec<u8>) {
        self.inner.lock().unwrap().ts.pin(&account_id, &account_pub);
    }

    /// KV-03-001: роли группы из owner-signed цепочки (`crypto/mlsroles.js`), проверенной в JS.
    ///
    /// Здесь ничего не проверяется и не подписывается: подпись владельца сверяется в JS против
    /// ключа, взятого из ДЕРЕВА (`member_account_keys`, ghost-defense-attested), — то есть источник
    /// доверия тот же, что у пинов. Сюда приходит уже принятый результат, как и с `add_revocation`.
    ///
    /// В ПАМЯТИ: `export_state` этого не сохраняет, поэтому мост в `mlsWiring.ts` пере-подаёт роли на
    /// старте. Без этого после перезапуска каждая группа оказалась бы в окне «ролей нет» — см.
    /// `policy::may_remove`, там же почему окно не «впустить всё» и не «отвергнуть всё».
    ///
    /// `admins` — ПОЛНОЕ новое множество (владельца перечислять не нужно, он админ по построению).
    pub fn set_group_roles(&self, group_id: Vec<u8>, owner: Vec<u8>, admins: Vec<Vec<u8>>) {
        self.inner.lock().unwrap().roles.insert(group_id, GroupRoles { owner, admins });
    }

    /// Our KeyPackage so peers can add us. Wraps KeyPackage::builder().build — each build() mints a FRESH
    /// init_key (one-time by design), whose private half is stored in the provider. Reusing ONE KP for two
    /// joins would reuse its init_key (a forward-secrecy hole); single-use KPs (make_key_packages) fix that.
    pub fn make_key_package(&self) -> Result<Vec<u8>, MlsError> {
        let g = self.inner.lock().unwrap();
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(kvant_caps())
            .build(CS, &g.provider, &g.signer, g.credential.clone())
            .map_err(m)?;
        bundle.key_package().tls_serialize_detached().map_err(m)
    }

    /// A POOL of `count` single-use KeyPackages (single-use hardening). Each carries a DISTINCT init_key
    /// (KeyPackage::builder().build mints one per call; all private init secrets persist in the provider),
    /// so each is consumed by exactly ONE join — the replay window is one add, not "forever". Every KP in
    /// the pool carries the SAME leaf (credential + account-cert + sig_key), so ghost-defense validates
    /// each one identically (validate_leafnode). The app publishes the pool; the server pops one per fetch.
    pub fn make_key_packages(&self, count: u32) -> Result<Vec<Vec<u8>>, MlsError> {
        let g = self.inner.lock().unwrap();
        let mut out = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let bundle = KeyPackage::builder()
                .leaf_node_capabilities(kvant_caps())
                .build(CS, &g.provider, &g.signer, g.credential.clone())
                .map_err(m)?;
            out.push(bundle.key_package().tls_serialize_detached().map_err(m)?);
        }
        Ok(out)
    }

    /// A LAST-RESORT KeyPackage — a deliberately REUSABLE fallback (LastResortExtension) for when the
    /// one-time pool is exhausted (mirrors X3DH's signed-prekey-only fallback). Reuse is a known,
    /// bounded MLS compromise, accepted only under pool exhaustion. Same leaf → same ghost-defense.
    pub fn make_last_resort_key_package(&self) -> Result<Vec<u8>, MlsError> {
        let g = self.inner.lock().unwrap();
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(kvant_caps())
            .mark_as_last_resort()
            .build(CS, &g.provider, &g.signer, g.credential.clone())
            .map_err(m)?;
        bundle.key_package().tls_serialize_detached().map_err(m)
    }

    /// Start a new group. Wraps MlsGroup::new. Returns the group_id.
    pub fn create_group(&self) -> Result<Vec<u8>, MlsError> {
        let mut g = self.inner.lock().unwrap();
        let group = {
            let Inner { provider, signer, credential, .. } = &mut *g;
            MlsGroup::new(&*provider, &*signer, &group_config(), credential.clone()).map_err(m)?
        };
        let gid = group.group_id().as_slice().to_vec();
        g.groups.insert(gid.clone(), group);
        Ok(gid)
    }

    /// Add a peer by their KeyPackage. Wraps guarded_add_members (GHOST-CHECKED) + merge.
    pub fn add_member(&self, group_id: Vec<u8>, peer_key_package: Vec<u8>) -> Result<AddResult, MlsError> {
        let kp_in = KeyPackageIn::tls_deserialize_exact(&peer_key_package).map_err(m)?;
        let mut g = self.inner.lock().unwrap();
        let kp = kp_in.validate(g.provider.crypto(), ProtocolVersion::Mls10).map_err(m)?;
        g.group_mut(&group_id)?; // ensure loaded into the cache (from storage if needed)
        // destructure for simultaneous &group / &provider / &signer / &ts borrows
        let Inner { provider, signer, ts, groups, .. } = &mut *g;
        let group = groups.get_mut(&group_id).unwrap();
        let (commit, welcome, _gi) =
            guarded_add_members(group, &*provider, &*signer, &[kp], &*ts).map_err(rej)?;
        group.merge_pending_commit(&*provider).map_err(m)?;
        let tree = group.export_ratchet_tree();
        Ok(AddResult {
            commit: commit.tls_serialize_detached().map_err(m)?,
            welcome: welcome.tls_serialize_detached().map_err(m)?,
            ratchet_tree: tree.tls_serialize_detached().map_err(m)?,
        })
    }

    /// Remove a member (all their device leaves) by account_id. Remove introduces NO new leaf key, so the
    /// auditor confirmed it needs no ghost-guard (unlike Add) — we call OpenMLS remove directly + merge.
    /// The removed member cannot read post-epoch traffic (PCS) and cannot participate further.
    /// Returns the commit wire to broadcast to remaining members.
    pub fn remove_member(&self, group_id: Vec<u8>, member_account_id: Vec<u8>) -> Result<Vec<u8>, MlsError> {
        let mut g = self.inner.lock().unwrap();
        g.group_mut(&group_id)?;
        let Inner { provider, signer, groups, .. } = &mut *g;
        let group = groups.get_mut(&group_id).unwrap();
        let targets: Vec<LeafNodeIndex> = group
            .members()
            .filter(|mem| cred_account_id(&mem.credential).as_deref() == Some(member_account_id.as_slice()))
            .map(|mem| mem.index)
            .collect();
        if targets.is_empty() {
            return Err(MlsError::Mls("member not in group".into()));
        }
        let (commit, _welcome, _gi) = group.remove_members(&*provider, &*signer, &targets).map_err(m)?;
        // N-03/многоадминные гонки: КОММИТ НЕ СЛИВАЕТСЯ ЗДЕСЬ. Раньше здесь стоял
        // merge_pending_commit сразу после создания — то есть автор уходил в новую эпоху ДО того,
        // как её принял хоть кто-то. При двух админах, удаляющих разных людей одновременно, это
        // давало не «один проиграл», а РАСКОЛ: обе стороны уже в разных N+1, а MLS не умеет
        // разслить коммит. Теперь коммит остаётся PENDING, и решение принимает вызывающий:
        //   merge_pending  — подтверждаю своё изменение (никто не обогнал);
        //   clear_pending  — меня обогнали: своё отменяю, применяю чужое и пересобираю заново.
        // Отменить можно ровно до мержа — в этом вся разница между «моё действие не применилось»
        // и «группа раскололась».  [pending-commit not merged here]
        commit.tls_serialize_detached().map_err(m)
    }

    /// Remove ONE DEVICE (a single leaf) of an account by (account_id, device_id) — multidevice device
    /// removal. Unlike remove_member (which drops ALL of an account's leaves), this targets the ONE leaf
    /// whose credential carries this device_id (cert.device_id = fingerprint of the device key, unique
    /// per-device). PCS: the removed device cannot read the post-epoch traffic; the account's OTHER devices
    /// are untouched. Removing the account's LAST device drops the account from the group (member_account_ids
    /// stops listing it, by construction). Remove introduces no new leaf key → no ghost-guard (like
    /// remove_member). Returns the commit wire to broadcast. Err if no leaf matches (account+device).
    pub fn remove_device(&self, group_id: Vec<u8>, account_id: Vec<u8>, device_id: Vec<u8>) -> Result<Vec<u8>, MlsError> {
        let mut g = self.inner.lock().unwrap();
        g.group_mut(&group_id)?;
        let Inner { provider, signer, groups, .. } = &mut *g;
        let group = groups.get_mut(&group_id).unwrap();
        let targets: Vec<LeafNodeIndex> = group
            .members()
            .filter(|mem| {
                cred_identity(&mem.credential)
                    .map(|(aid, cert)| aid == account_id && cert.device_id == device_id)
                    .unwrap_or(false)
            })
            .map(|mem| mem.index)
            .collect();
        if targets.is_empty() {
            return Err(MlsError::Mls("device leaf not in group".into()));
        }
        let (commit, _welcome, _gi) = group.remove_members(&*provider, &*signer, &targets).map_err(m)?;
        group.merge_pending_commit(&*provider).map_err(m)?;
        commit.tls_serialize_detached().map_err(m)
    }

    /// Register an account-signed device REVOCATION so ghost-defense refuses to re-admit a removed device
    /// (closes the re-add gap: without this the TrustStore held no revocations, so a revoked device's KP
    /// would pass validate_leaf on a later add). The revocation itself must be signed by the account key
    /// (verify_device_bundle re-checks it); a forged one is inert (verify_revocation fails at add time).
    /// Mirrors pin_account. `version` = CERT_VERSION.
    pub fn add_revocation(
        &self,
        version: u32,
        device_id: Vec<u8>,
        account_public_key: Vec<u8>,
        revoked_at: u64,
        signature: Vec<u8>,
    ) {
        let rev = Revocation { version, device_id, account_public_key, revoked_at, signature };
        self.inner.lock().unwrap().ts.revoke(rev);
    }

    /// The TRUE member list from the MLS group state (the ratchet tree) — NOT the app's local roster.
    /// Each entry = a member's account_id (the canonical-nick bytes carried in its BasicCredential),
    /// DEDUPED (multidevice: several device leaves may share one account_id). READ-ONLY: it only reads
    /// `MlsGroup::members()`, never mutates state. This is the source of truth the app roster syncs to
    /// after a membership commit (Add/Remove) is applied — so a NON-adder learns the real membership from
    /// the group itself instead of a partial local guess.
    pub fn member_account_ids(&self, group_id: Vec<u8>) -> Result<Vec<Vec<u8>>, MlsError> {
        let mut g = self.inner.lock().unwrap();
        let group = g.group_mut(&group_id)?; // load from storage if not cached (e.g. after import_state)
        let mut out: Vec<Vec<u8>> = Vec::new();
        for mem in group.members() {
            if let Some(aid) = cred_account_id(&mem.credential) {
                if !out.contains(&aid) {
                    out.push(aid); // dedup by account_id (multidevice = many leaves, one account)
                }
            }
        }
        Ok(out)
    }

    /// member_account_ids WITH each account's Ed25519 public key — the anchor for MLS-roles genesis
    /// verification. READ-ONLY (only reads `MlsGroup::members()`, mutates nothing).
    ///
    /// WHY THE KEY IS TRUSTWORTHY (not forgeable by a member): a leaf enters the tree ONLY through the
    /// ghost-defense validators — guarded_add_members (send), walk_staged_commit (receive Add/Update incl.
    /// commit-PATH), walk_welcome_tree (join, WHOLE tree), validate_queued_proposal (standalone/external).
    /// Each runs validate_leaf → verify_device_bundle, which (devicecert.rs) requires
    /// cert.account_public_key == the TOFU-PINNED key for that account_id (ct_eq) AND verifies the cert
    /// signature under that key. So by the time a leaf is IN the tree, its cert's account_public_key is
    /// the pinned, signature-verified account key — reading it back is reading an attested value. A forged
    /// key can't reach the tree: the commit/welcome carrying it fails closed (AccountMismatch/UnknownAccount).
    /// Deduped by account_id (multidevice: all leaves of one account carry the same account key — enforced
    /// by the same pin equality).
    pub fn member_account_keys(&self, group_id: Vec<u8>) -> Result<Vec<MemberAccountKey>, MlsError> {
        let mut g = self.inner.lock().unwrap();
        let group = g.group_mut(&group_id)?; // load from storage if not cached (e.g. after import_state)
        let mut out: Vec<MemberAccountKey> = Vec::new();
        for mem in group.members() {
            if let Some((account_id, cert)) = cred_identity(&mem.credential) {
                if !out.iter().any(|e| e.account_id == account_id) {
                    out.push(MemberAccountKey { account_id, account_public_key: cert.account_public_key });
                }
            }
        }
        Ok(out)
    }

    /// The TRUE per-DEVICE leaf list: (account_id, device_id) for EVERY leaf in the tree — one entry per
    /// device (NOT deduped by account), so the UI can show and target individual devices for removal. The
    /// device_id is the cert.device_id the ghost-defense validated (fingerprint of the MLS leaf key — which
    /// for a primary is the DEDICATED mlsLeaf key, distinct from the 1:1 device id the server's getDevices
    /// returns). READ-ONLY (only reads MlsGroup::members(), mutates nothing). This is the correct source for
    /// remove_device targeting — the same device_id remove_device filters on.
    pub fn member_devices(&self, group_id: Vec<u8>) -> Result<Vec<MemberDevice>, MlsError> {
        let mut g = self.inner.lock().unwrap();
        let group = g.group_mut(&group_id)?;
        let mut out: Vec<MemberDevice> = Vec::new();
        for mem in group.members() {
            if let Some((account_id, cert)) = cred_identity(&mem.credential) {
                out.push(MemberDevice { account_id, device_id: cert.device_id });
            }
        }
        Ok(out)
    }

    /// Encrypt an application message. Wraps MlsGroup::create_message.
    pub fn encrypt_message(&self, group_id: Vec<u8>, plaintext: Vec<u8>) -> Result<Vec<u8>, MlsError> {
        let mut g = self.inner.lock().unwrap();
        g.group_mut(&group_id)?; // load from storage if not cached (e.g. after import_state)
        let Inner { provider, signer, groups, .. } = &mut *g;
        let group = groups.get_mut(&group_id).unwrap();
        let msg = group.create_message(&*provider, &*signer, &plaintext).map_err(m)?;
        msg.tls_serialize_detached().map_err(m)
    }

    /// Receive any incoming wire message. Wraps dispatch_group_message (FAIL-CLOSED) under guard() [C1].
    pub fn process_incoming(&self, group_id: Vec<u8>, wire: Vec<u8>) -> Result<IncomingResult, MlsError> {
        let mut g = self.inner.lock().unwrap();
        g.group_mut(&group_id)?; // load from storage if not cached (e.g. after import_state)
        let Inner { provider, ts, roles, groups, .. } = &mut *g;
        let group = groups.get_mut(&group_id).unwrap();
        let gr = roles.get(&group_id);
        let disp = guard("dispatch_group_message", || {
            dispatch_group_message(group, &*provider, &wire, &*ts, gr).map_err(rej)
        })?;
        Ok(match disp {
            Disposition::Application(pt) => IncomingResult { kind: IncomingKind::Application, plaintext: Some(pt) },
            Disposition::CommitMerged => IncomingResult { kind: IncomingKind::CommitMerged, plaintext: None },
            Disposition::ProposalStored => IncomingResult { kind: IncomingKind::ProposalStored, plaintext: None },
        })
    }

    /// Join from a Welcome. Wraps dispatch_welcome (whole-tree ghost check + floor) under guard() [C1].
    pub fn join_from_welcome(&self, welcome_wire: Vec<u8>, ratchet_tree: Vec<u8>) -> Result<Vec<u8>, MlsError> {
        let msg_in = MlsMessageIn::tls_deserialize_exact(&welcome_wire).map_err(m)?;
        let welcome = match msg_in.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(MlsError::Mls("not a welcome".into())),
        };
        let tree_in = RatchetTreeIn::tls_deserialize_exact(&ratchet_tree).map_err(m)?;
        let mut g = self.inner.lock().unwrap();
        let Inner { provider, ts, .. } = &mut *g;
        let cfg = group_config();
        let group = guard("dispatch_welcome", || {
            dispatch_welcome(&*provider, cfg.join_config(), welcome, Some(tree_in), &*ts).map_err(rej)
        })?;
        let gid = group.group_id().as_slice().to_vec();
        g.groups.insert(gid.clone(), group);
        Ok(gid)
    }

    /// Export the sealed group state (Contract-2 ciphertext) for app-managed persistence (decision 2b).
    pub fn export_state(&self) -> Result<Vec<u8>, MlsError> {
        let g = self.inner.lock().unwrap();
        let dump = g.provider.storage().export_sealed();
        serde_json::to_vec(&dump).map_err(m)
    }

    /// ЗАГЛЯНУТЬ В КАДР, НЕ ОБРАБАТЫВАЯ ЕГО: эпоха и тип содержимого. И то и другое лежит в ОТКРЫТОЙ
    /// части PrivateMessage (RFC 9420 §6.3.1: group_id, epoch, content_type — до шифротекста), то есть
    /// узнать «это коммит для эпохи N» можно, ничего не применив и не расшифровав.
    ///
    /// Зачем это нужно, если есть process_message. Затем, что process_message — это ДЕЙСТВИЕ: он либо
    /// применяет, либо отказывает, и оба исхода необратимы. Двум задачам нужен ответ ДО действия:
    ///   * «устаревшая эпоха» против «всё остальное» — сегодня отказ приходит одной строкой текста
    ///     OpenMLS, и штатная гонка неотличима от подделки;
    ///   * гонка коммитов — пока свой коммит отложен, чужой коммит той же эпохи применится, и решать,
    ///     применять ли его, надо ПЕРЕД тем, как он применился.
    ///
    /// Ничего не проверяет и ничему не доверяет: значения берутся из неаутентифицированной части
    /// кадра и годятся ТОЛЬКО для маршрутизации решения. Подлинность по-прежнему устанавливает
    /// process_message.  [mls frame peek]
    pub fn peek_frame(&self, wire: Vec<u8>) -> Result<FramePeek, MlsError> {
        let msg = MlsMessageIn::tls_deserialize_exact(&wire).map_err(m)?;
        let proto = msg.try_into_protocol_message().map_err(m)?;
        Ok(FramePeek {
            epoch: proto.epoch().as_u64(),
            group_id: proto.group_id().as_slice().to_vec(),
            is_commit: matches!(proto.content_type(), ContentType::Commit),
            is_application: matches!(proto.content_type(), ContentType::Application),
        })
    }

    /// НОМЕР ЭПОХИ группы. Без него расхождение эпох (две ветки после одновременных коммитов) не
    /// видно ни в логе, ни в тесте: снаружи это выглядит как «сообщения перестали приходить».
    /// Читает состояние, ничего не меняет.  [mls epoch probe]
    pub fn group_epoch(&self, group_id: Vec<u8>) -> Result<u64, MlsError> {
        let mut g = self.inner.lock().unwrap();
        let group = g.group_mut(&group_id)?;
        Ok(group.epoch().as_u64())
    }

    /// ОТПЕЧАТОК СОСТОЯНИЯ ЧЛЕНСТВА: эпоха + ratchet tree + расширения GroupContext + ссылки на
    /// отложенные предложения. Двигается ТОЛЬКО при мерже, поэтому побайтовое равенство до и после
    /// отвергнутого сообщения доказывает, что состояние не сдвинулось, а неравенство у двух
    /// участников одной эпохи — что они разошлись. Определение то же, что у аудиторской проверки
    /// Q4 v2 внутри тестов, и вынесено сюда, чтобы у теста и у приложения был ОДИН отпечаток, а не
    /// два похожих.  [mls state fingerprint]
    pub fn group_state_fp(&self, group_id: Vec<u8>) -> Result<Vec<u8>, MlsError> {
        let mut g = self.inner.lock().unwrap();
        let group = g.group_mut(&group_id)?;
        Ok(state_fp(group))
    }

    /// Подтвердить СВОЙ отложенный коммит (никто не обогнал). Идемпотентности здесь нет и быть не
    /// может: мерж двигает эпоху, поэтому второй вызов вернёт ошибку, а не «уже сделано».
    /// [pending commit merged]
    pub fn merge_pending(&self, group_id: Vec<u8>) -> Result<(), MlsError> {
        let mut g = self.inner.lock().unwrap();
        let Inner { provider, groups, .. } = &mut *g;
        let group = groups.get_mut(&group_id).ok_or_else(|| MlsError::Mls("group not found".into()))?;
        group.merge_pending_commit(&*provider).map_err(m)
    }

    /// Отменить СВОЙ отложенный коммит — меня обогнали. Состояние остаётся в прежней эпохе, то есть
    /// чужой коммит для неё применим. Это и есть выход из гонки без раскола.
    /// [pending commit cleared]
    pub fn clear_pending(&self, group_id: Vec<u8>) -> Result<(), MlsError> {
        let mut g = self.inner.lock().unwrap();
        let Inner { provider, groups, .. } = &mut *g;
        let group = groups.get_mut(&group_id).ok_or_else(|| MlsError::Mls("group not found".into()))?;
        // clear_pending_commit принимает ХРАНИЛИЩЕ, а не провайдер (в отличие от merge_pending_commit
        // строкой выше) — сигнатуры OpenMLS 0.9 здесь несимметричны.
        group.clear_pending_commit(provider.storage()).map_err(m)
    }

    /// Restore sealed state exported earlier (survive app restart). Clears the live cache → reload on use.
    pub fn import_state(&self, blob: Vec<u8>) -> Result<(), MlsError> {
        let dump: Vec<(Vec<u8>, Vec<u8>)> = serde_json::from_slice(&blob).map_err(m)?;
        let mut g = self.inner.lock().unwrap();
        g.provider.storage().import_sealed(dump);
        g.groups.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests;

// ============================ Tier-2 stateful fuzzing surface ============================
// Off by default (feature = "fuzzing"); never compiled into the production cdylib. This EXPOSES the
// already-verified spike (dispatch_group_message / guarded_add_members / group ops) to libFuzzer over
// a VALID group fixture — it does NOT reimplement any security logic. Tier-1 fed raw bytes to parsers
// (libcrux never ran); Tier-2 feeds (mutated) VALID messages into process_message so libcrux actually
// decrypts (HPKE + ChaCha20Poly1305 + ML-KEM decap + Ed25519) — the paths Route-2 fixed.
//
// 🔴 DELIBERATELY OUTSIDE the Contract-1 guard(): a panic MUST surface to ASAN, not be swallowed into a
// typed error. In production, process_incoming still wraps this same dispatch in guard() (fail-closed);
// the fuzz path only removes the swallow so a real libcrux crash is observable.
#[cfg(feature = "fuzzing")]
pub mod fuzz {
    use super::*;
    use crate::as_validate::encode_identity;
    use crate::devicecert::mint_cert;
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};
    use std::sync::OnceLock;

    const KEK: [u8; 32] = [0x42; 32];

    // Build a client with a genuine account/device identity (fixed seeds, exactly like client/tests::mk).
    fn mk(account_seed: u8, device_seed: u8, account_id: &[u8]) -> (Arc<MlsClient>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        let account = SigningKey::from_bytes(&[account_seed; 32]);
        let device = SigningKey::from_bytes(&[device_seed; 32]);
        let device_priv = device.to_bytes().to_vec();
        let device_pub = device.verifying_key().to_bytes().to_vec();
        let account_pub = account.verifying_key().to_bytes().to_vec();
        let cert = mint_cert(&account, &device_pub, 0, 0);
        let identity = encode_identity(account_id, &cert);
        let client = MlsClient::new(KEK.to_vec(), device_priv.clone(), device_pub.clone(), identity.clone()).unwrap();
        (client, account_id.to_vec(), account_pub, device_priv, device_pub, identity)
    }

    /// The frozen restore-seed for Target A. All fields are plain bytes so a fresh bob can be rebuilt
    /// deterministically each iteration (process_message MUTATES state → per-iteration isolation is
    /// required for a reproducible crash: same seed + same input ⇒ same path).
    pub struct FixtureA {
        pub bob_state_blob: Vec<u8>,  // export_state of bob AT epoch-1 (after joining, before carol)
        pub bob_device_priv: Vec<u8>,
        pub bob_device_pub: Vec<u8>,
        pub bob_identity: Vec<u8>,
        pub gid: Vec<u8>,
        pub pins: Vec<(Vec<u8>, Vec<u8>)>, // (account_id, account_pub) bob must pin: alice, carol
        pub valid_commit: Vec<u8>,    // alice adds carol → a VALID membership message for bob@epoch1
        pub valid_app: Vec<u8>,       // alice encrypts → a VALID application message for bob@epoch1
    }

    static FIXTURE_A: OnceLock<FixtureA> = OnceLock::new();

    /// Build the 2-member X-Wing fixture ONCE (expensive: real keygen + Add + join). Both message
    /// templates are produced at bob's epoch-1 so a restored bob validates/decrypts them.
    pub fn fixture_a() -> &'static FixtureA {
        FIXTURE_A.get_or_init(|| {
            let (alice, a_id, a_pub, _apriv, _apub, _aid) = mk(1, 2, b"alice");
            let (bob, b_id, b_pub, b_priv, b_pubk, b_identity) = mk(3, 4, b"bob");
            let (carol, c_id, c_pub, _cpriv, _cpub, _cid) = mk(5, 6, b"carol");
            alice.pin_account(b_id.clone(), b_pub.clone());
            alice.pin_account(c_id.clone(), c_pub.clone());
            bob.pin_account(a_id.clone(), a_pub.clone());
            bob.pin_account(c_id.clone(), c_pub.clone());

            let gid = alice.create_group().unwrap();
            let add_bob = alice.add_member(gid.clone(), bob.make_key_package().unwrap()).unwrap();
            let bob_gid = bob.join_from_welcome(add_bob.welcome, add_bob.ratchet_tree).unwrap();
            assert_eq!(bob_gid, gid);

            // Snapshot bob at epoch-1 (bob is a member; alice has NOT yet added carol).
            let bob_state_blob = bob.export_state().unwrap();
            // Template 1: a genuine application message alice→group at epoch-1 (bob@epoch1 decrypts it).
            let valid_app = alice.encrypt_message(gid.clone(), b"ping".to_vec()).unwrap();
            // Template 2: alice adds carol → a genuine COMMIT valid for bob@epoch1 (we DON'T need alice
            // to keep it; the wire is what bob would receive). add_member merges on alice, but the
            // returned commit is framed for the epoch bob is still in.
            let add_carol = alice.add_member(gid.clone(), carol.make_key_package().unwrap()).unwrap();
            let valid_commit = add_carol.commit;

            FixtureA {
                bob_state_blob,
                bob_device_priv: b_priv,
                bob_device_pub: b_pubk,
                bob_identity: b_identity,
                gid,
                pins: vec![(a_id, a_pub), (c_id, c_pub)],
                valid_commit,
                valid_app,
            }
        })
    }

    // A FULL membership fingerprint frozen across a rejected dispatch (auditor Q4 v2): epoch + ratchet
    // tree + GroupContext extensions + pending-proposal refs. Advances ONLY on a merge, so byte-equality
    // before/after a reject proves NO membership state advanced. (Local copy — does not touch the
    // #[cfg(test)] helper in dispatch/tests.rs.)
    fn group_state_fp(g: &MlsGroup) -> Vec<u8> { super::state_fp(g) } // одно определение, см. state_fp выше

    /// Rebuild a fresh bob from the fixture seed (deterministic, per-iteration isolation).
    fn restore_bob(fx: &FixtureA) -> Arc<MlsClient> {
        let bob = MlsClient::new(
            KEK.to_vec(),
            fx.bob_device_priv.clone(),
            fx.bob_device_pub.clone(),
            fx.bob_identity.clone(),
        )
        .unwrap();
        bob.import_state(fx.bob_state_blob.clone()).unwrap();
        for (id, pk) in &fx.pins {
            bob.pin_account(id.clone(), pk.clone());
        }
        bob
    }

    /// TARGET A driver. Restore a fresh bob, feed `wire` (a libFuzzer-mutated VALID message) into
    /// dispatch_group_message OUTSIDE guard(). Invariant 1 (no-panic) is enforced by the fuzzer/ASAN
    /// simply by running unguarded. Invariant 2 (auditor Q4): on Err, bob's group_state_fp MUST be
    /// byte-identical before/after — a rejected message may NOT advance membership state.
    pub fn process_stateful(wire: &[u8]) {
        let fx = fixture_a();
        let bob = restore_bob(fx);
        let mut g = bob.inner.lock().unwrap();
        // load the group into the cache from the just-imported storage
        if g.group_mut(&fx.gid).is_err() {
            return; // fixture invariant broken → nothing to fuzz (never happens with the frozen seed)
        }
        let Inner { provider, ts, groups, .. } = &mut *g;
        let group = groups.get_mut(&fx.gid).unwrap();
        let fp_before = group_state_fp(group);
        // UNGUARDED on purpose — a panic here is a real libcrux/OpenMLS crash for ASAN to catch.
        match dispatch_group_message(group, &*provider, wire, &*ts) {
            Ok(_) => { /* Ok may legitimately advance state (a valid commit merges) — no invariant */ }
            Err(_) => {
                let fp_after = group_state_fp(group);
                assert!(
                    fp_after == fp_before,
                    "FAIL-CLOSED VIOLATION: a REJECTED message advanced bob's group state (Q4)"
                );
            }
        }
    }

    /// Emit Target A seed corpus (the two VALID templates) into `dir`. libFuzzer then MUTATES these —
    /// we do NOT hand-write a mutator (that's the fuzzer's job, as in Tier-1).
    pub fn emit_seeds_a(dir: &str) {
        let fx = fixture_a();
        let _ = std::fs::create_dir_all(dir);
        let write = |name: &str, bytes: &[u8]| {
            let _ = std::fs::write(format!("{dir}/{name}"), bytes);
        };
        write("valid_commit", &fx.valid_commit);
        write("valid_app", &fx.valid_app);
    }

    // ---------------------------- TARGET B: op-sequence ----------------------------
    // A tiny PROGRAM over three real members (alice/bob/carol). Each fuzz byte selects an operation;
    // state is rebuilt from scratch every input so iterations are naturally isolated. Invariants:
    //   • consistency — after both parties apply a commit, epochs + member sets agree,
    //   • PCS — once carol is removed, she can no longer decrypt a new-epoch message.
    // Costlier than A (X-Wing crypto per op) → run with fewer workers. Still exercises libcrux end to end.
    pub fn op_sequence(data: &[u8]) {
        let (alice, a_id, a_pub, ..) = mk(1, 2, b"alice");
        let (bob, b_id, b_pub, ..) = mk(3, 4, b"bob");
        let (carol, c_id, c_pub, ..) = mk(5, 6, b"carol");
        for (who, id) in [(&alice, &a_id), (&bob, &b_id), (&carol, &c_id)] {
            for (oid, opk) in [(&a_id, &a_pub), (&b_id, &b_pub), (&c_id, &c_pub)] {
                if oid != id { who.pin_account(oid.clone(), opk.clone()); }
            }
        }
        let gid = alice.create_group().unwrap();
        let add = alice.add_member(gid.clone(), bob.make_key_package().unwrap()).unwrap();
        if bob.join_from_welcome(add.welcome, add.ratchet_tree).is_err() { return; }

        let mut carol_in = false;
        let mut carol_last_removed_epoch_msg: Option<Vec<u8>> = None;

        for &b in data {
            match b % 5 {
                0 => {
                    // alice → group app; bob (and carol if in) process
                    if let Ok(w) = alice.encrypt_message(gid.clone(), b"a".to_vec()) {
                        let _ = bob.process_incoming(gid.clone(), w.clone());
                        if carol_in { let _ = carol.process_incoming(gid.clone(), w); }
                    }
                }
                1 => {
                    // bob → group app; alice (and carol if in) process
                    if let Ok(w) = bob.encrypt_message(gid.clone(), b"b".to_vec()) {
                        let _ = alice.process_incoming(gid.clone(), w.clone());
                        if carol_in { let _ = carol.process_incoming(gid.clone(), w); }
                    }
                }
                2 if !carol_in => {
                    // alice adds carol → bob applies the commit; carol joins via welcome
                    if let Ok(add) = alice.add_member(gid.clone(), carol.make_key_package().unwrap()) {
                        let _ = bob.process_incoming(gid.clone(), add.commit);
                        if carol.join_from_welcome(add.welcome, add.ratchet_tree).is_ok() {
                            carol_in = true;
                            // consistency after a membership change: all present agree on members + epoch
                            let am = sorted(alice.member_account_ids(gid.clone()).unwrap());
                            let bm = sorted(bob.member_account_ids(gid.clone()).unwrap());
                            assert_eq!(am, bm, "alice/bob disagree on members after add");
                            assert!(am.contains(&c_id), "carol missing from the member set after add");
                        }
                    }
                }
                3 if carol_in => {
                    // alice removes carol → bob applies; a NEW-epoch message must be UNREADABLE to carol (PCS)
                    if let Ok(commit) = alice.remove_member(gid.clone(), c_id.clone()) {
                        let _ = bob.process_incoming(gid.clone(), commit);
                        carol_in = false;
                        if let Ok(w) = alice.encrypt_message(gid.clone(), b"secret".to_vec()) {
                            carol_last_removed_epoch_msg = Some(w);
                        }
                    }
                }
                _ => {
                    // consistency probe: whenever both are live members, epochs+members must match
                    if let (Ok(am), Ok(bm)) =
                        (alice.member_account_ids(gid.clone()), bob.member_account_ids(gid.clone()))
                    {
                        assert_eq!(sorted(am), sorted(bm), "alice/bob member-set divergence");
                    }
                }
            }
            // PCS check: a removed carol must never decrypt the post-removal message
            if let Some(msg) = carol_last_removed_epoch_msg.take() {
                assert!(
                    carol.process_incoming(gid.clone(), msg).is_err(),
                    "PCS VIOLATION: removed carol decrypted a post-removal message"
                );
            }
        }
    }

    fn sorted(mut v: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        v.sort();
        v
    }
}
