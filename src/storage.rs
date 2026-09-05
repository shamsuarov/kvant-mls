// storage.rs — M2 Contract-2: an encrypting StorageProvider. It mirrors OpenMLS MemoryStorage's value
// encoding (serde_json) and key layout (label ∥ delimiter ∥ serialized-key ∥ version), but KSE1-seals every
// value before it touches the backing map — so the backing store (and therefore any disk/RAM dump, threat A4
// device seizure) only ever holds ciphertext. "No plaintext at rest by construction": there is no code path
// that inserts a plaintext value.
//
// Each MUTATING method (18 writes + 19 deletes/clear/remove) is tagged with its KEYSPACE via a structural
// per-keyspace counter (not a comment) so the harness can machine-check the security boundary:
//   FROZEN-ON-REJECT = Membership ∪ Config ∪ ProposalStore  → MUST be 0 writes on a rejected dispatch.
//   FREE-FOR-FS      = SecretRatchet ∪ KeyMaterial          → MAY advance on reject (forward secrecy).
// `interim_transcript` is tracked separately (a Membership field) so the auditor's literal-transcript
// write-count==0 is observable natively here, without OpenMLS `test-utils`.
//
// 🟡 Two evolution-hardens (auditor) make two properties STRUCTURAL rather than "true today by luck":
//   1. A reserved DELIMITER between label and key makes label prefix-collision (e.g. a future "Tree2" vs the
//      FROZEN "Tree") impossible — `label ∥ DELIM` is a prefix of a key IFF the key belongs to that exact label.
//   2. A SINGLE source of truth (LABEL_KEYSPACE) derives BOTH the write-counter tag and the frozen/free
//      rollback class from the label. There is no manual per-method keyspace to mistag, so the counter and the
//      rollback can never drift apart by construction.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use openmls_traits::storage::*;

// ----------------------------- keyspaces + counters --------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Keyspace {
    Membership,    // tree / context / confirmation_tag / interim_transcript / group_state / leaf_index / leaf_nodes
    Config,        // join_config / group_config
    ProposalStore, // queued proposals + refs
    SecretRatchet, // message_secrets / epoch_secrets / epoch_key_pairs — advances for FS
    KeyMaterial,   // signature / encryption keypairs / key_package / psk — provisioning
}
impl Keyspace {
    /// The security boundary: these keyspaces must not be mutated on a rejected dispatch.
    pub fn frozen_on_reject(self) -> bool {
        matches!(self, Keyspace::Membership | Keyspace::Config | Keyspace::ProposalStore)
    }
}

#[derive(Default, Debug)]
pub struct Counters {
    membership: AtomicU64,
    config: AtomicU64,
    proposal_store: AtomicU64,
    secret_ratchet: AtomicU64,
    key_material: AtomicU64,
    interim_transcript: AtomicU64, // subset of membership, tracked separately for the transcript assertion
}
impl Counters {
    fn bump(&self, ks: Keyspace) {
        let c = match ks {
            Keyspace::Membership => &self.membership,
            Keyspace::Config => &self.config,
            Keyspace::ProposalStore => &self.proposal_store,
            Keyspace::SecretRatchet => &self.secret_ratchet,
            Keyspace::KeyMaterial => &self.key_material,
        };
        c.fetch_add(1, Ordering::Relaxed);
    }
    /// Total mutations in the FROZEN-ON-REJECT keyspace (membership + config + proposal-store).
    pub fn frozen_writes(&self) -> u64 {
        self.membership.load(Ordering::Relaxed)
            + self.config.load(Ordering::Relaxed)
            + self.proposal_store.load(Ordering::Relaxed)
    }
    pub fn secret_ratchet_writes(&self) -> u64 {
        self.secret_ratchet.load(Ordering::Relaxed)
    }
    /// Literal interim-transcript-hash writes (the auditor's deferred item, observed natively here).
    pub fn interim_transcript_writes(&self) -> u64 {
        self.interim_transcript.load(Ordering::Relaxed)
    }
}

// ----------------------------- error -----------------------------------------

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum KseStorageError {
    #[error("serialization")]
    Serialization,
    #[error("at-rest seal/open failed")]
    AtRest,
}
impl From<serde_json::Error> for KseStorageError {
    fn from(_: serde_json::Error) -> Self {
        KseStorageError::Serialization
    }
}

// ----------------------------- the encrypting store --------------------------

#[derive(Debug)]
pub struct KseStorageProvider {
    values: RwLock<HashMap<Vec<u8>, Vec<u8>>>, // sealed values only
    kek: [u8; 32],
    pub counters: Counters,
}

// 🟡 HARDEN 1: a reserved delimiter byte separates the label from the serialized key. No label contains it
// (asserted structurally in tests), so `label ∥ DELIM` is a prefix of a storage key IFF the key belongs to
// that exact label. Prefix-collision between two labels (e.g. a future FREE "Tree2" silently matching the
// FROZEN "Tree" prefix → rollback corrupts the FS ratchet, or vice-versa) is therefore STRUCTURALLY
// impossible, not merely absent in today's label set.
const LABEL_DELIM: u8 = b'/';

fn build_key(label: &[u8], serialized_key: &[u8]) -> Vec<u8> {
    let mut k = label.to_vec();
    k.push(LABEL_DELIM);
    k.extend_from_slice(serialized_key);
    k.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));
    k
}

impl KseStorageProvider {
    pub fn new(kek: [u8; 32]) -> Self {
        KseStorageProvider { values: RwLock::new(HashMap::new()), kek, counters: Counters::default() }
    }

    // KSE1 envelope (same AEAD as the app's session-at-rest / lib.rs). AAD = the storage key, so a sealed
    // value cannot be relocated to a different key.
    fn seal(&self, storage_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, KseStorageError> {
        crate::kse1_seal(&self.kek, plaintext, storage_key).map_err(|_| KseStorageError::AtRest)
    }
    fn open(&self, storage_key: &[u8], blob: &[u8]) -> Result<Vec<u8>, KseStorageError> {
        crate::kse1_open(&self.kek, blob, storage_key).map_err(|_| KseStorageError::AtRest)
    }

    // --- internal mutating/reading helpers ---
    //
    // 🟡 HARDEN 2: the mutating helpers take ONLY the label; the keyspace (counter tag) is DERIVED from it via
    // `keyspace_for_label` — the same single source of truth `is_frozen_key` reads. There is no per-method
    // keyspace argument to mistag, so the counter and the rollback class cannot disagree by construction.

    fn put(&self, label: &[u8], key: &[u8], value: Vec<u8>) -> Result<(), KseStorageError> {
        let sk = build_key(label, key);
        let sealed = self.seal(&sk, &value)?;
        self.values.write().unwrap().insert(sk, sealed);
        self.counters.bump(keyspace_for_label(label));
        Ok(())
    }

    fn get<V: Entity<CURRENT_VERSION>>(&self, label: &[u8], key: &[u8]) -> Result<Option<V>, KseStorageError> {
        let sk = build_key(label, key);
        let values = self.values.read().unwrap();
        match values.get(&sk) {
            Some(sealed) => {
                let pt = self.open(&sk, sealed)?;
                Ok(Some(serde_json::from_slice(&pt)?))
            }
            None => Ok(None),
        }
    }

    fn get_list<V: Entity<CURRENT_VERSION>>(&self, label: &[u8], key: &[u8]) -> Result<Vec<V>, KseStorageError> {
        let sk = build_key(label, key);
        let values = self.values.read().unwrap();
        let inner: Vec<Vec<u8>> = match values.get(&sk) {
            Some(sealed) => serde_json::from_slice(&self.open(&sk, sealed)?)?,
            None => return Ok(vec![]),
        };
        inner.iter().map(|b| serde_json::from_slice(b).map_err(KseStorageError::from)).collect()
    }

    fn append(&self, label: &[u8], key: &[u8], value: Vec<u8>) -> Result<(), KseStorageError> {
        let sk = build_key(label, key);
        let mut values = self.values.write().unwrap();
        let mut list: Vec<Vec<u8>> = match values.get(&sk) {
            Some(sealed) => serde_json::from_slice(&self.open(&sk, sealed)?)?,
            None => vec![],
        };
        list.push(value);
        let sealed = self.seal(&sk, &serde_json::to_vec(&list)?)?;
        values.insert(sk, sealed);
        self.counters.bump(keyspace_for_label(label));
        Ok(())
    }

    fn remove_item(&self, label: &[u8], key: &[u8], value: Vec<u8>) -> Result<(), KseStorageError> {
        let sk = build_key(label, key);
        let mut values = self.values.write().unwrap();
        let mut list: Vec<Vec<u8>> = match values.get(&sk) {
            Some(sealed) => serde_json::from_slice(&self.open(&sk, sealed)?)?,
            None => vec![],
        };
        if let Some(pos) = list.iter().position(|x| x == &value) {
            list.remove(pos);
        }
        let sealed = self.seal(&sk, &serde_json::to_vec(&list)?)?;
        values.insert(sk, sealed);
        self.counters.bump(keyspace_for_label(label));
        Ok(())
    }

    fn del(&self, label: &[u8], key: &[u8]) -> Result<(), KseStorageError> {
        let sk = build_key(label, key);
        self.values.write().unwrap().remove(&sk);
        self.counters.bump(keyspace_for_label(label));
        Ok(())
    }
}

// labels — identical to MemoryStorage so the key layout matches.
const KEY_PACKAGE_LABEL: &[u8] = b"KeyPackage";
const PSK_LABEL: &[u8] = b"Psk";
const ENCRYPTION_KEY_PAIR_LABEL: &[u8] = b"EncryptionKeyPair";
const SIGNATURE_KEY_PAIR_LABEL: &[u8] = b"SignatureKeyPair";
const EPOCH_KEY_PAIRS_LABEL: &[u8] = b"EpochKeyPairs";
const TREE_LABEL: &[u8] = b"Tree";
const GROUP_CONTEXT_LABEL: &[u8] = b"GroupContext";
const INTERIM_TRANSCRIPT_HASH_LABEL: &[u8] = b"InterimTranscriptHash";
const CONFIRMATION_TAG_LABEL: &[u8] = b"ConfirmationTag";
const JOIN_CONFIG_LABEL: &[u8] = b"MlsGroupJoinConfig";
const OWN_LEAF_NODES_LABEL: &[u8] = b"OwnLeafNodes";
const GROUP_STATE_LABEL: &[u8] = b"GroupState";
const QUEUED_PROPOSAL_LABEL: &[u8] = b"QueuedProposal";
const PROPOSAL_QUEUE_REFS_LABEL: &[u8] = b"ProposalQueueRefs";
const OWN_LEAF_NODE_INDEX_LABEL: &[u8] = b"OwnLeafNodeIndex";
const EPOCH_SECRETS_LABEL: &[u8] = b"EpochSecrets";
const RESUMPTION_PSK_STORE_LABEL: &[u8] = b"ResumptionPsk";
const MESSAGE_SECRETS_LABEL: &[u8] = b"MessageSecrets";

// 🟡 HARDEN 2 — the SINGLE SOURCE OF TRUTH: label → keyspace. BOTH the per-write counter tag (via
// `keyspace_for_label`, called inside put/append/remove_item/del) AND the frozen/free rollback class (via
// `is_frozen_key`) derive from THIS one table and nowhere else. A future StorageProvider method cannot
// mis-tag its keyspace: it only names a label, and the keyspace follows. Adding a method whose label is
// missing here fails-closed (panic at the FFI boundary, Contract 1) rather than silently mis-classifying.
const LABEL_KEYSPACE: &[(&[u8], Keyspace)] = &[
    // KeyMaterial (FREE)
    (KEY_PACKAGE_LABEL, Keyspace::KeyMaterial),
    (PSK_LABEL, Keyspace::KeyMaterial),
    (ENCRYPTION_KEY_PAIR_LABEL, Keyspace::KeyMaterial),
    (SIGNATURE_KEY_PAIR_LABEL, Keyspace::KeyMaterial),
    // SecretRatchet (FREE — advances for forward secrecy)
    (EPOCH_KEY_PAIRS_LABEL, Keyspace::SecretRatchet),
    (EPOCH_SECRETS_LABEL, Keyspace::SecretRatchet),
    (RESUMPTION_PSK_STORE_LABEL, Keyspace::SecretRatchet),
    (MESSAGE_SECRETS_LABEL, Keyspace::SecretRatchet),
    // Membership (FROZEN-on-reject)
    (TREE_LABEL, Keyspace::Membership),
    (GROUP_CONTEXT_LABEL, Keyspace::Membership),
    (INTERIM_TRANSCRIPT_HASH_LABEL, Keyspace::Membership),
    (CONFIRMATION_TAG_LABEL, Keyspace::Membership),
    (OWN_LEAF_NODES_LABEL, Keyspace::Membership),
    (GROUP_STATE_LABEL, Keyspace::Membership),
    (OWN_LEAF_NODE_INDEX_LABEL, Keyspace::Membership),
    // Config (FROZEN-on-reject)
    (JOIN_CONFIG_LABEL, Keyspace::Config),
    // ProposalStore (FROZEN-on-reject)
    (QUEUED_PROPOSAL_LABEL, Keyspace::ProposalStore),
    (PROPOSAL_QUEUE_REFS_LABEL, Keyspace::ProposalStore),
];

/// Keyspace of a label, or None if the label is not registered in LABEL_KEYSPACE.
fn keyspace_for_label_opt(label: &[u8]) -> Option<Keyspace> {
    LABEL_KEYSPACE.iter().find(|(l, _)| *l == label).map(|(_, ks)| *ks)
}

/// Keyspace of a label. Panics on an UNREGISTERED label — that is a programming error (a new
/// StorageProvider method whose label was never added to LABEL_KEYSPACE), caught the first time the method
/// runs and converted to a typed error at the FFI panic boundary (Contract 1) rather than mis-tagging.
fn keyspace_for_label(label: &[u8]) -> Keyspace {
    keyspace_for_label_opt(label).expect("unregistered storage label — add it to LABEL_KEYSPACE")
}

/// The label portion of a built storage key = the bytes before the first reserved delimiter. Because no
/// label contains the delimiter (HARDEN 1, asserted in tests), the first delimiter always terminates the
/// label exactly, so this recovers the precise label that built the key.
fn label_of_key(key: &[u8]) -> Option<&[u8]> {
    key.iter().position(|&b| b == LABEL_DELIM).map(|p| &key[..p])
}

/// FROZEN-on-reject classification of a built storage key. Derived from the SAME label→keyspace table as the
/// write counter (HARDEN 2), so the rollback set and the counter tag cannot drift apart. The atomicity
/// rollback touches ONLY frozen keys, leaving SECRET-RATCHET/KEY-MATERIAL (FREE) advanced for FS.
fn is_frozen_key(key: &[u8]) -> bool {
    label_of_key(key).and_then(keyspace_for_label_opt).map(|ks| ks.frozen_on_reject()).unwrap_or(false)
}

fn epoch_key_pairs_id(
    group_id: &impl traits::GroupId<CURRENT_VERSION>,
    epoch: &impl traits::EpochKey<CURRENT_VERSION>,
    leaf_index: u32,
) -> Result<Vec<u8>, KseStorageError> {
    let mut key = serde_json::to_vec(group_id)?;
    key.extend_from_slice(&serde_json::to_vec(epoch)?);
    key.extend_from_slice(&serde_json::to_vec(&leaf_index)?);
    Ok(key)
}

impl StorageProvider<CURRENT_VERSION> for KseStorageProvider {
    type Error = KseStorageError;

    // ===== writes =====

    fn write_mls_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        self.put(JOIN_CONFIG_LABEL, &serde_json::to_vec(group_id)?, serde_json::to_vec(config)?)
    }

    fn append_own_leaf_node<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        self.append(OWN_LEAF_NODES_LABEL, &serde_json::to_vec(group_id)?, serde_json::to_vec(leaf_node)?)
    }

    fn queue_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        self.put(
            QUEUED_PROPOSAL_LABEL,
            &serde_json::to_vec(&(group_id, proposal_ref))?,
            serde_json::to_vec(proposal)?,
        )?;
        self.append(
            PROPOSAL_QUEUE_REFS_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(proposal_ref)?,
        )
    }

    fn write_tree<GroupId: traits::GroupId<CURRENT_VERSION>, TreeSync: traits::TreeSync<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        self.put(TREE_LABEL, &serde_json::to_vec(group_id)?, serde_json::to_vec(tree)?)
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        self.counters.interim_transcript.fetch_add(1, Ordering::Relaxed); // native transcript observation
        self.put(
            INTERIM_TRANSCRIPT_HASH_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(interim_transcript_hash)?,
        )
    }

    fn write_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        self.put(GROUP_CONTEXT_LABEL, &serde_json::to_vec(group_id)?, serde_json::to_vec(group_context)?)
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        self.put(CONFIRMATION_TAG_LABEL, &serde_json::to_vec(group_id)?, serde_json::to_vec(confirmation_tag)?)
    }

    fn write_group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        self.put(GROUP_STATE_LABEL, &serde_json::to_vec(group_id)?, serde_json::to_vec(group_state)?)
    }

    fn write_message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        self.put(MESSAGE_SECRETS_LABEL, &serde_json::to_vec(group_id)?, serde_json::to_vec(message_secrets)?)
    }

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        self.put(RESUMPTION_PSK_STORE_LABEL, &serde_json::to_vec(group_id)?, serde_json::to_vec(resumption_psk_store)?)
    }

    fn write_own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        self.put(OWN_LEAF_NODE_INDEX_LABEL, &serde_json::to_vec(group_id)?, serde_json::to_vec(own_leaf_index)?)
    }

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        self.put(EPOCH_SECRETS_LABEL, &serde_json::to_vec(group_id)?, serde_json::to_vec(group_epoch_secrets)?)
    }

    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        self.put(SIGNATURE_KEY_PAIR_LABEL, &serde_json::to_vec(public_key)?, serde_json::to_vec(signature_key_pair)?)
    }

    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        self.put(ENCRYPTION_KEY_PAIR_LABEL, &serde_json::to_vec(public_key)?, serde_json::to_vec(key_pair)?)
    }

    fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        let key = epoch_key_pairs_id(group_id, epoch, leaf_index)?;
        self.put(EPOCH_KEY_PAIRS_LABEL, &key, serde_json::to_vec(key_pairs)?)
    }

    fn write_key_package<
        HashReference: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        self.put(KEY_PACKAGE_LABEL, &serde_json::to_vec(hash_ref)?, serde_json::to_vec(key_package)?)
    }

    fn write_psk<PskId: traits::PskId<CURRENT_VERSION>, PskBundle: traits::PskBundle<CURRENT_VERSION>>(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        self.put(PSK_LABEL, &serde_json::to_vec(psk_id)?, serde_json::to_vec(psk)?)
    }

    // ===== reads (no counter, no mutation) =====

    fn mls_group_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        self.get(JOIN_CONFIG_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>, LeafNode: traits::LeafNode<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        self.get_list(OWN_LEAF_NODES_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn queued_proposal_refs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        self.get_list(PROPOSAL_QUEUE_REFS_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn queued_proposals<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        let refs: Vec<ProposalRef> = self.get_list(PROPOSAL_QUEUE_REFS_LABEL, &serde_json::to_vec(group_id)?)?;
        refs.into_iter()
            .map(|r| {
                let key = serde_json::to_vec(&(group_id, &r))?;
                let proposal = self.get(QUEUED_PROPOSAL_LABEL, &key)?.ok_or(KseStorageError::Serialization)?;
                Ok((r, proposal))
            })
            .collect()
    }

    fn tree<GroupId: traits::GroupId<CURRENT_VERSION>, TreeSync: traits::TreeSync<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        self.get(TREE_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn group_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        self.get(GROUP_CONTEXT_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        self.get(INTERIM_TRANSCRIPT_HASH_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        self.get(CONFIRMATION_TAG_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn group_state<GroupState: traits::GroupState<CURRENT_VERSION>, GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        self.get(GROUP_STATE_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        self.get(MESSAGE_SECRETS_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        self.get(RESUMPTION_PSK_STORE_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        self.get(OWN_LEAF_NODE_INDEX_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        self.get(EPOCH_SECRETS_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        self.get(SIGNATURE_KEY_PAIR_LABEL, &serde_json::to_vec(public_key)?)
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        self.get(ENCRYPTION_KEY_PAIR_LABEL, &serde_json::to_vec(public_key)?)
    }

    fn encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        let key = epoch_key_pairs_id(group_id, epoch, leaf_index)?;
        let sk = build_key(EPOCH_KEY_PAIRS_LABEL, &key);
        let values = self.values.read().unwrap();
        match values.get(&sk) {
            Some(sealed) => Ok(serde_json::from_slice(&self.open(&sk, sealed)?)?),
            None => Ok(vec![]),
        }
    }

    fn key_package<
        KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        self.get(KEY_PACKAGE_LABEL, &serde_json::to_vec(hash_ref)?)
    }

    fn psk<PskBundle: traits::PskBundle<CURRENT_VERSION>, PskId: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        self.get(PSK_LABEL, &serde_json::to_vec(psk_id)?)
    }

    // ===== deletes / clear / remove (mutating) =====

    fn remove_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        self.remove_item(
            PROPOSAL_QUEUE_REFS_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(proposal_ref)?,
        )?;
        self.del(QUEUED_PROPOSAL_LABEL, &serde_json::to_vec(&(group_id, proposal_ref))?)
    }

    fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.del(OWN_LEAF_NODES_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.del(JOIN_CONFIG_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(&self, group_id: &GroupId) -> Result<(), Self::Error> {
        self.del(TREE_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.del(CONFIRMATION_TAG_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.del(GROUP_STATE_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.del(GROUP_CONTEXT_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.counters.interim_transcript.fetch_add(1, Ordering::Relaxed);
        self.del(INTERIM_TRANSCRIPT_HASH_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.del(MESSAGE_SECRETS_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.del(RESUMPTION_PSK_STORE_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.del(OWN_LEAF_NODE_INDEX_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.del(EPOCH_SECRETS_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn clear_proposal_queue<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let refs: Vec<ProposalRef> = self.get_list(PROPOSAL_QUEUE_REFS_LABEL, &serde_json::to_vec(group_id)?)?;
        for r in refs {
            self.del(QUEUED_PROPOSAL_LABEL, &serde_json::to_vec(&(group_id, &r))?)?;
        }
        self.del(PROPOSAL_QUEUE_REFS_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_signature_key_pair<SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>>(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error> {
        self.del(SIGNATURE_KEY_PAIR_LABEL, &serde_json::to_vec(public_key)?)
    }

    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        self.del(ENCRYPTION_KEY_PAIR_LABEL, &serde_json::to_vec(public_key)?)
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        let key = epoch_key_pairs_id(group_id, epoch, leaf_index)?;
        self.del(EPOCH_KEY_PAIRS_LABEL, &key)
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<CURRENT_VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        self.del(KEY_PACKAGE_LABEL, &serde_json::to_vec(hash_ref)?)
    }

    fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(&self, psk_id: &PskKey) -> Result<(), Self::Error> {
        self.del(PSK_LABEL, &serde_json::to_vec(psk_id)?)
    }
}

// ----------------------------- composed provider -----------------------------
// libcrux crypto+rand (for X-Wing) with the encrypting storage. This is what the M2 client uses.

pub struct KseProvider {
    crypto: openmls_libcrux_crypto::CryptoProvider,
    storage: KseStorageProvider,
}
impl KseProvider {
    pub fn new(kek: [u8; 32]) -> Result<Self, openmls_traits::types::CryptoError> {
        Ok(KseProvider { crypto: openmls_libcrux_crypto::CryptoProvider::new()?, storage: KseStorageProvider::new(kek) })
    }
    pub fn storage(&self) -> &KseStorageProvider {
        &self.storage
    }
}

impl KseStorageProvider {
    // Atomicity primitive (auditor: "merge atomicity relies on the StorageProvider"). OpenMLS 0.8.1's
    // trait has no transaction hooks, so a multi-write merge is made all-or-nothing at the application
    // level: snapshot the FROZEN keyspace before merge_staged_commit, restore it on Err.
    //
    // 🔴 CRITICAL: snapshot/restore touch ONLY the FROZEN keyspace (membership/config/proposal-store).
    // The SECRET-RATCHET (FREE) keyspace is left exactly as-is — advanced. A whole-store rollback would
    // RESURRECT FS-forgotten ratchet keys (a forward-secrecy hole, the same class as the Q4 write-count
    // mistake). So `restore_frozen` removes all current FROZEN entries and reinstates the snapshot's,
    // never adding/removing a FREE (ratchet/secret) entry. The FROZEN classification is the same
    // single-source-of-truth `is_frozen_key` the write counter uses (HARDEN 2).
    pub fn snapshot_frozen(&self) -> HashMap<Vec<u8>, Vec<u8>> {
        self.values
            .read()
            .unwrap()
            .iter()
            .filter(|(k, _)| is_frozen_key(k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
    pub fn restore_frozen(&self, snap: HashMap<Vec<u8>, Vec<u8>>) {
        let mut values = self.values.write().unwrap();
        values.retain(|k, _| !is_frozen_key(k)); // drop ONLY current FROZEN entries (FREE untouched)
        for (k, v) in snap {
            values.insert(k, v); // reinstate the snapshot's FROZEN entries
        }
    }

    /// Export the entire sealed backing store (M3 app-managed persistence, decision 2b). Every value is a
    /// KSE1 envelope already (Contract-2), so the dump carries NO plaintext — the app persists it to a
    /// Keystore-encrypted file and re-imports on restart. Keys (storage-keys) are non-secret labels+ids.
    pub fn export_sealed(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.values.read().unwrap().iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
    /// Replace the backing store with a previously exported sealed dump (restore across app restart).
    pub fn import_sealed(&self, dump: Vec<(Vec<u8>, Vec<u8>)>) {
        let mut values = self.values.write().unwrap();
        values.clear();
        for (k, v) in dump {
            values.insert(k, v);
        }
    }

    /// On-device Contract-2 self-check (Diagnostics). Seal a known plaintext at a real label, then confirm
    /// (a) the backing store holds ONLY the KSE1 envelope — the plaintext marker appears NOWHERE at rest —
    /// and (b) seal→open round-trips to the exact bytes. Returns (no_plaintext_at_rest, roundtrip_ok).
    /// Uses a throwaway provider's own map, so the counter bump is inconsequential.
    pub fn selfcheck_contract2(&self) -> (bool, bool) {
        let marker: &[u8] = b"kvant-contract2-selfcheck-PLAINTEXT-marker-2f9c";
        if self.put(TREE_LABEL, b"selfcheck", marker.to_vec()).is_err() {
            return (false, false);
        }
        let sk = build_key(TREE_LABEL, b"selfcheck");
        let values = self.values.read().unwrap();
        let sealed = match values.get(&sk) {
            Some(s) => s,
            None => return (false, false),
        };
        let no_plaintext_at_rest = sealed.len() >= 4 + 12 + 16
            && &sealed[0..4] == b"KSE1"
            && !sealed.windows(marker.len()).any(|w| w == marker);
        let roundtrip_ok = matches!(self.open(&sk, sealed), Ok(pt) if pt == marker);
        (no_plaintext_at_rest, roundtrip_ok)
    }

    /// Contract-2 check: every value in the backing store is a KSE1 envelope (no plaintext at rest).
    #[cfg(test)]
    pub fn all_values_sealed(&self) -> bool {
        let v = self.values.read().unwrap();
        !v.is_empty() && v.values().all(|val| val.len() >= 4 + 12 + 16 && &val[0..4] == b"KSE1")
    }

    /// (frozen_entry_count, free_entry_count) — lets the harness prove restore_frozen leaves FREE alone.
    #[cfg(test)]
    pub fn frozen_free_counts(&self) -> (usize, usize) {
        let v = self.values.read().unwrap();
        let f = v.keys().filter(|k| is_frozen_key(k)).count();
        (f, v.len() - f)
    }
}
impl openmls_traits::OpenMlsProvider for KseProvider {
    type CryptoProvider = openmls_libcrux_crypto::CryptoProvider;
    type RandProvider = openmls_libcrux_crypto::CryptoProvider;
    type StorageProvider = KseStorageProvider;
    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }
    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }
    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

// ----------------------------- harden self-checks ----------------------------
// These run in the same `cargo test` and lock the two evolution-hardens in place: the delimiter and the
// single-source keyspace derivation are verified to hold for the WHOLE label set, not just today's usage.
#[cfg(test)]
mod harden {
    use super::*;

    // The full label set, paired with the keyspace each method PREVIOUSLY tagged by hand (pre-harden). The
    // harden derives the tag from the label instead; this list is the frozen reference proving the derive ==
    // the prior manual tag for every label (and therefore for all 57 call sites that use these labels).
    const PRIOR_MANUAL_TAG: &[(&[u8], Keyspace)] = &[
        (KEY_PACKAGE_LABEL, Keyspace::KeyMaterial),
        (PSK_LABEL, Keyspace::KeyMaterial),
        (ENCRYPTION_KEY_PAIR_LABEL, Keyspace::KeyMaterial),
        (SIGNATURE_KEY_PAIR_LABEL, Keyspace::KeyMaterial),
        (EPOCH_KEY_PAIRS_LABEL, Keyspace::SecretRatchet),
        (EPOCH_SECRETS_LABEL, Keyspace::SecretRatchet),
        (RESUMPTION_PSK_STORE_LABEL, Keyspace::SecretRatchet),
        (MESSAGE_SECRETS_LABEL, Keyspace::SecretRatchet),
        (TREE_LABEL, Keyspace::Membership),
        (GROUP_CONTEXT_LABEL, Keyspace::Membership),
        (INTERIM_TRANSCRIPT_HASH_LABEL, Keyspace::Membership),
        (CONFIRMATION_TAG_LABEL, Keyspace::Membership),
        (OWN_LEAF_NODES_LABEL, Keyspace::Membership),
        (GROUP_STATE_LABEL, Keyspace::Membership),
        (OWN_LEAF_NODE_INDEX_LABEL, Keyspace::Membership),
        (JOIN_CONFIG_LABEL, Keyspace::Config),
        (QUEUED_PROPOSAL_LABEL, Keyspace::ProposalStore),
        (PROPOSAL_QUEUE_REFS_LABEL, Keyspace::ProposalStore),
    ];

    // HARDEN 2: the derive (keyspace_for_label, the single source both the counter and is_frozen_key use)
    // yields EXACTLY the prior hand tag for every label. So the refactor changed no classification.
    #[test]
    fn derive_equals_prior_manual_tag_for_every_label() {
        assert_eq!(LABEL_KEYSPACE.len(), PRIOR_MANUAL_TAG.len(), "no label added/dropped by the harden");
        for (label, expected) in PRIOR_MANUAL_TAG {
            assert_eq!(keyspace_for_label(label), *expected, "label {:?} re-tagged by the harden", String::from_utf8_lossy(label));
        }
    }

    // HARDEN 1: no label contains the reserved delimiter — the premise that makes `label ∥ DELIM` prefix
    // matching exact. If a future label embeds the delimiter, this fails loudly.
    #[test]
    fn no_label_contains_the_delimiter() {
        for (label, _) in LABEL_KEYSPACE {
            assert!(!label.contains(&LABEL_DELIM), "label {:?} contains the reserved delimiter", String::from_utf8_lossy(label));
        }
    }

    // HARDEN 1, structural: even when one label is a textual prefix of another (the near-miss the auditor
    // flagged: MlsGroupJoinConfig vs MessageSecrets diverge at char 2; a future "Tree2" would share "Tree"),
    // the delimiter makes a key built from one label NEVER classify as the other. We prove it directly: a
    // synthetic FREE label "Tree2" must not be seen as the FROZEN "Tree".
    #[test]
    fn delimiter_defeats_prefix_collision() {
        // "Tree2" is a hypothetical future FREE label sharing the "Tree" (FROZEN) textual prefix.
        let collide = build_key(b"Tree2", b"\x00payload");
        // It must NOT be classified as the FROZEN "Tree" keyspace (Tree2 is unregistered → not frozen).
        assert!(!is_frozen_key(&collide), "delimiter must stop Tree2 from matching the FROZEN Tree prefix");
        // And the genuine "Tree" key still classifies FROZEN.
        let genuine = build_key(TREE_LABEL, b"\x00gid");
        assert!(is_frozen_key(&genuine), "genuine Tree key stays FROZEN");
        // label_of_key recovers the exact label, delimiter-terminated, regardless of payload bytes.
        assert_eq!(label_of_key(&collide), Some(&b"Tree2"[..]));
        assert_eq!(label_of_key(&genuine), Some(TREE_LABEL));
    }

    // No registered label is a textual prefix of another such that, WITHOUT the delimiter, build_key could
    // ambiguously prefix-match. With the delimiter the classification is exact; this documents the near-miss
    // pairs and asserts each real label only ever classifies as ITS OWN keyspace.
    #[test]
    fn every_label_classifies_as_only_itself() {
        for (label, ks) in LABEL_KEYSPACE {
            let key = build_key(label, b"x");
            assert_eq!(label_of_key(&key), Some(&label[..]));
            assert_eq!(keyspace_for_label_opt(label_of_key(&key).unwrap()), Some(*ks));
            assert_eq!(is_frozen_key(&key), ks.frozen_on_reject());
        }
    }
}

#[cfg(test)]
mod tests;
