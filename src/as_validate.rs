// as_validate.rs — M2 AS-callback (Authentication Service). The membership trust decision: every leaf
// that enters or rotates in the group must be a cert-verified device of a TOFU-pinned account. This is
// the MLS-level analogue of the 1:1 C3-LINKED gate, run on EVERY leaf path (auditor B1):
//
//   B1.1  validate on ALL leaf-introducing/rotating paths — Add + Update + external-join + the Commit
//         carrying them. NOT just Add: a member (or A2) can rotate via Update onto an UN-bound key.
//   B1.2  multidevice via the C3-LINKED device-cert chain (reuse devicecert.rs, do NOT reinvent): the
//         MLS leaf signature_key IS the device Ed25519 key the account cert certifies.
//   B1.3  on Welcome, validate the WHOLE ratchet tree (every Member), not just the incremental Add —
//         A2 may have written a ghost leaf into the tree; the joiner must detect it, never trust the tree.
//   +     revocation screened in the callback: a revoked device's leaf fails closed.
//   B2.4  a Commit/GCE proposal lowering required_capabilities below the floor is rejected (policy.rs).
//
// The device-cert travels INSIDE the BasicCredential identity (encode_identity) rather than a leaf
// extension, because OpenMLS's `Member` (used for the whole-tree Welcome walk) exposes the credential
// but not leaf extensions. So one decode path serves Add, Update and Welcome-tree uniformly.

use std::collections::HashMap;

use openmls::prelude::{
    BasicCredential, Credential, LeafNode, Proposal, StagedCommit,
};
use openmls::group::StagedWelcome;

use crate::devicecert::{verify_device_bundle, CertReject, DeviceCert, Revocation};
use crate::policy::{check_no_downgrade, DowngradeReject, KVANT_DEVCERT_EXT};

// ----------------------------- TrustStore ------------------------------------
// The relying-party trust state the AS-callback consults: account-id → pinned account Ed25519 key
// (the TOFU pins), the known revocations, and an optional `now` for cert TTL. A malicious server
// cannot add a pin (pins come from the user's TOFU / safety-number flow), so an account-id it has not
// pinned fails closed (UnknownAccount).
#[derive(Default)]
pub struct TrustStore {
    pins: HashMap<Vec<u8>, Vec<u8>>, // account_id -> account Ed25519 pubkey (32)
    revocations: Vec<Revocation>,
    now: Option<u64>,
}

impl TrustStore {
    pub fn new() -> Self {
        TrustStore { pins: HashMap::new(), revocations: Vec::new(), now: None }
    }
    pub fn pin(&mut self, account_id: &[u8], account_pub: &[u8]) {
        self.pins.insert(account_id.to_vec(), account_pub.to_vec());
    }
    pub fn revoke(&mut self, rev: Revocation) {
        self.revocations.push(rev);
    }
    pub fn set_now(&mut self, now: u64) {
        self.now = Some(now);
    }
    fn pinned(&self, account_id: &[u8]) -> Option<&Vec<u8>> {
        self.pins.get(account_id)
    }
}

// ----------------------------- typed rejections ------------------------------
#[derive(Debug, PartialEq, Eq)]
pub enum LeafReject {
    NotBasicCredential, // credential type != Basic (we never accept X.509 etc.)
    IdentityDecode,     // identity bytes are not a well-formed (account_id, cert) blob
    UnknownAccount,     // account-id is not TOFU-pinned → fail closed
    Cert(CertReject),   // device-cert / bundle verification failed (forged / wrong-account / revoked / …)
}

#[derive(Debug, PartialEq, Eq)]
pub enum CommitReject {
    Leaf(LeafReject),
    Downgrade(DowngradeReject),
}

// ----------------------------- identity encoding -----------------------------
// BasicCredential identity = MAGIC || lp(account_id) || cert_blob. Self-describing, length-prefixed,
// big-endian; decode is fully bounded (fail-closed on any short/overflowing field) so it is safe to
// fuzz directly (M2 Tier-1). Mirrors the devicecert.js field order so a JS-built credential decodes.
const IDENTITY_MAGIC: &[u8; 4] = b"KMI1";

struct W(Vec<u8>);
impl W {
    fn new() -> Self { W(Vec::new()) }
    fn u32(mut self, n: u32) -> Self { self.0.extend_from_slice(&n.to_be_bytes()); self }
    fn u64(mut self, n: u64) -> Self { self.0.extend_from_slice(&n.to_be_bytes()); self }
    fn lp(mut self, b: &[u8]) -> Self { self = self.u32(b.len() as u32); self.0.extend_from_slice(b); self }
    fn raw(mut self, b: &[u8]) -> Self { self.0.extend_from_slice(b); self }
    fn out(self) -> Vec<u8> { self.0 }
}

// Bounded reader — every accessor returns None rather than panicking on a malformed/short input.
struct R<'a> { b: &'a [u8], i: usize }
impl<'a> R<'a> {
    fn new(b: &'a [u8]) -> Self { R { b, i: 0 } }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.i.checked_add(n)?;
        if end > self.b.len() { return None; }
        let s = &self.b[self.i..end];
        self.i = end;
        Some(s)
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }
    fn lp(&mut self) -> Option<Vec<u8>> {
        let n = self.u32()? as usize;
        Some(self.take(n)?.to_vec())
    }
    fn done(&self) -> bool { self.i == self.b.len() }
}

pub fn encode_identity(account_id: &[u8], cert: &DeviceCert) -> Vec<u8> {
    W::new()
        .raw(IDENTITY_MAGIC)
        .lp(account_id)
        .u32(cert.version)
        .lp(&cert.device_id)
        .lp(&cert.device_public_key)
        .lp(&cert.account_public_key)
        .u64(cert.created_at)
        .u64(cert.expires_at)
        .lp(&cert.signature)
        .out()
}

/// Decode (account_id, cert) from a credential identity. Returns None on ANY malformed input — the
/// caller treats None as a fail-closed reject (IdentityDecode). Requires exact consumption (no trailing
/// bytes) so a truncated-then-padded forgery cannot smuggle data past the parser.
pub fn decode_identity(b: &[u8]) -> Option<(Vec<u8>, DeviceCert)> {
    let mut r = R::new(b);
    if r.take(4)? != IDENTITY_MAGIC { return None; }
    let account_id = r.lp()?;
    let cert = DeviceCert {
        version: r.u32()?,
        device_id: r.lp()?,
        device_public_key: r.lp()?,
        account_public_key: r.lp()?,
        created_at: r.u64()?,
        expires_at: r.u64()?,
        signature: r.lp()?,
    };
    if !r.done() { return None; }
    Some((account_id, cert))
}

// ----------------------------- leaf validation -------------------------------

/// The core AS decision for ONE leaf: its credential + signature_key must chain — via the C3-LINKED
/// device cert — to a TOFU-pinned account, and not be revoked. Fail-closed throughout.
pub fn validate_leaf(credential: &Credential, sig_key: &[u8], ts: &TrustStore) -> Result<(), LeafReject> {
    // Must be a BasicCredential (never X.509 / other).
    let basic = BasicCredential::try_from(credential.clone()).map_err(|_| LeafReject::NotBasicCredential)?;
    // Unpack the account-id + device cert carried in the identity.
    let (account_id, cert) = decode_identity(basic.identity()).ok_or(LeafReject::IdentityDecode)?;
    // The account-id MUST be one the user has pinned — an unknown account fails closed (no implicit trust).
    let account_pub = ts.pinned(&account_id).ok_or(LeafReject::UnknownAccount)?;
    // C3-LINKED: cert chains to the pinned account AND the MLS leaf signature_key is the certified device
    // key (verify_device_bundle), and the device is not revoked.
    verify_device_bundle(&cert, account_pub, sig_key, ts.now, &ts.revocations).map_err(LeafReject::Cert)
}

/// Validate a whole LeafNode (credential + signature_key). Used by the receive walks AND — symmetrically
/// — by the SEND-side membership guard (dispatch::guarded_add_members) on each added KeyPackage's leaf.
pub fn validate_leafnode(leaf: &LeafNode, ts: &TrustStore) -> Result<(), LeafReject> {
    validate_leaf(leaf.credential(), leaf.signature_key().as_slice(), ts)
}

// ----------------------------- staged-commit walk (B1.1 + B2.4) --------------

/// Walk a StagedCommit on EVERY leaf path before the caller merges it. Add + Update leaves are
/// AS-validated; GroupContextExtensions proposals are checked for downgrade (B2.4). Remove proposals
/// carry no new key material, so they are not AS-validated here (a revoked-leaf Remove is *desirable*).
/// Returns the first rejection — the caller MUST NOT call merge_staged_commit on Err (fail-closed,
/// leaving the group epoch unchanged = the no-state-mutation invariant).
pub fn walk_staged_commit(sc: &StagedCommit, ts: &TrustStore) -> Result<(), CommitReject> {
    for add in sc.add_proposals() {
        validate_leafnode(add.add_proposal().key_package().leaf_node(), ts).map_err(CommitReject::Leaf)?;
    }
    for upd in sc.update_proposals() {
        validate_leafnode(upd.update_proposal().leaf_node(), ts).map_err(CommitReject::Leaf)?;
    }
    // CRITICAL (auditor B1.1, the "secondary branch"): a self-update rotates the COMMITTER's own leaf
    // via the commit PATH — it is NOT an Update proposal, so update_proposals() above is empty for it.
    // The path leaf must be AS-validated too, or a member (or A2) silently rotates onto an un-bound key.
    if let Some(path_leaf) = sc.update_path_leaf_node() {
        validate_leafnode(path_leaf, ts).map_err(CommitReject::Leaf)?;
    }
    for q in sc.queued_proposals() {
        if let Proposal::GroupContextExtensions(gce) = q.proposal() {
            match gce.extensions().required_capabilities() {
                Some(rc) => check_no_downgrade(rc).map_err(CommitReject::Downgrade)?,
                // Dropping required_capabilities ENTIRELY is the strongest downgrade.
                None => return Err(CommitReject::Downgrade(
                    DowngradeReject::MissingRequiredExtension(KVANT_DEVCERT_EXT),
                )),
            }
        }
    }
    Ok(())
}

/// Validate a STANDALONE proposal (ProposalMessage / ExternalJoinProposalMessage) before storing it.
/// Same coverage as a commit's proposals: Add/Update leaves AS-validated, GCE downgrade-checked.
pub fn validate_queued_proposal(p: &Proposal, ts: &TrustStore) -> Result<(), CommitReject> {
    match p {
        Proposal::Add(add) => validate_leafnode(add.key_package().leaf_node(), ts).map_err(CommitReject::Leaf),
        Proposal::Update(upd) => validate_leafnode(upd.leaf_node(), ts).map_err(CommitReject::Leaf),
        Proposal::GroupContextExtensions(gce) => match gce.extensions().required_capabilities() {
            Some(rc) => check_no_downgrade(rc).map_err(CommitReject::Downgrade),
            None => Err(CommitReject::Downgrade(DowngradeReject::MissingRequiredExtension(KVANT_DEVCERT_EXT))),
        },
        _ => Ok(()),
    }
}

// ----------------------------- welcome whole-tree walk (B1.3) ----------------

/// On join, validate EVERY member of the ratchet tree — not just the leaf that added us. A2 may have
/// written a ghost (un-bound) leaf into the tree it sent us in the Welcome; we trust nothing in the
/// tree until each member's credential chains to a pinned account. Fail-closed on the first bad leaf.
pub fn walk_welcome_tree(sw: &StagedWelcome, ts: &TrustStore) -> Result<(), LeafReject> {
    for m in sw.members() {
        validate_leaf(&m.credential, &m.signature_key, ts)?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
