//! Generation-0.1 protocol persistence separate from representation byte files.

#[path = "v01_representation.rs"]
mod representation;

pub use representation::{
    AcceptOutcome, DurableBoundary, RepresentationSnapshot, RepresentationStore,
    RepresentationStoreError,
};

use bempic_model::v01::{ImmutableObservation, ObjectId};
use bempic_sync::v01::{
    collection_checkpoint, CollectionEntry, Cursor, Failure, FailureCode, NegotiatedProfile, Offer,
    OfferMode, Operation, Record, Summary,
};
use bempic_sync::v01_compact::{validate_negotiated_profile, validate_representation_descriptor};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct CapabilityCache {
    peer_profile_id: [u8; 32],
    expires_at: u64,
    profile: NegotiatedProfile,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct CollectionState {
    collection_id: [u8; 32],
    checkpoint: Summary,
    retained_entries: Vec<CollectionEntry>,
    reconciliation: Option<ReconciliationState>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ReconciliationState {
    prior: Summary,
    target: Summary,
    mode: OfferMode,
    cursor: Option<Cursor>,
    accepted_entries: Vec<CollectionEntry>,
    pages_complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ObjectBinding {
    object_id: ObjectId,
    immutable_semantics_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct FailureState {
    scope: Vec<u8>,
    code: FailureCode,
    retryable: bool,
    condition_changed: bool,
    automatic_retry_attempts: u8,
}

/// Durable observation of one scoped failure and its bounded retry state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailureRetrySnapshot {
    /// Exact failure code last observed for the scope.
    pub code: FailureCode,
    /// Whether the peer allowed retry after the condition changed.
    pub retryable: bool,
    /// Whether a changed condition was durably recorded.
    pub condition_changed: bool,
    /// Automatic retry attempts consumed for this failure observation.
    pub automatic_retry_attempts: u8,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
struct State {
    sequence: u64,
    capability_cache: Option<CapabilityCache>,
    collections: Vec<CollectionState>,
    receipt_ids: Vec<[u8; 16]>,
    #[serde(default)]
    object_bindings: Vec<ObjectBinding>,
    #[serde(default)]
    failures: Vec<FailureState>,
}

/// Two-slot copy-on-write protocol store.
///
/// Each save synchronizes a new sequence into the older slot. Reopen parses
/// both slots and selects the highest valid sequence, so an interrupted write
/// cannot advance state beyond the last recoverable record.
pub struct ProtocolStore {
    slots: [PathBuf; 2],
    state: State,
}

impl ProtocolStore {
    /// Open both durable slots, ignoring a torn newest slot when the other is valid.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        crate::durable::create_dir_all(root.as_ref())?;
        let slots = [
            root.as_ref().join("bempic-v01-state.0.json"),
            root.as_ref().join("bempic-v01-state.1.json"),
        ];
        let mut valid = Vec::new();
        let mut invalid_slots = 0_usize;
        for slot in &slots {
            if slot.exists() {
                match fs::read(slot).map_err(StoreError::Io).and_then(|bytes| {
                    serde_json::from_slice::<State>(&bytes).map_err(StoreError::Json)
                }) {
                    Ok(state) => valid.push(state),
                    Err(_) => invalid_slots += 1,
                }
            }
        }
        if valid.is_empty() && invalid_slots > 0 {
            return Err(StoreError::NoRecoverableSlot);
        }
        valid.sort_by_key(|state| state.sequence);
        Ok(Self {
            slots,
            state: valid.pop().unwrap_or_default(),
        })
    }

    /// Persist one negotiated profile, bound to a peer/profile identity and expiry.
    pub fn persist_negotiation(
        &mut self,
        peer_profile_id: [u8; 32],
        expires_at: u64,
        profile: NegotiatedProfile,
    ) -> Result<(), StoreError> {
        validate_negotiated_profile(&profile).map_err(|_| StoreError::UnsupportedCodec)?;
        self.state.capability_cache = Some(CapabilityCache {
            peer_profile_id,
            expires_at,
            profile,
        });
        self.save()
    }

    /// Return a non-stale cached negotiation only for the exact peer/profile.
    pub fn cached_negotiation(
        &self,
        peer_profile_id: [u8; 32],
        now: u64,
    ) -> Option<&NegotiatedProfile> {
        self.state
            .capability_cache
            .as_ref()
            .filter(|cache| cache.peer_profile_id == peer_profile_id && now <= cache.expires_at)
            .map(|cache| &cache.profile)
    }

    /// Install an initial empty checkpoint for one collection.
    pub fn initialize_collection(&mut self, checkpoint: Summary) -> Result<(), StoreError> {
        if self.collection(checkpoint.collection_id).is_some() {
            return Err(StoreError::CollectionConflict);
        }
        self.state.collections.push(CollectionState {
            collection_id: checkpoint.collection_id,
            checkpoint,
            retained_entries: Vec::new(),
            reconciliation: None,
        });
        self.state
            .collections
            .sort_by_key(|collection| collection.collection_id);
        self.save()
    }

    /// Read the last atomically committed checkpoint.
    pub fn checkpoint(&self, collection_id: [u8; 32]) -> Option<Summary> {
        self.collection(collection_id)
            .map(|collection| collection.checkpoint)
    }

    /// Read the last durable offer-page cursor.
    pub fn cursor(&self, collection_id: [u8; 32]) -> Option<Cursor> {
        self.collection(collection_id)
            .and_then(|collection| collection.reconciliation.as_ref())
            .and_then(|reconciliation| reconciliation.cursor)
    }

    /// Start a target without modifying the prior valid checkpoint.
    pub fn begin_reconciliation(
        &mut self,
        prior: Summary,
        target: Summary,
        mode: OfferMode,
    ) -> Result<(), StoreError> {
        if prior.collection_id != target.collection_id || prior.generation > target.generation {
            return Err(StoreError::CollectionConflict);
        }
        let collection = self
            .collection_mut(prior.collection_id)
            .ok_or(StoreError::UnknownCollection)?;
        if collection.checkpoint != prior {
            return Err(StoreError::CollectionConflict);
        }
        collection.reconciliation = Some(ReconciliationState {
            prior,
            target,
            mode,
            cursor: None,
            accepted_entries: Vec::new(),
            pages_complete: false,
        });
        self.save()
    }

    /// Durably accept one validated page and advance its explicit cursor.
    pub fn commit_offer_page(&mut self, offer: &Offer) -> Result<(), StoreError> {
        offer
            .validate()
            .map_err(|_| StoreError::CollectionConflict)?;
        for entry in &offer.descriptors {
            validate_representation_descriptor(&entry.descriptor)
                .map_err(|_| StoreError::UnsupportedCodec)?;
        }
        let collection = self
            .collection_mut(offer.collection_id)
            .ok_or(StoreError::UnknownCollection)?;
        let reconciliation = collection
            .reconciliation
            .as_mut()
            .ok_or(StoreError::NoReconciliation)?;
        if reconciliation.target.generation != offer.target_generation
            || reconciliation.mode != offer.mode
            || (offer.mode == OfferMode::Delta
                && reconciliation.prior.generation != offer.base_generation)
            || (offer.mode == OfferMode::Full && offer.base_generation != 0)
        {
            return Err(StoreError::CollectionConflict);
        }

        if reconciliation.cursor == Some(offer.last_cursor) {
            let page_is_retained = offer.descriptors.iter().all(|entry| {
                reconciliation
                    .accepted_entries
                    .iter()
                    .any(|accepted| accepted == entry)
            });
            if page_is_retained {
                return Ok(());
            }
            return Err(StoreError::CollectionConflict);
        }

        if let Some(cursor) = reconciliation.cursor {
            let advances = match (cursor, offer.first_cursor) {
                (Cursor::Delta(previous), Cursor::Delta(next)) => next > previous,
                (Cursor::Full(previous), Cursor::Full(next)) => next > previous,
                _ => false,
            };
            if !advances {
                return Err(StoreError::CursorRegression);
            }
        }
        for entry in &offer.descriptors {
            if reconciliation.accepted_entries.iter().any(|accepted| {
                accepted.sequence == entry.sequence || accepted.key() == entry.key()
            }) {
                return Err(StoreError::CollectionConflict);
            }
            reconciliation.accepted_entries.push(entry.clone());
        }
        reconciliation.cursor = Some(offer.last_cursor);
        reconciliation.pages_complete = !offer.more;
        self.save()
    }

    /// Validate the target digest, then atomically promote checkpoint and entries.
    pub fn finish_reconciliation(&mut self, collection_id: [u8; 32]) -> Result<(), StoreError> {
        let collection = self
            .collection_mut(collection_id)
            .ok_or(StoreError::UnknownCollection)?;
        let reconciliation = collection
            .reconciliation
            .as_ref()
            .ok_or(StoreError::NoReconciliation)?;
        if !reconciliation.pages_complete {
            return Err(StoreError::IncompletePages);
        }
        let mut entries = match reconciliation.mode {
            OfferMode::Delta => collection.retained_entries.clone(),
            OfferMode::Full => Vec::new(),
        };
        entries.extend(reconciliation.accepted_entries.clone());
        let computed =
            collection_checkpoint(collection_id, reconciliation.target.generation, &entries)
                .map_err(|_| StoreError::CollectionConflict)?;
        if computed != reconciliation.target {
            return Err(StoreError::TargetDigestMismatch);
        }
        collection.checkpoint = computed;
        collection.retained_entries = entries;
        collection.reconciliation = None;
        self.save()
    }

    /// Commit one receipt ID once; duplicates have no additional effect.
    pub fn commit_receipt(&mut self, idempotency_id: [u8; 16]) -> Result<bool, StoreError> {
        if self.state.receipt_ids.contains(&idempotency_id) {
            return Ok(false);
        }
        self.state.receipt_ids.push(idempotency_id);
        self.state.receipt_ids.sort_unstable();
        self.save()?;
        Ok(true)
    }

    /// Whether a receipt ID survived reopen.
    pub fn has_receipt(&self, idempotency_id: [u8; 16]) -> bool {
        self.state.receipt_ids.contains(&idempotency_id)
    }

    /// Durably bind an object ID to opaque application-owned immutable semantics.
    pub fn observe_immutable_object(
        &mut self,
        object_id: ObjectId,
        immutable_semantics_digest: [u8; 32],
    ) -> Result<ImmutableObservation, StoreError> {
        if let Some(binding) = self
            .state
            .object_bindings
            .iter()
            .find(|binding| binding.object_id == object_id)
        {
            return if binding.immutable_semantics_digest == immutable_semantics_digest {
                Ok(ImmutableObservation::Duplicate)
            } else {
                Err(StoreError::ImmutableObjectConflict)
            };
        }
        self.state.object_bindings.push(ObjectBinding {
            object_id,
            immutable_semantics_digest,
        });
        self.state
            .object_bindings
            .sort_by_key(|binding| binding.object_id);
        self.save()?;
        Ok(ImmutableObservation::New)
    }

    /// Return one durable opaque immutable-semantics binding.
    pub fn immutable_object_binding(&self, object_id: ObjectId) -> Option<[u8; 32]> {
        self.state
            .object_bindings
            .iter()
            .find(|binding| binding.object_id == object_id)
            .map(|binding| binding.immutable_semantics_digest)
    }

    /// Durably record a decoded failure and reset its single automatic-retry allowance.
    pub fn record_failure(&mut self, failure: &Failure) -> Result<(), StoreError> {
        Record {
            operation: Operation::Failure(failure.clone()),
            extensions: Vec::new(),
        }
        .exact_encoded_size()
        .map_err(|_| StoreError::InvalidFailure)?;
        let replacement = FailureState {
            scope: failure.scope.clone(),
            code: failure.code,
            retryable: failure.retryable,
            condition_changed: false,
            automatic_retry_attempts: 0,
        };
        if let Some(state) = self
            .state
            .failures
            .iter_mut()
            .find(|state| state.scope == failure.scope)
        {
            *state = replacement;
        } else {
            self.state.failures.push(replacement);
            self.state
                .failures
                .sort_by(|left, right| left.scope.cmp(&right.scope));
        }
        self.save()
    }

    /// Durably record that the failed scope's external condition changed.
    pub fn mark_failure_condition_changed(&mut self, scope: &[u8]) -> Result<(), StoreError> {
        let state = self
            .state
            .failures
            .iter_mut()
            .find(|state| state.scope == scope)
            .ok_or(StoreError::UnknownFailureScope)?;
        state.condition_changed = true;
        self.save()
    }

    /// Consume at most one automatic retry after an advertised, changed condition.
    pub fn take_failure_retry(&mut self, scope: &[u8]) -> Result<bool, StoreError> {
        let state = self
            .state
            .failures
            .iter_mut()
            .find(|state| state.scope == scope)
            .ok_or(StoreError::UnknownFailureScope)?;
        if !state.retryable || !state.condition_changed || state.automatic_retry_attempts != 0 {
            return Ok(false);
        }
        state.automatic_retry_attempts = 1;
        self.save()?;
        Ok(true)
    }

    /// Read the durable retry state for one exact failure scope.
    pub fn failure_retry_snapshot(&self, scope: &[u8]) -> Option<FailureRetrySnapshot> {
        self.state
            .failures
            .iter()
            .find(|state| state.scope == scope)
            .map(|state| FailureRetrySnapshot {
                code: state.code,
                retryable: state.retryable,
                condition_changed: state.condition_changed,
                automatic_retry_attempts: state.automatic_retry_attempts,
            })
    }

    fn collection(&self, collection_id: [u8; 32]) -> Option<&CollectionState> {
        self.state
            .collections
            .iter()
            .find(|collection| collection.collection_id == collection_id)
    }

    fn collection_mut(&mut self, collection_id: [u8; 32]) -> Option<&mut CollectionState> {
        self.state
            .collections
            .iter_mut()
            .find(|collection| collection.collection_id == collection_id)
    }

    fn save(&mut self) -> Result<(), StoreError> {
        let mut next = self.state.clone();
        next.sequence = next
            .sequence
            .checked_add(1)
            .ok_or(StoreError::SequenceExhausted)?;
        let bytes = serde_json::to_vec(&next)?;
        let index = usize::try_from(next.sequence % 2).expect("slot index is zero or one");
        let slot_existed = self.slots[index].exists();
        {
            let mut file = File::create(&self.slots[index])?;
            file.write_all(&bytes)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
        }
        if !slot_existed {
            crate::durable::sync_parent_directory(&self.slots[index])?;
        }
        self.state = next;
        Ok(())
    }
}

/// Durable protocol-state error.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Filesystem operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// JSON slot was malformed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Existing slots were present but none was recoverable.
    #[error("no recoverable protocol-state slot")]
    NoRecoverableSlot,
    /// Durable sequence exhausted.
    #[error("protocol-state sequence exhausted")]
    SequenceExhausted,
    /// Collection was not initialized.
    #[error("collection is not initialized")]
    UnknownCollection,
    /// Collection metadata, page, or descriptor conflicted.
    #[error("collection metadata conflict")]
    CollectionConflict,
    /// No target reconciliation is active.
    #[error("no target reconciliation is active")]
    NoReconciliation,
    /// Page cursor failed to advance.
    #[error("offer page cursor regressed")]
    CursorRegression,
    /// Last page has not been durably accepted.
    #[error("reconciliation pages are incomplete")]
    IncompletePages,
    /// Reconstructed target digest did not match the authority.
    #[error("reconstructed target checkpoint digest mismatch")]
    TargetDigestMismatch,
    /// A decoded failure did not satisfy core bounds.
    #[error("failure record is invalid")]
    InvalidFailure,
    /// No durable failure exists for the exact scope.
    #[error("failure scope is unknown")]
    UnknownFailureScope,
    /// An object ID was already bound to different immutable semantics.
    #[error("object ID conflicts with its durable immutable semantics binding")]
    ImmutableObjectConflict,
    /// Codec tuple, parameters, or schema are not supported by this profile.
    #[error("unsupported codec profile")]
    UnsupportedCodec,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bempic_model::v01::{
        fingerprint_from_hex, ObjectId, PreparedRepresentation, OPAQUE_SCHEMA_FINGERPRINT_HEX,
    };
    use bempic_sync::v01::{
        reconcile, CodecPreference, ProtocolGeneration, Reconciliation, SecurityClass,
    };
    use tempfile::tempdir;

    fn entry(sequence: u64) -> CollectionEntry {
        let byte = u8::try_from(sequence).expect("test sequence fits u8");
        let prepared = PreparedRepresentation::prepare(
            vec![byte; usize::from(byte) + 1],
            None,
            fingerprint_from_hex(OPAQUE_SCHEMA_FINGERPRINT_HEX).unwrap(),
            0x0001_0000,
            1,
            Vec::new(),
            None,
        )
        .unwrap();
        CollectionEntry {
            sequence,
            object_id: ObjectId::fixture(&[byte]),
            part_id: u32::from(byte),
            descriptor: prepared.descriptor,
        }
    }

    fn profile() -> NegotiatedProfile {
        let schema = entry(1).descriptor.schema_fingerprint;
        let preference = CodecPreference {
            codec_id: 0x0001_0000,
            revision: 1,
            schema_fingerprint: schema,
        };
        NegotiatedProfile {
            protocol: ProtocolGeneration { major: 0, minor: 1 },
            schema_fingerprint: preference.schema_fingerprint,
            codec_id: preference.codec_id,
            codec_revision: preference.revision,
            max_operation_octets: 65_540,
            max_data_payload_octets: 65_000,
            receipt_levels: 0b1111,
            security_class: SecurityClass::Public,
            extensions: Vec::new(),
        }
    }

    #[test]
    fn negotiation_receipt_and_expiry_survive_reopen() {
        let root = tempdir().unwrap();
        let peer = [4; 32];
        let receipt = [5; 16];
        {
            let mut store = ProtocolStore::open(root.path()).unwrap();
            store.persist_negotiation(peer, 100, profile()).unwrap();
            assert!(store.commit_receipt(receipt).unwrap());
            assert!(!store.commit_receipt(receipt).unwrap());
        }
        let reopened = ProtocolStore::open(root.path()).unwrap();
        assert_eq!(reopened.cached_negotiation(peer, 100), Some(&profile()));
        assert!(reopened.cached_negotiation(peer, 101).is_none());
        assert!(reopened.has_receipt(receipt));
    }

    #[test]
    fn stale_cache_renegotiates_and_invalid_tuples_never_replace_durable_profile() {
        let root = tempdir().unwrap();
        let peer = [0x44; 32];
        let mut store = ProtocolStore::open(root.path()).unwrap();
        store.persist_negotiation(peer, 10, profile()).unwrap();
        assert!(store.cached_negotiation(peer, 11).is_none());

        let refreshed = profile();
        store
            .persist_negotiation(peer, 20, refreshed.clone())
            .unwrap();
        for (codec_id, codec_revision) in [
            (0, 1),
            (u32::MAX, 1),
            (0xffff_0001, 2),
            (0x0001_0000, 0),
            (0x0001_0001, 1),
            (0x0001_0000, 2),
        ] {
            let mut invalid = refreshed.clone();
            invalid.codec_id = codec_id;
            invalid.codec_revision = codec_revision;
            assert!(matches!(
                store.persist_negotiation(peer, 30, invalid),
                Err(StoreError::UnsupportedCodec)
            ));
            assert_eq!(store.cached_negotiation(peer, 20), Some(&refreshed));
        }

        drop(store);
        let reopened = ProtocolStore::open(root.path()).unwrap();
        assert_eq!(reopened.cached_negotiation(peer, 20), Some(&refreshed));
        assert!(reopened.cached_negotiation(peer, 21).is_none());
    }

    #[test]
    fn immutable_bindings_reopen_and_conflicts_preserve_unrelated_state() {
        let root = tempdir().unwrap();
        let object_id = ObjectId([1; 32]);
        let unrelated = ObjectId([2; 32]);
        {
            let mut store = ProtocolStore::open(root.path()).unwrap();
            assert!(matches!(
                store.observe_immutable_object(object_id, [3; 32]),
                Ok(ImmutableObservation::New)
            ));
            assert!(matches!(
                store.observe_immutable_object(unrelated, [4; 32]),
                Ok(ImmutableObservation::New)
            ));
        }
        let mut reopened = ProtocolStore::open(root.path()).unwrap();
        assert!(matches!(
            reopened.observe_immutable_object(object_id, [3; 32]),
            Ok(ImmutableObservation::Duplicate)
        ));
        assert!(matches!(
            reopened.observe_immutable_object(object_id, [5; 32]),
            Err(StoreError::ImmutableObjectConflict)
        ));
        assert_eq!(reopened.immutable_object_binding(object_id), Some([3; 32]));
        assert_eq!(reopened.immutable_object_binding(unrelated), Some([4; 32]));
    }

    #[test]
    fn failure_retry_allowance_is_durable_and_single_use() {
        for retryable in [false, true] {
            let root = tempdir().unwrap();
            let scope = [0x53];
            let failure = Failure {
                code: FailureCode::StorageFailure,
                scope: scope.to_vec(),
                retryable,
                detail: None,
            };
            let mut store = ProtocolStore::open(root.path()).unwrap();
            store.record_failure(&failure).unwrap();
            store.mark_failure_condition_changed(&scope).unwrap();
            assert_eq!(store.take_failure_retry(&scope).unwrap(), retryable);
            drop(store);

            let mut reopened = ProtocolStore::open(root.path()).unwrap();
            let snapshot = reopened.failure_retry_snapshot(&scope).unwrap();
            assert_eq!(snapshot.code, FailureCode::StorageFailure);
            assert_eq!(snapshot.retryable, retryable);
            assert!(snapshot.condition_changed);
            assert_eq!(snapshot.automatic_retry_attempts, u8::from(retryable));
            assert!(!reopened.take_failure_retry(&scope).unwrap());
        }
    }

    #[test]
    fn durable_cursor_reopens_and_target_digest_must_match() {
        let root = tempdir().unwrap();
        let entries = (1..=5).map(entry).collect::<Vec<_>>();
        let empty = collection_checkpoint([7; 32], 0, &[]).unwrap();
        let target = collection_checkpoint([7; 32], 5, &entries).unwrap();
        let first = reconcile(target, &[], &entries, None, None, 2, 4_096).unwrap();
        let Reconciliation::Page(first) = first else {
            panic!("expected page")
        };
        {
            let mut store = ProtocolStore::open(root.path()).unwrap();
            store.initialize_collection(empty).unwrap();
            store
                .begin_reconciliation(empty, target, OfferMode::Full)
                .unwrap();
            store.commit_offer_page(&first).unwrap();
            assert_eq!(store.cursor([7; 32]), Some(first.last_cursor));
        }
        let mut reopened = ProtocolStore::open(root.path()).unwrap();
        assert_eq!(reopened.cursor([7; 32]), Some(first.last_cursor));
        let next = reconcile(
            target,
            &[],
            &entries,
            None,
            Some(first.last_cursor),
            128,
            4_096,
        )
        .unwrap();
        let Reconciliation::Page(next) = next else {
            panic!("expected page")
        };
        reopened.commit_offer_page(&next).unwrap();
        reopened.finish_reconciliation([7; 32]).unwrap();
        assert_eq!(reopened.checkpoint([7; 32]), Some(target));
        assert_eq!(reopened.cursor([7; 32]), None);
    }

    #[test]
    fn invalid_offer_tuple_is_rejected_before_cursor_or_page_mutation() {
        let root = tempdir().unwrap();
        let entries = vec![entry(1)];
        let empty = collection_checkpoint([0x71; 32], 0, &[]).unwrap();
        let target = collection_checkpoint([0x71; 32], 1, &entries).unwrap();
        let Reconciliation::Page(mut offer) =
            reconcile(target, &[], &entries, None, None, 1, 4_096).unwrap()
        else {
            panic!("expected page")
        };
        offer.descriptors[0].descriptor.codec_id = 0xffff_0001;
        offer.descriptors[0].descriptor.codec_revision = 2;

        let mut store = ProtocolStore::open(root.path()).unwrap();
        store.initialize_collection(empty).unwrap();
        store
            .begin_reconciliation(empty, target, OfferMode::Full)
            .unwrap();
        assert!(matches!(
            store.commit_offer_page(&offer),
            Err(StoreError::UnsupportedCodec)
        ));
        assert_eq!(store.cursor([0x71; 32]), None);
        drop(store);

        let reopened = ProtocolStore::open(root.path()).unwrap();
        assert_eq!(reopened.cursor([0x71; 32]), None);
        assert_eq!(reopened.checkpoint([0x71; 32]), Some(empty));
    }

    #[test]
    fn torn_newest_slot_recovers_prior_sequence() {
        let root = tempdir().unwrap();
        let peer = [8; 32];
        let mut store = ProtocolStore::open(root.path()).unwrap();
        store.persist_negotiation(peer, 100, profile()).unwrap();
        store.commit_receipt([1; 16]).unwrap();
        drop(store);

        let newest = root.path().join("bempic-v01-state.0.json");
        fs::write(&newest, b"{torn").unwrap();
        let recovered = ProtocolStore::open(root.path()).unwrap();
        assert!(recovered.cached_negotiation(peer, 1).is_some());
    }
}
