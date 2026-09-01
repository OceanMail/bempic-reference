//! Full-width v0.1 representation persistence and deterministic fault injection.

use bempic_model::v01::{PreparedRepresentation, RepresentationDescriptor, RepresentationId};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Named durable boundary used by the crash/failure matrix.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurableBoundary {
    /// Accepted descriptor state reached durable storage.
    DescriptorAccepted,
    /// New prefix bytes reached durable storage before the prefix state update.
    PrefixBytes,
    /// Prefix length and phase reached durable state storage.
    PrefixState,
    /// Integrity and decode verification reached durable state storage.
    VerifiedState,
    /// Verified bytes were atomically promoted to the complete path.
    CommitBytes,
    /// Committed phase reached durable state storage.
    CommittedState,
    /// Receipt idempotency state reached durable storage.
    ReceiptState,
    /// Corrupt complete staging bytes were moved to quarantine.
    QuarantineBytes,
    /// Quarantine/reset phase reached durable state storage.
    QuarantineState,
}

/// Byte result from one idempotent offset write.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AcceptOutcome {
    /// Newly durable payload octets.
    pub accepted_octets: u64,
    /// Matching replayed octets already durable.
    pub duplicate_octets: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DurableStatus {
    Absent,
    Offered,
    Partial,
    CompleteUnverified,
    Verified,
    Committed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct State {
    sequence: u64,
    descriptor: RepresentationDescriptor,
    status: DurableStatus,
    durable_prefix_octets: u64,
    receipt_ids: Vec<[u8; 16]>,
}

impl State {
    const fn new(descriptor: RepresentationDescriptor) -> Self {
        Self {
            sequence: 0,
            descriptor,
            status: DurableStatus::Absent,
            durable_prefix_octets: 0,
            receipt_ids: Vec::new(),
        }
    }
}

/// Stable read-only state used for deterministic contact planning and evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RepresentationSnapshot {
    /// Exact descriptor bound to this store.
    pub descriptor: RepresentationDescriptor,
    /// Whether the descriptor offer was durably accepted.
    pub descriptor_accepted: bool,
    /// Durable contiguous prefix in octets.
    pub durable_prefix_octets: u64,
    /// Whether integrity and deterministic decode passed.
    pub verified: bool,
    /// Whether exact bytes are atomically committed.
    pub committed: bool,
    /// Number of retained receipt idempotency IDs.
    pub receipt_count: usize,
}

/// Crash-conscious full-width representation store.
///
/// State uses two copy-on-write slots. Prefix bytes and the complete file are
/// independently reconciled on reopen so failure after any named durable
/// boundary cannot invent progress or lose a recoverable prefix.
pub struct RepresentationStore {
    slots: [PathBuf; 2],
    part_path: PathBuf,
    complete_path: PathBuf,
    quarantine_stem: PathBuf,
    state: State,
    fail_after: Option<DurableBoundary>,
    injected: bool,
}

impl RepresentationStore {
    /// Open or create a store with no injected failure.
    pub fn open(
        root: impl AsRef<Path>,
        descriptor: RepresentationDescriptor,
    ) -> Result<Self, RepresentationStoreError> {
        Self::open_with_fault(root, descriptor, None)
    }

    /// Open with one deterministic failure immediately after the named boundary.
    pub fn open_with_fault(
        root: impl AsRef<Path>,
        descriptor: RepresentationDescriptor,
        fail_after: Option<DurableBoundary>,
    ) -> Result<Self, RepresentationStoreError> {
        descriptor
            .validate()
            .map_err(|_| RepresentationStoreError::InvalidDescriptor)?;
        crate::durable::create_dir_all(root.as_ref())?;
        let stem = descriptor.representation_id.to_string();
        let slots = [
            root.as_ref().join(format!("{stem}.v01-state.0.json")),
            root.as_ref().join(format!("{stem}.v01-state.1.json")),
        ];
        let mut valid = Vec::new();
        let mut invalid_slots = 0_usize;
        for slot in &slots {
            if slot.exists() {
                match fs::read(slot)
                    .map_err(RepresentationStoreError::Io)
                    .and_then(|bytes| {
                        serde_json::from_slice::<State>(&bytes)
                            .map_err(RepresentationStoreError::Json)
                    }) {
                    Ok(state) if state.descriptor == descriptor => valid.push(state),
                    Ok(_) => return Err(RepresentationStoreError::IdentityConflict),
                    Err(_) => invalid_slots += 1,
                }
            }
        }
        if valid.is_empty() && invalid_slots > 0 {
            return Err(RepresentationStoreError::NoRecoverableSlot);
        }
        valid.sort_by_key(|state| state.sequence);
        let mut store = Self {
            slots,
            part_path: root.as_ref().join(format!("{stem}.part")),
            complete_path: root.as_ref().join(format!("{stem}.complete")),
            quarantine_stem: root.as_ref().join(format!("{stem}.corrupt")),
            state: valid.pop().unwrap_or_else(|| State::new(descriptor)),
            fail_after,
            injected: false,
        };
        store.reconcile()?;
        Ok(store)
    }

    /// Exact current durable state without reading payload bytes.
    pub fn snapshot(&self) -> RepresentationSnapshot {
        RepresentationSnapshot {
            descriptor: self.state.descriptor.clone(),
            descriptor_accepted: self.state.status != DurableStatus::Absent,
            durable_prefix_octets: self.state.durable_prefix_octets,
            verified: matches!(
                self.state.status,
                DurableStatus::Verified | DurableStatus::Committed
            ),
            committed: self.state.status == DurableStatus::Committed,
            receipt_count: self.state.receipt_ids.len(),
        }
    }

    /// Current staging path for deterministic corruption tests.
    pub fn part_path(&self) -> &Path {
        &self.part_path
    }

    /// Current committed path for inspection.
    pub fn complete_path(&self) -> &Path {
        &self.complete_path
    }

    /// Durably accept the exact offered descriptor.
    pub fn accept_descriptor(
        &mut self,
        descriptor: &RepresentationDescriptor,
    ) -> Result<bool, RepresentationStoreError> {
        if descriptor != &self.state.descriptor {
            return Err(RepresentationStoreError::IdentityConflict);
        }
        if self.state.status != DurableStatus::Absent {
            return Ok(false);
        }
        self.state.status = if descriptor.encoded_length == 0 {
            DurableStatus::CompleteUnverified
        } else {
            DurableStatus::Offered
        };
        self.save()?;
        self.trip(DurableBoundary::DescriptorAccepted)?;
        Ok(true)
    }

    /// Append or replay a non-empty contiguous DATA payload.
    pub fn accept_data(
        &mut self,
        representation_id: RepresentationId,
        offset: u64,
        payload: &[u8],
    ) -> Result<AcceptOutcome, RepresentationStoreError> {
        if representation_id != self.state.descriptor.representation_id {
            return Err(RepresentationStoreError::IdentityConflict);
        }
        if payload.is_empty() {
            return Err(RepresentationStoreError::EmptyData);
        }
        if self.state.status == DurableStatus::Absent {
            return Err(RepresentationStoreError::DescriptorNotAccepted);
        }
        let payload_octets =
            u64::try_from(payload.len()).map_err(|_| RepresentationStoreError::Length)?;
        let end = offset
            .checked_add(payload_octets)
            .ok_or(RepresentationStoreError::Length)?;
        if end > self.state.descriptor.encoded_length {
            return Err(RepresentationStoreError::DataExceedsDescriptor);
        }
        if self.state.status == DurableStatus::Committed {
            Self::verify_duplicate(&self.complete_path, offset, payload)?;
            return Ok(AcceptOutcome {
                accepted_octets: 0,
                duplicate_octets: payload_octets,
            });
        }
        if offset > self.state.durable_prefix_octets {
            return Err(RepresentationStoreError::NonContiguous);
        }
        let overlap_octets = payload_octets.min(self.state.durable_prefix_octets - offset);
        let overlap =
            usize::try_from(overlap_octets).map_err(|_| RepresentationStoreError::Length)?;
        if overlap > 0 {
            Self::verify_duplicate(&self.part_path, offset, &payload[..overlap])?;
        }
        if overlap == payload.len() {
            return Ok(AcceptOutcome {
                accepted_octets: 0,
                duplicate_octets: payload_octets,
            });
        }
        let suffix = &payload[overlap..];
        let part_existed = self.part_path.exists();
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.part_path)?;
        file.write_all(suffix)?;
        file.sync_all()?;
        if !part_existed {
            crate::durable::sync_parent_directory(&self.part_path)?;
        }
        self.trip(DurableBoundary::PrefixBytes)?;

        let accepted_octets =
            u64::try_from(suffix.len()).map_err(|_| RepresentationStoreError::Length)?;
        self.state.durable_prefix_octets = self
            .state
            .durable_prefix_octets
            .checked_add(accepted_octets)
            .ok_or(RepresentationStoreError::Length)?;
        self.state.status =
            if self.state.durable_prefix_octets == self.state.descriptor.encoded_length {
                DurableStatus::CompleteUnverified
            } else {
                DurableStatus::Partial
            };
        self.save()?;
        self.trip(DurableBoundary::PrefixState)?;
        Ok(AcceptOutcome {
            accepted_octets,
            duplicate_octets: overlap_octets,
        })
    }

    /// Verify length, digest, representation ID, and deterministic decode.
    ///
    /// A failed check quarantines staging bytes and resets to the accepted
    /// descriptor without committing a positive state.
    pub fn verify_staged_with<F>(
        &mut self,
        decode_validator: F,
    ) -> Result<bool, RepresentationStoreError>
    where
        F: FnOnce(&[u8], &RepresentationDescriptor) -> bool,
    {
        if self.state.status == DurableStatus::Committed {
            self.read_complete()?;
            return Ok(true);
        }
        if self.state.durable_prefix_octets != self.state.descriptor.encoded_length {
            return Ok(false);
        }
        let bytes = if self.part_path.exists() {
            fs::read(&self.part_path)?
        } else if self.state.descriptor.encoded_length == 0 {
            Vec::new()
        } else {
            return Err(RepresentationStoreError::NotComplete);
        };
        let prepared = PreparedRepresentation {
            descriptor: self.state.descriptor.clone(),
            bytes: bytes.clone(),
        };
        if !prepared.verify() || !decode_validator(&bytes, &self.state.descriptor) {
            self.quarantine()?;
            return Err(RepresentationStoreError::IntegrityOrDecode);
        }
        self.state.status = DurableStatus::Verified;
        self.save()?;
        self.trip(DurableBoundary::VerifiedState)?;
        Ok(true)
    }

    /// Atomically promote a verified staging representation.
    pub fn commit_verified(&mut self) -> Result<bool, RepresentationStoreError> {
        if self.state.status == DurableStatus::Committed {
            self.read_complete()?;
            return Ok(true);
        }
        if self.state.status != DurableStatus::Verified {
            return Ok(false);
        }
        if !self.part_path.exists() {
            let file = File::create(&self.part_path)?;
            file.sync_all()?;
        }
        crate::durable::replace_file(&self.part_path, &self.complete_path)?;
        self.trip(DurableBoundary::CommitBytes)?;
        self.state.status = DurableStatus::Committed;
        self.state.durable_prefix_octets = self.state.descriptor.encoded_length;
        self.save()?;
        self.trip(DurableBoundary::CommittedState)?;
        Ok(true)
    }

    /// Persist one delivered receipt ID once.
    pub fn commit_receipt(
        &mut self,
        idempotency_id: [u8; 16],
    ) -> Result<bool, RepresentationStoreError> {
        if self.state.receipt_ids.contains(&idempotency_id) {
            return Ok(false);
        }
        self.state.receipt_ids.push(idempotency_id);
        self.state.receipt_ids.sort_unstable();
        self.save()?;
        self.trip(DurableBoundary::ReceiptState)?;
        Ok(true)
    }

    /// Whether the exact receipt ID survived restart.
    pub fn has_receipt(&self, idempotency_id: [u8; 16]) -> bool {
        self.state.receipt_ids.contains(&idempotency_id)
    }

    /// Read committed bytes after full descriptor verification.
    pub fn read_complete(&self) -> Result<Vec<u8>, RepresentationStoreError> {
        if self.state.status != DurableStatus::Committed || !self.complete_path.exists() {
            return Err(RepresentationStoreError::NotComplete);
        }
        let bytes = fs::read(&self.complete_path)?;
        let prepared = PreparedRepresentation {
            descriptor: self.state.descriptor.clone(),
            bytes,
        };
        if !prepared.verify() {
            return Err(RepresentationStoreError::IntegrityOrDecode);
        }
        Ok(prepared.bytes)
    }

    fn reconcile(&mut self) -> Result<(), RepresentationStoreError> {
        let before = self.state.clone();
        if self.complete_path.exists() {
            let bytes = fs::read(&self.complete_path)?;
            let prepared = PreparedRepresentation {
                descriptor: self.state.descriptor.clone(),
                bytes,
            };
            if !prepared.verify() {
                return Err(RepresentationStoreError::IntegrityOrDecode);
            }
            self.state.status = DurableStatus::Committed;
            self.state.durable_prefix_octets = self.state.descriptor.encoded_length;
        } else {
            let actual = if self.part_path.exists() {
                fs::metadata(&self.part_path)?.len()
            } else {
                0
            };
            if actual > self.state.descriptor.encoded_length {
                return Err(RepresentationStoreError::DataExceedsDescriptor);
            }
            self.state.durable_prefix_octets = actual;
            self.state.status = if self.state.status == DurableStatus::Absent {
                if actual == 0 {
                    DurableStatus::Absent
                } else {
                    return Err(RepresentationStoreError::DescriptorNotAccepted);
                }
            } else if actual == self.state.descriptor.encoded_length {
                if self.state.status == DurableStatus::Verified {
                    DurableStatus::Verified
                } else {
                    DurableStatus::CompleteUnverified
                }
            } else if actual == 0 {
                DurableStatus::Offered
            } else {
                DurableStatus::Partial
            };
        }
        if self.state != before {
            self.save()?;
        }
        Ok(())
    }

    fn quarantine(&mut self) -> Result<(), RepresentationStoreError> {
        if self.part_path.exists() {
            let destination = self.next_quarantine();
            crate::durable::replace_file(&self.part_path, &destination)?;
            self.trip(DurableBoundary::QuarantineBytes)?;
        }
        self.state.status = DurableStatus::Offered;
        self.state.durable_prefix_octets = 0;
        self.save()?;
        self.trip(DurableBoundary::QuarantineState)
    }

    fn next_quarantine(&self) -> PathBuf {
        if !self.quarantine_stem.exists() {
            return self.quarantine_stem.clone();
        }
        for sequence in 1_u64.. {
            let candidate = self
                .quarantine_stem
                .with_extension(format!("corrupt.{sequence}"));
            if !candidate.exists() {
                return candidate;
            }
        }
        unreachable!("unbounded quarantine sequence")
    }

    fn verify_duplicate(
        path: &Path,
        offset: u64,
        expected: &[u8],
    ) -> Result<(), RepresentationStoreError> {
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut existing = vec![0; expected.len()];
        file.read_exact(&mut existing)?;
        if existing == expected {
            Ok(())
        } else {
            Err(RepresentationStoreError::ConflictingReplay)
        }
    }

    fn save(&mut self) -> Result<(), RepresentationStoreError> {
        let mut next = self.state.clone();
        next.sequence = next
            .sequence
            .checked_add(1)
            .ok_or(RepresentationStoreError::SequenceExhausted)?;
        let mut bytes = serde_json::to_vec(&next)?;
        bytes.push(b'\n');
        let index = usize::try_from(next.sequence % 2).expect("slot index is zero or one");
        let temporary = self.slots[index].with_extension("json.tmp");
        {
            let mut file = File::create(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        crate::durable::replace_file(&temporary, &self.slots[index])?;
        self.state = next;
        Ok(())
    }

    fn trip(&mut self, boundary: DurableBoundary) -> Result<(), RepresentationStoreError> {
        if !self.injected && self.fail_after == Some(boundary) {
            self.injected = true;
            Err(RepresentationStoreError::InjectedFailure(boundary))
        } else {
            Ok(())
        }
    }
}

/// Full-width representation persistence failure.
#[derive(Debug, Error)]
pub enum RepresentationStoreError {
    /// Filesystem operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Durable JSON state was malformed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Descriptor violates the v0.1 model.
    #[error("invalid v0.1 representation descriptor")]
    InvalidDescriptor,
    /// Existing state or data belongs to another representation.
    #[error("representation identity or descriptor conflict")]
    IdentityConflict,
    /// Existing state slots were present but none was recoverable.
    #[error("no recoverable representation-state slot")]
    NoRecoverableSlot,
    /// State sequence exhausted.
    #[error("representation-state sequence exhausted")]
    SequenceExhausted,
    /// DATA arrived before the descriptor was accepted.
    #[error("representation descriptor is not accepted")]
    DescriptorNotAccepted,
    /// DATA payload was empty.
    #[error("DATA payload must be non-empty")]
    EmptyData,
    /// Offset or length could not be represented safely.
    #[error("representation length is unsupported")]
    Length,
    /// DATA crossed the exact descriptor length.
    #[error("DATA exceeds the representation descriptor")]
    DataExceedsDescriptor,
    /// A gap would be introduced in the durable prefix.
    #[error("DATA is not contiguous with the durable prefix")]
    NonContiguous,
    /// Replayed DATA differs from durable bytes.
    #[error("replayed DATA conflicts with durable bytes")]
    ConflictingReplay,
    /// Length, digest, ID, schema, or deterministic decode failed.
    #[error("representation integrity or deterministic decode failed")]
    IntegrityOrDecode,
    /// Complete bytes were requested before atomic commit.
    #[error("representation is not committed")]
    NotComplete,
    /// Deterministic storage-failure matrix injection.
    #[error("injected failure after durable boundary {0:?}")]
    InjectedFailure(DurableBoundary),
}

#[cfg(test)]
mod tests {
    use super::*;
    use bempic_model::v01::{
        fingerprint_from_hex, PreparedRepresentation, OPAQUE_SCHEMA_FINGERPRINT_HEX,
    };
    use tempfile::tempdir;

    fn prepared(bytes: Vec<u8>) -> PreparedRepresentation {
        PreparedRepresentation::prepare(
            bytes,
            None,
            fingerprint_from_hex(OPAQUE_SCHEMA_FINGERPRINT_HEX).unwrap(),
            0xffff_0001,
            1,
            Vec::new(),
            None,
        )
        .unwrap()
    }

    fn opaque(bytes: &[u8], descriptor: &RepresentationDescriptor) -> bool {
        descriptor.schema_fingerprint
            == fingerprint_from_hex(OPAQUE_SCHEMA_FINGERPRINT_HEX).unwrap()
            && descriptor.decoded_length.is_none()
            && bytes.len() as u64 == descriptor.encoded_length
    }

    #[test]
    fn full_width_prefix_reopen_verify_decode_commit_and_receipt() {
        let root = tempdir().unwrap();
        let representation = prepared(b"full-width durable representation".repeat(8));
        {
            let mut store =
                RepresentationStore::open(root.path(), representation.descriptor.clone()).unwrap();
            store.accept_descriptor(&representation.descriptor).unwrap();
            store
                .accept_data(
                    representation.descriptor.representation_id,
                    0,
                    &representation.bytes[..31],
                )
                .unwrap();
        }
        let mut reopened =
            RepresentationStore::open(root.path(), representation.descriptor.clone()).unwrap();
        assert_eq!(reopened.snapshot().durable_prefix_octets, 31);
        reopened
            .accept_data(
                representation.descriptor.representation_id,
                31,
                &representation.bytes[31..],
            )
            .unwrap();
        assert!(reopened.verify_staged_with(opaque).unwrap());
        assert!(reopened.commit_verified().unwrap());
        assert!(reopened.commit_receipt([9; 16]).unwrap());
        assert!(!reopened.commit_receipt([9; 16]).unwrap());
        drop(reopened);
        let final_store =
            RepresentationStore::open(root.path(), representation.descriptor.clone()).unwrap();
        assert_eq!(final_store.read_complete().unwrap(), representation.bytes);
        assert!(final_store.has_receipt([9; 16]));
    }

    #[test]
    fn every_success_boundary_recovers_after_injected_failure() {
        let representation = prepared(b"boundary matrix".repeat(16));
        let boundaries = [
            DurableBoundary::DescriptorAccepted,
            DurableBoundary::PrefixBytes,
            DurableBoundary::PrefixState,
            DurableBoundary::VerifiedState,
            DurableBoundary::CommitBytes,
            DurableBoundary::CommittedState,
            DurableBoundary::ReceiptState,
        ];
        for boundary in boundaries {
            let root = tempdir().unwrap();
            let mut injected = RepresentationStore::open_with_fault(
                root.path(),
                representation.descriptor.clone(),
                Some(boundary),
            )
            .unwrap();
            let result = (|| {
                injected.accept_descriptor(&representation.descriptor)?;
                injected.accept_data(
                    representation.descriptor.representation_id,
                    0,
                    &representation.bytes,
                )?;
                injected.verify_staged_with(opaque)?;
                injected.commit_verified()?;
                injected.commit_receipt([7; 16])?;
                Ok::<(), RepresentationStoreError>(())
            })();
            assert!(matches!(
                result,
                Err(RepresentationStoreError::InjectedFailure(actual)) if actual == boundary
            ));
            drop(injected);

            let mut recovered =
                RepresentationStore::open(root.path(), representation.descriptor.clone()).unwrap();
            recovered
                .accept_descriptor(&representation.descriptor)
                .unwrap();
            let prefix = recovered.snapshot().durable_prefix_octets;
            if prefix < representation.descriptor.encoded_length {
                let start = usize::try_from(prefix).unwrap();
                recovered
                    .accept_data(
                        representation.descriptor.representation_id,
                        prefix,
                        &representation.bytes[start..],
                    )
                    .unwrap();
            }
            recovered.verify_staged_with(opaque).unwrap();
            recovered.commit_verified().unwrap();
            recovered.commit_receipt([7; 16]).unwrap();
            assert_eq!(recovered.read_complete().unwrap(), representation.bytes);
            assert!(recovered.has_receipt([7; 16]));
        }
    }

    #[test]
    fn corruption_quarantines_and_clean_retry_recovers() {
        let root = tempdir().unwrap();
        let representation = prepared(b"quarantine retry".repeat(8));
        let mut store =
            RepresentationStore::open(root.path(), representation.descriptor.clone()).unwrap();
        store.accept_descriptor(&representation.descriptor).unwrap();
        let mut corrupt = representation.bytes.clone();
        corrupt[0] ^= 0xff;
        store
            .accept_data(representation.descriptor.representation_id, 0, &corrupt)
            .unwrap();
        assert!(matches!(
            store.verify_staged_with(opaque),
            Err(RepresentationStoreError::IntegrityOrDecode)
        ));
        assert_eq!(store.snapshot().durable_prefix_octets, 0);
        store
            .accept_data(
                representation.descriptor.representation_id,
                0,
                &representation.bytes,
            )
            .unwrap();
        store.verify_staged_with(opaque).unwrap();
        store.commit_verified().unwrap();
        assert_eq!(store.read_complete().unwrap(), representation.bytes);
    }

    #[test]
    fn quarantine_boundaries_recover_without_false_commit() {
        let representation = prepared(b"quarantine boundary".repeat(8));
        for boundary in [
            DurableBoundary::QuarantineBytes,
            DurableBoundary::QuarantineState,
        ] {
            let root = tempdir().unwrap();
            let mut store = RepresentationStore::open_with_fault(
                root.path(),
                representation.descriptor.clone(),
                Some(boundary),
            )
            .unwrap();
            store.accept_descriptor(&representation.descriptor).unwrap();
            let mut corrupt = representation.bytes.clone();
            corrupt[0] ^= 0xff;
            store
                .accept_data(representation.descriptor.representation_id, 0, &corrupt)
                .unwrap();
            assert!(matches!(
                store.verify_staged_with(opaque),
                Err(RepresentationStoreError::InjectedFailure(actual)) if actual == boundary
            ));
            drop(store);

            let mut recovered =
                RepresentationStore::open(root.path(), representation.descriptor.clone()).unwrap();
            assert!(!recovered.snapshot().committed);
            assert_eq!(recovered.snapshot().durable_prefix_octets, 0);
            recovered
                .accept_data(
                    representation.descriptor.representation_id,
                    0,
                    &representation.bytes,
                )
                .unwrap();
            recovered.verify_staged_with(opaque).unwrap();
            recovered.commit_verified().unwrap();
            assert_eq!(recovered.read_complete().unwrap(), representation.bytes);
        }
    }

    #[test]
    fn zero_length_reopens_and_commits_without_a_part_file() {
        let root = tempdir().unwrap();
        let representation = prepared(Vec::new());
        let part_path = {
            let mut store =
                RepresentationStore::open(root.path(), representation.descriptor.clone()).unwrap();
            store.accept_descriptor(&representation.descriptor).unwrap();
            assert!(!store.part_path().exists());
            store.part_path().to_owned()
        };
        let mut reopened =
            RepresentationStore::open(root.path(), representation.descriptor.clone()).unwrap();
        assert!(!part_path.exists());
        assert!(reopened.verify_staged_with(opaque).unwrap());
        assert!(reopened.commit_verified().unwrap());
        assert_eq!(reopened.read_complete().unwrap(), Vec::<u8>::new());
    }
}
