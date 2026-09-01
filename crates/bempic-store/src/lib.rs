#![forbid(unsafe_code)]
//! Persistent contiguous-prefix storage for cross-contact continuation.

/// Crash-conscious v0.1 negotiation, checkpoint, page-cursor, and receipt state.
pub mod v01;

use bempic_model::{ContentDigest, PreparedRepresentation, RepresentationId};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Persistent synchronization progress used by the exchange engine.
pub trait ProgressStore {
    /// Exact representation identity bound to this state.
    fn representation_id(&self) -> RepresentationId;
    /// Contiguous prefix already persisted.
    fn progress(&self) -> u64;
    /// Whether exact bytes are verified and committed.
    fn is_complete(&self) -> bool;
    /// Durable peer record ceiling agreed by capability exchange.
    fn negotiated_max_record_size(&self) -> Option<u16>;
    /// Persist a negotiated ceiling, monotonically narrowing an existing value.
    fn persist_negotiated_max_record_size(&mut self, maximum: u16) -> Result<u16, StoreError>;
    /// Whether a named negotiation phase survived the prior contact.
    fn flag(&self, flag: StateFlag) -> bool;
    /// Persist a negotiation phase.
    fn mark(&mut self, flag: StateFlag) -> Result<(), StoreError>;
    /// Append or idempotently replay offset data.
    fn accept_data(&mut self, offset: u64, payload: &[u8]) -> Result<AcceptOutcome, StoreError>;
    /// Verify an exact complete staging prefix without committing it.
    fn verify_staged(&mut self) -> Result<bool, StoreError>;
    /// Atomically commit a previously verified staging prefix.
    fn commit_verified(&mut self) -> Result<bool, StoreError>;
    /// Verify a complete prefix and make it durable.
    fn verify_and_commit(&mut self) -> Result<bool, StoreError>;
    /// Read exact committed bytes after re-verification.
    fn read_complete(&self) -> Result<Vec<u8>, StoreError>;
}

/// Negotiation and result phases retained across disconnects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateFlag {
    /// Sender capability record arrived.
    SenderCapabilities,
    /// Receiver capability record was emitted.
    ReceiverCapabilities,
    /// Collection summary arrived.
    Summary,
    /// Exact representation offer arrived.
    Offer,
    /// Stored receipt was emitted.
    Receipt,
}

/// Byte accounting returned by an idempotent store write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptOutcome {
    /// Newly persisted bytes.
    pub accepted_bytes: u64,
    /// Matching bytes that were already persisted.
    pub duplicate_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Empty,
    Offered,
    Partial,
    CompleteUnverified,
    Verified,
    Complete,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct State {
    representation_id: [u8; 16],
    digest: [u8; 32],
    size: u64,
    kind: u8,
    schema_fingerprint: [u8; 16],
    #[serde(default)]
    negotiated_max_record_size: Option<u16>,
    phases: u8,
    status: Status,
    accepted_bytes: u64,
}

impl State {
    fn for_representation(representation: &PreparedRepresentation) -> Self {
        Self {
            representation_id: representation.id.0,
            digest: representation.digest.0,
            size: representation.size(),
            kind: representation.kind as u8,
            schema_fingerprint: representation.schema_fingerprint,
            negotiated_max_record_size: None,
            phases: 0,
            status: Status::Empty,
            accepted_bytes: 0,
        }
    }

    fn matches(&self, representation: &PreparedRepresentation) -> bool {
        self.representation_id == representation.id.0
            && self.digest == representation.digest.0
            && self.size == representation.size()
            && self.kind == representation.kind as u8
            && self.schema_fingerprint == representation.schema_fingerprint
    }
}

/// Reference file-backed receiver state.
pub struct FileStore {
    representation: PreparedRepresentation,
    state_path: PathBuf,
    part_path: PathBuf,
    complete_path: PathBuf,
    corrupt_path: PathBuf,
    state: State,
}

impl FileStore {
    /// Open or create state, then reconcile it with durable byte files.
    pub fn open(
        root: impl AsRef<Path>,
        representation: PreparedRepresentation,
    ) -> Result<Self, StoreError> {
        fs::create_dir_all(root.as_ref())?;
        let stem = representation.id.to_string();
        let state_path = root.as_ref().join(format!("{stem}.json"));
        let part_path = root.as_ref().join(format!("{stem}.part"));
        let complete_path = root.as_ref().join(format!("{stem}.complete"));
        let corrupt_path = root.as_ref().join(format!("{stem}.corrupt"));
        let state = if state_path.exists() {
            let bytes = fs::read(&state_path)?;
            let loaded: State = serde_json::from_slice(&bytes)?;
            if !loaded.matches(&representation) {
                return Err(StoreError::IdentityConflict);
            }
            loaded
        } else {
            State::for_representation(&representation)
        };
        let mut store = Self {
            representation,
            state_path,
            part_path,
            complete_path,
            corrupt_path,
            state,
        };
        store.reconcile()?;
        Ok(store)
    }

    /// Path to committed exact bytes, useful for inspection tools.
    pub fn complete_path(&self) -> &Path {
        &self.complete_path
    }

    /// Path to a current incomplete prefix.
    pub fn part_path(&self) -> &Path {
        &self.part_path
    }

    fn reconcile(&mut self) -> Result<(), StoreError> {
        if self.state.negotiated_max_record_size.is_none()
            && (self.flag(StateFlag::SenderCapabilities)
                || self.flag(StateFlag::ReceiverCapabilities))
        {
            // Pre-fix state did not retain the negotiated value. Explicitly
            // repeat capability exchange instead of guessing a larger limit.
            self.state.phases &= !phase_bit(StateFlag::SenderCapabilities);
            self.state.phases &= !phase_bit(StateFlag::ReceiverCapabilities);
        }
        if self.complete_path.exists() {
            let bytes = fs::read(&self.complete_path)?;
            if u64::try_from(bytes.len()).map_err(|_| StoreError::Length)?
                != self.representation.size()
            {
                return Err(StoreError::ImpossibleCommittedSize);
            }
            verify_digest(&bytes, self.representation.digest)?;
            self.state.status = Status::Complete;
            self.state.accepted_bytes = self.representation.size();
        } else {
            let actual = if self.part_path.exists() {
                fs::metadata(&self.part_path)?.len()
            } else {
                0
            };
            if actual > self.representation.size() {
                return Err(StoreError::DataExceedsOffer);
            }
            self.state.accepted_bytes = actual;
            self.state.status = if actual == self.representation.size() {
                if self.state.status == Status::Verified {
                    let bytes = if self.part_path.exists() {
                        fs::read(&self.part_path)?
                    } else {
                        Vec::new()
                    };
                    verify_digest(&bytes, self.representation.digest)?;
                    Status::Verified
                } else {
                    Status::CompleteUnverified
                }
            } else if actual == 0 {
                match self.state.status {
                    Status::Offered => Status::Offered,
                    _ => Status::Empty,
                }
            } else {
                Status::Partial
            };
        }
        self.save()
    }

    fn save(&self) -> Result<(), StoreError> {
        let mut bytes = serde_json::to_vec(&self.state)?;
        bytes.push(b'\n');
        let temporary = self.state_path.with_extension("json.tmp");
        {
            let mut file = File::create(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        replace_file(&temporary, &self.state_path)?;
        Ok(())
    }

    fn next_quarantine(&self) -> PathBuf {
        if !self.corrupt_path.exists() {
            return self.corrupt_path.clone();
        }
        for sequence in 1_u64.. {
            let candidate = self
                .corrupt_path
                .with_extension(format!("corrupt.{sequence}"));
            if !candidate.exists() {
                return candidate;
            }
        }
        unreachable!("unbounded sequence")
    }
}

impl ProgressStore for FileStore {
    fn representation_id(&self) -> RepresentationId {
        self.representation.id
    }

    fn progress(&self) -> u64 {
        self.state.accepted_bytes
    }

    fn is_complete(&self) -> bool {
        self.state.status == Status::Complete && self.complete_path.exists()
    }

    fn negotiated_max_record_size(&self) -> Option<u16> {
        self.state.negotiated_max_record_size
    }

    fn persist_negotiated_max_record_size(&mut self, maximum: u16) -> Result<u16, StoreError> {
        let effective = self
            .state
            .negotiated_max_record_size
            .map_or(maximum, |existing| existing.min(maximum));
        self.state.negotiated_max_record_size = Some(effective);
        self.save()?;
        Ok(effective)
    }

    fn flag(&self, flag: StateFlag) -> bool {
        self.state.phases & phase_bit(flag) != 0
    }

    fn mark(&mut self, flag: StateFlag) -> Result<(), StoreError> {
        self.state.phases |= phase_bit(flag);
        match flag {
            StateFlag::SenderCapabilities
            | StateFlag::ReceiverCapabilities
            | StateFlag::Summary
            | StateFlag::Receipt => {}
            StateFlag::Offer => {
                if self.state.status == Status::Empty {
                    self.state.status = Status::Offered;
                }
            }
        }
        self.save()
    }

    fn accept_data(&mut self, offset: u64, payload: &[u8]) -> Result<AcceptOutcome, StoreError> {
        let payload_len = u64::try_from(payload.len()).map_err(|_| StoreError::Length)?;
        let end = offset.checked_add(payload_len).ok_or(StoreError::Length)?;
        if end > self.representation.size() {
            return Err(StoreError::DataExceedsOffer);
        }
        if self.is_complete() {
            let mut file = File::open(&self.complete_path)?;
            file.seek(SeekFrom::Start(offset))?;
            let mut existing = vec![0; payload.len()];
            file.read_exact(&mut existing)?;
            if existing != payload {
                return Err(StoreError::ConflictingDuplicate);
            }
            return Ok(AcceptOutcome {
                accepted_bytes: 0,
                duplicate_bytes: payload_len,
            });
        }
        if offset > self.progress() {
            return Err(StoreError::NonContiguous);
        }

        let overlap_u64 = payload_len.min(self.progress() - offset);
        let overlap = usize::try_from(overlap_u64).map_err(|_| StoreError::Length)?;
        if overlap > 0 {
            let mut file = File::open(&self.part_path)?;
            file.seek(SeekFrom::Start(offset))?;
            let mut existing = vec![0; overlap];
            file.read_exact(&mut existing)?;
            if existing != payload[..overlap] {
                return Err(StoreError::ConflictingDuplicate);
            }
        }
        if overlap == payload.len() {
            return Ok(AcceptOutcome {
                accepted_bytes: 0,
                duplicate_bytes: payload_len,
            });
        }
        let append_offset = offset + overlap_u64;
        if append_offset != self.progress() {
            return Err(StoreError::NonContiguous);
        }
        let suffix = &payload[overlap..];
        if !suffix.is_empty() {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.part_path)?;
            file.write_all(suffix)?;
            file.sync_all()?;
        }
        let accepted = u64::try_from(suffix.len()).map_err(|_| StoreError::Length)?;
        self.state.accepted_bytes += accepted;
        self.state.status = if self.state.accepted_bytes == self.representation.size() {
            Status::CompleteUnverified
        } else {
            Status::Partial
        };
        self.save()?;
        Ok(AcceptOutcome {
            accepted_bytes: accepted,
            duplicate_bytes: overlap_u64,
        })
    }

    fn verify_staged(&mut self) -> Result<bool, StoreError> {
        if self.is_complete() {
            self.read_complete()?;
            return Ok(true);
        }
        if self.progress() != self.representation.size() {
            return Ok(false);
        }
        let bytes = if self.part_path.exists() {
            fs::read(&self.part_path)?
        } else if self.representation.size() == 0 {
            Vec::new()
        } else {
            return Err(StoreError::NotComplete);
        };
        if verify_digest(&bytes, self.representation.digest).is_err()
            || !self.representation.verify()
        {
            if self.part_path.exists() {
                fs::rename(&self.part_path, self.next_quarantine())?;
            }
            self.state.accepted_bytes = 0;
            self.state.status = Status::Offered;
            self.state.phases &= !phase_bit(StateFlag::Receipt);
            self.save()?;
            return Err(StoreError::Integrity);
        }
        self.state.status = Status::Verified;
        self.save()?;
        Ok(true)
    }

    fn commit_verified(&mut self) -> Result<bool, StoreError> {
        if self.is_complete() {
            self.read_complete()?;
            return Ok(true);
        }
        if self.state.status != Status::Verified {
            return Ok(false);
        }
        if !self.part_path.exists() {
            let file = File::create(&self.part_path)?;
            file.sync_all()?;
        }
        replace_file(&self.part_path, &self.complete_path)?;
        self.state.status = Status::Complete;
        self.state.accepted_bytes = self.representation.size();
        self.save()?;
        Ok(true)
    }

    fn verify_and_commit(&mut self) -> Result<bool, StoreError> {
        if !self.verify_staged()? {
            return Ok(false);
        }
        self.commit_verified()
    }

    fn read_complete(&self) -> Result<Vec<u8>, StoreError> {
        if !self.is_complete() {
            return Err(StoreError::NotComplete);
        }
        let bytes = fs::read(&self.complete_path)?;
        verify_digest(&bytes, self.representation.digest)?;
        Ok(bytes)
    }
}

fn verify_digest(bytes: &[u8], expected: ContentDigest) -> Result<(), StoreError> {
    let actual = Sha256::digest(bytes);
    if actual.as_slice() == expected.0 {
        Ok(())
    } else {
        Err(StoreError::Integrity)
    }
}

const fn phase_bit(flag: StateFlag) -> u8 {
    match flag {
        StateFlag::SenderCapabilities => 1 << 0,
        StateFlag::ReceiverCapabilities => 1 << 1,
        StateFlag::Summary => 1 << 2,
        StateFlag::Offer => 1 << 3,
        StateFlag::Receipt => 1 << 4,
    }
}

#[cfg(windows)]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    if destination.exists() {
        fs::remove_file(destination)?;
    }
    fs::rename(source, destination)
}

#[cfg(not(windows))]
fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

/// Persistence or integrity failure.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Filesystem operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// State JSON could not be decoded or encoded.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Existing state belongs to different exact bytes.
    #[error("persisted state belongs to another representation")]
    IdentityConflict,
    /// Committed file size differs from the exact offer.
    #[error("committed representation has an impossible size")]
    ImpossibleCommittedSize,
    /// Offset or length could not be represented safely.
    #[error("data length cannot be represented")]
    Length,
    /// Incoming data crossed the exact advertised size.
    #[error("data exceeds advertised representation size")]
    DataExceedsOffer,
    /// The prefix store cannot accept a hole.
    #[error("non-contiguous data cannot be accepted")]
    NonContiguous,
    /// Replayed data differs from durable bytes.
    #[error("duplicate data conflicts with persisted bytes")]
    ConflictingDuplicate,
    /// Whole-representation digest mismatch.
    #[error("whole-representation digest mismatch")]
    Integrity,
    /// Committed bytes were requested before completion.
    #[error("representation is not complete")]
    NotComplete,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bempic_model::prepare_binary;
    use tempfile::tempdir;

    #[test]
    fn interrupt_reopen_resume_and_reconstruct() {
        let root = tempdir().unwrap();
        let representation = prepare_binary((0_u8..=255).cycle().take(2000).collect::<Vec<_>>());
        {
            let mut store = FileStore::open(root.path(), representation.clone()).unwrap();
            store.accept_data(0, &representation.bytes[..333]).unwrap();
        }
        let mut reopened = FileStore::open(root.path(), representation.clone()).unwrap();
        assert_eq!(reopened.progress(), 333);
        reopened
            .accept_data(333, &representation.bytes[333..])
            .unwrap();
        assert!(reopened.verify_and_commit().unwrap());
        drop(reopened);
        let final_store = FileStore::open(root.path(), representation.clone()).unwrap();
        assert_eq!(final_store.read_complete().unwrap(), representation.bytes);
    }

    #[test]
    fn duplicate_is_idempotent_but_conflict_fails() {
        let root = tempdir().unwrap();
        let representation = prepare_binary(b"duplicate fixture".to_vec());
        let mut store = FileStore::open(root.path(), representation.clone()).unwrap();
        assert_eq!(store.accept_data(0, b"dupl").unwrap().accepted_bytes, 4);
        assert_eq!(store.accept_data(0, b"dupl").unwrap().duplicate_bytes, 4);
        assert!(matches!(
            store.accept_data(0, b"Dupl"),
            Err(StoreError::ConflictingDuplicate)
        ));
    }

    #[test]
    fn absent_zero_length_part_commits_and_reopens() {
        let root = tempdir().unwrap();
        let representation = prepare_binary(Vec::new());
        let mut store = FileStore::open(root.path(), representation.clone()).unwrap();
        assert_eq!(store.progress(), representation.size());
        assert!(!store.part_path().exists());
        assert!(store.verify_and_commit().unwrap());
        assert!(store.is_complete());
        assert_eq!(store.read_complete().unwrap(), Vec::<u8>::new());

        let reopened = FileStore::open(root.path(), representation).unwrap();
        assert!(reopened.is_complete());
        assert_eq!(reopened.read_complete().unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn negotiated_record_ceiling_persists_and_only_narrows() {
        let root = tempdir().unwrap();
        let representation = prepare_binary(b"negotiation".to_vec());
        let mut store = FileStore::open(root.path(), representation.clone()).unwrap();
        assert_eq!(store.persist_negotiated_max_record_size(512).unwrap(), 512);
        assert_eq!(
            store.persist_negotiated_max_record_size(1_024).unwrap(),
            512
        );
        drop(store);

        let mut reopened = FileStore::open(root.path(), representation).unwrap();
        assert_eq!(reopened.negotiated_max_record_size(), Some(512));
        assert_eq!(
            reopened.persist_negotiated_max_record_size(128).unwrap(),
            128
        );
    }

    #[test]
    fn required_prefix_interruption_matrix_reopens_at_exact_durable_bytes() {
        let bytes = (0_u8..=255).cycle().take(1_000).collect::<Vec<_>>();
        for percentage in [0_u64, 1, 10, 50, 90] {
            let root = tempdir().unwrap();
            let representation = prepare_binary(bytes.clone());
            let prefix = representation.size() * percentage / 100;
            if prefix > 0 {
                let mut store = FileStore::open(root.path(), representation.clone()).unwrap();
                store
                    .accept_data(0, &representation.bytes[..prefix as usize])
                    .unwrap();
            }
            let mut reopened = FileStore::open(root.path(), representation.clone()).unwrap();
            assert_eq!(reopened.progress(), prefix);
            reopened
                .accept_data(prefix, &representation.bytes[prefix as usize..])
                .unwrap();
            assert!(reopened.verify_and_commit().unwrap());
            assert_eq!(reopened.read_complete().unwrap(), representation.bytes);
        }
    }

    #[test]
    fn post_verification_pre_commit_reopens_and_commits_without_payload() {
        let root = tempdir().unwrap();
        let representation = prepare_binary(b"verified staging".to_vec());
        {
            let mut store = FileStore::open(root.path(), representation.clone()).unwrap();
            store.accept_data(0, &representation.bytes).unwrap();
            assert!(store.verify_staged().unwrap());
            assert!(!store.is_complete());
        }
        let mut reopened = FileStore::open(root.path(), representation.clone()).unwrap();
        assert_eq!(reopened.progress(), representation.size());
        assert!(reopened.commit_verified().unwrap());
        assert_eq!(reopened.read_complete().unwrap(), representation.bytes);
    }

    #[test]
    fn post_commit_pre_receipt_reopens_without_false_or_lost_commit() {
        let root = tempdir().unwrap();
        let representation = prepare_binary(b"commit before receipt".to_vec());
        {
            let mut store = FileStore::open(root.path(), representation.clone()).unwrap();
            store.accept_data(0, &representation.bytes).unwrap();
            assert!(store.verify_and_commit().unwrap());
            assert!(!store.flag(StateFlag::Receipt));
        }
        let mut reopened = FileStore::open(root.path(), representation).unwrap();
        assert!(reopened.is_complete());
        assert!(!reopened.flag(StateFlag::Receipt));
        reopened.mark(StateFlag::Receipt).unwrap();
        drop(reopened);
        let final_store = FileStore::open(
            root.path(),
            prepare_binary(b"commit before receipt".to_vec()),
        )
        .unwrap();
        assert!(final_store.flag(StateFlag::Receipt));
    }

    #[test]
    fn corrupt_complete_prefix_is_quarantined_and_clean_retry_commits() {
        let root = tempdir().unwrap();
        let representation = prepare_binary(b"expected bytes".to_vec());
        let mut store = FileStore::open(root.path(), representation.clone()).unwrap();
        store.accept_data(0, b"corrupted byte").unwrap();
        assert!(matches!(store.verify_staged(), Err(StoreError::Integrity)));
        assert_eq!(store.progress(), 0);
        assert!(!store.part_path().exists());
        assert!(root
            .path()
            .read_dir()
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry
                .path()
                .extension()
                .is_some_and(|value| value == "corrupt")));
        store.accept_data(0, &representation.bytes).unwrap();
        assert!(store.verify_and_commit().unwrap());
        assert_eq!(store.read_complete().unwrap(), representation.bytes);
    }
}
