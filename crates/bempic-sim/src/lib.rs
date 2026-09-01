#![forbid(unsafe_code)]
//! Deterministic complete-record carrier simulation and transfer harness.

/// Integrated full-width v0.1 experimental transfer path.
pub mod v01;

use bempic_carrier::{
    CarrierDirection, CarrierError, CostPrecision, DeliveryOutcome, OpaqueRecordCarrier,
    Opportunity,
};
use bempic_model::PreparedRepresentation;
use bempic_store::{FileStore, ProgressStore, StateFlag, StoreError};
use bempic_sync::{
    data_record_overhead, Accounting, Capabilities, Data, Direction, Offer, Operation, Receipt,
    ReceiptStage, Request, Summary, SyncError, MAX_OPERATION_RECORD_SIZE,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

/// Application-supplied authorization fact for a source in deterministic tests.
///
/// This is not production authentication. It models the specification rule
/// that any application-authorized source holding the identical representation
/// may provide a suffix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedSource {
    /// Opaque application source identity.
    pub source_id: [u8; 32],
    /// Exact representation this source may provide.
    pub representation_id: bempic_model::RepresentationId,
}

/// Exact, deterministic carrier parameters for one contact.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CarrierConfig {
    /// Hard total serialized BEMPIC byte budget for the contact.
    pub byte_budget: u64,
    /// Serialization bandwidth in bits per second.
    pub bandwidth_bps: u64,
    /// Fixed one-way delivery latency for each record.
    pub latency_ms: u64,
    /// Abrupt disconnect time relative to contact start.
    pub disconnect_after_ms: Option<u64>,
    /// Largest complete BEMPIC record accepted.
    pub max_record_bytes: usize,
    /// Carrier framing charged per submitted record.
    pub carrier_overhead_bytes: u64,
    /// Complete-record reliability declaration.
    pub reliable: bool,
}

impl CarrierConfig {
    /// Validate simulator values before a run.
    pub fn validate(&self) -> Result<(), SimulationError> {
        if self.bandwidth_bps == 0 {
            return Err(SimulationError::ZeroBandwidth);
        }
        if self.max_record_bytes == 0 {
            return Err(SimulationError::ZeroRecordSize);
        }
        Ok(())
    }
}

/// One reproducible carrier action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CarrierEvent {
    /// Direction presented by BEMPIC.
    pub direction: CarrierDirection,
    /// Complete record size presented to the carrier.
    pub record_bytes: u64,
    /// Charged carrier bytes including configured framing.
    pub carrier_bytes: u64,
    /// Whether the complete record was delivered.
    pub delivered: bool,
    /// Time at which delivery or disconnection resolved the action.
    pub resolved_at_ms: u64,
}

/// Carrier-level counters kept separate from BEMPIC protocol counters.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CarrierMetrics {
    /// Carrier byte precision label.
    pub carrier_cost_precision: CostPrecision,
    /// Link byte precision label; unavailable in this simulator.
    pub link_cost_precision: CostPrecision,
    /// Complete BEMPIC record bytes submitted.
    pub submitted_bempic_bytes: u64,
    /// Submitted records including lost-at-disconnect records.
    pub submitted_records: u64,
    /// Delivered complete records.
    pub delivered_records: u64,
    /// Records not delivered because contact ended before arrival.
    pub lost_records: u64,
    /// BEMPIC bytes submitted in records that did not arrive before disconnect.
    pub lost_bempic_bytes: u64,
    /// Total carrier bytes charged.
    pub carrier_bytes: u64,
    /// Deterministic elapsed contact time.
    pub elapsed_ms: u64,
}

impl CarrierMetrics {
    /// Merge another contact into a complete run.
    pub fn merge(&mut self, other: &Self) {
        if self.carrier_cost_precision == CostPrecision::Unavailable {
            self.carrier_cost_precision = other.carrier_cost_precision;
        } else if self.carrier_cost_precision != other.carrier_cost_precision {
            self.carrier_cost_precision = CostPrecision::Estimated;
        }
        if self.link_cost_precision == CostPrecision::Unavailable {
            self.link_cost_precision = other.link_cost_precision;
        } else if self.link_cost_precision != other.link_cost_precision {
            self.link_cost_precision = CostPrecision::Estimated;
        }
        self.submitted_bempic_bytes += other.submitted_bempic_bytes;
        self.submitted_records += other.submitted_records;
        self.delivered_records += other.delivered_records;
        self.lost_records += other.lost_records;
        self.lost_bempic_bytes += other.lost_bempic_bytes;
        self.carrier_bytes += other.carrier_bytes;
        self.elapsed_ms += other.elapsed_ms;
    }
}

/// Deterministic carrier implementation with no wall-clock dependency.
pub struct DeterministicCarrier {
    config: CarrierConfig,
    spent_bempic_bytes: u64,
    elapsed_ms: u64,
    disconnected: bool,
    events: Vec<CarrierEvent>,
    metrics: CarrierMetrics,
}

impl DeterministicCarrier {
    /// Create an empty deterministic contact.
    pub fn new(config: CarrierConfig) -> Result<Self, SimulationError> {
        config.validate()?;
        Ok(Self {
            config,
            spent_bempic_bytes: 0,
            elapsed_ms: 0,
            disconnected: config.disconnect_after_ms == Some(0),
            events: Vec::new(),
            metrics: CarrierMetrics {
                carrier_cost_precision: CostPrecision::Exact,
                ..CarrierMetrics::default()
            },
        })
    }

    /// Exact event log in submission order.
    pub fn events(&self) -> &[CarrierEvent] {
        &self.events
    }

    /// Current contact metrics.
    pub fn metrics(&self) -> &CarrierMetrics {
        &self.metrics
    }

    /// Serialized BEMPIC bytes consumed from the hard contact budget.
    pub const fn spent_bempic_bytes(&self) -> u64 {
        self.spent_bempic_bytes
    }

    fn serialization_ms(&self, bytes: u64) -> u64 {
        let bit_millis = u128::from(bytes) * 8_000;
        let bandwidth = u128::from(self.config.bandwidth_bps);
        u64::try_from(bit_millis.div_ceil(bandwidth)).unwrap_or(u64::MAX)
    }
}

impl OpaqueRecordCarrier for DeterministicCarrier {
    fn opportunity(&self) -> Opportunity {
        Opportunity {
            max_record_bytes: self.config.max_record_bytes,
            remaining_bempic_bytes: self
                .config
                .byte_budget
                .saturating_sub(self.spent_bempic_bytes),
            reliable: self.config.reliable,
        }
    }

    fn transmit(
        &mut self,
        direction: CarrierDirection,
        record: &[u8],
    ) -> Result<DeliveryOutcome, CarrierError> {
        if self.disconnected {
            return Err(CarrierError::Disconnected);
        }
        if record.len() > self.config.max_record_bytes {
            return Err(CarrierError::RecordTooLarge);
        }
        let record_bytes = u64::try_from(record.len()).map_err(|_| CarrierError::RecordTooLarge)?;
        if record_bytes > self.opportunity().remaining_bempic_bytes {
            return Err(CarrierError::BudgetExceeded);
        }
        let carrier_bytes = record_bytes.saturating_add(self.config.carrier_overhead_bytes);
        let arrival = self
            .elapsed_ms
            .saturating_add(self.serialization_ms(carrier_bytes))
            .saturating_add(self.config.latency_ms);
        let delivered = match self.config.disconnect_after_ms {
            Some(cutoff) => arrival <= cutoff,
            None => true,
        };
        let resolved_at_ms = if delivered {
            arrival
        } else {
            self.config.disconnect_after_ms.unwrap_or(arrival)
        };
        self.elapsed_ms = resolved_at_ms;
        self.spent_bempic_bytes += record_bytes;
        self.metrics.submitted_bempic_bytes += record_bytes;
        self.metrics.submitted_records += 1;
        self.metrics.carrier_bytes += carrier_bytes;
        self.metrics.elapsed_ms = self.elapsed_ms;
        if delivered {
            self.metrics.delivered_records += 1;
        } else {
            self.metrics.lost_records += 1;
            self.metrics.lost_bempic_bytes += record_bytes;
            self.disconnected = true;
        }
        self.events.push(CarrierEvent {
            direction,
            record_bytes,
            carrier_bytes,
            delivered,
            resolved_at_ms,
        });
        Ok(DeliveryOutcome {
            delivered,
            bempic_bytes: record_bytes,
            carrier_bytes,
            delivered_at_ms: delivered.then_some(arrival),
        })
    }

    fn elapsed_ms(&self) -> u64 {
        self.elapsed_ms
    }

    fn carrier_cost_precision(&self) -> CostPrecision {
        CostPrecision::Exact
    }
}

/// Result of one contact opportunity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContactReport {
    /// Configured contact budget.
    pub budget_bytes: u64,
    /// Serialized BEMPIC bytes submitted.
    pub spent_bytes: u64,
    /// Prefix at contact start.
    pub progress_before: u64,
    /// Prefix after delivered operations.
    pub progress_after: u64,
    /// Exact bytes have been verified and committed.
    pub complete: bool,
    /// Stored receipt was delivered.
    pub receipt_sent: bool,
    /// BEMPIC accounting domain.
    pub accounting: Accounting,
    /// Carrier accounting domain.
    pub carrier: CarrierMetrics,
    /// Deterministic carrier event log.
    pub events: Vec<CarrierEvent>,
}

/// Complete multi-contact transfer report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TransferReport {
    /// Contact reports, one per reopened receiver instance.
    pub contacts: Vec<ContactReport>,
    /// Aggregate BEMPIC accounting.
    pub accounting: Accounting,
    /// Aggregate carrier accounting.
    pub carrier: CarrierMetrics,
    /// Exact reconstructed bytes.
    pub reconstructed: Vec<u8>,
}

fn advertised_record_limit(config: CarrierConfig) -> u16 {
    u16::try_from(config.max_record_bytes.min(usize::from(u16::MAX)))
        .expect("carrier record limit is bounded to u16")
}

fn effective_record_limit<S: ProgressStore>(store: &S, carrier: &DeterministicCarrier) -> usize {
    let negotiated = store
        .negotiated_max_record_size()
        .map_or(MAX_OPERATION_RECORD_SIZE, usize::from);
    carrier
        .opportunity()
        .max_record_bytes
        .min(negotiated)
        .min(MAX_OPERATION_RECORD_SIZE)
}

/// Advance one representation through a carrier opportunity.
#[allow(clippy::too_many_lines)]
pub fn run_contact<S: ProgressStore>(
    representation: &PreparedRepresentation,
    store: &mut S,
    config: CarrierConfig,
) -> Result<ContactReport, SimulationError> {
    if store.representation_id() != representation.id {
        return Err(SimulationError::IdentityConflict);
    }
    let mut carrier = DeterministicCarrier::new(config)?;
    let mut accounting = Accounting::default();
    let before = store.progress();

    macro_rules! deliver {
        ($operation:expr, $carrier_direction:expr, $accounting_direction:expr) => {{
            let operation = $operation;
            let encoded = operation.encode()?;
            if encoded.len() > effective_record_limit(store, &carrier)
                || u64::try_from(encoded.len()).unwrap_or(u64::MAX)
                    > carrier.opportunity().remaining_bempic_bytes
            {
                None
            } else {
                let outcome = carrier.transmit($carrier_direction, &encoded)?;
                accounting.add($accounting_direction, &operation, encoded.len());
                Some(outcome.delivered)
            }
        }};
    }

    if !store.flag(StateFlag::SenderCapabilities) {
        let advertised = advertised_record_limit(config);
        let value = Operation::Capabilities(Capabilities {
            encoding_generation: 0,
            max_record_size: advertised,
            features: 0,
        });
        match deliver!(
            value,
            CarrierDirection::SenderToReceiver,
            Direction::SenderToReceiver
        ) {
            Some(true) => {
                store.persist_negotiated_max_record_size(advertised)?;
                store.mark(StateFlag::SenderCapabilities)?;
            }
            Some(false) | None => return Ok(report(config, before, store, accounting, &carrier)),
        }
    }
    if !store.flag(StateFlag::ReceiverCapabilities) {
        let advertised = advertised_record_limit(config);
        let value = Operation::Capabilities(Capabilities {
            encoding_generation: 0,
            max_record_size: advertised,
            features: 0,
        });
        match deliver!(
            value,
            CarrierDirection::ReceiverToSender,
            Direction::ReceiverToSender
        ) {
            Some(true) => {
                store.persist_negotiated_max_record_size(advertised)?;
                store.mark(StateFlag::ReceiverCapabilities)?;
            }
            Some(false) | None => return Ok(report(config, before, store, accounting, &carrier)),
        }
    }
    if !store.flag(StateFlag::Summary) {
        let value = Operation::Summary(Summary {
            item_count: 0,
            digest: representation.id.0,
        });
        match deliver!(
            value,
            CarrierDirection::SenderToReceiver,
            Direction::SenderToReceiver
        ) {
            Some(true) => store.mark(StateFlag::Summary)?,
            Some(false) | None => return Ok(report(config, before, store, accounting, &carrier)),
        }
    }
    if !store.flag(StateFlag::Offer) && !store.is_complete() {
        let value = Operation::Offer(Offer::from(representation));
        match deliver!(
            value,
            CarrierDirection::SenderToReceiver,
            Direction::SenderToReceiver
        ) {
            Some(true) => store.mark(StateFlag::Offer)?,
            Some(false) | None => return Ok(report(config, before, store, accounting, &carrier)),
        }
    }

    if !store.is_complete()
        && store.progress() == representation.size()
        && store.verify_and_commit()?
    {
        accounting.useful_committed_bytes += representation.size();
    }

    if !store.is_complete() {
        let request_size = Operation::Request(Request {
            representation_id: representation.id,
            offset: store.progress(),
            max_payload_bytes: 0,
        })
        .encode()?
        .len();
        let opportunity = carrier.opportunity();
        let budget_capacity = opportunity.remaining_bempic_bytes.saturating_sub(
            u64::try_from(request_size + data_record_overhead()).unwrap_or(u64::MAX),
        );
        let record_capacity =
            effective_record_limit(store, &carrier).saturating_sub(data_record_overhead());
        let remaining = representation.size().saturating_sub(store.progress());
        let payload_limit = remaining
            .min(budget_capacity)
            .min(u64::try_from(record_capacity).unwrap_or(u64::MAX))
            .min(u64::from(u32::MAX));
        if payload_limit > 0 {
            let offset = store.progress();
            let request = Operation::Request(Request {
                representation_id: representation.id,
                offset,
                max_payload_bytes: u32::try_from(payload_limit).expect("bounded to u32"),
            });
            match deliver!(
                request,
                CarrierDirection::ReceiverToSender,
                Direction::ReceiverToSender
            ) {
                Some(true) => {}
                Some(false) | None => {
                    return Ok(report(config, before, store, accounting, &carrier));
                }
            }
            let start = usize::try_from(offset).map_err(|_| SimulationError::Length)?;
            let end = start
                .checked_add(usize::try_from(payload_limit).map_err(|_| SimulationError::Length)?)
                .ok_or(SimulationError::Length)?;
            let payload = representation.bytes[start..end].to_vec();
            let data = Operation::Data(Data {
                representation_id: representation.id,
                offset,
                payload: payload.clone(),
            });
            let delivery = deliver!(
                data,
                CarrierDirection::SenderToReceiver,
                Direction::SenderToReceiver
            );
            if delivery.is_some() {
                accounting.representation_payload_bytes += payload_limit;
            }
            match delivery {
                Some(true) => {
                    let outcome = store.accept_data(offset, &payload)?;
                    accounting.duplicate_payload_bytes += outcome.duplicate_bytes;
                    if store.progress() == representation.size() && store.verify_and_commit()? {
                        accounting.useful_committed_bytes += representation.size();
                    }
                }
                Some(false) | None => {
                    return Ok(report(config, before, store, accounting, &carrier));
                }
            }
        }
    }

    if store.is_complete() && !store.flag(StateFlag::Receipt) {
        let receipt = Operation::Receipt(Receipt {
            representation_id: representation.id,
            stage: ReceiptStage::Stored,
            digest: representation.digest,
        });
        if let Some(true) = deliver!(
            receipt,
            CarrierDirection::ReceiverToSender,
            Direction::ReceiverToSender
        ) {
            store.mark(StateFlag::Receipt)?;
        }
    }
    Ok(report(config, before, store, accounting, &carrier))
}

/// Run a contact only after checking an application-supplied source authorization.
pub fn run_authorized_contact<S: ProgressStore>(
    representation: &PreparedRepresentation,
    store: &mut S,
    config: CarrierConfig,
    source: AuthorizedSource,
) -> Result<ContactReport, SimulationError> {
    if source.representation_id != representation.id {
        return Err(SimulationError::UnauthorizedSource);
    }
    run_contact(representation, store, config)
}

fn report<S: ProgressStore>(
    config: CarrierConfig,
    before: u64,
    store: &S,
    accounting: Accounting,
    carrier: &DeterministicCarrier,
) -> ContactReport {
    ContactReport {
        budget_bytes: config.byte_budget,
        spent_bytes: carrier.spent_bempic_bytes(),
        progress_before: before,
        progress_after: store.progress(),
        complete: store.is_complete(),
        receipt_sent: store.flag(StateFlag::Receipt),
        accounting,
        carrier: carrier.metrics().clone(),
        events: carrier.events().to_vec(),
    }
}

/// Reopen receiver state before every configured contact and run to receipt.
pub fn run_until_complete(
    root: impl AsRef<Path>,
    representation: &PreparedRepresentation,
    contacts: &[CarrierConfig],
    max_contacts: usize,
) -> Result<TransferReport, SimulationError> {
    if contacts.is_empty() {
        return Err(SimulationError::NoContacts);
    }
    let mut reports = Vec::new();
    let mut accounting = Accounting::default();
    let mut carrier = CarrierMetrics::default();
    for number in 0..max_contacts {
        let config = contacts[number % contacts.len()];
        let mut store = FileStore::open(root.as_ref(), representation.clone())?;
        let report = run_contact(representation, &mut store, config)?;
        accounting.merge(&report.accounting);
        carrier.merge(&report.carrier);
        let done = report.receipt_sent;
        reports.push(report);
        if done {
            let reopened = FileStore::open(root.as_ref(), representation.clone())?;
            return Ok(TransferReport {
                contacts: reports,
                accounting,
                carrier,
                reconstructed: reopened.read_complete()?,
            });
        }
    }
    Err(SimulationError::ContactLimit(max_contacts))
}

/// Simulation or exchange failure.
#[derive(Debug, Error)]
pub enum SimulationError {
    /// Carrier configuration had zero bandwidth.
    #[error("bandwidth must be positive")]
    ZeroBandwidth,
    /// Carrier configuration had no complete-record capacity.
    #[error("maximum record size must be positive")]
    ZeroRecordSize,
    /// Contact sequence was empty.
    #[error("at least one contact configuration is required")]
    NoContacts,
    /// Requested state and representation identities differed.
    #[error("store and representation identities differ")]
    IdentityConflict,
    /// Offset could not be converted safely.
    #[error("representation length is unsupported")]
    Length,
    /// Application-supplied source authorization did not cover the representation.
    #[error("source is not authorized for this representation")]
    UnauthorizedSource,
    /// Transfer did not finish in the bounded contact count.
    #[error("transfer did not finish in {0} contacts")]
    ContactLimit(usize),
    /// Carrier rejected a submitted record.
    #[error(transparent)]
    Carrier(#[from] CarrierError),
    /// Operation serialization failed.
    #[error(transparent)]
    Sync(#[from] SyncError),
    /// Persistent state failed.
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use bempic_model::prepare_binary;
    use tempfile::tempdir;

    fn contact(byte_budget: u64, disconnect_after_ms: Option<u64>) -> CarrierConfig {
        CarrierConfig {
            byte_budget,
            bandwidth_bps: 1_200,
            latency_ms: 150,
            disconnect_after_ms,
            max_record_bytes: 128,
            carrier_overhead_bytes: 8,
            reliable: true,
        }
    }

    #[test]
    fn deterministic_budget_bandwidth_latency_disconnect_metrics() {
        let config = contact(100, Some(500));
        let mut left = DeterministicCarrier::new(config).unwrap();
        let mut right = DeterministicCarrier::new(config).unwrap();
        let a = left
            .transmit(CarrierDirection::SenderToReceiver, &[0; 40])
            .unwrap();
        let b = right
            .transmit(CarrierDirection::SenderToReceiver, &[0; 40])
            .unwrap();
        assert_eq!(a, b);
        assert_eq!(left.events(), right.events());
        assert!(a.delivered);
        let lost = left
            .transmit(CarrierDirection::ReceiverToSender, &[0; 40])
            .unwrap();
        assert!(!lost.delivered);
        assert_eq!(left.metrics().lost_records, 1);
        assert_eq!(left.elapsed_ms(), 500);
    }

    #[test]
    fn interruption_reopen_resume_exactly() {
        let root = tempdir().unwrap();
        let representation = prepare_binary((0_u8..=255).cycle().take(4096).collect::<Vec<_>>());
        let contacts = [
            contact(190, None),
            contact(240, Some(800)),
            contact(300, None),
        ];
        let run = run_until_complete(root.path(), &representation, &contacts, 200).unwrap();
        assert_eq!(run.reconstructed, representation.bytes);
        assert_eq!(run.accounting.useful_committed_bytes, representation.size());
        assert!(run.contacts.len() > 2);
        assert!(run
            .contacts
            .iter()
            .all(|item| item.spent_bytes <= item.budget_bytes));
    }

    #[test]
    fn final_suffix_interruption_reopens_commits_and_receipts() {
        let root = tempdir().unwrap();
        let representation = prepare_binary(b"durable final suffix".repeat(8));
        {
            let mut store = FileStore::open(root.path(), representation.clone()).unwrap();
            store.accept_data(0, &representation.bytes).unwrap();
            assert_eq!(store.progress(), representation.size());
            assert!(!store.is_complete());
        }

        let mut reopened = FileStore::open(root.path(), representation.clone()).unwrap();
        assert_eq!(reopened.progress(), representation.size());
        assert!(!reopened.is_complete());
        let report = run_contact(&representation, &mut reopened, contact(512, None)).unwrap();
        assert!(report.complete);
        assert!(report.receipt_sent);
        assert_eq!(report.accounting.representation_payload_bytes, 0);
        assert_eq!(
            report.accounting.useful_committed_bytes,
            representation.size()
        );
        assert_eq!(reopened.read_complete().unwrap(), representation.bytes);
    }

    #[test]
    fn zero_length_representation_transfers_without_part_file() {
        let root = tempdir().unwrap();
        let representation = prepare_binary(Vec::new());
        let run =
            run_until_complete(root.path(), &representation, &[contact(512, None)], 2).unwrap();
        assert_eq!(run.contacts.len(), 1);
        assert_eq!(run.reconstructed, Vec::<u8>::new());
        assert_eq!(run.accounting.representation_payload_bytes, 0);
        assert!(run.contacts[0].complete);
        assert!(run.contacts[0].receipt_sent);
    }

    #[test]
    fn larger_later_carrier_stays_within_persisted_negotiated_limit() {
        let root = tempdir().unwrap();
        let representation = prepare_binary(vec![0x5a; 1_000]);
        let first_config = contact(300, None);
        let mut first_store = FileStore::open(root.path(), representation.clone()).unwrap();
        let first = run_contact(&representation, &mut first_store, first_config).unwrap();
        assert!(first.progress_after > 0);
        assert_eq!(first_store.negotiated_max_record_size(), Some(128));
        drop(first_store);

        let mut second_config = contact(2_000, None);
        second_config.max_record_bytes = 1_024;
        let mut reopened = FileStore::open(root.path(), representation.clone()).unwrap();
        let second = run_contact(&representation, &mut reopened, second_config).unwrap();
        assert_eq!(reopened.negotiated_max_record_size(), Some(128));
        assert!(second.events.iter().all(|event| event.record_bytes <= 128));
        assert!(second.progress_after > first.progress_after);
    }

    #[test]
    fn carrier_above_envelope_is_capped_without_oversized_operation() {
        let root = tempdir().unwrap();
        let representation = prepare_binary(vec![0xa5; 70_000]);
        let mut config = contact(100_000, None);
        config.max_record_bytes = MAX_OPERATION_RECORD_SIZE + 4_096;
        config.bandwidth_bps = 10_000_000;
        let mut store = FileStore::open(root.path(), representation.clone()).unwrap();
        let report = run_contact(&representation, &mut store, config).unwrap();

        assert_eq!(store.negotiated_max_record_size(), Some(u16::MAX));
        assert!(report
            .events
            .iter()
            .all(|event| u16::try_from(event.record_bytes).is_ok()));
        assert_eq!(report.progress_after, u64::from(u16::MAX) - 29);
        assert!(!report.complete);
    }

    #[test]
    fn resume_through_different_authorized_source_and_carrier() {
        let root = tempdir().unwrap();
        let representation = prepare_binary(vec![0x3c; 800]);
        let first_source = AuthorizedSource {
            source_id: [1; 32],
            representation_id: representation.id,
        };
        let second_source = AuthorizedSource {
            source_id: [2; 32],
            representation_id: representation.id,
        };
        let first_progress = {
            let mut store = FileStore::open(root.path(), representation.clone()).unwrap();
            run_authorized_contact(
                &representation,
                &mut store,
                contact(300, None),
                first_source,
            )
            .unwrap()
            .progress_after
        };
        assert!(first_progress > 0);

        let mut alternate_carrier = contact(2_000, None);
        alternate_carrier.bandwidth_bps = 19_200;
        alternate_carrier.latency_ms = 75;
        alternate_carrier.carrier_overhead_bytes = 11;
        let mut reopened = FileStore::open(root.path(), representation.clone()).unwrap();
        let report = run_authorized_contact(
            &representation,
            &mut reopened,
            alternate_carrier,
            second_source,
        )
        .unwrap();
        assert!(report.progress_after > first_progress);
        while !reopened.is_complete() {
            run_authorized_contact(
                &representation,
                &mut reopened,
                alternate_carrier,
                second_source,
            )
            .unwrap();
        }
        assert_eq!(reopened.read_complete().unwrap(), representation.bytes);

        let unauthorized = AuthorizedSource {
            source_id: [3; 32],
            representation_id: prepare_binary(b"other".to_vec()).id,
        };
        assert!(matches!(
            run_authorized_contact(
                &representation,
                &mut reopened,
                alternate_carrier,
                unauthorized
            ),
            Err(SimulationError::UnauthorizedSource)
        ));
    }
}
