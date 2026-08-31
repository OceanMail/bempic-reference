#![forbid(unsafe_code)]
//! Carrier contract below BEMPIC and above M4P or another substrate.
//!
//! This API intentionally has no routing, TTL, fragmentation, radio, or ARQ.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Direction of an opaque BEMPIC record.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CarrierDirection {
    /// Initiating sender to receiving application.
    SenderToReceiver,
    /// Receiver to initiating sender.
    ReceiverToSender,
}

/// Current opportunity exposed to BEMPIC by a carrier binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Opportunity {
    /// Largest complete opaque record accepted now.
    pub max_record_bytes: usize,
    /// Remaining BEMPIC byte budget for this contact.
    pub remaining_bempic_bytes: u64,
    /// Whether the carrier declares complete-record integrity/reliability.
    pub reliable: bool,
}

/// Outcome of presenting one complete opaque record to a carrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliveryOutcome {
    /// Whether the complete record reached the other endpoint.
    pub delivered: bool,
    /// BEMPIC record bytes consumed from the hard application budget.
    pub bempic_bytes: u64,
    /// Bytes charged by the carrier when exposed.
    pub carrier_bytes: u64,
    /// Time after the contact epoch when delivery occurred.
    pub delivered_at_ms: Option<u64>,
}

/// Narrow interface implemented by deterministic simulation and future bindings.
pub trait OpaqueRecordCarrier {
    /// Inspect the current complete-record opportunity.
    fn opportunity(&self) -> Opportunity;
    /// Present a complete BEMPIC operation as opaque application bytes.
    fn transmit(
        &mut self,
        direction: CarrierDirection,
        record: &[u8],
    ) -> Result<DeliveryOutcome, CarrierError>;
    /// Elapsed deterministic time since the carrier/contact epoch.
    fn elapsed_ms(&self) -> u64;
}

/// Carrier rejected a record before transfer.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum CarrierError {
    /// Record is larger than the complete-record opportunity.
    #[error("record exceeds carrier opportunity")]
    RecordTooLarge,
    /// Hard BEMPIC byte budget would be crossed.
    #[error("record exceeds remaining BEMPIC byte budget")]
    BudgetExceeded,
    /// Carrier is no longer connected.
    #[error("carrier disconnected")]
    Disconnected,
}
