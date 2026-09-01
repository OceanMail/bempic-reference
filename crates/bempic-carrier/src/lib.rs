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

/// Truthfulness label for lower-layer byte counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostPrecision {
    /// Binding reports measured or contractually exact octets.
    Exact,
    /// Binding reports a documented conservative estimate.
    Estimated,
    /// Lower layer did not expose this cost domain.
    Unavailable,
}

impl Default for CostPrecision {
    fn default() -> Self {
        Self::Unavailable
    }
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
    /// Precision of carrier-byte counters returned by this binding.
    fn carrier_cost_precision(&self) -> CostPrecision {
        CostPrecision::Unavailable
    }
    /// Precision of link-byte counters, if any.
    fn link_cost_precision(&self) -> CostPrecision {
        CostPrecision::Unavailable
    }
}

/// One record observed by the mock M4P application binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MockM4pRecord {
    /// BEMPIC direction at the opaque application boundary.
    pub direction: CarrierDirection,
    /// Exact opaque bytes; the binding does not parse them.
    pub bytes: Vec<u8>,
}

/// Mock M4P opaque-record adapter used only to prove the layer boundary.
///
/// The type intentionally contains no peer address, route, TTL, fragment,
/// deduplication, custody, radio, or retransmission state. Those remain M4P or
/// `DataLink` responsibilities.
pub struct MockM4pBinding<C> {
    inner: C,
    records: Vec<MockM4pRecord>,
}

impl<C> MockM4pBinding<C> {
    /// Wrap a complete-record carrier without changing its opportunity contract.
    pub const fn new(inner: C) -> Self {
        Self {
            inner,
            records: Vec::new(),
        }
    }

    /// Opaque records admitted through the application binding.
    pub fn records(&self) -> &[MockM4pRecord] {
        &self.records
    }

    /// Recover the wrapped test carrier.
    pub fn into_inner(self) -> C {
        self.inner
    }
}

impl<C: OpaqueRecordCarrier> OpaqueRecordCarrier for MockM4pBinding<C> {
    fn opportunity(&self) -> Opportunity {
        self.inner.opportunity()
    }

    fn transmit(
        &mut self,
        direction: CarrierDirection,
        record: &[u8],
    ) -> Result<DeliveryOutcome, CarrierError> {
        let outcome = self.inner.transmit(direction, record)?;
        self.records.push(MockM4pRecord {
            direction,
            bytes: record.to_vec(),
        });
        Ok(outcome)
    }

    fn elapsed_ms(&self) -> u64 {
        self.inner.elapsed_ms()
    }

    fn carrier_cost_precision(&self) -> CostPrecision {
        self.inner.carrier_cost_precision()
    }

    fn link_cost_precision(&self) -> CostPrecision {
        self.inner.link_cost_precision()
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    struct CompleteRecordTestCarrier;

    impl OpaqueRecordCarrier for CompleteRecordTestCarrier {
        fn opportunity(&self) -> Opportunity {
            Opportunity {
                max_record_bytes: 128,
                remaining_bempic_bytes: 128,
                reliable: true,
            }
        }

        fn transmit(
            &mut self,
            _direction: CarrierDirection,
            record: &[u8],
        ) -> Result<DeliveryOutcome, CarrierError> {
            Ok(DeliveryOutcome {
                delivered: true,
                bempic_bytes: record.len() as u64,
                carrier_bytes: record.len() as u64 + 8,
                delivered_at_ms: Some(1),
            })
        }

        fn elapsed_ms(&self) -> u64 {
            1
        }

        fn carrier_cost_precision(&self) -> CostPrecision {
            CostPrecision::Exact
        }
    }

    #[test]
    fn mock_m4p_binding_preserves_one_complete_opaque_record() {
        let mut binding = MockM4pBinding::new(CompleteRecordTestCarrier);
        let bytes = b"opaque BEMPIC record";
        let result = binding
            .transmit(CarrierDirection::SenderToReceiver, bytes)
            .unwrap();
        assert!(result.delivered);
        assert_eq!(binding.records().len(), 1);
        assert_eq!(binding.records()[0].bytes, bytes);
        assert_eq!(binding.carrier_cost_precision(), CostPrecision::Exact);
        assert_eq!(binding.link_cost_precision(), CostPrecision::Unavailable);
    }
}
