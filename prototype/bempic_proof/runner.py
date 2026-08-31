"""Reusable restart-between-contacts runner for proof experiments."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .exchange import Accounting, ContactQuote, ContactReport, ProofExchange
from .model import Message, PreparedRepresentation
from .store import ReceiverStore


@dataclass(frozen=True, slots=True)
class TransferRun:
    reports: tuple[ContactReport, ...]
    quotes: tuple[ContactQuote, ...]
    accounting: Accounting
    value: Message | bytes

    @property
    def contacts(self) -> int:
        return len(self.reports)

    @property
    def simulated_restarts(self) -> int:
        return max(0, self.contacts - 1)

    @property
    def predicted_bempic_bytes(self) -> int:
        return sum(quote.predicted_spent_bytes for quote in self.quotes)

    @property
    def prediction_error_bytes(self) -> int:
        return self.accounting.total_bempic_bytes - self.predicted_bempic_bytes


def run_until_complete(
    root: Path,
    representation: PreparedRepresentation,
    contact_windows: tuple[int, ...],
    *,
    max_record_size: int = 96,
    max_contacts: int = 1_000,
    corrupt_contacts: frozenset[int] = frozenset(),
) -> TransferRun:
    """Reopen receiver state for every contact and run through final RESULT."""

    if not contact_windows:
        raise ValueError("at least one contact window is required")
    if max_contacts <= 0:
        raise ValueError("max_contacts must be positive")

    total = Accounting()
    reports = []
    quotes = []
    for contact_number in range(1, max_contacts + 1):
        receiver = ReceiverStore(root, representation)
        exchange = ProofExchange(
            representation,
            receiver,
            max_record_size=max_record_size,
        )
        budget = contact_windows[(contact_number - 1) % len(contact_windows)]
        corrupt_next_data = contact_number in corrupt_contacts
        quote = exchange.quote_contact(
            budget,
            corrupt_next_data=corrupt_next_data,
        )
        report = exchange.run_contact(
            budget,
            corrupt_next_data=corrupt_next_data,
        )
        if (
            quote.predicted_spent_bytes != report.spent_bytes
            or quote.predicted_progress_after != report.progress_after
            or quote.predicted_complete != report.complete
            or quote.predicted_result_sent != report.result_sent
        ):
            raise AssertionError("contact quote did not match actual transfer")
        total.merge(report.accounting)
        quotes.append(quote)
        reports.append(report)
        if report.result_sent:
            final_receiver = ReceiverStore(root, representation)
            return TransferRun(
                tuple(reports),
                tuple(quotes),
                total,
                final_receiver.read_complete(),
            )

    raise RuntimeError(f"proof did not complete within {max_contacts} contacts")

