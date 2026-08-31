"""Deterministic constrained-contact exchange for the semantic proof."""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .model import PreparedRepresentation
from .operations import (
    Capabilities,
    Data,
    Offer,
    Operation,
    Request,
    Result,
    Summary,
    data_record_overhead,
    decode_operation,
    encode_operation,
)
from .store import IntegrityError, ReceiverStore


@dataclass(slots=True)
class Accounting:
    sender_to_receiver_bytes: int = 0
    receiver_to_sender_bytes: int = 0
    representation_payload_bytes: int = 0
    duplicate_payload_bytes: int = 0
    useful_committed_bytes: int = 0
    integrity_failures: int = 0
    operation_bytes: dict[str, int] = field(default_factory=dict)

    @property
    def total_bempic_bytes(self) -> int:
        return self.sender_to_receiver_bytes + self.receiver_to_sender_bytes

    def add(self, direction: str, name: str, record_size: int) -> None:
        if direction == "sender_to_receiver":
            self.sender_to_receiver_bytes += record_size
        elif direction == "receiver_to_sender":
            self.receiver_to_sender_bytes += record_size
        else:
            raise ValueError(f"unknown direction: {direction}")
        self.operation_bytes[name] = self.operation_bytes.get(name, 0) + record_size

    def merge(self, other: "Accounting") -> None:
        self.sender_to_receiver_bytes += other.sender_to_receiver_bytes
        self.receiver_to_sender_bytes += other.receiver_to_sender_bytes
        self.representation_payload_bytes += other.representation_payload_bytes
        self.duplicate_payload_bytes += other.duplicate_payload_bytes
        self.useful_committed_bytes += other.useful_committed_bytes
        self.integrity_failures += other.integrity_failures
        for name, count in other.operation_bytes.items():
            self.operation_bytes[name] = self.operation_bytes.get(name, 0) + count


@dataclass(frozen=True, slots=True)
class ContactReport:
    budget_bytes: int
    spent_bytes: int
    progress_before: int
    progress_after: int
    complete: bool
    result_sent: bool
    accounting: Accounting


@dataclass(frozen=True, slots=True)
class ContactQuote:
    """Side-effect-free prediction for one contact in the proof harness."""

    budget_bytes: int
    predicted_spent_bytes: int
    progress_before: int
    predicted_progress_after: int
    predicted_complete: bool
    predicted_result_sent: bool
    accounting: Accounting


class _Budget:
    def __init__(self, limit: int) -> None:
        if limit < 0:
            raise ValueError("contact budget cannot be negative")
        self.limit = limit
        self.used = 0

    @property
    def remaining(self) -> int:
        return self.limit - self.used

    def consume(self, count: int) -> bool:
        if count > self.remaining:
            return False
        self.used += count
        return True


class ProofExchange:
    """Advance one immutable representation through one contact window."""

    def __init__(
        self,
        representation: PreparedRepresentation,
        receiver: ReceiverStore,
        *,
        max_record_size: int = 96,
    ) -> None:
        offer_size = len(
            encode_operation(
                Offer(
                    representation.representation_id,
                    int(representation.kind),
                    representation.size,
                    representation.digest,
                )
            )
        )
        minimum = max(data_record_overhead() + 1, offer_size)
        if max_record_size < minimum:
            raise ValueError(f"max_record_size must be at least {minimum}")
        self.representation = representation
        self.receiver = receiver
        self.max_record_size = max_record_size

    def quote_contact(
        self,
        budget_bytes: int,
        *,
        corrupt_next_data: bool = False,
    ) -> ContactQuote:
        """Predict an exact contact result without mutating receiver state.

        This intentionally expensive clone-and-execute oracle belongs to the
        measurement harness. It is not a proposed protocol mechanism.
        """

        with tempfile.TemporaryDirectory(prefix="bempic-quote-") as temporary:
            shadow_root = Path(temporary)
            for source in (
                self.receiver.state_path,
                self.receiver.part_path,
                self.receiver.complete_path,
            ):
                if source.exists():
                    shutil.copy2(source, shadow_root / source.name)
            shadow_receiver = ReceiverStore(shadow_root, self.representation)
            report = ProofExchange(
                self.representation,
                shadow_receiver,
                max_record_size=self.max_record_size,
            ).run_contact(
                budget_bytes,
                corrupt_next_data=corrupt_next_data,
            )
        return ContactQuote(
            budget_bytes=report.budget_bytes,
            predicted_spent_bytes=report.spent_bytes,
            progress_before=report.progress_before,
            predicted_progress_after=report.progress_after,
            predicted_complete=report.complete,
            predicted_result_sent=report.result_sent,
            accounting=report.accounting,
        )

    def run_contact(
        self,
        budget_bytes: int,
        *,
        corrupt_next_data: bool = False,
    ) -> ContactReport:
        budget = _Budget(budget_bytes)
        accounting = Accounting()
        before = self.receiver.progress

        def emit(operation: Operation, direction: str) -> bool:
            record = encode_operation(operation)
            if len(record) > self.max_record_size:
                raise ValueError("operation exceeds negotiated record size")
            if not budget.consume(len(record)):
                return False
            decoded = decode_operation(record)
            accounting.add(direction, type(decoded).__name__.lower(), len(record))
            return True

        if not self.receiver.flag("sender_caps_received"):
            operation = Capabilities(0, self.max_record_size, 0)
            if not emit(operation, "sender_to_receiver"):
                return self._report(budget_bytes, budget, before, accounting)
            self.receiver.mark("sender_caps_received")

        if not self.receiver.flag("receiver_caps_sent"):
            operation = Capabilities(0, self.max_record_size, 0)
            if not emit(operation, "receiver_to_sender"):
                return self._report(budget_bytes, budget, before, accounting)
            self.receiver.mark("receiver_caps_sent")

        if not self.receiver.flag("summary_seen"):
            operation = Summary(0, self.representation.representation_id)
            if not emit(operation, "sender_to_receiver"):
                return self._report(budget_bytes, budget, before, accounting)
            self.receiver.mark("summary_seen")

        if not self.receiver.flag("offer_seen") and not self.receiver.is_complete:
            operation = Offer(
                self.representation.representation_id,
                int(self.representation.kind),
                self.representation.size,
                self.representation.digest,
            )
            if not emit(operation, "sender_to_receiver"):
                return self._report(budget_bytes, budget, before, accounting)
            self.receiver.mark("offer_seen")

        if not self.receiver.is_complete:
            request_overhead = len(
                encode_operation(
                    Request(self.representation.representation_id, self.receiver.progress, 0)
                )
            )
            data_overhead = data_record_overhead()
            remaining_representation = self.representation.size - self.receiver.progress
            payload_limit = min(
                remaining_representation,
                self.max_record_size - data_overhead,
                budget.remaining - request_overhead - data_overhead,
                0xFFFFFFFF,
            )
            if payload_limit > 0:
                offset = self.receiver.progress
                request = Request(
                    self.representation.representation_id,
                    offset,
                    payload_limit,
                )
                if not emit(request, "receiver_to_sender"):
                    raise AssertionError("calculated request did not fit")
                payload = self.representation.encoded[offset : offset + payload_limit]
                transmitted = payload
                if corrupt_next_data and transmitted:
                    transmitted = bytes((transmitted[0] ^ 0x01,)) + transmitted[1:]
                data = Data(self.representation.representation_id, offset, transmitted)
                if not emit(data, "sender_to_receiver"):
                    raise AssertionError("calculated data operation did not fit")
                accepted, duplicate = self.receiver.accept_data(offset, transmitted)
                accounting.representation_payload_bytes += len(transmitted)
                accounting.duplicate_payload_bytes += duplicate
                if accepted and self.receiver.progress == self.representation.size:
                    try:
                        self.receiver.verify_and_commit()
                        accounting.useful_committed_bytes += self.representation.size
                    except IntegrityError:
                        accounting.integrity_failures += 1

        if self.receiver.is_complete and not self.receiver.flag("result_sent"):
            result = Result(
                self.representation.representation_id,
                True,
                self.representation.digest,
            )
            if emit(result, "receiver_to_sender"):
                self.receiver.mark("result_sent")

        return self._report(budget_bytes, budget, before, accounting)

    def _report(
        self,
        budget_bytes: int,
        budget: _Budget,
        before: int,
        accounting: Accounting,
    ) -> ContactReport:
        if budget.used > budget.limit:
            raise AssertionError("hard contact budget was exceeded")
        return ContactReport(
            budget_bytes=budget_bytes,
            spent_bytes=budget.used,
            progress_before=before,
            progress_after=self.receiver.progress,
            complete=self.receiver.is_complete,
            result_sent=self.receiver.flag("result_sent"),
            accounting=accounting,
        )

