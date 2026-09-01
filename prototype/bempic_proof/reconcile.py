"""Bounded OFFER pagination after a collection-summary mismatch."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .exchange import Accounting
from .model import PreparedRepresentation
from .operations import Offer, decode_operation, encode_operation


@dataclass(frozen=True, slots=True)
class OfferPage:
    offered: tuple[PreparedRepresentation, ...]
    next_cursor: int | None
    accounting: Accounting

    @property
    def complete(self) -> bool:
        return self.next_cursor is None


def missing_representations(
    available: Iterable[PreparedRepresentation],
    known: Iterable[PreparedRepresentation],
) -> tuple[PreparedRepresentation, ...]:
    """Return deterministic representation-level set difference.

    Exact duplicates collapse to one set member. A reused short identifier with
    different metadata is rejected instead of silently hiding an object.
    """

    def index(
        representations: Iterable[PreparedRepresentation],
    ) -> dict[bytes, PreparedRepresentation]:
        indexed: dict[bytes, PreparedRepresentation] = {}
        for item in representations:
            existing = indexed.get(item.representation_id)
            if existing is not None and existing != item:
                raise ValueError("conflicting representation_id in collection")
            indexed[item.representation_id] = item
        return indexed

    available_by_id = index(available)
    known_by_id = index(known)
    for representation_id in available_by_id.keys() & known_by_id.keys():
        if available_by_id[representation_id] != known_by_id[representation_id]:
            raise ValueError("representation_id collision between collections")

    return tuple(
        sorted(
            (
                item
                for representation_id, item in available_by_id.items()
                if representation_id not in known_by_id
            ),
            key=lambda item: item.representation_id,
        )
    )


def offer_page(
    missing: tuple[PreparedRepresentation, ...],
    *,
    cursor: int = 0,
    budget_bytes: int,
    max_record_size: int = 96,
) -> OfferPage:
    """Offer as many complete records as fit without splitting an operation."""

    if not 0 <= cursor <= len(missing):
        raise ValueError("cursor is outside the missing representation set")
    if budget_bytes < 0:
        raise ValueError("budget_bytes cannot be negative")

    accounting = Accounting()
    offered = []
    used = 0
    index = cursor
    while index < len(missing):
        representation = missing[index]
        operation = Offer(
            representation.representation_id,
            int(representation.kind),
            representation.size,
            representation.digest,
        )
        record = encode_operation(operation)
        if len(record) > max_record_size:
            raise ValueError("offer exceeds maximum record size")
        if used + len(record) > budget_bytes:
            break
        decoded = decode_operation(record)
        accounting.add(
            "sender_to_receiver",
            type(decoded).__name__.lower(),
            len(record),
        )
        used += len(record)
        offered.append(representation)
        index += 1

    if accounting.total_bempic_bytes > budget_bytes:
        raise AssertionError("offer page exceeded its byte budget")
    next_cursor = index if index < len(missing) else None
    return OfferPage(tuple(offered), next_cursor, accounting)

