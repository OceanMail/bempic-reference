"""Minimal deterministic collection-summary comparison for the proof."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Iterable

from .exchange import Accounting
from .model import PreparedRepresentation
from .operations import Capabilities, Summary, decode_operation, encode_operation


@dataclass(frozen=True, slots=True)
class SummaryExchange:
    equal: bool
    cached_capabilities: bool
    accounting: Accounting
    left_digest: bytes
    right_digest: bytes


def collection_digest(representations: Iterable[PreparedRepresentation]) -> bytes:
    """Digest a set without depending on insertion order."""

    ordered = sorted(
        representations,
        key=lambda item: (item.representation_id, item.digest, int(item.kind)),
    )
    digest = hashlib.sha256(b"BEMPIC-COLLECTION-SUMMARY0")
    digest.update(struct.pack(">I", len(ordered)))
    for representation in ordered:
        digest.update(representation.representation_id)
        digest.update(representation.digest)
        digest.update(struct.pack(">BQ", int(representation.kind), representation.size))
    return digest.digest()[:16]


def compare_collections(
    left: Iterable[PreparedRepresentation],
    right: Iterable[PreparedRepresentation],
    *,
    cached_capabilities: bool,
    max_record_size: int = 96,
) -> SummaryExchange:
    """Exchange two summaries and report equality with exact proof byte counts."""

    left_items = tuple(left)
    right_items = tuple(right)
    left_digest = collection_digest(left_items)
    right_digest = collection_digest(right_items)
    accounting = Accounting()

    def emit(operation: Capabilities | Summary, direction: str) -> None:
        record = encode_operation(operation)
        if len(record) > max_record_size:
            raise ValueError("summary operation exceeds maximum record size")
        decoded = decode_operation(record)
        accounting.add(direction, type(decoded).__name__.lower(), len(record))

    if not cached_capabilities:
        emit(
            Capabilities(0, max_record_size, 0),
            "sender_to_receiver",
        )
        emit(
            Capabilities(0, max_record_size, 0),
            "receiver_to_sender",
        )
    emit(Summary(len(left_items), left_digest), "sender_to_receiver")
    emit(Summary(len(right_items), right_digest), "receiver_to_sender")

    return SummaryExchange(
        equal=left_digest == right_digest,
        cached_capabilities=cached_capabilities,
        accounting=accounting,
        left_digest=left_digest,
        right_digest=right_digest,
    )

