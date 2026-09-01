"""Replaceable operation records for the executable proof.

These byte assignments exist only so the proof can count and constrain every
application-protocol byte. They are not a proposed or stable BEMPIC wire format.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import TypeAlias

RECORD_MAGIC = b"B0"
ENVELOPE_SIZE = 5


class OperationError(ValueError):
    """Raised for a malformed or unsupported proof operation."""


class Kind(IntEnum):
    CAPABILITIES = 1
    SUMMARY = 2
    OFFER = 3
    REQUEST = 4
    DATA = 5
    RESULT = 6


@dataclass(frozen=True, slots=True)
class Capabilities:
    """Disposable proof encoding generation and local record capabilities.

    ``encoding_generation`` identifies the experimental operation encoding only;
    it is not mailbox state, a collection revision, or a protocol version.
    """

    encoding_generation: int
    max_record_size: int
    features: int = 0


@dataclass(frozen=True, slots=True)
class Summary:
    """Collection cardinality plus its order-independent digest."""

    item_count: int
    digest: bytes


@dataclass(frozen=True, slots=True)
class Offer:
    representation_id: bytes
    representation_kind: int
    size: int
    digest: bytes


@dataclass(frozen=True, slots=True)
class Request:
    representation_id: bytes
    offset: int
    max_payload_bytes: int


@dataclass(frozen=True, slots=True)
class Data:
    representation_id: bytes
    offset: int
    payload: bytes


@dataclass(frozen=True, slots=True)
class Result:
    representation_id: bytes
    accepted: bool
    digest: bytes


Operation: TypeAlias = Capabilities | Summary | Offer | Request | Data | Result


def _validate_id(value: bytes, field: str) -> None:
    if len(value) != 16:
        raise ValueError(f"{field} must be 16 bytes")


def _envelope(kind: Kind, payload: bytes) -> bytes:
    if len(payload) > 0xFFFF:
        raise ValueError("operation payload exceeds proof envelope limit")
    return RECORD_MAGIC + bytes((kind,)) + struct.pack(">H", len(payload)) + payload


def encode_operation(operation: Operation) -> bytes:
    if isinstance(operation, Capabilities):
        if not 0 <= operation.encoding_generation <= 0xFF:
            raise ValueError("encoding_generation must fit one byte")
        if not ENVELOPE_SIZE <= operation.max_record_size <= 0xFFFF:
            raise ValueError("max_record_size is outside proof limits")
        if not 0 <= operation.features <= 0xFF:
            raise ValueError("features must fit one byte")
        payload = struct.pack(
            ">BHB",
            operation.encoding_generation,
            operation.max_record_size,
            operation.features,
        )
        return _envelope(Kind.CAPABILITIES, payload)
    if isinstance(operation, Summary):
        if not 0 <= operation.item_count <= (1 << 64) - 1:
            raise ValueError("item_count must fit an unsigned 64-bit integer")
        if len(operation.digest) != 16:
            raise ValueError("summary digest must be 16 bytes")
        return _envelope(Kind.SUMMARY, struct.pack(">Q", operation.item_count) + operation.digest)
    if isinstance(operation, Offer):
        _validate_id(operation.representation_id, "representation_id")
        if not 0 <= operation.representation_kind <= 0xFF:
            raise ValueError("representation_kind must fit one byte")
        if len(operation.digest) != 32:
            raise ValueError("offer digest must be 32 bytes")
        payload = b"".join(
            (
                operation.representation_id,
                bytes((operation.representation_kind,)),
                struct.pack(">Q", operation.size),
                operation.digest,
            )
        )
        return _envelope(Kind.OFFER, payload)
    if isinstance(operation, Request):
        _validate_id(operation.representation_id, "representation_id")
        payload = operation.representation_id + struct.pack(
            ">QI", operation.offset, operation.max_payload_bytes
        )
        return _envelope(Kind.REQUEST, payload)
    if isinstance(operation, Data):
        _validate_id(operation.representation_id, "representation_id")
        return _envelope(
            Kind.DATA,
            operation.representation_id + struct.pack(">Q", operation.offset) + operation.payload,
        )
    if isinstance(operation, Result):
        _validate_id(operation.representation_id, "representation_id")
        if len(operation.digest) != 32:
            raise ValueError("result digest must be 32 bytes")
        payload = operation.representation_id + bytes((operation.accepted,)) + operation.digest
        return _envelope(Kind.RESULT, payload)
    raise TypeError(f"unsupported operation type: {type(operation)!r}")


def decode_operation(record: bytes) -> Operation:
    if len(record) < ENVELOPE_SIZE:
        raise OperationError("truncated operation envelope")
    if record[:2] != RECORD_MAGIC:
        raise OperationError("invalid operation magic")
    try:
        kind = Kind(record[2])
    except ValueError as error:
        raise OperationError("unknown mandatory proof operation") from error
    payload_length = struct.unpack(">H", record[3:5])[0]
    payload = record[5:]
    if payload_length != len(payload):
        raise OperationError("operation length does not match envelope")

    if kind is Kind.CAPABILITIES:
        if len(payload) != 4:
            raise OperationError("invalid capabilities length")
        encoding_generation, max_record_size, features = struct.unpack(">BHB", payload)
        return Capabilities(encoding_generation, max_record_size, features)
    if kind is Kind.SUMMARY:
        if len(payload) != 24:
            raise OperationError("invalid summary length")
        return Summary(struct.unpack(">Q", payload[:8])[0], payload[8:])
    if kind is Kind.OFFER:
        if len(payload) != 57:
            raise OperationError("invalid offer length")
        return Offer(
            payload[:16],
            payload[16],
            struct.unpack(">Q", payload[17:25])[0],
            payload[25:],
        )
    if kind is Kind.REQUEST:
        if len(payload) != 28:
            raise OperationError("invalid request length")
        offset, max_payload = struct.unpack(">QI", payload[16:])
        return Request(payload[:16], offset, max_payload)
    if kind is Kind.DATA:
        if len(payload) < 24:
            raise OperationError("invalid data length")
        return Data(payload[:16], struct.unpack(">Q", payload[16:24])[0], payload[24:])
    if kind is Kind.RESULT:
        if len(payload) != 49 or payload[16] not in (0, 1):
            raise OperationError("invalid result record")
        return Result(payload[:16], bool(payload[16]), payload[17:])
    raise AssertionError("unreachable operation kind")


def data_record_overhead() -> int:
    return len(encode_operation(Data(b"\0" * 16, 0, b"")))

