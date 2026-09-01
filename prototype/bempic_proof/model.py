"""Application objects used by the non-normative proof."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import IntEnum


class RepresentationKind(IntEnum):
    """Semantic validation class for an immutable proof representation."""

    MESSAGE = 1
    BINARY = 2


@dataclass(frozen=True, slots=True)
class AttachmentDescriptor:
    """Metadata for one independently retrievable attachment representation."""

    part_id: bytes
    filename: str
    media_type: str
    representation_id: bytes
    size: int
    digest: bytes

    def __post_init__(self) -> None:
        if len(self.part_id) != 16:
            raise ValueError("part_id must be exactly 16 bytes")
        if not self.filename:
            raise ValueError("attachment filename is required")
        if not self.media_type:
            raise ValueError("attachment media_type is required")
        if len(self.representation_id) != 16:
            raise ValueError("attachment representation_id must be 16 bytes")
        if not 0 <= self.size <= (1 << 64) - 1:
            raise ValueError("attachment size must fit an unsigned 64-bit integer")
        if len(self.digest) != 32:
            raise ValueError("attachment digest must be a full SHA-256 digest")


@dataclass(frozen=True, slots=True)
class Message:
    """The deliberately small, immutable first-proof message model."""

    logical_id: bytes
    created_at: int
    sender: str
    recipients: tuple[str, ...]
    subject: str | None
    body: str
    attachments: tuple[AttachmentDescriptor, ...] = ()

    def __post_init__(self) -> None:
        if len(self.logical_id) != 16:
            raise ValueError("logical_id must be exactly 16 bytes in proof generation 0")
        if not 0 <= self.created_at <= (1 << 64) - 1:
            raise ValueError("created_at must fit an unsigned 64-bit integer")
        if not self.sender:
            raise ValueError("sender is required")
        if not self.recipients:
            raise ValueError("at least one recipient is required")
        if len(self.recipients) > 255:
            raise ValueError("proof generation 0 permits at most 255 recipients")
        if len(self.attachments) > 255:
            raise ValueError("proof generation 0 permits at most 255 attachments")
        part_ids = {attachment.part_id for attachment in self.attachments}
        if len(part_ids) != len(self.attachments):
            raise ValueError("attachment part_id values must be unique within a message")


@dataclass(frozen=True, slots=True)
class PreparedRepresentation:
    """Exact immutable bytes offered for transfer."""

    representation_id: bytes
    digest: bytes
    encoded: bytes
    kind: RepresentationKind

    def __post_init__(self) -> None:
        if len(self.representation_id) != 16:
            raise ValueError("representation_id must be 16 bytes")
        if len(self.digest) != 32:
            raise ValueError("digest must be a full SHA-256 digest")
        if not isinstance(self.kind, RepresentationKind):
            raise ValueError("kind must be a RepresentationKind")
        calculated = hashlib.sha256(self.encoded).digest()
        if self.digest != calculated:
            raise ValueError("digest must match the encoded representation")
        if self.representation_id != calculated[:16]:
            raise ValueError("representation_id must be the proof digest prefix")

    @property
    def size(self) -> int:
        return len(self.encoded)

