"""Deterministic generation-0 message encoding for experimentation only."""

from __future__ import annotations

import hashlib
import struct

from .model import (
    AttachmentDescriptor,
    Message,
    PreparedRepresentation,
    RepresentationKind,
)

MESSAGE_MAGIC = b"BMSG0"
MAX_TEXT_BYTES = 1 << 20


class DecodeError(ValueError):
    """Raised when experimental message bytes are invalid."""


def _encode_short_text(value: str, field: str) -> bytes:
    encoded = value.encode("utf-8")
    if len(encoded) > 0xFFFE:
        raise ValueError(f"{field} exceeds the proof's 65534-byte limit")
    return struct.pack(">H", len(encoded)) + encoded


def encode_message(message: Message) -> bytes:
    """Encode one immutable message using the replaceable proof encoding."""

    sender = _encode_short_text(message.sender, "sender")
    recipients = b"".join(
        _encode_short_text(recipient, "recipient")
        for recipient in message.recipients
    )
    if message.subject is None:
        subject = struct.pack(">H", 0xFFFF)
    else:
        subject = _encode_short_text(message.subject, "subject")
    body = message.body.encode("utf-8")
    if len(body) > MAX_TEXT_BYTES:
        raise ValueError("body exceeds the proof's one-MiB safety limit")

    attachments = []
    for attachment in message.attachments:
        attachments.append(
            b"".join(
                (
                    attachment.part_id,
                    _encode_short_text(attachment.filename, "attachment filename"),
                    _encode_short_text(attachment.media_type, "attachment media type"),
                    attachment.representation_id,
                    struct.pack(">Q", attachment.size),
                    attachment.digest,
                )
            )
        )

    return b"".join(
        (
            MESSAGE_MAGIC,
            message.logical_id,
            struct.pack(">Q", message.created_at),
            sender,
            struct.pack(">B", len(message.recipients)),
            recipients,
            subject,
            struct.pack(">I", len(body)),
            body,
            struct.pack(">B", len(attachments)),
            b"".join(attachments),
        )
    )


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def take(self, count: int) -> bytes:
        if count < 0 or self.offset + count > len(self.data):
            raise DecodeError("truncated message representation")
        result = self.data[self.offset : self.offset + count]
        self.offset += count
        return result

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack(">I", self.take(4))[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]

    def short_text(self, field: str, *, nullable: bool = False) -> str | None:
        length = self.u16()
        if nullable and length == 0xFFFF:
            return None
        if length == 0xFFFF:
            raise DecodeError(f"invalid {field} length")
        try:
            return self.take(length).decode("utf-8")
        except UnicodeDecodeError as error:
            raise DecodeError(f"{field} is not valid UTF-8") from error


def decode_message(data: bytes) -> Message:
    """Decode and strictly validate one experimental message representation."""

    reader = _Reader(data)
    if reader.take(len(MESSAGE_MAGIC)) != MESSAGE_MAGIC:
        raise DecodeError("invalid message magic")
    logical_id = reader.take(16)
    created_at = reader.u64()
    sender = reader.short_text("sender")
    recipient_count = reader.u8()
    if recipient_count == 0:
        raise DecodeError("message has no recipients")
    recipients = tuple(
        reader.short_text("recipient") for _ in range(recipient_count)
    )
    subject = reader.short_text("subject", nullable=True)
    body_length = reader.u32()
    if body_length > MAX_TEXT_BYTES:
        raise DecodeError("body length exceeds safety limit")
    try:
        body = reader.take(body_length).decode("utf-8")
    except UnicodeDecodeError as error:
        raise DecodeError("body is not valid UTF-8") from error
    attachment_count = reader.u8()
    attachments = []
    for _ in range(attachment_count):
        attachments.append(
            AttachmentDescriptor(
                part_id=reader.take(16),
                filename=reader.short_text("attachment filename"),
                media_type=reader.short_text("attachment media type"),
                representation_id=reader.take(16),
                size=reader.u64(),
                digest=reader.take(32),
            )
        )
    if reader.offset != len(data):
        raise DecodeError("trailing bytes after message representation")

    return Message(
        logical_id=logical_id,
        created_at=created_at,
        sender=sender,
        recipients=recipients,
        subject=subject,
        body=body,
        attachments=tuple(attachments),
    )


def prepare_message(message: Message) -> PreparedRepresentation:
    """Prepare immutable bytes and identities before quoting their exact cost."""

    encoded = encode_message(message)
    digest = hashlib.sha256(encoded).digest()
    return PreparedRepresentation(
        representation_id=digest[:16],
        digest=digest,
        encoded=encoded,
        kind=RepresentationKind.MESSAGE,
    )


def prepare_binary(content: bytes) -> PreparedRepresentation:
    """Prepare one opaque binary representation for optional retrieval."""

    encoded = bytes(content)
    digest = hashlib.sha256(encoded).digest()
    return PreparedRepresentation(
        representation_id=digest[:16],
        digest=digest,
        encoded=encoded,
        kind=RepresentationKind.BINARY,
    )


def prepare_attachment(
    filename: str,
    media_type: str,
    content: bytes,
    *,
    part_id: bytes | None = None,
) -> tuple[AttachmentDescriptor, PreparedRepresentation]:
    """Create metadata plus the separately selectable attachment bytes."""

    representation = prepare_binary(content)
    if part_id is None:
        identity_input = b"\0".join(
            (
                b"BEMPIC-PART0",
                filename.encode("utf-8"),
                media_type.encode("utf-8"),
                representation.digest,
            )
        )
        part_id = hashlib.sha256(identity_input).digest()[:16]
    descriptor = AttachmentDescriptor(
        part_id=part_id,
        filename=filename,
        media_type=media_type,
        representation_id=representation.representation_id,
        size=representation.size,
        digest=representation.digest,
    )
    return descriptor, representation

