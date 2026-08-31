"""Deterministic, synthetic, redistributable benchmark fixtures."""

from __future__ import annotations

import gzip
import hashlib
from dataclasses import dataclass
from email.message import EmailMessage
from email.policy import SMTP

from .bempic_proof import (
    Message,
    PreparedRepresentation,
    prepare_attachment,
)


@dataclass(frozen=True, slots=True)
class Fixture:
    name: str
    message: Message
    attachments: tuple[PreparedRepresentation, ...]
    rfc5322_mime: bytes


def _identity(label: str) -> bytes:
    return hashlib.sha256(f"bempic-fixture:{label}".encode()).digest()[:16]


def _deterministic_noise(size: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < size:
        output.extend(hashlib.sha256(f"noise:{counter}".encode()).digest())
        counter += 1
    return bytes(output[:size])


def _as_mime(message: Message, attachments: tuple[PreparedRepresentation, ...]) -> bytes:
    mime = EmailMessage(policy=SMTP)
    mime["From"] = message.sender
    mime["To"] = ", ".join(message.recipients)
    if message.subject is not None:
        mime["Subject"] = message.subject
    mime["Date"] = "Sun, 30 Aug 2026 12:00:00 -0800"
    mime["Message-ID"] = f"<{message.logical_id.hex()}@fixtures.bempic.test>"
    mime.set_content(message.body, charset="utf-8")
    for descriptor, representation in zip(message.attachments, attachments, strict=True):
        maintype, separator, subtype = descriptor.media_type.partition("/")
        if not separator:
            maintype, subtype = "application", "octet-stream"
        mime.add_attachment(
            representation.encoded,
            maintype=maintype,
            subtype=subtype,
            filename=descriptor.filename,
        )
    if mime.is_multipart():
        mime.set_boundary(f"bempic-{message.logical_id.hex()}")
    return mime.as_bytes(policy=SMTP)


def _fixture(
    name: str,
    body: str,
    *,
    subject: str,
    attachment_specs: tuple[tuple[str, str, bytes], ...] = (),
) -> Fixture:
    descriptors = []
    representations = []
    for filename, media_type, content in attachment_specs:
        descriptor, representation = prepare_attachment(filename, media_type, content)
        descriptors.append(descriptor)
        representations.append(representation)
    message = Message(
        logical_id=_identity(name),
        created_at=1_788_112_800,
        sender="shore@example.test",
        recipients=("vessel@example.test",),
        subject=subject,
        body=body,
        attachments=tuple(descriptors),
    )
    attachments = tuple(representations)
    return Fixture(name, message, attachments, _as_mime(message, attachments))


def build_fixtures() -> tuple[Fixture, ...]:
    typical_paragraph = (
        "Weather remains calm along the route. Maintain the planned watch "
        "schedule and report fuel, battery, and position at the next contact. "
    )
    reply = (
        "Acknowledged. We will hold the present course.\n\n"
        "> Earlier message:\n"
        "> Maintain the planned watch schedule and report at next contact.\n"
    )
    international = (
        "Météo stable. 日本語の試験。Проверка связи. God vind videre. " * 8
    )
    compressible_attachment = (
        b"UTC,latitude,longitude,wind_knots\n"
        + b"2026-08-30T20:00Z,55.342,-131.646,12\n" * 240
    )
    already_compressed = gzip.compress(
        _deterministic_noise(10 * 1024), mtime=0
    )

    return (
        _fixture(
            "tiny_plain",
            "Position received. All well aboard.",
            subject="Position received",
        ),
        _fixture(
            "typical_plain",
            typical_paragraph * 8,
            subject="Route and watch update",
        ),
        _fixture(
            "international_text",
            international,
            subject="International text — météo / 天気 / погода",
        ),
        _fixture(
            "reply_chain",
            reply * 8,
            subject="Re: Watch schedule",
        ),
        _fixture(
            "compressible_attachment",
            "A route table is available; fetch it only if needed.",
            subject="Optional route table",
            attachment_specs=(("route.csv", "text/csv", compressible_attachment),),
        ),
        _fixture(
            "already_compressed_attachment",
            "A compressed sensor archive is available on request.",
            subject="Optional sensor archive",
            attachment_specs=(
                ("sensor.bin.gz", "application/gzip", already_compressed),
            ),
        ),
    )

