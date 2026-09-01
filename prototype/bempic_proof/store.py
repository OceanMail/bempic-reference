"""Small crash-conscious receiver store used by the proof."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

from .codec import decode_message
from .model import Message, PreparedRepresentation, RepresentationKind


class StoreError(RuntimeError):
    """Raised when persisted state conflicts with an incoming operation."""


class IntegrityError(StoreError):
    """Raised when a complete representation fails whole-object verification."""


class ReceiverStore:
    """Persist a contiguous prefix and commit only verified representations."""

    def __init__(self, root: Path, representation: PreparedRepresentation) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.representation = representation
        stem = representation.representation_id.hex()
        self.state_path = self.root / f"{stem}.json"
        self.part_path = self.root / f"{stem}.part"
        self.complete_path = self.root / f"{stem}.complete"
        self.corrupt_path = self.root / f"{stem}.corrupt"
        self._state = self._load_or_create_state()
        self._reconcile_progress()

    def _new_state(self) -> dict[str, Any]:
        return {
            "representation_id": self.representation.representation_id.hex(),
            "digest": self.representation.digest.hex(),
            "size": self.representation.size,
            "kind": int(self.representation.kind),
            "sender_caps_received": False,
            "receiver_caps_sent": False,
            "summary_seen": False,
            "offer_seen": False,
            "result_sent": False,
            "status": "empty",
            "accepted_bytes": 0,
        }

    def _load_or_create_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            state = self._new_state()
            self._write_state(state)
            return state
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise StoreError("receiver state is unreadable") from error
        expected = self._new_state()
        for key in ("representation_id", "digest", "size", "kind"):
            if state.get(key) != expected[key]:
                raise StoreError("persisted state belongs to another representation")
        return state

    def _write_state(self, state: dict[str, Any]) -> None:
        temporary = self.state_path.with_suffix(".json.tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(state, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, self.state_path)

    def _save(self) -> None:
        self._write_state(self._state)

    def _reconcile_progress(self) -> None:
        if self.complete_path.exists():
            committed = self.complete_path.read_bytes()
            actual = len(committed)
            if actual != self.representation.size:
                raise StoreError("committed representation has an impossible size")
            digest = hashlib.sha256(committed).digest()
            if not hmac.compare_digest(digest, self.representation.digest):
                raise IntegrityError("committed representation digest mismatch")
            self._state["status"] = "complete"
            self._state["accepted_bytes"] = actual
            self._save()
            return
        actual = self.part_path.stat().st_size if self.part_path.exists() else 0
        if actual > self.representation.size:
            raise StoreError("partial representation exceeds advertised size")
        self._state["accepted_bytes"] = actual
        if actual and self._state["status"] == "empty":
            self._state["status"] = "partial"
        self._save()

    @property
    def progress(self) -> int:
        return int(self._state["accepted_bytes"])

    @property
    def is_complete(self) -> bool:
        return self._state["status"] == "complete" and self.complete_path.exists()

    def flag(self, name: str) -> bool:
        if name not in {
            "sender_caps_received",
            "receiver_caps_sent",
            "summary_seen",
            "offer_seen",
            "result_sent",
        }:
            raise KeyError(name)
        return bool(self._state[name])

    def mark(self, name: str) -> None:
        self.flag(name)
        self._state[name] = True
        self._save()

    def accept_data(self, offset: int, payload: bytes) -> tuple[int, int]:
        """Persist data and return (new_bytes, duplicate_bytes)."""

        if self.is_complete:
            if offset + len(payload) > self.representation.size:
                raise StoreError("data exceeds complete representation")
            existing = self.complete_path.read_bytes()[offset : offset + len(payload)]
            if not hmac.compare_digest(existing, payload):
                raise StoreError("duplicate data conflicts with committed bytes")
            return 0, len(payload)
        if offset > self.progress:
            raise StoreError("non-contiguous data cannot be accepted by this proof")
        if offset + len(payload) > self.representation.size:
            raise StoreError("data exceeds advertised representation size")
        if offset < self.progress:
            overlap = min(len(payload), self.progress - offset)
            with self.part_path.open("rb") as handle:
                handle.seek(offset)
                existing = handle.read(overlap)
            if not hmac.compare_digest(existing, payload[:overlap]):
                raise StoreError("duplicate data conflicts with persisted prefix")
            if overlap == len(payload):
                return 0, len(payload)
            payload = payload[overlap:]
            offset += overlap

        if offset != self.progress:
            raise StoreError("data does not begin at the retained prefix")
        if payload:
            with self.part_path.open("ab") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        self._state["accepted_bytes"] = self.progress + len(payload)
        self._state["status"] = "partial"
        self._save()
        return len(payload), 0

    def _decode_committed(self, encoded: bytes) -> Message | bytes:
        if self.representation.kind is RepresentationKind.MESSAGE:
            return decode_message(encoded)
        if self.representation.kind is RepresentationKind.BINARY:
            return encoded
        raise StoreError("unsupported representation kind")

    def verify_and_commit(self) -> Message | bytes | None:
        if self.is_complete:
            return self.read_complete()
        if self.progress != self.representation.size:
            return None
        encoded = self.part_path.read_bytes()
        digest = hashlib.sha256(encoded).digest()
        if not hmac.compare_digest(digest, self.representation.digest):
            quarantine = self.corrupt_path
            sequence = 1
            while quarantine.exists():
                quarantine = self.corrupt_path.with_suffix(f".corrupt.{sequence}")
                sequence += 1
            os.replace(self.part_path, quarantine)
            self._state["accepted_bytes"] = 0
            self._state["status"] = "offered"
            self._state["result_sent"] = False
            self._save()
            raise IntegrityError("whole-representation digest mismatch")
        value = self._decode_committed(encoded)
        os.replace(self.part_path, self.complete_path)
        self._state["status"] = "complete"
        self._state["accepted_bytes"] = self.representation.size
        self._save()
        return value

    def read_complete(self) -> Message | bytes:
        if not self.is_complete:
            raise StoreError("representation is not committed")
        committed = self.complete_path.read_bytes()
        digest = hashlib.sha256(committed).digest()
        if not hmac.compare_digest(digest, self.representation.digest):
            raise IntegrityError("committed representation digest mismatch")
        return self._decode_committed(committed)

