"""Independent RFC 8785, identity, bundle, and operation-vector verifier."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from typing import Any

import rfc8785


ROOT = Path(__file__).resolve().parents[1]
BUNDLE_ROOT = ROOT / "test-vectors" / "v0.1-experimental"
MANIFEST_PATH = BUNDLE_ROOT / "manifest.json"


class VerificationError(Exception):
    """Independent verification failed."""


def schema_fingerprint(canonical: bytes) -> str:
    material = (
        b"BEMPIC-SCHEMA-FINGERPRINT-v0.1\0"
        + struct.pack(">I", len(canonical))
        + canonical
    )
    return hashlib.sha256(material).hexdigest()


def representation_id(fixture: dict[str, Any]) -> str:
    parameters = bytes.fromhex(fixture["codec_parameters_hex"])
    encoded = bytes.fromhex(fixture["encoded_hex"])
    digest = hashlib.sha256(encoded).digest()
    material = b"".join(
        (
            b"BEMPIC-REPRESENTATION-ID-v0.1\0",
            bytes.fromhex(fixture["schema_fingerprint"]),
            struct.pack(">I", fixture["codec_id"]),
            struct.pack(">I", fixture["codec_revision"]),
            struct.pack(">I", len(parameters)),
            parameters,
            struct.pack(">Q", len(encoded)),
            digest,
        )
    )
    return hashlib.sha256(material).hexdigest()


class Reader:
    """Strict independent decoder for the published REQUEST vector only."""

    def __init__(self, value: bytes) -> None:
        self.value = value
        self.position = 0

    def take(self, count: int) -> bytes:
        end = self.position + count
        if end > len(self.value):
            raise VerificationError("truncated vector")
        result = self.value[self.position : end]
        self.position = end
        return result

    def u8(self) -> int:
        return self.take(1)[0]

    def u64(self) -> int:
        return struct.unpack(">Q", self.take(8))[0]

    def done(self) -> None:
        if self.position != len(self.value):
            raise VerificationError("trailing vector bytes")


def decode_representation_request(encoded: bytes) -> dict[str, Any]:
    if len(encoded) < 7 or encoded[:2] != b"B1" or encoded[2] != 4:
        raise VerificationError("invalid REQUEST envelope")
    declared = struct.unpack(">I", encoded[3:7])[0]
    if declared != len(encoded) - 7:
        raise VerificationError("false REQUEST envelope length")
    reader = Reader(encoded[7:])
    if reader.u8() != 1:
        raise VerificationError("not REPRESENTATION_DATA")
    result: dict[str, Any] = {
        "variant": "REPRESENTATION_DATA",
        "budget_id": reader.take(16).hex(),
        "max_total_bempic_bytes": str(reader.u64()),
        "max_sender_to_receiver_bytes": str(reader.u64()),
        "max_receiver_to_sender_bytes": str(reader.u64()),
    }
    count = reader.u8()
    if not 1 <= count <= 128:
        raise VerificationError("selection count bound")
    selections = []
    identifiers: set[str] = set()
    for _ in range(count):
        identifier = reader.take(32).hex()
        if identifier in identifiers:
            raise VerificationError("duplicate selection")
        identifiers.add(identifier)
        offset = reader.u64()
        desired = reader.u64()
        if offset > 1_073_741_824 or not 1 <= desired <= 1_073_741_824:
            raise VerificationError("selection scalar bound")
        selections.append(
            {
                "representation_id": identifier,
                "durable_prefix_offset": str(offset),
                "max_desired_payload_octets": str(desired),
            }
        )
    if reader.u8() != 0:
        raise VerificationError("unexpected extension count")
    reader.done()
    result["selections"] = selections
    return result


def strict_json(value: str) -> Any:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, item in pairs:
            if key in output:
                raise VerificationError("duplicate JSON key")
            output[key] = item
        return output

    def reject_constant(constant: str) -> None:
        raise VerificationError(f"invalid JSON constant {constant}")

    return json.loads(
        value,
        object_pairs_hook=object_pairs,
        parse_constant=reject_constant,
    )


def verify() -> dict[str, Any]:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    expected_bundle_digest = manifest["bundle_digest"]
    digest_value = dict(manifest)
    digest_value["bundle_digest"] = None
    canonical_manifest = rfc8785.dumps(digest_value)
    bundle_digest = hashlib.sha256(
        b"BEMPIC-TEST-VECTOR-BUNDLE-v0.1\0"
        + struct.pack(">Q", len(canonical_manifest))
        + canonical_manifest
    ).hexdigest()
    if bundle_digest != expected_bundle_digest:
        raise VerificationError("bundle digest mismatch")

    for file_entry in manifest["files"]:
        path = BUNDLE_ROOT / file_entry["path"]
        raw = path.read_bytes()
        if len(raw) != file_entry["length"]:
            raise VerificationError(f"file length mismatch: {path}")
        if hashlib.sha256(raw).hexdigest() != file_entry["sha256"]:
            raise VerificationError(f"file digest mismatch: {path}")

    catalog = strict_json((BUNDLE_ROOT / "catalog.json").read_text(encoding="utf-8"))
    expected_catalog_ids = [f"V{index:02d}" for index in range(1, 16)]
    actual_catalog_ids = [entry["id"] for entry in catalog["entries"]]
    if actual_catalog_ids != expected_catalog_ids:
        raise VerificationError("mandatory vector catalog IDs/order mismatch")
    allowed_statuses = {"pass", "partial", "fail", "blocked"}
    for entry in catalog["entries"]:
        if entry["status"] not in allowed_statuses:
            raise VerificationError(f"invalid catalog status: {entry['id']}")
        if entry["status"] in {"partial", "blocked"} and not entry.get("pending"):
            raise VerificationError(f"catalog gap lacks pending inventory: {entry['id']}")
    if catalog["implementation_status"] != manifest["mandatory_catalog_status"]:
        raise VerificationError("catalog and manifest completion status differ")
    question_ids = [question["id"] for question in catalog["proposed_specification_questions"]]
    if len(question_ids) != len(set(question_ids)) or not question_ids:
        raise VerificationError("specification questions must be non-empty and unique")

    fingerprints: dict[str, str] = {}
    for descriptor in manifest["schema_descriptors"]:
        raw = (BUNDLE_ROOT / descriptor["path"]).read_bytes()
        canonical = rfc8785.dumps(strict_json(raw.decode("utf-8")))
        actual = schema_fingerprint(canonical)
        if actual != descriptor["fingerprint"]:
            raise VerificationError(f"schema fingerprint mismatch: {descriptor['path']}")
        fingerprints[descriptor["path"]] = actual

    for fixture in manifest["representation_fixtures"]:
        encoded = bytes.fromhex(fixture["encoded_hex"])
        if str(len(encoded)) != fixture["encoded_length"]:
            raise VerificationError("representation length mismatch")
        if hashlib.sha256(encoded).hexdigest() != fixture["content_digest_sha256"]:
            raise VerificationError("content digest mismatch")
        if representation_id(fixture) != fixture["representation_id"]:
            raise VerificationError("representation ID mismatch")
        if fixture["decoded_value_hex"] != fixture["encoded_hex"]:
            raise VerificationError("opaque exact reconstruction mismatch")

    valid = next(vector for vector in manifest["vectors"] if vector["kind"] == "valid")
    encoded = bytes.fromhex(valid["expected_encoded_hex"])
    if len(encoded) != valid["expected_encoded_length"]:
        raise VerificationError("operation vector length mismatch")
    decoded = decode_representation_request(encoded)
    if decoded != valid["decoded_value"]:
        raise VerificationError("independent operation decode mismatch")

    invalid = next(vector for vector in manifest["vectors"] if vector["kind"] == "invalid")
    try:
        decode_representation_request(bytes.fromhex(invalid["input_hex"]))
    except VerificationError:
        pass
    else:
        raise VerificationError("malformed operation unexpectedly accepted")

    jcs_vectors = json.loads(
        (ROOT / "schemas" / "v0.1" / "jcs-canonicalization-vectors.json").read_text(
            encoding="utf-8"
        )
    )
    for vector in jcs_vectors["valid"]:
        if rfc8785.dumps(vector["value"]).decode("utf-8") != vector["canonical"]:
            raise VerificationError(f"JCS valid vector mismatch: {vector['name']}")
    for vector in jcs_vectors["invalid"]:
        try:
            rfc8785.dumps(strict_json(vector["json"]))
        except (VerificationError, UnicodeEncodeError, rfc8785.CanonicalizationError):
            pass
        else:
            raise VerificationError(f"JCS invalid vector accepted: {vector['name']}")

    return {
        "status": "pass",
        "verifier": "python-independent-v0.1",
        "rfc8785_version": "0.1.4",
        "specification_commit": manifest["specification_commit"],
        "bundle_digest": bundle_digest,
        "schema_fingerprints": fingerprints,
        "valid_vectors": 1,
        "invalid_vectors": 1,
        "mandatory_catalog_entries": len(catalog["entries"]),
        "mandatory_catalog_status": catalog["implementation_status"],
        "proposed_specification_questions": len(question_ids),
        "jcs_valid_vectors": len(jcs_vectors["valid"]),
        "jcs_invalid_vectors": len(jcs_vectors["invalid"]),
    }


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2, sort_keys=True))
