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
COMPACT_ARTIFACT_PATH = (
    ROOT / "benchmarks" / "results" / "compact-codec-public-evidence-2026-09-02.json"
)
COMPACT_VECTOR_PATH = (
    ROOT / "test-vectors" / "v0.1-public-experimental-codec" / "vectors.json"
)
COMPACT_CODEC_ID = 0x00010000
COMPACT_CODEC_REVISION = 1
COMPACT_MAX_RECORD = 1_048_576
SPECIFICATION_COMMIT = "7d29453c87b6f08f1abf6214c4ca64dd82030e99"
COMPACT_PROFILE_SHA256 = (
    "bc82364f7ac2f563bbdc0ea15f3d9b1f9127d6ac88376bf19a6dc642dc731127"
)
COMPACT_SCHEMA_FINGERPRINT = (
    "d8906a1cefbf89e4f29b4a0f636cfbfa1e9c6301e7e3a4fe213c090066f8e797"
)


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


def public_tuple_supported(vector: dict[str, Any]) -> bool:
    codec_id = vector["codec_id"]
    revision = vector["revision"]
    if codec_id in (0, 0xFFFFFFFF) or 0x80000000 <= codec_id <= 0xFFFFFFFE:
        return False
    return (
        codec_id == COMPACT_CODEC_ID
        and revision == COMPACT_CODEC_REVISION
        and vector["schema_fingerprint"] == COMPACT_SCHEMA_FINGERPRINT
        and vector["parameters_hex"] == ""
    )


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


def encode_uvarint(value: int) -> bytes:
    output = bytearray()
    while True:
        low = value & 0x7F
        value >>= 7
        if value == 0:
            output.append(low)
            return bytes(output)
        output.append(low | 0x80)


def maximum_public_capabilities_witness() -> bytes:
    """Independently construct the public-profile maximum CAPABILITIES record."""
    payload = bytearray([8])
    for major in range(8):
        payload.extend(struct.pack(">HH", major, 0xFFFF))
    payload.append(1)
    schema = bytes.fromhex(COMPACT_SCHEMA_FINGERPRINT)
    payload.extend(schema)
    payload.append(1)
    payload.extend(struct.pack(">II", COMPACT_CODEC_ID, COMPACT_CODEC_REVISION))
    payload.extend(schema)
    payload.extend(struct.pack(">I", COMPACT_MAX_RECORD))
    payload.extend(struct.pack(">Q", 1_073_741_824))
    payload.extend((0xFF, 0))  # all receipt levels; public security class
    payload.append(32)
    for extension_id in range(32):
        payload.extend(struct.pack(">I", extension_id))
        payload.append(int(extension_id % 2 == 0))
    payload.append(32)
    for extension_id in range(32):
        payload.extend(struct.pack(">I", extension_id))
        payload.extend((0,))
        payload.extend(struct.pack(">H", 1_024))
        payload.extend(b"\xa5" * 1_024)
    body = b"\x00" + payload
    return b"\xb1" + encode_uvarint(len(body)) + body


def decode_uvarint(value: bytes, position: int) -> tuple[int, int]:
    start = position
    result = 0
    for shift in range(0, 64, 7):
        if position >= len(value):
            raise VerificationError("truncated")
        byte = value[position]
        position += 1
        if shift == 63 and byte > 1:
            raise VerificationError("varint overflow")
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if value[start:position] != encode_uvarint(result):
                raise VerificationError("non-canonical varint")
            return result, position
    raise VerificationError("varint overflow")


def compact_summary_binding(summary: dict[str, Any]) -> bytes:
    return hashlib.sha256(
        b"".join(
            (
                b"BEMPIC-COMPACT-SUMMARY-CACHE-v0.1\0",
                bytes.fromhex(summary["collection_id"]),
                struct.pack(">Q", summary["generation"]),
                struct.pack(">Q", summary["item_count"]),
                bytes.fromhex(summary["collection_digest"]),
            )
        )
    ).digest()


def decode_compact(
    encoded: bytes, cached_summary: dict[str, Any] | None = None
) -> dict[str, Any]:
    if len(encoded) < 3:
        raise VerificationError("truncated")
    if len(encoded) > COMPACT_MAX_RECORD:
        raise VerificationError("compact operation size before body allocation")
    header = encoded[0]
    if header & 0xF8 != 0xB0 or not 1 <= header & 0x07 <= 7:
        raise VerificationError("candidate header")
    tag = header & 0x07
    body_length, position = decode_uvarint(encoded, 1)
    if body_length != len(encoded) - position:
        raise VerificationError("compact envelope length")
    form = encoded[position]
    position += 1
    if tag == 1 and form == 1 and position == len(encoded):
        return {
            "operation": "CAPABILITIES",
            "protocol": [0, 1],
            "schema_fingerprint": COMPACT_SCHEMA_FINGERPRINT,
            "codec_id": COMPACT_CODEC_ID,
            "codec_revision": COMPACT_CODEC_REVISION,
            "max_operation_octets": COMPACT_MAX_RECORD,
            "max_data_payload_octets": 1_000_000,
            "receipt_levels": 15,
            "security_class": "public",
            "extensions": [],
        }
    if tag == 2 and form == 2:
        if position + 32 > len(encoded):
            raise VerificationError("truncated")
        binding = encoded[position : position + 32]
        position += 32
        if position != len(encoded):
            raise VerificationError("trailing bytes")
        if cached_summary is None:
            raise VerificationError("cached summary context")
        if binding != compact_summary_binding(cached_summary):
            raise VerificationError("cached summary binding")
        return {"operation": "SUMMARY", **cached_summary}
    if tag == 2 and form == 1:
        if position + 32 > len(encoded):
            raise VerificationError("truncated")
        collection_id = encoded[position : position + 32].hex()
        position += 32
        generation, position = decode_uvarint(encoded, position)
        item_count, position = decode_uvarint(encoded, position)
        if position + 32 != len(encoded):
            raise VerificationError("trailing or truncated summary")
        collection_digest = encoded[position : position + 32].hex()
        result = {
            "collection_id": collection_id,
            "generation": generation,
            "item_count": item_count,
            "collection_digest": collection_digest,
        }
        if cached_summary == result:
            raise VerificationError("non-canonical full cached summary")
        return {"operation": "SUMMARY", **result}
    raise VerificationError("non-canonical compact form")


def prescribed_v01_summary() -> dict[str, Any]:
    collection_id = hashlib.sha256(b"BEMPIC-V01-COLLECTION\0").digest()
    keys = []
    for index in range(100):
        object_id = hashlib.sha256(
            b"BEMPIC-V01-OBJECT\0" + struct.pack(">I", index)
        ).digest()
        encoded_body = f"message-{index:03}\n".encode("utf-8")
        content_digest = hashlib.sha256(encoded_body).digest()
        representation_material = b"".join(
            (
                b"BEMPIC-REPRESENTATION-ID-v0.1\0",
                bytes.fromhex(COMPACT_SCHEMA_FINGERPRINT),
                struct.pack(">I", COMPACT_CODEC_ID),
                struct.pack(">I", COMPACT_CODEC_REVISION),
                struct.pack(">I", 0),
                struct.pack(">Q", len(encoded_body)),
                content_digest,
            )
        )
        representation_id_value = hashlib.sha256(representation_material).digest()
        keys.append(object_id + struct.pack(">I", 0) + representation_id_value)
    digest_material = b"".join(
        (
            b"BEMPIC-COLLECTION-v0.1\0",
            collection_id,
            struct.pack(">Q", 100),
            struct.pack(">Q", 100),
            *keys,
        )
    )
    return {
        "collection_id": collection_id.hex(),
        "generation": 100,
        "item_count": 100,
        "collection_digest": hashlib.sha256(digest_material).hexdigest(),
    }


def verify_segments(segments: list[dict[str, Any]], total: int) -> None:
    position = 0
    for segment in segments:
        start_text, end_text = segment["range"].split("..", 1)
        start = int(start_text)
        end = int(end_text)
        if start != position or end - start != segment["octets"]:
            raise VerificationError("non-contiguous byte-breakdown segment")
        position = end
    if position != total:
        raise VerificationError("byte-breakdown does not cover complete record")


def verify_compact_artifact() -> dict[str, Any]:
    artifact = strict_json(COMPACT_ARTIFACT_PATH.read_text(encoding="utf-8"))
    vector_pack = strict_json(COMPACT_VECTOR_PATH.read_text(encoding="utf-8"))
    if artifact["specification_commit"] != SPECIFICATION_COMMIT:
        raise VerificationError("compact evidence targets the wrong specification")
    if artifact["codec"] != {
        "approved": False,
        "canonical_parameters_hex": "",
        "id": COMPACT_CODEC_ID,
        "mandatory": False,
        "normative_profile_sha256": COMPACT_PROFILE_SHA256,
        "profile": "docs/EXPERIMENTAL-COMPACT-CODEC-v0.1.md",
        "production_security_promise": False,
        "registry_allocation": "experimental",
        "revision": COMPACT_CODEC_REVISION,
        "stable_wire_promise": False,
        "status": "public-experimental-not-approved-not-mandatory",
    }:
        raise VerificationError("public experimental codec status mismatch")
    artifact_digest = hashlib.sha256(COMPACT_ARTIFACT_PATH.read_bytes()).hexdigest()
    if vector_pack["evidence_artifact"] != {
        "path": "benchmarks/results/compact-codec-public-evidence-2026-09-02.json",
        "sha256": artifact_digest,
    }:
        raise VerificationError("compact vector artifact binding mismatch")
    if artifact["codec"]["normative_profile_sha256"] != COMPACT_PROFILE_SHA256:
        raise VerificationError("normative compact profile digest mismatch")
    if vector_pack["codec"] != artifact["codec"]:
        raise VerificationError("compact vector profile mismatch")
    if vector_pack["vectors"] != artifact["boundary_vectors"]:
        raise VerificationError("compact vector/artifact cases differ")
    if vector_pack["tuple_validation_vectors"] != artifact["tuple_validation_vectors"]:
        raise VerificationError("public tuple vector/artifact cases differ")
    if vector_pack["maximum_witnesses"] != artifact["maximum_witnesses"]:
        raise VerificationError("compact vector/artifact witnesses differ")

    expected_summary = prescribed_v01_summary()
    fixture = artifact["prescribed_v01_fixture"]
    for name, expected in expected_summary.items():
        if fixture[name] != expected:
            raise VerificationError(f"prescribed V01 fixture mismatch: {name}")
    if fixture["messages"] != 100 or fixture["first_index"] != 0 or fixture["last_index"] != 99:
        raise VerificationError("prescribed V01 fixture range mismatch")
    if fixture["collection_entry_semantics"] != (
        "opaque-body-surrogate-not-canonical-manifest-representation"
    ) or fixture["mandatory_vector_status"] != (
        "blocked-no-normative-manifest-instance-encoding"
    ):
        raise VerificationError("prescribed V01 evidence scope overclaims manifest bytes")

    before = artifact["before_b1"]
    after = artifact["after_public_experimental_codec"]
    legacy_capabilities = bytes.fromhex(before["capabilities_hex"])
    legacy_summary = bytes.fromhex(before["summary_hex"])
    if len(legacy_capabilities) != before["capability_operation_octets"] or len(
        legacy_capabilities
    ) != 102:
        raise VerificationError("legacy capability measurement mismatch")
    if len(legacy_summary) != before["warm_no_change_octets"] or len(legacy_summary) != 88:
        raise VerificationError("legacy summary measurement mismatch")
    if before["cold_no_change_octets"] != 2 * len(legacy_capabilities) + len(legacy_summary):
        raise VerificationError("legacy cold measurement identity mismatch")

    capabilities = bytes.fromhex(after["capabilities_hex"])
    cold_summary = bytes.fromhex(after["cold_summary_hex"])
    warm_summary = bytes.fromhex(after["warm_summary_hex"])
    if decode_compact(capabilities)["schema_fingerprint"] != COMPACT_SCHEMA_FINGERPRINT:
        raise VerificationError("static capability did not restore the full fingerprint")
    if decode_compact(cold_summary) != {"operation": "SUMMARY", **expected_summary}:
        raise VerificationError("cold summary decode mismatch")
    if decode_compact(warm_summary, expected_summary) != {
        "operation": "SUMMARY",
        **expected_summary,
    }:
        raise VerificationError("warm summary decode mismatch")
    if after["warm_no_change_octets"] != len(warm_summary) or not after["warm_gate_pass"]:
        raise VerificationError("warm compactness gate mismatch")
    if after["cold_no_change_octets"] != 2 * len(capabilities) + len(cold_summary):
        raise VerificationError("cold compactness identity mismatch")
    if not after["cold_gate_pass"]:
        raise VerificationError("cold compactness gate mismatch")

    verify_segments(before["capabilities_segments"], len(legacy_capabilities))
    verify_segments(before["summary_segments"], len(legacy_summary))
    verify_segments(after["capabilities_segments"], len(capabilities))
    verify_segments(after["warm_summary_segments"], len(warm_summary))
    verify_segments(after["cold_summary_segments"], len(cold_summary))

    profile_legacy_maxima = {
        "CAPABILITIES": 33_282,
        "SUMMARY": 33_080,
        "OFFER": 55_717,
        "REQUEST": 39_186,
        "DATA": 1_048_576,
        "RECEIPT": 33_341,
        "FAILURE": 33_326,
    }
    if {entry["kind"] for entry in artifact["maximum_witnesses"]} != set(
        profile_legacy_maxima
    ):
        raise VerificationError("maximum witness operation inventory mismatch")
    for witness in artifact["maximum_witnesses"]:
        legacy_maximum = profile_legacy_maxima[witness["kind"]]
        body = 1 + legacy_maximum - 7
        expected_maximum = 1 + len(encode_uvarint(body)) + body
        if witness["legacy_encoded_length"] != legacy_maximum:
            raise VerificationError("legacy maximum witness mismatch")
        if witness["encoded_length"] != expected_maximum:
            raise VerificationError("compact maximum formula mismatch")
        if witness["analysis"]["maximum_encoded_octets"] != expected_maximum:
            raise VerificationError("compact maximum analysis mismatch")
        if len(witness["sha256"]) != 64:
            raise VerificationError("maximum witness digest width mismatch")
        if witness["kind"] == "CAPABILITIES":
            independently_encoded = maximum_public_capabilities_witness()
            if len(independently_encoded) != witness["encoded_length"]:
                raise VerificationError("public CAPABILITIES witness length mismatch")
            if hashlib.sha256(independently_encoded).hexdigest() != witness["sha256"]:
                raise VerificationError(
                    "public CAPABILITIES witness content/security mismatch"
                )

    valid_vectors = 0
    invalid_vectors = 0
    for vector in artifact["boundary_vectors"]:
        kind = vector["kind"]
        if kind.startswith("valid"):
            valid_vectors += 1
            encoded = bytes.fromhex(vector["encoded_hex"])
            cached = expected_summary if vector.get("requires_exact_cached_summary") else None
            decode_compact(encoded, cached)
            if len(encoded) != vector["encoded_length"]:
                raise VerificationError("compact valid vector length mismatch")
            continue
        invalid_vectors += 1
        if kind == "invalid-one-past":
            if vector["symbolic_octets"] != COMPACT_MAX_RECORD + 1:
                raise VerificationError("one-past vector mismatch")
            continue
        cached = (
            expected_summary
            if vector.get("requires_exact_cached_summary")
            or vector["name"] == "full-summary-when-cache-matches"
            else None
        )
        try:
            decode_compact(bytes.fromhex(vector["input_hex"]), cached)
        except VerificationError as error:
            if str(error) != vector["expected_error"]:
                raise VerificationError(
                    f"compact invalid vector error mismatch: {vector['name']}"
                ) from error
        else:
            raise VerificationError(f"compact invalid vector accepted: {vector['name']}")

    tuple_vectors = artifact["tuple_validation_vectors"]
    if len(tuple_vectors) != 9:
        raise VerificationError("public tuple vector inventory mismatch")
    for vector in tuple_vectors:
        accepted = public_tuple_supported(vector)
        if accepted != (vector["expected"] == "accept"):
            raise VerificationError(f"public tuple decision mismatch: {vector['name']}")
    if artifact["manifest_codec"] != {
        "pretty_json_fixture_is_conforming_codec_bytes": False,
        "public_revision_1_supports_schema": False,
        "schema_fingerprint": "0ac001efba42837aade054401d9d307d16ad4715feac288fcb3d1711e4b961da",
        "status": "blocked-no-normative-instance-encoding",
    }:
        raise VerificationError("manifest codec blocker mismatch")

    if artifact["numeric_precision_vectors"]["status"] != "not-applicable":
        raise VerificationError("numeric precision applicability mismatch")
    return {
        "artifact_sha256": artifact_digest,
        "vector_pack_sha256": hashlib.sha256(COMPACT_VECTOR_PATH.read_bytes()).hexdigest(),
        "warm_no_change_octets": after["warm_no_change_octets"],
        "cold_no_change_octets": after["cold_no_change_octets"],
        "valid_vectors": valid_vectors,
        "invalid_vectors": invalid_vectors,
        "maximum_witnesses": len(artifact["maximum_witnesses"]),
        "tuple_validation_vectors": len(tuple_vectors),
    }


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


def representation_id_from_bytes(
    schema_fingerprint_hex: str,
    codec_id: int,
    codec_revision: int,
    encoded: bytes,
) -> str:
    digest = hashlib.sha256(encoded).digest()
    material = b"".join(
        (
            b"BEMPIC-REPRESENTATION-ID-v0.1\0",
            bytes.fromhex(schema_fingerprint_hex),
            struct.pack(">I", codec_id),
            struct.pack(">I", codec_revision),
            struct.pack(">I", 0),
            struct.pack(">Q", len(encoded)),
            digest,
        )
    )
    return hashlib.sha256(material).hexdigest()


def manifest_semantic_octets(fixture: dict[str, Any]) -> int:
    total = 32 + 8
    total += len(fixture["sender"].encode("utf-8"))
    total += sum(len(value.encode("utf-8")) for value in fixture["recipients"])
    if fixture["subject"] is not None:
        total += len(fixture["subject"].encode("utf-8"))
    for part in fixture["parts"]:
        total += 4 + 1 + len(part["media_type"].encode("ascii"))
        if part["filename"] is not None:
            total += len(part["filename"].encode("utf-8"))
    return total


def update_length_prefixed(hasher: Any, value: bytes) -> None:
    hasher.update(struct.pack(">Q", len(value)))
    hasher.update(value)


def oceanmail_semantics_digest(fixture: dict[str, Any]) -> str:
    hasher = hashlib.sha256()
    hasher.update(b"OCEANMAIL-IMMUTABLE-SEMANTICS-v1\0")
    hasher.update(struct.pack(">Q", int(fixture["created_at"])))
    update_length_prefixed(hasher, fixture["sender_nfc"].encode("utf-8"))
    recipients = fixture["recipients_nfc"]
    hasher.update(struct.pack(">I", len(recipients)))
    for recipient in recipients:
        update_length_prefixed(hasher, recipient.encode("utf-8"))
    subject = fixture["subject_nfc"]
    hasher.update(b"\x01" if subject is not None else b"\x00")
    if subject is not None:
        update_length_prefixed(hasher, subject.encode("utf-8"))
    hasher.update(struct.pack(">I", fixture["part_id"]))
    update_length_prefixed(hasher, fixture["media_type"].encode("ascii"))
    update_length_prefixed(hasher, fixture["body_nfc"].encode("utf-8"))
    return hasher.hexdigest()


def verify_failure_record(encoded_hex: str, code: int, retryable: bool) -> None:
    encoded = bytes.fromhex(encoded_hex)
    if encoded[:3] != b"B1\x07" or len(encoded) < 7:
        raise VerificationError("invalid FAILURE envelope")
    if struct.unpack(">I", encoded[3:7])[0] != len(encoded) - 7:
        raise VerificationError("false FAILURE envelope length")
    payload = encoded[7:]
    if payload != bytes((code, 1, 0x53, int(retryable), 0, 0)):
        raise VerificationError("FAILURE payload mismatch")


def verify_tranche3(
    manifest: dict[str, Any], catalog: dict[str, Any]
) -> dict[str, Any]:
    evidence = strict_json((BUNDLE_ROOT / "tranche3-evidence.json").read_text("utf-8"))
    oceanmail = strict_json(
        (BUNDLE_ROOT / "semantic-fixtures/oceanmail-immutable-object-v1.json").read_text(
            "utf-8"
        )
    )
    manifest_fixture = strict_json(
        (BUNDLE_ROOT / "semantic-fixtures/message-manifest-full-width.json").read_text(
            "utf-8"
        )
    )
    ack_fixture = strict_json(
        (BUNDLE_ROOT / "semantic-fixtures/ack-response.json").read_text("utf-8")
    )
    measurements = strict_json(
        (
            ROOT
            / "benchmarks/results/conformance-tranche-3-2026-09-01.json"
        ).read_text("utf-8")
    )

    expected_specification = SPECIFICATION_COMMIT
    if evidence["specification_commit"] != expected_specification:
        raise VerificationError("tranche-3 specification commit mismatch")
    if evidence["conformance_claim"] is not False:
        raise VerificationError("tranche-3 evidence makes a conformance claim")
    if evidence["codec"]["current_id"] != COMPACT_CODEC_ID:
        raise VerificationError("public codec ID mismatch")
    if evidence["codec"]["current_revision"] != COMPACT_CODEC_REVISION:
        raise VerificationError("public codec revision mismatch")
    if evidence["codec"]["registry_allocation"] != "experimental":
        raise VerificationError("public codec allocation status mismatch")
    if evidence["codec"]["status"] != "public-experimental-not-approved-not-mandatory":
        raise VerificationError("public codec status mismatch")
    if not evidence["codec"]["generator_accepts_exact_allocated_id_revision"]:
        raise VerificationError("allocated public codec generation failed")
    if evidence["codec"]["stable_wire_promise"] or evidence["codec"][
        "production_security_promise"
    ]:
        raise VerificationError("experimental codec makes a stability or security promise")

    if oceanmail["source_commit"] != "cc55c1b7d5a03aa2e5cc8cd617f9d1bb7b6a3600":
        raise VerificationError("OceanMail evidence commit mismatch")
    if oceanmail_semantics_digest(oceanmail) != oceanmail["immutable_semantics_digest"]:
        raise VerificationError("OceanMail immutable semantics digest mismatch")
    if oceanmail["object_id_in_digest"] or oceanmail["bempic_core_policy_imported"]:
        raise VerificationError("OceanMail policy leaked into BEMPIC evidence")
    immutable = evidence["immutable_object_semantics"]
    if not all(
        immutable[name]
        for name in (
            "first_observation",
            "duplicate_observation",
            "reopened_before_duplicate_and_conflict",
            "conflict_error",
            "original_binding_preserved",
            "unrelated_binding_preserved",
        )
    ):
        raise VerificationError("immutable object conflict evidence mismatch")

    manifest_semantic = manifest_semantic_octets(manifest_fixture)
    if int(manifest_fixture["semantic_octets"]) != manifest_semantic:
        raise VerificationError("manifest semantic octets mismatch")
    if manifest_fixture["representation_descriptor_contribution"] != "0":
        raise VerificationError("manifest descriptor contribution is nonzero")

    semantic = evidence["semantic_accounting"]
    if semantic["endpoint_a_binding"] != manifest["endpoint_a_binding"]:
        raise VerificationError("endpoint A binding mismatch")
    if semantic["endpoint_b_binding"] != manifest["endpoint_b_binding"]:
        raise VerificationError("endpoint B binding mismatch")
    expected_values: dict[str, tuple[bytes, int]] = {
        "manifest-accepted-selection-1": (
            (BUNDLE_ROOT / "semantic-fixtures/message-manifest-full-width.json").read_bytes(),
            manifest_semantic,
        ),
        "body-accepted-selection-2": (
            oceanmail["body_nfc"].encode("utf-8"),
            len(oceanmail["body_nfc"].encode("utf-8")),
        ),
        "response-accepted-selection-3": (
            bytes.fromhex(ack_fixture["decoded_value_hex"]),
            int(ack_fixture["semantic_octets"]),
        ),
    }
    file_entries = {entry["path"]: entry for entry in manifest["files"]}
    directional = {"send": 0, "receive": 0}
    counted: set[tuple[str, str]] = set()
    for fixture in semantic["semantic_fixtures"]:
        path_text = fixture["semantic_fixture_path"]
        path = Path(path_text)
        if path.is_absolute() or ".." in path.parts or path_text not in file_entries:
            raise VerificationError("semantic fixture path escapes bundle")
        raw = (BUNDLE_ROOT / path).read_bytes()
        if fixture["semantic_fixture_sha256"] != hashlib.sha256(raw).hexdigest():
            raise VerificationError("semantic fixture digest mismatch")
        if int(fixture["semantic_fixture_octets"]) != len(raw):
            raise VerificationError("semantic fixture file length mismatch")
        if fixture["representation_descriptor_contribution"] != "0":
            raise VerificationError("descriptor bytes contaminated semantics")
        encoded, expected_semantic = expected_values[fixture["selection_event"]]
        if int(fixture["semantic_octets"]) != expected_semantic:
            raise VerificationError("independent semantic value mismatch")
        if fixture["identity_derivation"] == "semantic-fixture-sha256-not-codec-representation":
            expected_id = hashlib.sha256(encoded).hexdigest()
        elif fixture["identity_derivation"] == "public-codec-representation-id":
            expected_id = representation_id_from_bytes(
                fixture["schema_fingerprint"],
                COMPACT_CODEC_ID,
                COMPACT_CODEC_REVISION,
                encoded,
            )
        else:
            raise VerificationError("unknown semantic fixture identity derivation")
        if fixture["representation_id"] != expected_id:
            raise VerificationError("semantic fixture representation ID mismatch")
        key = (fixture["direction"], fixture["representation_id"])
        if key not in counted:
            counted.add(key)
            directional[fixture["direction"]] += expected_semantic
    if semantic["duplicate_selection_counted"]:
        raise VerificationError("duplicate semantic selection was counted")
    if int(semantic["semantic_bytes_send"]) != directional["send"]:
        raise VerificationError("semantic send counter mismatch")
    if int(semantic["semantic_bytes_receive"]) != directional["receive"]:
        raise VerificationError("semantic receive counter mismatch")
    if int(semantic["semantic_bytes"]) != sum(directional.values()):
        raise VerificationError("semantic total identity mismatch")

    vectors = evidence["vectors"]
    if vectors["V01"]["equal-warm-100"] != {
        "bempic_total_bytes": "35",
        "maximum": "64",
        "pass": True,
    }:
        raise VerificationError("V01 warm measurement mismatch")
    if vectors["V01"]["equal-cold-100"] != {
        "bempic_total_bytes": "75",
        "maximum": "128",
        "pass": True,
    }:
        raise VerificationError("V01 cold measurement mismatch")
    if vectors["V02"]["new_manifest_count"] != 1 or vectors["V02"][
        "retransmitted_prior_manifest_bytes"
    ] != "0":
        raise VerificationError("V02 delta mismatch")
    if vectors["V03"]["page_sizes"] != [128, 128, 1] or not all(
        vectors["V03"][name]
        for name in ("reopen_after_page_1", "target_digest_consistent", "final_cursor_cleared")
    ):
        raise VerificationError("V03 paging evidence mismatch")

    v04 = vectors["V04"]["cases"]
    required_v04 = {
        "tiny",
        "typical",
        "international-nfc",
        "reply-chain",
        "absent-subject",
        "maximum-recipients",
        "maximum-parts",
        "maximum-representations-per-part",
        "every-maximum-metadata-length",
    }
    if {case["case"] for case in v04["valid"]} != required_v04:
        raise VerificationError("V04 valid inventory mismatch")
    if len(v04["invalid"]) < 12 or not all(
        case["rejected_before_mutation"] for case in v04["invalid"]
    ):
        raise VerificationError("V04 one-past rejection mismatch")
    if v04["one_past_manifest_decoded_octets"] != 65_537 or not any(
        case["case"] == "one-past-manifest-allocation"
        and case["error"] == "manifest_octets violates a v0.1 bound"
        for case in v04["invalid"]
    ):
        raise VerificationError("V04 aggregate manifest bound mismatch")
    if vectors["V05"]["unselected_representation_payload_bytes"] != "0":
        raise VerificationError("V05 unselected payload mismatch")

    compressible = bytes(4096)
    incompressible = bytes(range(256)) * 16
    for name, raw in (
        ("compressible-selected", compressible),
        ("incompressible-selected", incompressible),
    ):
        value = vectors["V06"][name]
        if value["content_digest"] != hashlib.sha256(raw).hexdigest():
            raise VerificationError(f"V06 digest mismatch: {name}")
        expected_id = representation_id_from_bytes(
            COMPACT_SCHEMA_FINGERPRINT,
            COMPACT_CODEC_ID,
            COMPACT_CODEC_REVISION,
            raw,
        )
        if value["representation_id"] != expected_id or not value["exact_reconstruction"]:
            raise VerificationError(f"V06 representation mismatch: {name}")
    if not vectors["V07"]["one-past-representation"]["rejected_before_allocation"]:
        raise VerificationError("V07 one-past allocation accepted")

    expected_rows = [
        ("V08-C01", "offset-0", "sender", "memory"),
        ("V08-C02", "offset-0", "receiver", "representation-file"),
        ("V08-C03", "offset-0", "both", "durable-store"),
        ("V08-C04", "offset-1-percent", "sender", "representation-file"),
        ("V08-C05", "offset-1-percent", "receiver", "durable-store"),
        ("V08-C06", "offset-1-percent", "both", "memory"),
        ("V08-C07", "offset-10-percent", "sender", "durable-store"),
        ("V08-C08", "offset-10-percent", "receiver", "memory"),
        ("V08-C09", "offset-10-percent", "both", "representation-file"),
        ("V08-C10", "offset-50-percent", "sender", "memory"),
        ("V08-C11", "offset-50-percent", "receiver", "representation-file"),
        ("V08-C12", "offset-50-percent", "both", "durable-store"),
        ("V08-C13", "offset-90-percent", "sender", "representation-file"),
        ("V08-C14", "offset-90-percent", "receiver", "durable-store"),
        ("V08-C15", "offset-90-percent", "both", "memory"),
        ("V08-C16", "final-byte", "sender", "durable-store"),
        ("V08-C17", "final-byte", "receiver", "memory"),
        ("V08-C18", "final-byte", "both", "representation-file"),
        ("V08-C19", "post-verify-pre-commit", "sender", "memory"),
        ("V08-C20", "post-verify-pre-commit", "receiver", "representation-file"),
        ("V08-C21", "post-verify-pre-commit", "both", "durable-store"),
        ("V08-C22", "post-commit-pre-receipt", "sender", "representation-file"),
        ("V08-C23", "post-commit-pre-receipt", "receiver", "durable-store"),
        ("V08-C24", "post-commit-pre-receipt", "both", "memory"),
    ]
    rows = vectors["V08"]["rows"]
    required_fields = {
        "row_id",
        "fixture_digest",
        "trace_digest",
        "encoded_length",
        "interruption_point",
        "computed_prefix",
        "restart_party",
        "storage_surface",
        "storage_backend",
        "durable_state_before",
        "recovered_state",
        "recovered_prefix",
        "first_resumed_offset",
        "new_payload_bytes",
        "duplicate_payload_bytes",
        "retransmitted_durable_prefix_bytes",
        "receipt_state_before",
        "receipt_state_after",
        "final_content_digest",
        "final_representation_id",
        "final_decode",
        "result",
    }
    fixture_raw = bytes(range(256)) * 3 + bytes(range(232))
    fixture_digest = hashlib.sha256(fixture_raw).hexdigest()
    for row, expected in zip(rows, expected_rows, strict=True):
        if (
            row["row_id"],
            row["interruption_point"],
            row["restart_party"],
            row["storage_surface"],
        ) != expected:
            raise VerificationError("V08 authoritative row mismatch")
        if not required_fields <= row.keys():
            raise VerificationError("V08 row evidence field missing")
        if row["fixture_digest"] != fixture_digest or row["encoded_length"] != "1000":
            raise VerificationError("V08 fixture mismatch")
        if row["recovered_prefix"] != row["first_resumed_offset"]:
            raise VerificationError("V08 resume offset mismatch")
        if row["duplicate_payload_bytes"] != "0" or row[
            "retransmitted_durable_prefix_bytes"
        ] != "0":
            raise VerificationError("V08 duplicate/retransmission mismatch")
        if row["receipt_state_before"] or not row["receipt_state_after"]:
            raise VerificationError("V08 receipt ordering mismatch")
        if not row["final_decode"] or row["final_state"] != "committed":
            raise VerificationError("V08 reconstruction mismatch")
        trace = {
            "row_id": row["row_id"],
            "point": row["interruption_point"],
            "restart": row["restart_party"],
            "storage": row["storage_surface"],
            "computed_prefix": row["computed_prefix"],
            "recovered_prefix": row["recovered_prefix"],
            "final_digest": row["fixture_digest"],
        }
        trace_bytes = json.dumps(
            trace, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        if row["trace_digest"] != hashlib.sha256(trace_bytes).hexdigest():
            raise VerificationError("V08 trace digest mismatch")
    if not vectors["V08"]["pair_coverage"]["complete"]:
        raise VerificationError("V08 pair coverage incomplete")

    expected_v11 = {
        "corrupt-final-byte": "INTEGRITY_FAILURE",
        "conflicting-overlap": "METADATA_CONFLICT",
        "gap": "RANGE_INVALID",
        "false-length-short": "RANGE_INVALID",
        "false-length-long": "PARTIAL-no-positive-receipt",
        "false-digest": "INTEGRITY_FAILURE",
        "false-representation-id": "INTEGRITY_FAILURE",
        "object-id-metadata-conflict": "METADATA_CONFLICT",
    }
    for case in vectors["V11"]["cases"]:
        if case["observed_outcome"] != expected_v11[case["case"]] or case[
            "result"
        ] != "pass":
            raise VerificationError("V11 outcome mismatch")
    if not vectors["V11"]["unrelated_exact_reconstruction"]:
        raise VerificationError("V11 unrelated state was damaged")

    v12_cases = vectors["V12"]["cases"]
    operation_names = {case["operation"] for case in v12_cases}
    if len(v12_cases) != 42 or operation_names != {
        "CAPABILITIES",
        "SUMMARY",
        "OFFER",
        "REQUEST",
        "DATA",
        "RECEIPT",
        "FAILURE",
    }:
        raise VerificationError("V12 operation/domain inventory mismatch")
    if any(case["result"] != "pass" or case["quote_error_bytes"] != "0" for case in v12_cases):
        raise VerificationError("V12 budget outcome mismatch")

    v13 = vectors["V13"]["cases"]
    if not all(
        v13["stale-cache-recovery"][name]
        for name in ("warm_hit", "stale_miss", "renegotiated", "fresh_hit")
    ):
        raise VerificationError("V13 stale-cache recovery mismatch")
    if not v13["unknown-optional-extension"]["skipped"] or not v13[
        "unknown-critical-extension"
    ]["rejected"]:
        raise VerificationError("V13 extension behavior mismatch")
    if v13["compatible-tuple"]["codec_id"] != COMPACT_CODEC_ID:
        raise VerificationError("V13 public tuple selection mismatch")
    rejection_cases = {
        "mismatched-schema",
        "unknown-codec",
        "private-use-codec",
        "revision-zero-downgrade",
        "unsupported-revision",
        "mixed-private-public-peer",
    }
    if any(
        v13[name]["failure"] != "UnsupportedCodec" or v13[name]["mutation"]
        for name in rejection_cases
    ):
        raise VerificationError("V13 public tuple rejection mismatch")
    if len(vectors["V14"]["cases"]) != 12:
        raise VerificationError("V14 before/after inventory mismatch")

    failure_names = [
        "UNSUPPORTED_VERSION",
        "UNSUPPORTED_SCHEMA",
        "UNSUPPORTED_CODEC",
        "UNSUPPORTED_CRITICAL_EXTENSION",
        "MALFORMED_OPERATION",
        "LIMIT_EXCEEDED",
        "UNKNOWN_OBJECT",
        "METADATA_CONFLICT",
        "RANGE_INVALID",
        "INTEGRITY_FAILURE",
        "STORAGE_FAILURE",
        "POLICY_REJECTED",
        "CHECKPOINT_UNKNOWN",
    ]
    v15 = vectors["V15"]["cases"]
    if len(v15) != 26:
        raise VerificationError("V15 case count mismatch")
    for case in v15:
        code = failure_names.index(case["code"])
        retryable = case["advertised_retryable"]
        verify_failure_record(case["encoded_hex"], code, retryable)
        expected_after = "committed" if retryable else "partial"
        if (
            case["automatic_retry_attempts"] != int(retryable)
            or not case["retry_condition_changed"]
            or case["first_retry_authorized"] != retryable
            or case["second_retry_authorized"]
            or not case["retry_state_reopened"]
            or not case["retry_bounded"]
            or case["affected_state_before"] != "partial"
            or case["affected_state_after"] != expected_after
        ):
            raise VerificationError("V15 bounded retry mismatch")
        unrelated_digest = hashlib.sha256(b"unrelated-committed-v15").hexdigest()
        if (
            case["unrelated_content_digest"] != unrelated_digest
            or case["unrelated_committed_state"] != "usable"
            or not case["scoped_mutation"]
            or case["result"] != "pass"
        ):
            raise VerificationError("V15 scoped state mismatch")
        state_trace = {
            "code": case["code"],
            "retryable": retryable,
            "affected_before": case["affected_state_before"],
            "affected_after": case["affected_state_after"],
            "condition_changed": case["retry_condition_changed"],
            "first_retry_authorized": case["first_retry_authorized"],
            "second_retry_authorized": case["second_retry_authorized"],
            "automatic_retry_attempts": case["automatic_retry_attempts"],
            "unrelated_digest": case["unrelated_content_digest"],
            "unrelated_usable": case["unrelated_committed_state"] == "usable",
        }
        state_trace_bytes = json.dumps(
            state_trace, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        if case["state_trace_digest"] != hashlib.sha256(state_trace_bytes).hexdigest():
            raise VerificationError("V15 state trace digest mismatch")

    metric_names = {
        "semantic_bytes",
        "semantic_bytes_send",
        "semantic_bytes_receive",
        "bempic_total_bytes",
        "bempic_operation_bytes_send",
        "bempic_operation_bytes_receive",
        "representation_payload_bytes",
        "useful_committed_bytes",
        "duplicate_bempic_bytes",
        "duplicate_representation_payload_bytes",
        "unselected_representation_payload_bytes",
        "retransmitted_durable_prefix_bytes",
        "retransmitted_prior_manifest_bytes",
        "resume_control_bytes",
        "bempic_bytes_to_first_body_payload_octet",
        "bempic_bytes_to_first_body_commit",
        "preflight_quoted_bempic_bytes",
        "quote_error_bytes",
    }
    scope = measurements["measurement_scope"]
    if not metric_names <= scope.keys():
        raise VerificationError("tranche-3 required metric missing")
    if int(scope["semantic_bytes"]) != int(scope["semantic_bytes_send"]) + int(
        scope["semantic_bytes_receive"]
    ):
        raise VerificationError("measurement semantic identity mismatch")
    if int(scope["bempic_total_bytes"]) != int(
        scope["bempic_operation_bytes_send"]
    ) + int(scope["bempic_operation_bytes_receive"]):
        raise VerificationError("measurement BEMPIC identity mismatch")
    compact_measurement = measurements["compact_no_change_100_messages"]
    if compact_measurement["warm_no_change_octets"] != 35 or compact_measurement[
        "cold_no_change_octets"
    ] != 75:
        raise VerificationError("measurement compact values mismatch")
    if measurements["v08_rows"] != 24 or measurements["v12_budget_cases"] != 42:
        raise VerificationError("measurement evidence counts mismatch")

    return {
        "semantic_bytes": int(semantic["semantic_bytes"]),
        "semantic_bytes_send": directional["send"],
        "semantic_bytes_receive": directional["receive"],
        "v08_rows": len(rows),
        "v12_cases": len(v12_cases),
        "v15_cases": len(v15),
        "required_metrics": len(metric_names),
        "catalog_counts": catalog["counts"],
    }


def verify() -> dict[str, Any]:
    manifest = strict_json(MANIFEST_PATH.read_text(encoding="utf-8"))
    if manifest["specification_commit"] != SPECIFICATION_COMMIT:
        raise VerificationError("bundle targets the wrong specification commit")
    if manifest["codec"]["id"] != COMPACT_CODEC_ID or manifest["codec"][
        "revision"
    ] != COMPACT_CODEC_REVISION:
        raise VerificationError("bundle public codec tuple mismatch")
    if manifest["codec"]["status"] != "public-experimental-not-approved-not-mandatory":
        raise VerificationError("bundle public codec status mismatch")
    if any(
        manifest["codec"][name]
        for name in (
            "approved",
            "mandatory",
            "stable_wire_promise",
            "production_security_promise",
        )
    ):
        raise VerificationError("bundle overclaims the experimental codec")
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
    observed_counts = {status: 0 for status in allowed_statuses}
    for entry in catalog["entries"]:
        if entry["status"] not in allowed_statuses:
            raise VerificationError(f"invalid catalog status: {entry['id']}")
        observed_counts[entry["status"]] += 1
        if entry["status"] == "blocked" and not entry.get("result"):
            raise VerificationError(f"catalog blocker lacks result: {entry['id']}")
    observed_counts["total"] = len(catalog["entries"])
    if observed_counts != catalog["counts"] or observed_counts != manifest["catalog_counts"]:
        raise VerificationError("catalog counts mismatch")
    if catalog["implementation_status"] != manifest["mandatory_catalog_status"]:
        raise VerificationError("catalog and manifest completion status differ")

    fingerprints: dict[str, str] = {}
    for descriptor in manifest["schema_descriptors"]:
        raw = (BUNDLE_ROOT / descriptor["path"]).read_bytes()
        canonical = rfc8785.dumps(strict_json(raw.decode("utf-8")))
        actual = schema_fingerprint(canonical)
        if actual != descriptor["fingerprint"]:
            raise VerificationError(f"schema fingerprint mismatch: {descriptor['path']}")
        fingerprints[descriptor["path"]] = actual

    tranche3_result = verify_tranche3(manifest, catalog)

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

    compact_result = verify_compact_artifact()
    fuzz_report = strict_json(
        (ROOT / "conformance" / "fuzz-report.json").read_text(encoding="utf-8")
    )
    if (
        fuzz_report["specification_commit"] != SPECIFICATION_COMMIT
        or fuzz_report["deterministic_seed"] != 4_775_307_987_118_129_153
        or fuzz_report["seed_corpus_sha256"]
        != "7e0e577ad3f43435963cce0e28da1761a207682b166efc4ed650510c7831656b"
        or fuzz_report["random_cases"] != 50_000
        or fuzz_report["exact_size_property_cases"] != 4_100
        or fuzz_report["compact_exact_size_property_cases"] != 4_100
        or fuzz_report["unresolved_findings"] != 0
        or "public experimental compact codec" not in fuzz_report["methodology"]
    ):
        raise VerificationError("malformed/property report mismatch")

    return {
        "status": "pass",
        "verifier": "python-independent-v0.1",
        "rfc8785_version": "0.1.4",
        "specification_commit": manifest["specification_commit"],
        "bundle_digest": bundle_digest,
        "schema_fingerprints": fingerprints,
        "mandatory_catalog_entries": len(catalog["entries"]),
        "mandatory_catalog_status": catalog["implementation_status"],
        "jcs_valid_vectors": len(jcs_vectors["valid"]),
        "jcs_invalid_vectors": len(jcs_vectors["invalid"]),
        "public_experimental_codec": compact_result,
        "malformed_property_cases": {
            "random": fuzz_report["random_cases"],
            "b1_structured": fuzz_report["structured_malformed_cases"],
            "public_compact_structured": fuzz_report["compact_structured_malformed_cases"],
            "exact_size_per_codec": fuzz_report["exact_size_property_cases"],
            "unresolved_findings": fuzz_report["unresolved_findings"],
        },
        "tranche3": tranche3_result,
    }


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2, sort_keys=True))
