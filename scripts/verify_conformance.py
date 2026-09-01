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
    ROOT / "benchmarks" / "results" / "compact-codec-evidence-2026-09-01.json"
)
COMPACT_VECTOR_PATH = ROOT / "test-vectors" / "v0.1-compact-candidate" / "vectors.json"
COMPACT_CODEC_ID = 0xFFFF0001
COMPACT_CODEC_REVISION = 2
COMPACT_MAX_RECORD = 1_048_576
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
    if artifact["specification_commit"] != "40da35bd150290d039a185fb95388422ede5f1d1":
        raise VerificationError("compact evidence targets the wrong specification")
    if artifact["codec"] != {
        "canonical_parameters_hex": "",
        "id": COMPACT_CODEC_ID,
        "profile": "docs/EXPERIMENTAL-COMPACT-CODEC-v0.1.md",
        "profile_sha256": "0633ed81272a89d085ceb8ae01aef82ac1749a9babe2fac9b59d0d1f3529fce8",
        "registry_allocation": None,
        "revision": COMPACT_CODEC_REVISION,
        "status": "implementation-local-private-use-nonconformant",
    }:
        raise VerificationError("compact private-use status mismatch")
    artifact_digest = hashlib.sha256(COMPACT_ARTIFACT_PATH.read_bytes()).hexdigest()
    if vector_pack["evidence_artifact"] != {
        "path": "benchmarks/results/compact-codec-evidence-2026-09-01.json",
        "sha256": artifact_digest,
    }:
        raise VerificationError("compact vector artifact binding mismatch")
    profile_path = ROOT / artifact["codec"]["profile"]
    if hashlib.sha256(profile_path.read_bytes()).hexdigest() != artifact["codec"][
        "profile_sha256"
    ]:
        raise VerificationError("compact profile digest mismatch")
    if vector_pack["codec"] != artifact["codec"]:
        raise VerificationError("compact vector profile mismatch")
    if vector_pack["vectors"] != artifact["boundary_vectors"]:
        raise VerificationError("compact vector/artifact cases differ")
    if vector_pack["maximum_witnesses"] != artifact["maximum_witnesses"]:
        raise VerificationError("compact vector/artifact witnesses differ")

    expected_summary = prescribed_v01_summary()
    fixture = artifact["prescribed_v01_fixture"]
    for name, expected in expected_summary.items():
        if fixture[name] != expected:
            raise VerificationError(f"prescribed V01 fixture mismatch: {name}")
    if fixture["messages"] != 100 or fixture["first_index"] != 0 or fixture["last_index"] != 99:
        raise VerificationError("prescribed V01 fixture range mismatch")

    before = artifact["before_b1"]
    after = artifact["after_compact_candidate"]
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

    legacy_maxima = {
        "CAPABILITIES": 34_362,
        "SUMMARY": 33_080,
        "OFFER": 186_789,
        "REQUEST": 39_186,
        "DATA": 1_048_576,
        "RECEIPT": 33_341,
        "FAILURE": 33_326,
    }
    if {entry["kind"] for entry in artifact["maximum_witnesses"]} != set(legacy_maxima):
        raise VerificationError("maximum witness operation inventory mismatch")
    for witness in artifact["maximum_witnesses"]:
        legacy_maximum = legacy_maxima[witness["kind"]]
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

    compact_result = verify_compact_artifact()

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
        "compact_candidate": compact_result,
    }


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2, sort_keys=True))
