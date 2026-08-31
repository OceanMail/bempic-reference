"""Run deterministic byte measurements for the executable BEMPIC proof."""

from __future__ import annotations

import gzip
import json
import platform
import tempfile
import zlib
from pathlib import Path

from .bempic_proof import (
    Accounting,
    PreparedRepresentation,
    compare_collections,
    missing_representations,
    offer_page,
    prepare_message,
)
from .bempic_proof.runner import TransferRun, run_until_complete
from .fixtures import build_fixtures

BENCHMARK_CONTACT = (65_535,)
BENCHMARK_RECORD_SIZE = 4_096


def _raw_deflate(data: bytes) -> bytes:
    compressor = zlib.compressobj(level=9, wbits=-15)
    return compressor.compress(data) + compressor.flush()


def _compression_sizes(representations: tuple[PreparedRepresentation, ...]) -> dict[str, int]:
    return {
        "uncompressed": sum(item.size for item in representations),
        "deflate_raw": sum(len(_raw_deflate(item.encoded)) for item in representations),
        "zlib": sum(len(zlib.compress(item.encoded, level=9)) for item in representations),
        "gzip": sum(
            len(gzip.compress(item.encoded, compresslevel=9, mtime=0))
            for item in representations
        ),
    }


def _run(root: Path, representation: PreparedRepresentation) -> TransferRun:
    return run_until_complete(
        root,
        representation,
        BENCHMARK_CONTACT,
        max_record_size=BENCHMARK_RECORD_SIZE,
        max_contacts=1_000,
    )


def _merge_runs(runs: tuple[TransferRun, ...]) -> Accounting:
    total = Accounting()
    for run in runs:
        total.merge(run.accounting)
    return total


def build_report() -> dict[str, object]:
    results = []
    compression_totals = {
        "uncompressed": 0,
        "deflate_raw": 0,
        "zlib": 0,
        "gzip": 0,
    }
    total_mime = 0
    total_full_exchange = 0
    collection = []

    with tempfile.TemporaryDirectory(prefix="bempic-benchmark-") as temporary:
        root = Path(temporary)
        for fixture in build_fixtures():
            manifest = prepare_message(fixture.message)
            fixture_root = root / fixture.name
            manifest_run = _run(fixture_root, manifest)
            if manifest_run.value != fixture.message:
                raise AssertionError(f"{fixture.name}: manifest did not round trip")

            attachment_runs = tuple(
                _run(fixture_root, attachment) for attachment in fixture.attachments
            )
            for run, attachment in zip(
                attachment_runs, fixture.attachments, strict=True
            ):
                if run.value != attachment.encoded:
                    raise AssertionError(f"{fixture.name}: attachment did not round trip")

            all_representations = (manifest,) + fixture.attachments
            collection.extend(all_representations)
            full_accounting = _merge_runs((manifest_run,) + attachment_runs)
            sizes = _compression_sizes(all_representations)
            for name, size in sizes.items():
                compression_totals[name] += size

            attachment_bytes = sum(item.size for item in fixture.attachments)
            selected_attachment_payload = sum(
                run.accounting.representation_payload_bytes
                for run in attachment_runs
            )
            total_mime += len(fixture.rfc5322_mime)
            total_full_exchange += full_accounting.total_bempic_bytes
            results.append(
                {
                    "name": fixture.name,
                    "rfc5322_mime_bytes": len(fixture.rfc5322_mime),
                    "manifest_representation_bytes": manifest.size,
                    "attachment_representation_bytes": attachment_bytes,
                    "all_representation_bytes": sum(
                        item.size for item in all_representations
                    ),
                    "metadata_only_exchange_bytes": (
                        manifest_run.accounting.total_bempic_bytes
                    ),
                    "metadata_attachment_payload_bytes": 0,
                    "full_exchange_bytes": full_accounting.total_bempic_bytes,
                    "full_exchange_predicted_bytes": sum(
                        run.predicted_bempic_bytes
                        for run in (manifest_run,) + attachment_runs
                    ),
                    "full_exchange_prediction_error_bytes": sum(
                        run.prediction_error_bytes
                        for run in (manifest_run,) + attachment_runs
                    ),
                    "full_exchange_contacts": sum(
                        run.contacts for run in (manifest_run,) + attachment_runs
                    ),
                    "full_exchange_duplicate_payload_bytes": (
                        full_accounting.duplicate_payload_bytes
                    ),
                    "selected_attachment_payload_bytes": (
                        selected_attachment_payload
                    ),
                    "compression_candidate_bytes": sizes,
                }
            )

    warm_no_change = compare_collections(
        collection, collection, cached_capabilities=True
    )
    cold_no_change = compare_collections(
        collection, collection, cached_capabilities=False
    )
    mismatch = compare_collections(
        collection[:-1], collection, cached_capabilities=True
    )
    missing = missing_representations(collection, collection[:-1])
    discovery_page = offer_page(missing, budget_bytes=62)

    return {
        "schema": "bempic-proof-benchmark-0",
        "python": platform.python_version(),
        "fixture_count": len(results),
        "b2f_baseline": "not yet integrated",
        "notes": [
            "All formats and byte assignments are experimental.",
            (
                "Compression sizes include each representation independently "
                "but not protocol negotiation."
            ),
            (
                "Full exchange counts CAPABILITIES, SUMMARY, OFFER, REQUEST, "
                "DATA, and RESULT records."
            ),
            (
                "Each representation currently pays a separate cold exchange; "
                "cross-representation capability reuse is not implemented."
            ),
            "Attachment metadata exchange sends zero attachment content bytes before selection.",
            "Discovery pagination uses local harness state, not a wire cursor.",
        ],
        "totals": {
            "rfc5322_mime_bytes": total_mime,
            "full_exchange_bytes": total_full_exchange,
            "full_exchange_predicted_bytes": sum(
                result["full_exchange_predicted_bytes"] for result in results
            ),
            "full_exchange_prediction_error_bytes": sum(
                result["full_exchange_prediction_error_bytes"]
                for result in results
            ),
            "compression_candidate_bytes": compression_totals,
        },
        "collection_summary": {
            "warm_no_change_bytes": warm_no_change.accounting.total_bempic_bytes,
            "warm_no_change_equal": warm_no_change.equal,
            "cold_no_change_bytes": cold_no_change.accounting.total_bempic_bytes,
            "cold_no_change_equal": cold_no_change.equal,
            "warm_changed_bytes": mismatch.accounting.total_bempic_bytes,
            "warm_changed_equal": mismatch.equal,
        },
        "incremental_discovery": {
            "known_representation_count": len(collection) - 1,
            "available_representation_count": len(collection),
            "summary_bytes": mismatch.accounting.total_bempic_bytes,
            "offer_bytes": discovery_page.accounting.total_bempic_bytes,
            "total_bytes": (
                mismatch.accounting.total_bempic_bytes
                + discovery_page.accounting.total_bempic_bytes
            ),
            "offered_representation_count": len(discovery_page.offered),
            "complete": discovery_page.complete,
        },
        "fixtures": results,
    }


def main() -> None:
    print(json.dumps(build_report(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

