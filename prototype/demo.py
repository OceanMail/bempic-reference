"""Run the two-node interrupted-transfer proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path

from .bempic_proof import (
    Message,
    PreparedRepresentation,
    TransferRun,
    prepare_attachment,
    prepare_message,
    run_until_complete,
)

DEFAULT_WINDOWS = (128, 71, 83, 67, 96)


def _message() -> tuple[Message, bytes, PreparedRepresentation]:
    identity = hashlib.sha256(b"bempic-proof-message-1").digest()[:16]
    attachment_content = b"UTC,wind_knots\n" + b"2026-08-30T20:00Z,12\n" * 48
    descriptor, attachment = prepare_attachment(
        "route-weather.csv", "text/csv", attachment_content
    )
    message = Message(
        logical_id=identity,
        created_at=1_788_112_800,
        sender="shore@example.test",
        recipients=("sea-witch@example.test",),
        subject="BEMPIC interrupted-link proof",
        body=(
            "This tiny message crosses several constrained contact windows. "
            "The receiver is reopened from disk between contacts and requests "
            "only the unreceived suffix of the immutable representation."
        ),
        attachments=(descriptor,),
    )
    return message, attachment_content, attachment


def _run_report(run: TransferRun) -> dict[str, object]:
    accounting = run.accounting
    return {
        "contacts": run.contacts,
        "simulated_restarts": run.simulated_restarts,
        "bempic_sender_to_receiver_bytes": accounting.sender_to_receiver_bytes,
        "bempic_receiver_to_sender_bytes": accounting.receiver_to_sender_bytes,
        "bempic_total_bytes": accounting.total_bempic_bytes,
        "predicted_bempic_bytes": run.predicted_bempic_bytes,
        "prediction_error_bytes": run.prediction_error_bytes,
        "representation_payload_bytes": accounting.representation_payload_bytes,
        "duplicate_payload_bytes": accounting.duplicate_payload_bytes,
        "useful_committed_bytes": accounting.useful_committed_bytes,
        "integrity_failures": accounting.integrity_failures,
        "operation_bytes": dict(sorted(accounting.operation_bytes.items())),
        "contact_reports": [
            {
                "contact": number,
                "budget": report.budget_bytes,
                "spent": report.spent_bytes,
                "progress_before": report.progress_before,
                "progress_after": report.progress_after,
                "complete": report.complete,
                "result_sent": report.result_sent,
            }
            for number, report in enumerate(run.reports, start=1)
        ],
    }


def run_demo(root: Path, windows: tuple[int, ...] = DEFAULT_WINDOWS) -> dict[str, object]:
    message, attachment_content, attachment = _message()
    manifest = prepare_message(message)
    manifest_run = run_until_complete(
        root,
        manifest,
        windows,
        max_record_size=96,
    )
    attachment_part = root / f"{attachment.representation_id.hex()}.part"
    attachment_complete = root / f"{attachment.representation_id.hex()}.complete"
    deferred_content_files = int(attachment_part.exists()) + int(attachment_complete.exists())

    attachment_run = run_until_complete(
        root,
        attachment,
        (256, 384, 512),
        max_record_size=256,
    )
    return {
        "status": (
            "complete"
            if manifest_run.value == message and attachment_run.value == attachment_content
            else "decode-mismatch"
        ),
        "manifest_representation_bytes": manifest.size,
        "attachment_representation_bytes": attachment.size,
        "deferred_attachment_content_files_before_selection": deferred_content_files,
        "deferred_attachment_payload_bytes_before_selection": 0,
        "manifest_transfer": _run_report(manifest_run),
        "selected_attachment_transfer": _run_report(attachment_run),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--state-dir",
        type=Path,
        help="retain proof state in this directory instead of a temporary directory",
    )
    args = parser.parse_args()

    if args.state_dir is not None:
        result = run_demo(args.state_dir)
    else:
        with tempfile.TemporaryDirectory(prefix="bempic-proof-") as temporary:
            result = run_demo(Path(temporary))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

