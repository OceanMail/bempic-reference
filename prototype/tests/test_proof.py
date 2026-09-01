from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from prototype.bempic_proof import (
    Accounting,
    IntegrityError,
    Message,
    PreparedRepresentation,
    ProofExchange,
    ReceiverStore,
    RepresentationKind,
    StoreError,
    collection_digest,
    compare_collections,
    decode_message,
    encode_message,
    prepare_attachment,
    prepare_binary,
    prepare_message,
    missing_representations,
    offer_page,
)
from prototype.bempic_proof.codec import DecodeError
from prototype.bempic_proof.operations import (
    Capabilities,
    Data,
    Offer,
    OperationError,
    Request,
    Result,
    Summary,
    decode_operation,
    encode_operation,
)
from prototype.benchmark import build_report
from prototype.fixtures import build_fixtures


def fixture_message(body: str | None = None) -> Message:
    return Message(
        logical_id=hashlib.sha256(b"fixture-message").digest()[:16],
        created_at=1_788_112_800,
        sender="sender@example.test",
        recipients=("one@example.test", "two@example.test"),
        subject="Interrupted synchronization",
        body=body or ("useful text " * 40),
    )


class CodecTests(unittest.TestCase):
    def test_message_round_trip_is_deterministic(self) -> None:
        message = fixture_message()
        first = encode_message(message)
        second = encode_message(message)
        self.assertEqual(first, second)
        self.assertEqual(decode_message(first), message)
        self.assertEqual(prepare_message(message).size, len(first))

    def test_message_decoder_rejects_truncation_and_trailing_bytes(self) -> None:
        encoded = encode_message(fixture_message())
        with self.assertRaises(DecodeError):
            decode_message(encoded[:-1])
        with self.assertRaises(DecodeError):
            decode_message(encoded + b"x")

    def test_prepared_representation_rejects_false_integrity_metadata(self) -> None:
        encoded = b"integrity invariant"
        digest = hashlib.sha256(encoded).digest()
        with self.assertRaises(ValueError):
            PreparedRepresentation(
                representation_id=digest[:16],
                digest=b"\x00" * 32,
                encoded=encoded,
                kind=RepresentationKind.BINARY,
            )

    def test_all_proof_operations_round_trip(self) -> None:
        representation = prepare_message(fixture_message())
        operations = (
            Capabilities(0, 96, 0),
            Summary(1, representation.representation_id),
            Offer(
                representation.representation_id,
                int(representation.kind),
                representation.size,
                representation.digest,
            ),
            Request(representation.representation_id, 17, 31),
            Data(representation.representation_id, 17, b"payload"),
            Result(representation.representation_id, True, representation.digest),
        )
        for operation in operations:
            with self.subTest(operation=type(operation).__name__):
                self.assertEqual(decode_operation(encode_operation(operation)), operation)

    def test_unknown_operation_is_rejected(self) -> None:
        with self.assertRaises(OperationError):
            decode_operation(b"B0\xff\x00\x00")

    def test_attachment_part_id_must_be_unique_within_message(self) -> None:
        descriptor, _ = prepare_attachment("same.txt", "text/plain", b"same")
        message = fixture_message("duplicate part identity")
        with self.assertRaises(ValueError):
            Message(
                logical_id=message.logical_id,
                created_at=message.created_at,
                sender=message.sender,
                recipients=message.recipients,
                subject=message.subject,
                body=message.body,
                attachments=(descriptor, descriptor),
            )


class ExchangeTests(unittest.TestCase):
    def test_contact_quotes_are_exact_and_side_effect_free(self) -> None:
        representation = prepare_message(fixture_message("metering quote " * 12))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            windows = (0, 8, 17, 62, 96, 128, 77)
            for contact_number in range(1, 100):
                store = ReceiverStore(root, representation)
                exchange = ProofExchange(representation, store)
                state_before = {
                    path.name: path.read_bytes()
                    for path in root.iterdir()
                    if path.is_file()
                }
                budget = windows[(contact_number - 1) % len(windows)]
                quote = exchange.quote_contact(budget)
                state_after_quote = {
                    path.name: path.read_bytes()
                    for path in root.iterdir()
                    if path.is_file()
                }
                self.assertEqual(state_after_quote, state_before)

                report = exchange.run_contact(budget)
                self.assertEqual(quote.predicted_spent_bytes, report.spent_bytes)
                self.assertEqual(
                    quote.predicted_progress_after, report.progress_after
                )
                self.assertEqual(quote.predicted_complete, report.complete)
                self.assertEqual(quote.predicted_result_sent, report.result_sent)
                self.assertEqual(quote.accounting, report.accounting)
                if report.result_sent:
                    break
            else:
                self.fail("quoted exchange did not complete")

    def test_contact_quote_predicts_corruption_failure(self) -> None:
        representation = prepare_binary(b"corruption quote" * 8)
        with tempfile.TemporaryDirectory() as temporary:
            store = ReceiverStore(Path(temporary), representation)
            exchange = ProofExchange(representation, store, max_record_size=512)
            quote = exchange.quote_contact(1024, corrupt_next_data=True)
            report = exchange.run_contact(1024, corrupt_next_data=True)
            self.assertEqual(quote.predicted_spent_bytes, report.spent_bytes)
            self.assertEqual(quote.predicted_progress_after, report.progress_after)
            self.assertEqual(quote.predicted_complete, report.complete)
            self.assertEqual(quote.accounting, report.accounting)
            self.assertEqual(report.accounting.integrity_failures, 1)

    def test_interrupted_contacts_resume_without_payload_retransmission(self) -> None:
        message = fixture_message()
        representation = prepare_message(message)
        total = Accounting()
        contacts = 0
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            windows = (128, 71, 83, 67, 96)
            for contacts in range(1, 101):
                receiver = ReceiverStore(root, representation)
                report = ProofExchange(representation, receiver).run_contact(
                    windows[(contacts - 1) % len(windows)]
                )
                total.merge(report.accounting)
                self.assertLessEqual(report.spent_bytes, report.budget_bytes)
                if report.result_sent:
                    break
            else:
                self.fail("exchange did not complete")

            reopened = ReceiverStore(root, representation)
            self.assertEqual(reopened.read_complete(), message)

        self.assertGreater(contacts, 2)
        self.assertEqual(total.representation_payload_bytes, representation.size)
        self.assertEqual(total.duplicate_payload_bytes, 0)
        self.assertEqual(total.useful_committed_bytes, representation.size)

    def test_every_contact_respects_its_hard_budget(self) -> None:
        representation = prepare_message(fixture_message())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for budget in range(0, 130):
                receiver = ReceiverStore(root, representation)
                report = ProofExchange(representation, receiver).run_contact(budget)
                self.assertLessEqual(report.spent_bytes, budget)

    def test_corruption_is_never_committed_and_clean_retry_recovers(self) -> None:
        message = fixture_message("integrity proof " * 8)
        representation = prepare_message(message)
        total = Accounting()
        saw_failure = False
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corrupt = True
            for _ in range(20):
                receiver = ReceiverStore(root, representation)
                report = ProofExchange(representation, receiver).run_contact(
                    256, corrupt_next_data=corrupt
                )
                corrupt = False
                total.merge(report.accounting)
                if report.accounting.integrity_failures:
                    saw_failure = True
                    self.assertFalse(ReceiverStore(root, representation).is_complete)
                    break
            self.assertTrue(saw_failure)

            for _ in range(20):
                receiver = ReceiverStore(root, representation)
                report = ProofExchange(representation, receiver).run_contact(256)
                total.merge(report.accounting)
                if report.result_sent:
                    break
            else:
                self.fail("clean retry did not complete")
            self.assertEqual(ReceiverStore(root, representation).read_complete(), message)

        self.assertEqual(total.integrity_failures, 1)
        self.assertGreater(total.representation_payload_bytes, representation.size)

    def test_matching_duplicate_is_idempotent_and_conflict_is_rejected(self) -> None:
        representation = prepare_message(fixture_message("duplicate proof"))
        with tempfile.TemporaryDirectory() as temporary:
            store = ReceiverStore(Path(temporary), representation)
            chunk = representation.encoded[:12]
            self.assertEqual(store.accept_data(0, chunk), (12, 0))
            self.assertEqual(store.accept_data(0, chunk), (0, 12))
            self.assertEqual(store.progress, 12)
            with self.assertRaises(StoreError):
                store.accept_data(0, b"x" + chunk[1:])

    def test_reopened_committed_file_is_reverified(self) -> None:
        representation = prepare_message(fixture_message("commit verification"))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for _ in range(20):
                store = ReceiverStore(root, representation)
                report = ProofExchange(representation, store).run_contact(256)
                if report.result_sent:
                    break
            else:
                self.fail("exchange did not complete")

            store = ReceiverStore(root, representation)
            committed = bytearray(store.complete_path.read_bytes())
            committed[-1] ^= 0x01
            store.complete_path.write_bytes(committed)
            with self.assertRaises(IntegrityError):
                ReceiverStore(root, representation)

    def test_attachment_bytes_are_deferred_until_explicitly_selected(self) -> None:
        attachment_content = (b"weather-routing-data\n" * 64) + bytes(range(64))
        descriptor, attachment = prepare_attachment(
            "routing.txt", "text/plain", attachment_content
        )
        message = fixture_message("The attachment is available on request.")
        message = Message(
            logical_id=message.logical_id,
            created_at=message.created_at,
            sender=message.sender,
            recipients=message.recipients,
            subject=message.subject,
            body=message.body,
            attachments=(descriptor,),
        )
        manifest = prepare_message(message)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest_total = Accounting()
            for _ in range(30):
                store = ReceiverStore(root, manifest)
                report = ProofExchange(manifest, store).run_contact(256)
                manifest_total.merge(report.accounting)
                if report.result_sent:
                    break
            else:
                self.fail("manifest transfer did not complete")

            decoded = ReceiverStore(root, manifest).read_complete()
            self.assertEqual(decoded, message)
            self.assertEqual(manifest_total.representation_payload_bytes, manifest.size)
            self.assertFalse((root / f"{attachment.representation_id.hex()}.part").exists())
            self.assertFalse((root / f"{attachment.representation_id.hex()}.complete").exists())

            attachment_total = Accounting()
            for _ in range(30):
                store = ReceiverStore(root, attachment)
                report = ProofExchange(
                    attachment, store, max_record_size=512
                ).run_contact(1024)
                attachment_total.merge(report.accounting)
                if report.result_sent:
                    break
            else:
                self.fail("selected attachment transfer did not complete")

            self.assertEqual(
                ReceiverStore(root, attachment).read_complete(), attachment_content
            )
            self.assertEqual(
                attachment_total.representation_payload_bytes, len(attachment_content)
            )
            self.assertEqual(attachment_total.duplicate_payload_bytes, 0)

    def test_binary_representation_round_trip(self) -> None:
        content = bytes(range(256)) * 4
        representation = prepare_binary(content)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for _ in range(20):
                store = ReceiverStore(root, representation)
                report = ProofExchange(
                    representation, store, max_record_size=512
                ).run_contact(1024)
                if report.result_sent:
                    break
            else:
                self.fail("binary transfer did not complete")
            self.assertEqual(ReceiverStore(root, representation).read_complete(), content)


class BenchmarkTests(unittest.TestCase):
    def test_synthetic_corpus_and_report_are_deterministic(self) -> None:
        first_fixtures = build_fixtures()
        second_fixtures = build_fixtures()
        self.assertEqual(first_fixtures, second_fixtures)
        self.assertEqual(build_report(), build_report())

    def test_attachment_benchmarks_defer_content_until_selection(self) -> None:
        report = build_report()
        attachment_fixtures = [
            fixture
            for fixture in report["fixtures"]
            if fixture["attachment_representation_bytes"]
        ]
        self.assertGreaterEqual(len(attachment_fixtures), 2)
        for fixture in attachment_fixtures:
            self.assertEqual(fixture["metadata_attachment_payload_bytes"], 0)
            self.assertEqual(
                fixture["selected_attachment_payload_bytes"],
                fixture["attachment_representation_bytes"],
            )
            self.assertEqual(fixture["full_exchange_duplicate_payload_bytes"], 0)

    def test_no_change_summary_meets_initial_byte_gates(self) -> None:
        collection = tuple(
            prepare_message(fixture.message) for fixture in build_fixtures()
        )
        warm = compare_collections(
            collection, reversed(collection), cached_capabilities=True
        )
        cold = compare_collections(
            collection, collection, cached_capabilities=False
        )
        self.assertTrue(warm.equal)
        self.assertTrue(cold.equal)
        self.assertLessEqual(warm.accounting.total_bempic_bytes, 64)
        self.assertLessEqual(cold.accounting.total_bempic_bytes, 128)
        self.assertEqual(warm.accounting.total_bempic_bytes, 58)
        self.assertEqual(cold.accounting.total_bempic_bytes, 76)

    def test_collection_summary_detects_one_added_representation(self) -> None:
        collection = tuple(
            prepare_message(fixture.message) for fixture in build_fixtures()
        )
        changed = collection + (prepare_binary(b"one additional object"),)
        comparison = compare_collections(
            collection, changed, cached_capabilities=True
        )
        self.assertFalse(comparison.equal)
        self.assertNotEqual(collection_digest(collection), collection_digest(changed))
        self.assertEqual(comparison.accounting.total_bempic_bytes, 58)

    def test_incremental_discovery_offers_only_one_added_representation(self) -> None:
        known = tuple(
            prepare_binary(f"known-{number}".encode()) for number in range(100)
        )
        added = prepare_binary(b"one new representation")
        missing = missing_representations(known + (added,), known)
        self.assertEqual(missing, (added,))

        too_small = offer_page(missing, budget_bytes=61)
        self.assertEqual(too_small.offered, ())
        self.assertEqual(too_small.next_cursor, 0)
        self.assertEqual(too_small.accounting.total_bempic_bytes, 0)

        exact = offer_page(missing, budget_bytes=62)
        self.assertEqual(exact.offered, (added,))
        self.assertTrue(exact.complete)
        self.assertEqual(exact.accounting.total_bempic_bytes, 62)

    def test_offer_pages_are_deterministic_and_budget_bounded(self) -> None:
        missing = tuple(
            prepare_binary(f"missing-{number}".encode()) for number in range(5)
        )
        missing = missing_representations(reversed(missing), ())
        cursor = 0
        observed = []
        while cursor is not None:
            page = offer_page(missing, cursor=cursor, budget_bytes=124)
            self.assertLessEqual(page.accounting.total_bempic_bytes, 124)
            self.assertLessEqual(len(page.offered), 2)
            observed.extend(page.offered)
            cursor = page.next_cursor
        self.assertEqual(tuple(observed), missing)

    def test_reconciliation_rejects_short_identifier_collision(self) -> None:
        message = prepare_message(fixture_message("collision check"))
        conflicting = PreparedRepresentation(
            representation_id=message.representation_id,
            digest=message.digest,
            encoded=message.encoded,
            kind=RepresentationKind.BINARY,
        )
        with self.assertRaises(ValueError):
            missing_representations((message,), (conflicting,))


if __name__ == "__main__":
    unittest.main()

