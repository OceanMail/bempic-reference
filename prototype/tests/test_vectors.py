from __future__ import annotations

import json
import unittest
from pathlib import Path

from prototype.bempic_proof import Message, encode_message, prepare_message


VECTOR = (
    Path(__file__).parents[2]
    / "test-vectors"
    / "experimental-v0"
    / "tiny-message.json"
)


class CrossLanguageVectorTests(unittest.TestCase):
    def test_rust_and_python_message_bytes_are_exactly_equal(self) -> None:
        vector = json.loads(VECTOR.read_text(encoding="utf-8"))
        self.assertFalse(vector["normative"])
        value = vector["message"]
        message = Message(
            logical_id=bytes.fromhex(vector["logical_id_hex"]),
            created_at=value["created_at"],
            sender=value["sender"],
            recipients=tuple(value["recipients"]),
            subject=value["subject"],
            body=value["body"],
        )
        encoded = encode_message(message)
        prepared = prepare_message(message)
        self.assertEqual(encoded.hex(), vector["encoded_hex"])
        self.assertEqual(len(encoded), vector["encoded_size"])
        self.assertEqual(prepared.representation_id.hex(), vector["representation_id_hex"])
        self.assertEqual(prepared.digest.hex(), vector["sha256_hex"])


if __name__ == "__main__":
    unittest.main()

