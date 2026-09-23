"""The Python client reproduces the shared payload-binding vectors (docs/protocol/payload-binding-vectors.json).

Payload binding (MAGP section 8.3.9) only works if the agent's language and the executing service's language compute the
SAME digest for the same payload. The vectors are generated from the TypeScript implementation (the source of truth) and
checked by BOTH suites — backend/src/features/magp/payload-binding.test.ts and this file — so a canonicalisation
difference (number spelling, key order beyond the BMP, string escapes) fails a test instead of silently making every bound
request unclaimable.

Run:  python -m unittest discover -s integrations/metamynd-client/tests
"""

from __future__ import annotations

import json
import unittest

from _support import REPO  # noqa: F401  (also puts src/ on sys.path)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from metamynd_client import (
    PayloadNotCanonicalizable,
    canonical_payload,
    load_key,
    payload_binding_message,
    payload_digest,
    payload_rebind_message,
)

DOC = json.loads((REPO / "docs" / "protocol" / "payload-binding-vectors.json").read_text(encoding="utf-8"))
KEY = load_key(DOC["seed"])
PUBLIC = Ed25519PublicKey.from_public_bytes(bytes.fromhex(DOC["publicKey"]))


class PayloadVectors(unittest.TestCase):
    def test_every_canonical_vector(self) -> None:
        for v in DOC["canonical"]:
            with self.subTest(v["name"]):
                # json.loads gives Python's view of the text (1.0 is a float, 1152921504606846977 an int): the canonical form
                # must still be JavaScript's, byte for byte.
                self.assertEqual(canonical_payload(json.loads(v["jsonText"])), v["canonical"])
                self.assertEqual(payload_digest(json.loads(v["jsonText"])), v["digest"])

    def test_every_reject_vector(self) -> None:
        for v in DOC["reject"]:
            with self.subTest(v["name"]):
                with self.assertRaises(PayloadNotCanonicalizable):
                    canonical_payload(json.loads(v["jsonText"]))

    def test_every_binding_vector(self) -> None:
        for v in DOC["binding"]:
            with self.subTest(v["name"]):
                f = v["fields"]
                digest = payload_digest(json.loads(v["payloadJsonText"]))
                self.assertEqual(digest, v["payloadDigest"])
                message = payload_binding_message(f["agentDid"], f["action"], f["nonce"], f["issuedAt"], digest)
                self.assertEqual(message, v["message"])
                self.assertEqual(KEY.sign(message.encode("utf-8")).hex(), v["signature"], "Ed25519 is deterministic")
                PUBLIC.verify(bytes.fromhex(v["signature"]), message.encode("utf-8"))

    def test_every_rebind_vector(self) -> None:
        """The LATE binding (MAGP 8.3.11): a hold that already exists, so the message also names the authorization id."""
        for v in DOC["rebind"]:
            with self.subTest(v["name"]):
                f = v["fields"]
                digest = payload_digest(json.loads(v["payloadJsonText"]))
                self.assertEqual(digest, v["payloadDigest"])
                message = payload_rebind_message(f["agentDid"], f["action"], f["authorizationId"], f["nonce"], f["issuedAt"], digest)
                self.assertEqual(message, v["message"])
                self.assertEqual(KEY.sign(message.encode("utf-8")).hex(), v["signature"], "Ed25519 is deterministic")
                PUBLIC.verify(bytes.fromhex(v["signature"]), message.encode("utf-8"))

    def test_the_rebind_message_is_its_own_domain_and_names_the_hold(self) -> None:
        f = DOC["rebind"][0]["fields"]
        digest = DOC["rebind"][0]["payloadDigest"]
        late = payload_rebind_message(f["agentDid"], f["action"], f["authorizationId"], f["nonce"], f["issuedAt"], digest)
        early = payload_binding_message(f["agentDid"], f["action"], f["nonce"], f["issuedAt"], digest)
        self.assertTrue(late.startswith("MAGP-PAYLOAD-REBIND-v1|") and early.startswith("MAGP-PAYLOAD-v1|"))
        other_hold = payload_rebind_message(f["agentDid"], f["action"], "00000000-0000-4000-8000-000000000000", f["nonce"], f["issuedAt"], digest)
        self.assertNotEqual(late, other_hold, "a different authorization id is a different message: the digest cannot be lifted onto another hold")

    def test_python_values_that_javascript_would_spell_differently(self) -> None:
        # Not in the JSON file (JSON cannot tell 250.0 from 250): the Python types where the trap is.
        self.assertEqual(canonical_payload({"amount": 250.0}), '{"amount":250}')
        self.assertEqual(canonical_payload({"a": 0.00005}), '{"a":0.00005}')  # repr() alone gives 5e-05
        self.assertEqual(canonical_payload([1e21, 1e-7, -0.0]), "[1e+21,1e-7,0]")
        self.assertEqual(canonical_payload({"n": 2**60 + 1}), '{"n":1152921504606847000}', "an int the gate's JSON.parse holds as a double")
        self.assertEqual(canonical_payload((1, 2)), "[1,2]", "a tuple is a JSON array")
        self.assertEqual(payload_digest({"a": True, "b": None}), payload_digest(json.loads('{"b":null,"a":true}')))

    def test_an_int_subclass_is_its_number_not_its_name(self) -> None:
        import enum

        class Level(enum.IntEnum):
            HIGH = 3

        self.assertEqual(canonical_payload({"level": Level.HIGH}), '{"level":3}')

    def test_utf16_key_order_is_not_code_point_order(self) -> None:
        # U+1F600 (a surrogate pair, D83D DE00) sorts BEFORE U+FFFF in UTF-16, but after it by code point.
        self.assertEqual(canonical_payload({"￿": 1, "\U0001f600": 2, "a": 3}), '{"a":3,"\U0001f600":2,"￿":1}')

    def test_what_json_cannot_carry_is_refused_not_normalised(self) -> None:
        import datetime
        import decimal

        for bad in (float("nan"), float("inf"), {"a": float("-inf")}, b"bytes", datetime.datetime(2026, 1, 1), decimal.Decimal("1.5"),
                    {1, 2}, {1: "non-string key"}, "\ud800", {"\udc00": 1}, object(), lambda: 1):
            with self.subTest(repr(bad)[:40]):
                with self.assertRaises(PayloadNotCanonicalizable):
                    canonical_payload(bad)

    def test_limits(self) -> None:
        deep: object = 1
        for _ in range(32):
            deep = [deep]
        canonical_payload(deep)  # 32 nested arrays put the scalar at depth 32: the limit, allowed (same rule as the TypeScript)
        with self.assertRaises(PayloadNotCanonicalizable):
            canonical_payload([deep])
        with self.assertRaises(PayloadNotCanonicalizable):
            canonical_payload("x" * (256 * 1024 + 1))

    def test_control_characters_and_solidus(self) -> None:
        self.assertEqual(canonical_payload("\x00\x08\x1f\x7f/ "), '"\\u0000\\b\\u001f\x7f/ "')


if __name__ == "__main__":
    unittest.main()
