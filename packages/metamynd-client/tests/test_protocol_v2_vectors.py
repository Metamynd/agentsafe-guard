"""The Python client reproduces the v2 (signed-jurisdiction) vectors: docs/protocol/authorize-v2-vectors.json.

MAGP §8.3.12: a request that carries `jurisdiction` signs the eight v1 fields, then the literal tag MAGP-AUTH-v2, then
the jurisdiction; one that does not signs the v1 message byte for byte. The vectors are generated from the gate's own
`buildAuthMessage` and checked by the backend's authorize-v2-vectors.test.ts too, so the two cannot drift.

Also: the client normalises a caller's jurisdiction, sends exactly the value it signed, never promotes one from
`context`, and refuses a malformed one before anything is signed or sent.

Run:  python -m unittest discover -s integrations/metamynd-client/tests
"""

from __future__ import annotations

import json
import unittest

from _support import REPO, new_agent_key  # noqa: F401  (also puts src/ on sys.path)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from metamynd_client import (
    AUTH_MESSAGE_V2_TAG,
    JURISDICTION_REASON_CODES,
    MetaMyndClient,
    Verdict,
    canonical_message,
    load_key,
    normalize_jurisdiction,
)

DOC = json.loads((REPO / "docs" / "protocol" / "authorize-v2-vectors.json").read_text(encoding="utf-8"))
KEY = load_key(DOC["seed"])
PUBLIC = Ed25519PublicKey.from_public_bytes(bytes.fromhex(DOC["publicKey"]))


def _message(fields: dict) -> str:
    f = fields
    return canonical_message(
        f["agentDid"], f["action"], f["amount"], f["currency"], f["merchant"], f["nonce"], f["issuedAt"], resource=f["resource"], jurisdiction=f["jurisdiction"]
    )


class V2Vectors(unittest.TestCase):
    def test_the_file_pins_the_v2_shape(self) -> None:
        self.assertEqual(DOC["algorithm"], "Ed25519")
        self.assertEqual(DOC["versionTag"], "MAGP-AUTH-v2")
        self.assertEqual(AUTH_MESSAGE_V2_TAG, DOC["versionTag"])
        self.assertEqual(DOC["fieldOrder"][-2:], ["MAGP-AUTH-v2", "jurisdiction"])
        self.assertTrue(any(v["fields"]["jurisdiction"] is None for v in DOC["vectors"]), "a v1 control vector")
        self.assertTrue(any(v["fields"]["jurisdiction"] for v in DOC["vectors"]))

    def test_every_vector_byte_for_byte(self) -> None:
        for vector in DOC["vectors"]:
            with self.subTest(vector["name"]):
                message = _message(vector["fields"])
                self.assertEqual(message, vector["message"])
                self.assertEqual(KEY.sign(message.encode("utf-8")).hex(), vector["signature"])
                PUBLIC.verify(bytes.fromhex(vector["signature"]), message.encode("utf-8"))

    def test_a_v2_signature_does_not_verify_as_v1_and_the_reverse(self) -> None:
        v2 = next(v for v in DOC["vectors"] if v["fields"]["jurisdiction"])
        as_v1 = _message({**v2["fields"], "jurisdiction": None})
        with self.assertRaises(Exception):
            PUBLIC.verify(bytes.fromhex(v2["signature"]), as_v1.encode("utf-8"))
        control = next(v for v in DOC["vectors"] if v["fields"]["jurisdiction"] is None)
        as_v2 = _message({**control["fields"], "jurisdiction": "SG"})
        with self.assertRaises(Exception):
            PUBLIC.verify(bytes.fromhex(control["signature"]), as_v2.encode("utf-8"))


class Normalisation(unittest.TestCase):
    def test_accepts_two_letters_trimmed_upper_cased(self) -> None:
        self.assertEqual(normalize_jurisdiction("sg"), "SG")
        self.assertEqual(normalize_jurisdiction("  De "), "DE")
        self.assertIsNone(normalize_jurisdiction(None))

    def test_refuses_anything_else(self) -> None:
        for bad in ("", " ", "S", "SGP", "S1", "ß", "é", "Singapore", 42):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    normalize_jurisdiction(bad)  # type: ignore[arg-type]


class SignedAndSent(unittest.TestCase):
    def setUp(self) -> None:
        key, seed = new_agent_key()
        self.public = key.public_key()
        self.client = MetaMyndClient("http://127.0.0.1:9", "did:key:z6MkJurisdictionTest", seed)

    def _verifies(self, body: dict) -> bool:
        message = canonical_message(
            body["agentDid"], body["action"], body["amount"], body["currency"], body.get("merchant"), body["nonce"], body["issuedAt"],
            resource=body.get("resource"), jurisdiction=body.get("jurisdiction"),
        )
        try:
            self.public.verify(bytes.fromhex(body["signature"]), message.encode("utf-8"))
            return True
        except Exception:
            return False

    def test_jurisdiction_is_normalised_sent_top_level_and_signed_v2(self) -> None:
        body = dict(self.client.sign_request("flight-purchase", 150, merchant="skyward-air", jurisdiction=" sg ").body)
        self.assertEqual(body["jurisdiction"], "SG")
        self.assertTrue(self._verifies(body))
        stripped = {k: v for k, v in body.items() if k != "jurisdiction"}
        self.assertFalse(self._verifies(stripped), "stripping the field must break the signature")
        self.assertFalse(self._verifies({**body, "jurisdiction": "DE"}), "changing the field must break the signature")

    def test_no_jurisdiction_is_v1_and_no_field(self) -> None:
        body = dict(self.client.sign_request("flight-purchase", 150).body)
        self.assertNotIn("jurisdiction", body)
        self.assertTrue(self._verifies(body))

    def test_a_context_jurisdiction_is_never_promoted(self) -> None:
        body = dict(self.client.sign_request("flight-purchase", 150, context={"jurisdiction": "SG", "riskLevel": "low"}).body)
        self.assertNotIn("jurisdiction", body)
        self.assertTrue(self._verifies(body))

    def test_a_malformed_jurisdiction_is_refused_before_signing(self) -> None:
        with self.assertRaises(ValueError):
            self.client.sign_request("flight-purchase", 150, jurisdiction="SGP")
        with self.assertRaises(ValueError):
            self.client.authorize("flight-purchase", 150, jurisdiction="1A")  # refused before any network call

    def test_the_three_codes_are_surfaced(self) -> None:
        self.assertEqual(JURISDICTION_REASON_CODES, {"JURISDICTION_REQUIRED", "JURISDICTION_NOT_ALLOWED", "JURISDICTION_MISMATCH"})
        refused = Verdict.from_response({"data": {"decision": "block", "reasonCode": "JURISDICTION_MISMATCH"}})
        self.assertTrue(refused.jurisdiction_refused)
        self.assertFalse(refused.permitted)
        self.assertFalse(Verdict.from_response({"data": {"decision": "block", "reasonCode": "SOP_SPEND_CAP"}}).jurisdiction_refused)


if __name__ == "__main__":
    unittest.main()
