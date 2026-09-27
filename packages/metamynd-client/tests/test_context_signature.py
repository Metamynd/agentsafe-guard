"""The Python client signs the context the way the gate verifies it (MAGP section 8.3.13, context-claim binding).

`envelope_hash` must be byte-for-byte the gate's `envelopeHashFor`, so the shared vectors
(docs/protocol/context-signature-vectors.json, generated from the backend) are reproduced here: each envelope hash, and
each `envelopeSignature` under the vectors' public test key (Ed25519 is deterministic). test_real_guard.py then hands
default-signed requests to the real Node mcp-guard.

Run:  python -m unittest discover -s integrations/metamynd-client/tests
"""

from __future__ import annotations

import json
import os
import unittest
from unittest import mock

from _support import REPO  # noqa: F401  (also puts src/ on sys.path)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from metamynd_client import MetaMyndClient, envelope_hash, load_key

DOC = json.loads((REPO / "docs" / "protocol" / "context-signature-vectors.json").read_text(encoding="utf-8"))
KEY = load_key(DOC["seed"])
PUBLIC = Ed25519PublicKey.from_public_bytes(bytes.fromhex(DOC["publicKey"]))


class ContextSignatureVectors(unittest.TestCase):
    def test_every_vector_hash_and_signature(self) -> None:
        self.assertGreaterEqual(len(DOC["vectors"]), 4)
        for v in DOC["vectors"]:
            with self.subTest(v["name"]):
                h = envelope_hash(v["request"])
                self.assertEqual(h, v["envelopeHash"])
                self.assertEqual(KEY.sign(h.encode("utf-8")).hex(), v["request"]["envelopeSignature"])

    def test_an_altered_context_changes_the_hash(self) -> None:
        v = DOC["vectors"][0]
        self.assertNotEqual(envelope_hash({**v["request"], "itinerary": {**v["request"]["itinerary"], "riskLevel": "critical"}}), v["envelopeHash"])
        self.assertNotEqual(envelope_hash({**v["request"], "trace": {"workflowId": "other"}}), v["envelopeHash"])


class DefaultOnOptOut(unittest.TestCase):
    def setUp(self) -> None:
        self.did = DOC["agentDid"]

    def test_default_request_carries_a_verifying_envelope_signature(self) -> None:
        body = MetaMyndClient("http://127.0.0.1:1", self.did, DOC["seed"]).sign_request("pay", 150.0, merchant="m", context={"riskLevel": "low"}).body
        # The gate hashes the JSON it receives: round-trip it the way the wire does.
        wire = json.loads(json.dumps(dict(body)))
        PUBLIC.verify(bytes.fromhex(wire["envelopeSignature"]), envelope_hash(wire).encode("utf-8"))

    def test_no_context_is_signed_too(self) -> None:
        body = MetaMyndClient("http://127.0.0.1:1", self.did, DOC["seed"]).sign_request("read", 0).body
        self.assertNotIn("itinerary", body)
        PUBLIC.verify(bytes.fromhex(body["envelopeSignature"]), envelope_hash(body).encode("utf-8"))

    def test_sign_context_false_omits_it(self) -> None:
        body = MetaMyndClient("http://127.0.0.1:1", self.did, DOC["seed"], sign_context=False).sign_request("pay", 1, context={"riskLevel": "low"}).body
        self.assertNotIn("envelopeSignature", body)

    def test_from_env_opt_out(self) -> None:
        env = {"AGENT_DID": self.did, "AGENT_KEY": DOC["seed"], "METAMYND_API": "http://127.0.0.1:1"}
        with mock.patch.dict(os.environ, {**env, "METAMYND_SIGN_CONTEXT": "false"}, clear=False):
            self.assertFalse(MetaMyndClient.from_env().sign_context)
        with mock.patch.dict(os.environ, env, clear=False):
            os.environ.pop("METAMYND_SIGN_CONTEXT", None)
            self.assertTrue(MetaMyndClient.from_env().sign_context)


if __name__ == "__main__":
    unittest.main()
