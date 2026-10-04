"""An agent settling its OWN hold that nobody has claimed (MAGP section 8.7.4; 2026-10-03 pre-beta rerun, N-8).

The gate used to accept an unsigned capture or void of an unclaimed hold from anyone holding the authorization id — which the
agent hands to every gateway it asks to execute. It now takes one only from the hold's agent (a MAGP-SETTLE-v1 signature), a
counterparty the owner registered, or, for an open testnet owner, anyone. This checks what the client puts on the wire: a
signature over exactly that call, which verifies for it and for no other.
"""

from __future__ import annotations

import unittest

from _support import new_agent_key
from cryptography.exceptions import InvalidSignature
from fake_gate import FakeGate
from metamynd_client import MetaMyndClient, agent_settle_message

AUTH = "33333333-3333-4333-8333-333333333333"
DID = "did:key:z6MkSettle"


class SettleSignature(unittest.TestCase):
    def setUp(self) -> None:
        self.key, seed = new_agent_key()
        self.gate = FakeGate(self.key.public_key())
        self.client = MetaMyndClient(self.gate.start(), DID, seed, timeout=5)
        self.addCleanup(self.gate.stop)

    def _last(self, suffix: str) -> dict:
        for path, body in reversed(list(zip(self.gate.paths, self.gate.bodies))):
            if path.endswith(suffix):
                return body
        raise AssertionError(f"no POST to *{suffix}")

    def _verifies(self, message: str, signature_hex: str) -> bool:
        try:
            self.key.public_key().verify(bytes.fromhex(signature_hex), message.encode("utf-8"))
            return True
        except InvalidSignature:
            return False

    def test_the_message_matches_the_issuer_byte_for_byte(self) -> None:
        # The same vector backend/src/features/policy/mandate/settle-authority.test.ts pins.
        self.assertEqual(agent_settle_message("void", "did:x", "a", "n", "t", ["why|not"]), "MAGP-SETTLE-v1|void|did:x|a|n|t|why\\|not")

    def test_a_void_is_signed_by_the_agent_over_that_void(self) -> None:
        self.client.void(AUTH, "no longer needed")
        body = self._last("/void")
        proof = body["agentProof"]
        self.assertEqual(proof["agentDid"], DID)
        signed = agent_settle_message("void", DID, AUTH, proof["nonce"], proof["issuedAt"], ["no longer needed"])
        self.assertTrue(self._verifies(signed, proof["signature"]))
        # ...and for no other call: another reason, another verb, another hold
        for other in (
            agent_settle_message("void", DID, AUTH, proof["nonce"], proof["issuedAt"], [""]),
            agent_settle_message("capture", DID, AUTH, proof["nonce"], proof["issuedAt"], ["no longer needed"]),
            agent_settle_message("void", DID, "44444444-4444-4444-8444-444444444444", proof["nonce"], proof["issuedAt"], ["no longer needed"]),
        ):
            self.assertFalse(self._verifies(other, proof["signature"]))

    def test_a_capture_signs_the_amount_as_the_issuer_prints_it(self) -> None:
        self.client.capture(AUTH, 250.0, booking_ref="PNR-1")
        proof = self._last("/capture")["agentProof"]
        # 250.0 is "250" in JavaScript, which is what the issuer rebuilds from the JSON number.
        self.assertTrue(self._verifies(agent_settle_message("capture", DID, AUTH, proof["nonce"], proof["issuedAt"], ["250", "PNR-1", ""]), proof["signature"]))

    def test_every_settlement_uses_a_fresh_nonce(self) -> None:
        self.client.void(AUTH)
        first = self._last("/void")["agentProof"]["nonce"]
        self.client.void(AUTH)
        self.assertNotEqual(self._last("/void")["agentProof"]["nonce"], first)


if __name__ == "__main__":
    unittest.main()
