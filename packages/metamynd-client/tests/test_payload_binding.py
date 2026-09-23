"""Payload binding from the agent's side (MAGP section 8.3.9) — what the Python client puts on the wire.

The digest and message formats are pinned to the shared vectors in `test_payload_vectors.py`; this file checks the
behaviour around them: that `payload=` reaches the request, that the signature genuinely verifies for THAT authorization,
that a payload JSON cannot carry stops the call before anything is sent, and that a request without a payload is exactly
what it always was.
"""

from __future__ import annotations

import asyncio
import json
import unittest

from _support import new_agent_key, public_hex  # noqa: F401
from cryptography.exceptions import InvalidSignature
from fake_gate import FakeGate
from metamynd_client import MetaMyndClient, NO_PAYLOAD, PayloadNotCanonicalizable, guard_tool, governance_headers, payload_binding_message, payload_digest, payload_rebind_message

PAYLOAD = {"passenger": "A. Traveller", "payee": {"iban": "GB00AAAA", "name": "Skyward Air"}, "amount": 250}
CTX = {"riskLevel": "low"}


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.key, seed = new_agent_key()
        self.gate = FakeGate(self.key.public_key())
        self.client = MetaMyndClient(self.gate.start(), "did:key:z6MkPayload", seed, timeout=5)
        self.addCleanup(self.gate.stop)


class SignedRequest(_Base):
    def test_a_request_without_a_payload_carries_no_binding(self) -> None:
        body = self.client.sign_request("flight-purchase", 250, merchant="skyward-air", context=CTX).body
        self.assertNotIn("payloadDigest", body)
        self.assertNotIn("payloadSignature", body)

    def test_a_payload_adds_a_digest_and_a_signature_that_verifies_for_this_authorization(self) -> None:
        body = self.client.sign_request("flight-purchase", 250, merchant="skyward-air", context=CTX, payload=PAYLOAD).body
        self.assertEqual(body["payloadDigest"], payload_digest(PAYLOAD))
        message = payload_binding_message(body["agentDid"], body["action"], body["nonce"], body["issuedAt"], body["payloadDigest"])
        self.key.public_key().verify(bytes.fromhex(body["payloadSignature"]), message.encode("utf-8"))
        # ...and for no other: a different nonce, or a different action, does not verify
        for other in (
            payload_binding_message(body["agentDid"], body["action"], "0" * 32, body["issuedAt"], body["payloadDigest"]),
            payload_binding_message(body["agentDid"], "wire-transfer", body["nonce"], body["issuedAt"], body["payloadDigest"]),
        ):
            with self.assertRaises(InvalidSignature):
                self.key.public_key().verify(bytes.fromhex(body["payloadSignature"]), other.encode("utf-8"))

    def test_the_binding_survives_the_header_the_gateway_reads(self) -> None:
        signed = self.client.sign_request("flight-purchase", 250, merchant="skyward-air", context=CTX, payload=PAYLOAD)
        carried = json.loads(signed.header_value())
        self.assertEqual(carried["payloadDigest"], payload_digest(PAYLOAD))
        signed.header_value().encode("ascii")

    def test_a_payload_JSON_cannot_carry_stops_the_call_before_anything_is_sent(self) -> None:
        for bad in ({"when": __import__("datetime").datetime(2026, 1, 1)}, {"n": float("nan")}, {"raw": b"bytes"}):
            with self.assertRaises(PayloadNotCanonicalizable):
                self.client.authorize("flight-purchase", 250, merchant="skyward-air", context=CTX, payload=bad)
        self.assertEqual(self.gate.paths, [], "a payload that cannot be bound is never sent unbound")

    def test_omitting_payload_and_passing_NO_PAYLOAD_explicitly_are_identical_and_unbound(self) -> None:
        omitted = self.client.sign_request("flight-purchase", 250, merchant="skyward-air", context=CTX).body
        explicit = self.client.sign_request("flight-purchase", 250, merchant="skyward-air", context=CTX, payload=NO_PAYLOAD).body
        for body in (omitted, explicit):
            self.assertNotIn("payloadDigest", body)
            self.assertNotIn("payloadSignature", body)

    def test_payload_None_binds_the_literal_JSON_null_distinct_from_omitted(self) -> None:
        body = self.client.sign_request("flight-purchase", 250, merchant="skyward-air", context=CTX, payload=None).body
        self.assertEqual(body["payloadDigest"], payload_digest(None))
        self.assertNotEqual(body["payloadDigest"], payload_digest(PAYLOAD))
        message = payload_binding_message(body["agentDid"], body["action"], body["nonce"], body["issuedAt"], body["payloadDigest"])
        self.key.public_key().verify(bytes.fromhex(body["payloadSignature"]), message.encode("utf-8"))


class Authorize(_Base):
    def test_authorize_sends_the_binding_and_the_gate_verifies_it(self) -> None:
        verdict = self.client.authorize("flight-purchase", 250, merchant="skyward-air", context=CTX, payload=PAYLOAD)
        self.assertEqual(verdict.decision, "allow", verdict.raw)
        self.assertEqual(self.gate.payload_failures, 0)
        self.assertEqual(self.gate.requests[-1]["payloadDigest"], payload_digest(PAYLOAD))
        self.assertEqual(self.gate.holds[verdict.authorization_id]["payloadDigest"], payload_digest(PAYLOAD))
        self.assertEqual(verdict.signed.body["payloadDigest"], payload_digest(PAYLOAD), "the handoff for a gateway carries the binding")

    def test_the_verdict_carries_event_id_a_DIFFERENT_id_from_authorization_id(self) -> None:
        # event_id is what GET /magp/evidence/{event_id}/proof needs (spec 10.3); authorization_id (the
        # mandate hold) does not work there — the fake gate deliberately mints the two independently, the
        # same way the real one does, so a test that swapped them would fail here.
        verdict = self.client.authorize("flight-purchase", 250, merchant="skyward-air", context=CTX)
        self.assertEqual(verdict.decision, "allow", verdict.raw)
        self.assertEqual(verdict.event_id, self.gate.last_event_id)
        self.assertNotEqual(verdict.event_id, verdict.authorization_id)

    def test_authorize_without_a_payload_is_unchanged(self) -> None:
        verdict = self.client.authorize("flight-purchase", 250, merchant="skyward-air", context=CTX)
        self.assertEqual(verdict.decision, "allow")
        self.assertNotIn("payloadDigest", self.gate.requests[-1])
        self.assertIsNone(self.gate.holds[verdict.authorization_id]["payloadDigest"])

    def test_a_gate_that_does_not_acknowledge_the_binding_is_refused_and_the_hold_released(self) -> None:
        # An older backend ignores the digest fields, or a proxy strips them: the request was never bound.
        self.gate.echo_payload_digest = False
        verdict = self.client.authorize("flight-purchase", 250, merchant="skyward-air", context=CTX, payload=PAYLOAD)
        self.assertEqual((verdict.decision, verdict.reason_code), ("block", "PAYLOAD_BINDING_NOT_CONFIRMED"))
        self.assertFalse(verdict.permitted)
        self.assertIsNone(verdict.authorization_id, "the caller must not be handed an authorization it believes is bound")
        self.assertTrue(any(p.endswith("/void") for p in self.gate.paths), "the hold that was just made is released")
        # an UNBOUND request against the same gate is unaffected
        self.assertEqual(self.client.authorize("flight-purchase", 250, merchant="skyward-air", context=CTX).decision, "allow")

    def test_an_escalation_must_acknowledge_the_binding_too(self) -> None:
        held = self.client.authorize("flight-purchase", 100, merchant="skyward-air", context={"riskLevel": "high"}, payload=PAYLOAD)
        self.assertEqual(held.decision, "escalate", "an honest gate acknowledges: the escalation stays")
        self.gate.echo_payload_digest = False
        refused = self.client.authorize("flight-purchase", 100, merchant="skyward-air", context={"riskLevel": "high"}, payload=PAYLOAD)
        self.assertEqual((refused.decision, refused.reason_code), ("block", "PAYLOAD_BINDING_NOT_CONFIRMED"))

    def test_a_tampered_digest_is_refused_by_the_gate_double(self) -> None:
        signed = self.client.sign_request("flight-purchase", 250, merchant="skyward-air", context=CTX, payload=PAYLOAD)
        forged = {**signed.body, "payloadDigest": payload_digest({**PAYLOAD, "payee": {"iban": "XX99EVIL", "name": "Skyward Air"}})}
        code, out = self.gate.post("/policy/mandate/authorize", forged)
        self.assertEqual((code, out["data"]["reasonCode"]), (403, "PAYLOAD_BINDING_INVALID"))
        self.assertEqual(self.gate.payload_failures, 1)


class BindPayload(_Base):
    """A reviewer's MODIFY leaves a hold with no digest; `bind_payload` binds the payload of the action that WILL run (8.3.11)."""

    def _hold(self) -> str:
        verdict = self.client.authorize("flight-purchase", 250, merchant="skyward-air", context=CTX)  # unbound, like a modified hold
        return verdict.authorization_id

    def test_binds_an_unbound_hold_and_the_signature_names_that_hold(self) -> None:
        auth_id = self._hold()
        result = self.client.bind_payload(auth_id, "flight-purchase", PAYLOAD)
        self.assertTrue(result.bound, result.reason_code)
        self.assertEqual(result.payload_digest, payload_digest(PAYLOAD))
        self.assertEqual(self.gate.holds[auth_id]["payloadDigest"], payload_digest(PAYLOAD))
        self.assertEqual(self.gate.payload_failures, 0, "the fake gate rebuilt the REBIND message by hand and verified it")
        body = self.gate.bind_requests[-1]
        message = payload_rebind_message(body["agentDid"], body["action"], auth_id, body["nonce"], body["issuedAt"], body["payloadDigest"])
        self.key.public_key().verify(bytes.fromhex(body["payloadSignature"]), message.encode("utf-8"))
        for wrong in (
            payload_rebind_message(body["agentDid"], body["action"], "00000000-0000-4000-8000-000000000000", body["nonce"], body["issuedAt"], body["payloadDigest"]),
            payload_binding_message(body["agentDid"], body["action"], body["nonce"], body["issuedAt"], body["payloadDigest"]),
        ):
            with self.assertRaises(InvalidSignature):
                self.key.public_key().verify(bytes.fromhex(body["payloadSignature"]), wrong.encode("utf-8"))

    def test_a_retry_is_idempotent_and_a_different_digest_is_refused(self) -> None:
        auth_id = self._hold()
        self.assertTrue(self.client.bind_payload(auth_id, "flight-purchase", PAYLOAD).bound)
        again = self.client.bind_payload(auth_id, "flight-purchase", PAYLOAD)
        self.assertTrue(again.bound and again.already_bound)
        other = self.client.bind_payload(auth_id, "flight-purchase", {**PAYLOAD, "payee": {"iban": "XX99EVIL", "name": "Skyward Air"}})
        self.assertFalse(other.bound)
        self.assertEqual(other.reason_code, "PAYLOAD_ALREADY_BOUND")
        self.assertEqual(self.gate.holds[auth_id]["payloadDigest"], payload_digest(PAYLOAD), "a bound digest is never overwritten")

    def test_a_gate_that_predates_late_binding_does_not_confirm_it(self) -> None:
        auth_id = self._hold()
        self.gate.echo_payload_digest = False
        result = self.client.bind_payload(auth_id, "flight-purchase", PAYLOAD)
        self.assertFalse(result.bound)
        self.assertEqual(result.reason_code, "PAYLOAD_BINDING_NOT_CONFIRMED", "a success that does not echo our digest is NOT bound")

    def test_an_unknown_hold_is_not_found(self) -> None:
        result = self.client.bind_payload("00000000-0000-4000-8000-000000000000", "flight-purchase", PAYLOAD)
        self.assertEqual((result.bound, result.reason_code), (False, "AUTHORIZATION_NOT_FOUND"))

    def test_a_payload_JSON_cannot_carry_sends_nothing(self) -> None:
        auth_id = self._hold()
        before = len(self.gate.bind_requests)
        with self.assertRaises(PayloadNotCanonicalizable):
            self.client.bind_payload(auth_id, "flight-purchase", {"n": float("nan")})
        self.assertEqual(len(self.gate.bind_requests), before)

    def test_a_gate_that_answers_with_something_other_than_a_json_object_raises_runtime_error(self) -> None:
        """A proxy's error page, a `null`, a list: never AttributeError, and never `bound`."""
        from unittest import mock

        auth_id = self._hold()
        for weird in (None, [], ["x"], "oops", 7):
            with self.subTest(weird=weird):
                with mock.patch.object(self.client, "_post", return_value=weird):
                    with self.assertRaises(RuntimeError) as caught:
                        self.client.bind_payload(auth_id, "flight-purchase", PAYLOAD)
                self.assertIn("NOT bound", str(caught.exception))
        # a JSON object whose `data` is not an object is simply not a confirmation
        with mock.patch.object(self.client, "_post", return_value={"success": True, "data": ["x"]}):
            result = self.client.bind_payload(auth_id, "flight-purchase", PAYLOAD)
        self.assertEqual((result.bound, result.reason_code), (False, "PAYLOAD_BINDING_NOT_CONFIRMED"))

    def test_an_unreachable_gate_raises_the_payload_is_not_bound(self) -> None:
        auth_id = self._hold()
        self.gate.stop()
        with self.assertRaises(RuntimeError) as caught:
            self.client.bind_payload(auth_id, "flight-purchase", PAYLOAD)
        self.assertIn("NOT bound", str(caught.exception))


class GuardTool(_Base):
    def test_map_args_can_return_the_payload_and_the_wrapped_tool_hands_it_off(self) -> None:
        seen: list = []

        def book(vendor: str, amount: float, iban: str) -> str:
            seen.append(json.loads(governance_headers()["x-magp-request"]))
            return "booked"

        def map_args(vendor: str, amount: float, iban: str) -> dict:
            return {"amount": amount, "merchant": vendor, "context": CTX, "payload": {"vendor": vendor, "amount": amount, "iban": iban}}

        self.assertEqual(guard_tool(self.client, "flight-purchase", book, map_args)("skyward-air", 250, "GB00AAAA"), "booked")
        self.assertEqual(seen[0]["payloadDigest"], payload_digest({"vendor": "skyward-air", "amount": 250, "iban": "GB00AAAA"}))
        self.assertEqual(self.gate.payload_failures, 0)

    def test_map_args_omitting_the_payload_key_is_unbound_but_returning_None_for_it_binds_null(self) -> None:
        seen: list = []

        def book() -> str:
            seen.append(json.loads(governance_headers()["x-magp-request"]))
            return "booked"

        unbound = guard_tool(self.client, "flight-purchase", book, lambda: {"amount": 250, "merchant": "skyward-air", "context": CTX})
        self.assertEqual(unbound(), "booked")
        self.assertNotIn("payloadDigest", seen[-1])

        bound_null = guard_tool(self.client, "flight-purchase", book, lambda: {"amount": 250, "merchant": "skyward-air", "context": CTX, "payload": None})
        self.assertEqual(bound_null(), "booked")
        self.assertEqual(seen[-1]["payloadDigest"], payload_digest(None))

    def test_an_uncanonicalizable_payload_raises_before_the_tool_runs(self) -> None:
        ran: list = []

        def book(vendor: str, amount: float) -> str:
            ran.append(1)
            return "booked"

        map_args = lambda vendor, amount: {"amount": amount, "merchant": vendor, "context": CTX, "payload": {"when": {1, 2}}}  # noqa: E731
        with self.assertRaises(PayloadNotCanonicalizable):
            guard_tool(self.client, "flight-purchase", book, map_args)("skyward-air", 250)
        self.assertEqual(ran, [])
        self.assertEqual(self.gate.paths, [])

    def test_the_async_path_binds_the_payload_too(self) -> None:
        seen: list = []

        async def book(vendor: str, amount: float) -> str:
            seen.append(json.loads(governance_headers()["x-magp-request"]))
            return "booked"

        map_args = lambda vendor, amount: {"amount": amount, "merchant": vendor, "context": CTX, "payload": {"vendor": vendor}}  # noqa: E731
        self.assertEqual(asyncio.run(guard_tool(self.client, "flight-purchase", book, map_args)("skyward-air", 250)), "booked")
        self.assertEqual(seen[0]["payloadDigest"], payload_digest({"vendor": "skyward-air"}))


if __name__ == "__main__":
    unittest.main()
