"""Behaviours an independent review found wrong in the first cut of 0.2.0, each pinned so it cannot come back.

Every test here failed against that version: a `modified` escalation polled to the full timeout, a cancelled async
tool left a live hold, an async callable that is not an `async def` lost its signed request, a 200 with an HTML body
escaped as a JSONDecodeError, and repr() printed the live signature.
"""

from __future__ import annotations

import asyncio
import time
import unittest

from _support import new_agent_key, public_hex
from fake_gate import FakeGate
from metamynd_client import GovernanceBlocked, MetaMyndClient, governance_headers, guard_tool

CTX = lambda vendor, amount: {"amount": amount, "merchant": vendor, "context": {"riskLevel": "low"}}  # noqa: E731


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        key, seed = new_agent_key()
        self.gate = FakeGate(key.public_key())
        self.client = MetaMyndClient(self.gate.start(), "did:key:z6MkBehaviour", seed, timeout=5)
        self.addCleanup(self.gate.stop)


class EscalationTerminalStates(_Base):
    def test_a_modified_escalation_stops_the_wait_at_once_and_is_not_permission(self) -> None:
        held = self.client.authorize("flight-purchase", 100, merchant="skyward-air", context={"riskLevel": "high"})
        self.gate.modify(held.escalation_id)
        slept: list = []
        started = time.monotonic()
        status = self.client.wait_for_escalation(held.escalation_id, timeout=600, interval=1, _sleep=slept.append)
        self.assertLess(time.monotonic() - started, 5, "a modified escalation is terminal: it must not poll to the timeout")
        self.assertEqual(slept, [])
        self.assertTrue(status.resolved)
        self.assertFalse(status.may_proceed, "what was asked for is not what a reviewer changed it to")
        self.assertEqual(status.next_escalation_id, "esc-next")
        self.assertEqual(status.modified_action, {"amount": 50})


class NoSecretsInReprs(_Base):
    def test_repr_never_prints_the_live_signature(self) -> None:
        verdict = self.client.authorize("flight-purchase", 100, merchant="skyward-air", context={"riskLevel": "low"})
        signature = verdict.signed.body["signature"]
        for obj in (verdict, verdict.signed):
            self.assertNotIn(signature, repr(obj))
            self.assertNotIn(signature, str(obj))


class GateFailures(_Base):
    def test_a_200_with_an_html_body_is_the_documented_runtime_error(self) -> None:
        self.gate.html_200 = True
        with self.assertRaises(RuntimeError):
            self.client.authorize("flight-purchase", 100, merchant="skyward-air", context={"riskLevel": "low"})

    def test_a_lost_capture_response_is_reported_as_unknown_not_as_a_block(self) -> None:
        self.gate.stop()  # nothing listens any more
        with self.assertRaises(RuntimeError) as caught:
            self.client.capture("00000000-0000-4000-8000-000000000000", 100)
        self.assertIn("UNKNOWN", str(caught.exception), "a capture that may have committed is not 'treat as block'")
        with self.assertRaises(RuntimeError) as blocked:
            self.client.authorize("flight-purchase", 100, merchant="skyward-air", context={"riskLevel": "low"})
        self.assertIn("treat as block", str(blocked.exception))

    def test_capture_sends_pay_to_only_when_given(self) -> None:
        # A settlement below the authorization needs the account paid (the owner's payee directory, MAGP 8.7.14).
        self.client.capture("00000000-0000-4000-8000-000000000001", 200, pay_to="0.0.5005")
        self.assertEqual(self.gate.bodies[-1].get("payTo"), "0.0.5005")
        self.assertEqual(self.gate.bodies[-1].get("amountCharged"), 200)
        self.client.capture("00000000-0000-4000-8000-000000000001", 250)
        self.assertNotIn("payTo", self.gate.bodies[-1])

    def test_an_authorization_id_cannot_climb_out_of_its_path_segment(self) -> None:
        self.client.void("a/../../x")
        self.assertTrue(self.gate.paths, "the fake records request paths")
        self.assertNotIn("/../", self.gate.paths[-1], "the id is one path segment, escaped")


class SettlementRefusals(_Base):
    """0.5.3: a refusal carries the gate's stable code (MAGP 8.7.8) in `reason_code`, never a sentence to parse."""

    def _hold(self) -> str:
        verdict = self.client.authorize("flight-purchase", 100, merchant="skyward-air", context={"riskLevel": "low"})
        self.assertTrue(verdict.permitted, verdict)
        return verdict.authorization_id

    def test_a_refusal_is_its_code_with_the_sentence_only_in_detail(self) -> None:
        auth = self._hold()
        lowered = self.client.capture(auth, 40)
        self.assertFalse(lowered.ok)
        self.assertEqual(lowered.reason_code, "COUNTERPARTY_MISMATCH")
        self.assertEqual(lowered.message, "COUNTERPARTY_MISMATCH", "the message of a refusal is the bare code")
        self.assertTrue(lowered.detail.startswith("COUNTERPARTY_MISMATCH: "), lowered.detail)
        self.assertEqual(self.client.capture(auth, 500).reason_code, "AMOUNT_EXCEEDS_AUTHORIZED")

    def test_a_repeat_capture_is_not_held_and_a_repeat_void_is_not_an_error(self) -> None:
        auth = self._hold()
        first = self.client.capture(auth, 100)
        self.assertTrue(first.ok)
        self.assertEqual((first.reason_code, first.detail), ("", ""))
        again = self.client.capture(auth, 100)
        self.assertFalse(again.ok)
        self.assertEqual(again.reason_code, "NOT_HELD", "409 NOT_HELD: the first capture landed — read outcome()")
        self.assertEqual(self.client.outcome(auth).outcome, "settled")
        void = self.client.void(auth)
        self.assertFalse(void.ok)
        self.assertEqual(void.reason_code, "NOT_HELD", "a 200 NOT_HELD void carries its code in data.reasonCode, not the message")

    def test_an_unknown_id_is_authorization_not_found_and_its_outcome_fails_closed(self) -> None:
        missing = "00000000-0000-4000-8000-00000000dead"
        self.assertEqual(self.client.capture(missing, 1).reason_code, "AUTHORIZATION_NOT_FOUND")
        self.assertEqual(self.client.void(missing).reason_code, "AUTHORIZATION_NOT_FOUND")
        out = self.client.outcome(missing)
        self.assertEqual(out.outcome, "unknown")
        self.assertFalse(out.retry_safe)
        self.assertEqual(out.raw.get("reasonCode"), "AUTHORIZATION_NOT_FOUND")


class GuardedAsyncTools(_Base):
    def test_an_object_with_an_async_call_hands_off_the_signed_request(self) -> None:
        seen: list = []

        class Tool:
            async def __call__(self, vendor: str, amount: float) -> dict:
                seen.append(governance_headers().get("x-magp-request", ""))
                return {"ok": True}

        async def run() -> dict:
            return await guard_tool(self.client, "flight-purchase", Tool(), CTX)("skyward-air", 100)

        self.assertEqual(asyncio.run(run()), {"ok": True})
        self.assertIn("authorizationId", seen[0], "the tool must see the signed request, not {}")
        self.assertEqual(governance_headers(), {})

    def test_a_sync_function_that_returns_a_coroutine_keeps_the_handoff_until_it_is_awaited(self) -> None:
        seen: list = []

        async def inner(vendor: str, amount: float) -> dict:
            seen.append(governance_headers().get("x-magp-request", ""))
            return {"ok": True}

        async def run() -> dict:
            return await guard_tool(self.client, "flight-purchase", lambda vendor, amount: inner(vendor, amount), CTX)("skyward-air", 100)

        self.assertEqual(asyncio.run(run()), {"ok": True})
        self.assertIn("authorizationId", seen[0])
        self.assertEqual(governance_headers(), {})

    def test_an_async_generator_tool_is_refused_at_wrap_time(self) -> None:
        async def stream(vendor: str, amount: float):  # noqa: ANN202
            yield 1

        with self.assertRaises(TypeError):
            guard_tool(self.client, "flight-purchase", stream, CTX)

    def test_cancelling_an_async_guarded_call_releases_the_hold_it_created(self) -> None:
        """The gate call runs in a worker thread that cannot be stopped: if it permits after the caller has gone,
        the hold must be released, or the budget stays reserved until its TTL with nothing holding a handle to it."""
        self.gate.delay = 0.6
        ran: list = []

        async def tool(vendor: str, amount: float) -> dict:
            ran.append(1)
            return {"ok": True}

        async def run() -> None:
            guarded = guard_tool(self.client, "flight-purchase", tool, CTX)
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(guarded("skyward-air", 100), timeout=0.1)
            await asyncio.sleep(1.5)  # let the worker finish, the callback fire, and the void land

        asyncio.run(run())
        self.assertEqual(ran, [], "the tool never ran")
        states = [h["state"] for h in self.gate.holds.values()]
        self.assertEqual(states, ["voided"], f"the permitted-but-abandoned hold must be released, got {states}")

    def test_a_refusal_while_cancelled_does_not_leak_or_raise_unretrieved_errors(self) -> None:
        async def tool(vendor: str, amount: float) -> dict:
            return {"ok": True}

        self.gate.delay = 0.3

        async def run() -> None:
            guarded = guard_tool(self.client, "permissions.update", tool, CTX)  # not granted: the gate blocks
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(guarded("skyward-air", 100), timeout=0.05)
            await asyncio.sleep(0.8)

        asyncio.run(run())
        self.assertEqual(self.gate.holds, {})
        with self.assertRaises(GovernanceBlocked):
            asyncio.run(guard_tool(self.client, "permissions.update", tool, CTX)("skyward-air", 100))


if __name__ == "__main__":
    unittest.main()
