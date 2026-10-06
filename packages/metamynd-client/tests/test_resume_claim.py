"""Two processes resuming one approval run it once (0.17.0, MAGP 9a.6; pre-beta rerun 4, F-2).

Before: the client's resume lock was per client object, so two processes (two clients) resuming the same approved escalation
with an in-process tool both ran it. resume() now takes the one resume at the gate (MAGP-RESUME-CLAIM-v1; v2 since 0.19.0, binding the approved request and
context — pre-beta rerun 6 F-1-NF-R) before running.
"""

from __future__ import annotations

import threading
import unittest

from _support import new_agent_key
from fake_gate import FakeGate
from metamynd_client import GovernanceBlocked, MetaMyndClient, guard_tool

FLIGHT = lambda airline, amount: {"amount": amount, "merchant": airline, "context": {"riskLevel": "high"}}  # noqa: E731


class ResumeClaim(unittest.TestCase):
    def setUp(self) -> None:
        key, self.seed = new_agent_key()
        self.gate = FakeGate(key.public_key())
        self.api = self.gate.start()
        self.ran: list = []
        self.lock = threading.Lock()

    def tearDown(self) -> None:
        self.gate.stop()

    def process(self) -> "object":
        """A separate process: its own client, its own wrapped tool (so its own in-process lock)."""
        client = MetaMyndClient(self.api, "did:key:z6MkResumeClaim", self.seed, timeout=5)

        def book(airline: str, amount: float) -> str:
            with self.lock:
                self.ran.append((airline, amount))
            return "booked"

        return guard_tool(client, "flight-purchase", book, FLIGHT, resume_timeout=2)

    def approved(self) -> str:
        with self.assertRaises(GovernanceBlocked) as held:
            self.process()("skyward-air", 90)
        esc = held.exception.verdict.escalation_id
        self.gate.approve(esc)
        return esc

    def test_two_processes_resuming_at_once_run_the_tool_once(self) -> None:
        esc = self.approved()
        a, b = self.process(), self.process()
        outcomes: list = []

        def resume(tool: "object") -> None:
            try:
                outcomes.append(tool.resume(esc, "skyward-air", 90))
            except GovernanceBlocked as refused:
                outcomes.append(refused.verdict.reason_code)

        threads = [threading.Thread(target=resume, args=(t,)) for t in (a, b)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(self.ran), 1, "the tool ran once")
        self.assertIn("booked", outcomes)
        # The loser is refused either way: IN_USE when it reached the claim while the winner held it, ALREADY_USED when the
        # winner had already finished and settled before the loser looked.
        (refused,) = [o for o in outcomes if o != "booked"]
        self.assertIn(refused, ("AUTHORIZATION_IN_USE", "AUTHORIZATION_ALREADY_USED"))

    def test_a_gate_without_the_resume_claim_resumes_as_before(self) -> None:
        self.gate.resume_claims = False
        esc = self.approved()
        self.assertEqual(self.process().resume(esc, "skyward-air", 90), "booked")
    # ---- F-1-NF-R (0.19.0, pre-beta rerun 6): the claim binds the approved request and context at the GATE -----------------

    def claims(self) -> list:
        return [b for p, b in zip(self.gate.paths, self.gate.bodies) if p.endswith("/resume-claim")]

    def test_a_v2_gate_gets_a_v2_claim_carrying_the_digests_of_the_call(self) -> None:
        esc = self.approved()
        self.assertEqual(self.process().resume(esc, "skyward-air", 90), "booked")
        (claim,) = self.claims()
        status = self.gate.get(f"/policy/escalations/{esc}/status")[1]["data"]
        self.assertEqual(claim["requestDigest"], status["requestDigest"])
        self.assertEqual(claim["contextDigest"], status["contextDigest"])

    def test_an_outdated_v1_claim_of_an_approval_is_refused_and_takes_nothing(self) -> None:
        # What metamynd-client <= 0.18 sends: MAGP-RESUME-CLAIM-v1, no digests.
        esc = self.approved()
        client = MetaMyndClient(self.api, "did:key:z6MkResumeClaim", self.seed, timeout=5)
        auth = self.gate.escalations[esc]["authorizationId"]
        self.assertEqual(client.claim_resume(esc, auth), "AUTHORIZATION_CONTEXT_REQUIRED")
        self.assertEqual(self.process().resume(esc, "skyward-air", 90), "booked", "the resume is still there for an upgraded SDK")

    def test_the_gate_refuses_an_altered_context_the_sdk_could_not_check(self) -> None:
        # A status without contextDigest leaves the SDK nothing to compare; the claim still states the context of the call.
        self.gate.context_binding = False
        client = MetaMyndClient(self.api, "did:key:z6MkResumeClaim", self.seed, timeout=5)
        record = guard_tool(client, "flight-purchase", lambda target, op: self.ran.append((target, op)),
                            lambda target, op: {"amount": 90, "merchant": "skyward-air", "context": {"riskLevel": "high", "target": target, "op": op}},
                            resume_timeout=2)
        with self.assertRaises(GovernanceBlocked) as held:
            record("record-A", "read")
        esc = held.exception.verdict.escalation_id
        self.gate.approve(esc)
        with self.assertRaises(GovernanceBlocked) as refused:
            record.resume(esc, "record-B", "delete-all")
        self.assertEqual(refused.exception.verdict.reason_code, "AUTHORIZATION_CONTEXT_MISMATCH")
        self.assertEqual(self.ran, [], "nothing ran")
        record.resume(esc, "record-A", "read")
        self.assertEqual(self.ran, [("record-A", "read")])

    def test_a_gate_that_knows_only_v1_gets_v1(self) -> None:
        self.gate.resume_claim_version = None
        esc = self.approved()
        self.assertEqual(self.process().resume(esc, "skyward-air", 90), "booked")
        (claim,) = self.claims()
        self.assertNotIn("requestDigest", claim)


if __name__ == "__main__":
    unittest.main()
