"""Two processes resuming one approval run it once (0.17.0, MAGP 9a.6; pre-beta rerun 4, F-2).

Before: the client's resume lock was per client object, so two processes (two clients) resuming the same approved escalation
with an in-process tool both ran it. resume() now takes the one resume at the gate (MAGP-RESUME-CLAIM-v1) before running.
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


if __name__ == "__main__":
    unittest.main()
