"""A hold the tool's gateway claimed is the gateway's to settle (0.16.0; pre-beta rerun 4, F-3).

Before: guard_tool captured every hold of a call that ran, at the full authorized amount. When the tool was a gateway that
claimed the hold and settles it itself, the agent's capture raced the gateway's: landing first, it was recorded
`unattested` and the gateway's real (possibly lower) charge was refused. Each case talks to `fake_gate.py`.
"""

from __future__ import annotations

import unittest

from _support import new_agent_key
from fake_gate import FakeGate
from metamynd_client import MetaMyndClient, guard_tool

FLIGHT = lambda airline, amount: {"amount": amount, "merchant": airline, "context": {"riskLevel": "low"}}  # noqa: E731


class SettleRace(unittest.TestCase):
    def setUp(self) -> None:
        key, seed = new_agent_key()
        self.gate = FakeGate(key.public_key())
        self.client = MetaMyndClient(self.gate.start(), "did:key:z6MkSettleRace", seed, timeout=5)

    def tearDown(self) -> None:
        self.gate.stop()

    def test_a_hold_the_gateway_claimed_is_left_to_the_gateway(self) -> None:
        def gateway_call(airline: str, amount: float) -> str:
            # What a scaffolded gateway does before it runs the tool: claim the hold it was handed.
            (auth_id,) = list(self.gate.holds)
            self.gate.holds[auth_id]["claimed"] = True
            return "booked"

        book = guard_tool(self.client, "flight-purchase", gateway_call, FLIGHT)
        self.assertEqual(book("skyward-air", 120), "booked")
        self.assertEqual([h["state"] for h in self.gate.holds.values()], ["held"], "the agent did not capture the gateway's hold")

    def test_an_unclaimed_hold_of_a_tool_that_ran_is_still_captured(self) -> None:
        book = guard_tool(self.client, "flight-purchase", lambda airline, amount: "ran", FLIGHT)
        book("skyward-air", 120)
        self.assertEqual([h["state"] for h in self.gate.holds.values()], ["captured"])


if __name__ == "__main__":
    unittest.main()
