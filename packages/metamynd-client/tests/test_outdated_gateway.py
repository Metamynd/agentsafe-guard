"""An approval resumed through a gateway that predates the approved-context binding (0.20.0; pre-beta rerun 6, FW6-1).

Before: the old gateway's claim was refused AUTHORIZATION_CONTEXT_REQUIRED (nothing ran there), the tool relayed that
refusal, and resume() VOIDED the approved hold as "tool did not run". The resume after upgrading the gateway then said
AUTHORIZATION_ALREADY_USED — wrong, it was voided — and the owner had to approve the same request again. Now the hold is
kept, the exception says which gateway to upgrade, the gate re-opens the one resume, and a voided approval is reported
AUTHORIZATION_VOIDED.
"""

from __future__ import annotations

import unittest
import warnings

from _support import new_agent_key
from fake_gate import FakeGate
from metamynd_client import GovernanceBlocked, MetaMyndClient, Verdict, guard_tool

FLIGHT = lambda airline, amount: {"amount": amount, "merchant": airline, "context": {"riskLevel": "high"}}  # noqa: E731


class OutdatedGateway(unittest.TestCase):
    def setUp(self) -> None:
        key, self.seed = new_agent_key()
        self.gate = FakeGate(key.public_key())
        self.api = self.gate.start()
        self.client = MetaMyndClient(self.api, "did:key:z6MkOutdatedGateway", self.seed, timeout=5)
        self.gateway = {"outdated": True, "ran": 0, "code": "AUTHORIZATION_CONTEXT_REQUIRED"}

    def tearDown(self) -> None:
        self.gate.stop()

    def tool(self) -> "object":
        gate, gateway = self.gate, self.gateway

        def book(airline: str, amount: float) -> str:
            if gateway["outdated"]:
                if gateway["code"] == "AUTHORIZATION_CONTEXT_REQUIRED":
                    # What the real gate does for a signed claim refused this way (escalation.repository reopenResume).
                    for e in gate.escalations.values():
                        e["resumeClaimed"] = False
                raise GovernanceBlocked(Verdict(decision="block", reason_code=gateway["code"]), "flight-purchase")
            gateway["ran"] += 1
            return "booked"

        return guard_tool(self.client, "flight-purchase", book, FLIGHT, resume_timeout=2)

    def approved(self) -> "tuple[str, str]":
        with self.assertRaises(GovernanceBlocked) as held:
            self.tool()("skyward-air", 90)
        esc = held.exception.verdict.escalation_id
        self.gate.approve(esc)
        return esc, self.gate.escalations[esc]["authorizationId"]

    def test_the_reproduced_defect_the_approved_hold_is_kept_and_the_error_names_the_upgrade(self) -> None:
        esc, auth = self.approved()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            with self.assertRaises(GovernanceBlocked) as refused:
                self.tool().resume(esc, "skyward-air", 90)
        exc = refused.exception
        self.assertEqual(exc.verdict.reason_code, "AUTHORIZATION_CONTEXT_REQUIRED")
        self.assertEqual(self.gate.holds[auth]["state"], "held", "the approval's hold is not voided")
        self.assertTrue(exc.upgrade_required)
        self.assertTrue(exc.hold_kept)
        self.assertIn("agentsafe-mcp-guard >= 0.27.0", exc.detail)
        self.assertTrue(any("Upgrade it" in str(w.message) for w in caught))

    def test_after_the_upgrade_resume_runs_the_approval_once_without_a_second_approval(self) -> None:
        esc, _ = self.approved()
        tool = self.tool()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with self.assertRaises(GovernanceBlocked):
                tool.resume(esc, "skyward-air", 90)
        self.gateway["outdated"] = False
        self.assertEqual(tool.resume(esc, "skyward-air", 90), "booked")
        self.assertEqual(self.gateway["ran"], 1)

    def test_any_other_downstream_refusal_still_releases_the_hold(self) -> None:
        esc, auth = self.approved()
        self.gateway["code"] = "AGENT_NOT_ADMITTED"
        with self.assertRaises(GovernanceBlocked) as refused:
            self.tool().resume(esc, "skyward-air", 90)
        self.assertEqual(self.gate.holds[auth]["state"], "voided")
        self.assertFalse(getattr(refused.exception, "upgrade_required", False))

    def test_a_voided_approval_is_reported_voided_not_already_used(self) -> None:
        esc, _ = self.approved()
        self.gateway["code"] = "AGENT_NOT_ADMITTED"
        with self.assertRaises(GovernanceBlocked):
            self.tool().resume(esc, "skyward-air", 90)  # an ordinary refusal: voided, as before
        self.gateway["outdated"] = False
        with self.assertRaises(GovernanceBlocked) as again:
            self.tool().resume(esc, "skyward-air", 90)
        self.assertEqual(again.exception.verdict.reason_code, "AUTHORIZATION_VOIDED")
        self.assertIn("approve the request again", again.exception.verdict.hint or "")
        self.assertEqual(self.gateway["ran"], 0)


if __name__ == "__main__":
    unittest.main()
