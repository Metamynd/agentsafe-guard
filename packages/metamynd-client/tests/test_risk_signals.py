"""A refusal names the risk the issuer derived (0.15.0; pre-beta rerun 4, F-4).

Before: a "low" $105 payment on a $150 cap came back escalate/RISK_REVIEW exactly like a call the agent itself flagged high,
and nothing told the agent (or the model reading the refusal) that the gate had derived the risk. The gate now returns
`riskSignals`; `Verdict.risk_signals` exposes them and the refusal message a model reads names them.
"""

from __future__ import annotations

import unittest

from metamynd_client import GovernanceBlocked, GovernanceRefusal, Verdict, _refusal_message

SIGNAL = {"signal": "amount-share", "level": "high", "detail": "70% of the 150 per-transaction cap (review from 70%)"}


def escalated(**extra: object) -> Verdict:
    return Verdict.from_response({"data": {"decision": "escalate", "reasonCode": "RISK_REVIEW", "escalationId": "esc-1", **extra}})


class RiskSignals(unittest.TestCase):
    def test_an_issuer_derived_escalation_names_its_cause(self) -> None:
        v = escalated(riskSignals=[SIGNAL])
        self.assertEqual(v.risk_signals, [SIGNAL])
        message = _refusal_message(v, "flight-purchase")
        self.assertIn("Risk derived by the issuer: amount-share: 70% of the 150 per-transaction cap", message)
        refusal = GovernanceRefusal(v, "flight-purchase")
        self.assertEqual(refusal["riskSignals"], [SIGNAL])
        self.assertIn("amount-share", refusal["message"])

    def test_an_escalation_the_agent_asked_for_says_nothing_more(self) -> None:
        v = escalated()
        self.assertEqual(v.risk_signals, [])
        self.assertNotIn("derived", _refusal_message(v, "flight-purchase"))
        self.assertNotIn("riskSignals", GovernanceRefusal(v, "flight-purchase"), "every other refusal keeps its shape")

    def test_the_raised_exception_names_it_too(self) -> None:
        # FW N-1 (pre-beta rerun 5): Node's thrown message named the derived risk, Python's raised one did not.
        raised = str(GovernanceBlocked(escalated(riskSignals=[SIGNAL]), "flight-purchase"))
        self.assertIn("escalate/RISK_REVIEW (risk derived by the issuer: amount-share: 70% of the 150 per-transaction cap", raised)
        self.assertEqual(str(GovernanceBlocked(escalated(), "flight-purchase")), "flight-purchase refused: escalate/RISK_REVIEW")

    def test_anything_that_is_not_a_list_of_objects_is_ignored(self) -> None:
        self.assertEqual(escalated(riskSignals="high").risk_signals, [])
        self.assertEqual(escalated(riskSignals=["high", SIGNAL]).risk_signals, [SIGNAL])


if __name__ == "__main__":
    unittest.main()
