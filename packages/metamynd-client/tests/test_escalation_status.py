"""EscalationStatus reports what became of an approval (0.21.0, pre-beta rerun 6 resume-status nit).

The gate keeps `status: approved` after the approved action ran, because SDKs key on it, and adds `executed`,
`executedAt` and `outcome` beside it. An older gate sends none of them: the properties are None, never a guess.
"""

from __future__ import annotations

import unittest

from metamynd_client import EscalationStatus


class EscalationExecution(unittest.TestCase):
    def test_a_current_gate_reports_execution_beside_approved(self) -> None:
        raw = {"status": "approved", "executed": True, "executedAt": "2026-10-06T00:30:00.000Z", "outcome": "settled"}
        s = EscalationStatus(status="approved", reason_code="ESCALATION_APPROVED", authorization_id="a1", raw=raw)
        self.assertTrue(s.may_proceed)
        self.assertIs(s.executed, True)
        self.assertEqual(s.executed_at, "2026-10-06T00:30:00.000Z")
        self.assertEqual(s.outcome, "settled")

    def test_an_older_gate_reports_nothing(self) -> None:
        s = EscalationStatus(status="approved", reason_code="ESCALATION_APPROVED", authorization_id="a1", raw={"status": "approved"})
        self.assertIsNone(s.executed)
        self.assertIsNone(s.executed_at)
        self.assertIsNone(s.outcome)

    def test_a_non_boolean_executed_is_not_trusted(self) -> None:
        s = EscalationStatus(status="approved", reason_code="X", raw={"executed": "yes"})
        self.assertIsNone(s.executed)


if __name__ == "__main__":
    unittest.main()
