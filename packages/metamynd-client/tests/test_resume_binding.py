"""resume() runs only the request the owner approved (0.14.0, MAGP 9a.5; pre-beta rerun 4, F-1).

Before: resume() signed and ran whatever args it was given under the approval's authorization. An owner approved $5 to
skyward-air; resume(..., 5000) or resume with merchant 'shadow-broker' ran an in-process tool while the ledger recorded $5.
The gate now returns `requestDigest` with an approved status, and resume() refuses arguments that do not reproduce it.
"""

from __future__ import annotations

import json
import pathlib
import unittest

from _support import new_agent_key
from fake_gate import FakeGate
from metamynd_client import GovernanceBlocked, MetaMyndClient, approved_context_digest, guard_agent_tool, guard_tool, resume_request_digest

VECTORS = pathlib.Path(__file__).resolve().parents[3] / "docs" / "protocol" / "resume-binding-vectors.json"
FLIGHT = lambda airline, amount, risk="high": {"amount": amount, "merchant": airline, "context": {"riskLevel": risk},  # noqa: E731
                                               "payload": {"amount": amount, "merchant": airline, "currency": "USD"}}


class Vectors(unittest.TestCase):
    def test_reproduces_every_vector(self) -> None:
        for v in json.loads(VECTORS.read_text(encoding="utf-8"))["vectors"]:
            f = v["fields"]
            with self.subTest(v["name"]):
                self.assertEqual(resume_request_digest(f["authorizationId"], f["action"], f.get("amount"), f.get("currency"),
                                                       f.get("merchant"), f.get("resource"), f.get("payloadDigest")), v["digest"])

    def test_reproduces_every_context_vector(self) -> None:
        for v in json.loads(VECTORS.read_text(encoding="utf-8"))["contextVectors"]:
            with self.subTest(v["name"]):
                self.assertEqual(approved_context_digest(v["context"]), v["digest"])


class ResumeBinding(unittest.TestCase):
    def setUp(self) -> None:
        key, seed = new_agent_key()
        self.gate = FakeGate(key.public_key())
        self.client = MetaMyndClient(self.gate.start(), "did:key:z6MkResumeBind", seed, timeout=5)
        self.ran: list = []
        self.book = guard_tool(self.client, "flight-purchase", lambda airline, amount, risk="high": self.ran.append((airline, amount)) or "booked",
                               FLIGHT, resume_timeout=2)

    def tearDown(self) -> None:
        self.gate.stop()

    def approved_escalation(self) -> str:
        with self.assertRaises(GovernanceBlocked) as held:
            self.book("skyward-air", 5)
        esc = held.exception.verdict.escalation_id
        self.gate.approve(esc)
        return esc

    def test_the_approved_args_run(self) -> None:
        esc = self.approved_escalation()
        self.assertEqual(self.book.resume(esc, "skyward-air", 5), "booked")
        self.assertEqual(self.ran, [("skyward-air", 5)])

    def test_other_args_are_refused_and_the_tool_never_runs(self) -> None:
        for airline, amount in [("skyward-air", 5000), ("skyward-air", 4), ("shadow-broker", 5)]:
            with self.subTest(airline=airline, amount=amount):
                esc = self.approved_escalation()
                with self.assertRaises(GovernanceBlocked) as refused:
                    self.book.resume(esc, airline, amount)
                self.assertEqual(refused.exception.verdict.reason_code, "ESCALATION_REQUEST_MISMATCH")
                self.assertEqual(refused.exception.verdict.decision, "block")
                self.assertEqual(self.ran, [])
                hold = self.gate.holds[self.gate.escalations[esc]["authorizationId"]]
                self.assertEqual(hold["state"], "held", "the approved hold is left for the right request")

    def test_the_approved_context_is_bound_too_its_risk_level_included(self) -> None:
        # F-1-NF (0.18.0): the context the owner approved is bound, so a resume that lowers the agent's risk claim is refused.
        esc = self.approved_escalation()
        with self.assertRaises(GovernanceBlocked) as refused:
            self.book.resume(esc, "skyward-air", 5, "low")
        self.assertEqual(refused.exception.verdict.reason_code, "ESCALATION_REQUEST_MISMATCH")
        self.assertEqual(self.ran, [])
        self.assertEqual(self.book.resume(esc, "skyward-air", 5, "high"), "booked")

    def test_a_gate_that_predates_the_context_binding_checks_what_it_can(self) -> None:
        self.gate.context_binding = False
        esc = self.approved_escalation()
        self.assertEqual(self.book.resume(esc, "skyward-air", 5, "low"), "booked")

    def test_guard_agent_tool_refuses_too(self) -> None:
        tool = guard_agent_tool(self.client, "flight-purchase", lambda airline, amount, risk="high": self.ran.append(1) or "booked", FLIGHT, resume_timeout=2)
        esc = self.approved_escalation()
        out = tool.resume(esc, "skyward-air", 5000)
        self.assertIn("ESCALATION_REQUEST_MISMATCH", str(out))
        self.assertEqual(self.ran, [])

    def test_a_gate_that_predates_request_digest_resumes_as_before(self) -> None:
        self.gate.resume_binding = False
        esc = self.approved_escalation()
        self.assertEqual(self.book.resume(esc, "skyward-air", 5000), "booked")


class ValuelessContextBinding(unittest.TestCase):
    """F-1-NF (pre-beta rerun 5): an approval of read record-A was resumed as delete-all record-B and ran."""

    def setUp(self) -> None:
        key, seed = new_agent_key()
        self.gate = FakeGate(key.public_key(), grants={"perform-action": 0.0})
        self.client = MetaMyndClient(self.gate.start(), "did:key:z6MkResumeCtx", seed, timeout=5)
        self.ran: list = []
        self.act = guard_tool(self.client, "perform-action", lambda target, op: self.ran.append((target, op)) or "done",
                              lambda target, op: {"context": {"riskLevel": "high", "target": target, "op": op}}, resume_timeout=2)

    def tearDown(self) -> None:
        self.gate.stop()

    def test_an_altered_operation_is_refused_and_nothing_runs(self) -> None:
        with self.assertRaises(GovernanceBlocked) as held:
            self.act("record-A", "read")
        esc = held.exception.verdict.escalation_id
        self.gate.approve(esc)
        with self.assertRaises(GovernanceBlocked) as refused:
            self.act.resume(esc, "record-B", "delete-all")
        self.assertEqual(refused.exception.verdict.reason_code, "ESCALATION_REQUEST_MISMATCH")
        self.assertEqual(self.ran, [])
        self.assertEqual(self.act.resume(esc, "record-A", "read"), "done")
        self.assertEqual(self.ran, [("record-A", "read")])


if __name__ == "__main__":
    unittest.main()
