"""What guard_tool does with the hold a permitted call was granted, and resuming an approved escalation (0.12.0).

Pre-beta rerun 3 (D-2/D-3/E-1): an unclaimed hold lapses with its TTL, so a tool that RAN handed its budget back after
15 minutes and a tool that FAILED kept it reserved until then; the examples stranded every hold they were granted; and an
approved escalation took ~15 lines of hand-written code to run. Each case here talks to `fake_gate.py`.
"""

from __future__ import annotations

import asyncio
import threading
import unittest

from _support import new_agent_key
from fake_gate import FakeGate
from metamynd_client import GovernanceBlocked, MetaMyndClient, ToolNotExecuted, governance_headers, guard_agent_tool, guard_tool

FLIGHT = lambda airline, amount, risk="low": {"amount": amount, "merchant": airline, "context": {"riskLevel": risk}}  # noqa: E731


class HoldSettlement(unittest.TestCase):
    def setUp(self) -> None:
        key, seed = new_agent_key()
        self.gate = FakeGate(key.public_key())
        self.client = MetaMyndClient(self.gate.start(), "did:key:z6MkHolds", seed, timeout=5)

    def tearDown(self) -> None:
        self.gate.stop()

    def states(self) -> "list[str]":
        return [h["state"] for h in self.gate.holds.values()]

    def test_a_tool_that_ran_has_its_hold_captured(self) -> None:
        book = guard_tool(self.client, "flight-purchase", lambda airline, amount: {"pnr": "P1"}, FLIGHT)
        self.assertEqual(book("skyward-air", 120), {"pnr": "P1"})
        self.assertEqual(self.states(), ["captured"])

    def test_settle_none_leaves_the_hold_alone(self) -> None:
        book = guard_tool(self.client, "flight-purchase", lambda airline, amount: "ok", FLIGHT, settle="none")
        book("skyward-air", 120)
        self.assertEqual(self.states(), ["held"])

    def test_a_downstream_refusal_releases_the_hold_and_still_raises(self) -> None:
        def refused_by_gateway(airline: str, amount: float) -> None:
            from metamynd_client import Verdict

            raise GovernanceBlocked(Verdict(decision="block", reason_code="AGENT_NOT_ADMITTED"), "flight-purchase")

        book = guard_tool(self.client, "flight-purchase", refused_by_gateway, FLIGHT)
        with self.assertRaises(GovernanceBlocked):
            book("skyward-air", 80)
        self.assertEqual(self.states(), ["voided"])

    def test_tool_not_executed_releases_any_other_error_keeps_the_hold(self) -> None:
        def nothing_ran(airline: str, amount: float) -> None:
            raise ToolNotExecuted("validation failed before the call")

        def may_have_run(airline: str, amount: float) -> None:
            raise ConnectionError("socket closed after the request was sent")

        with self.assertRaises(ToolNotExecuted):
            guard_tool(self.client, "flight-purchase", nothing_ran, FLIGHT)("skyward-air", 10)
        with self.assertRaises(ConnectionError):
            guard_tool(self.client, "flight-purchase", may_have_run, FLIGHT)("skyward-air", 10)
        self.assertEqual(sorted(self.states()), ["held", "voided"], "the ambiguous failure keeps its hold")

    def test_release_on_error_opts_in(self) -> None:
        def upstream_422(airline: str, amount: float) -> None:
            err = RuntimeError("422")
            err.status = 422  # type: ignore[attr-defined]
            raise err

        for flag in (True, lambda e: getattr(e, "status", None) == 422):
            with self.assertRaises(RuntimeError):
                guard_tool(self.client, "flight-purchase", upstream_422, FLIGHT, release_on_error=flag)("skyward-air", 10)
        with self.assertRaises(RuntimeError):
            guard_tool(self.client, "flight-purchase", upstream_422, FLIGHT, release_on_error=lambda e: False)("skyward-air", 10)
        self.assertEqual(sorted(self.states()), ["held", "voided", "voided"])

    def test_async_tools_settle_the_same_way(self) -> None:
        async def ran(airline: str, amount: float) -> str:
            return "ok"

        async def nothing_ran(airline: str, amount: float) -> None:
            raise ToolNotExecuted("no")

        async def go() -> None:
            await guard_tool(self.client, "flight-purchase", ran, FLIGHT)("skyward-air", 10)
            with self.assertRaises(ToolNotExecuted):
                await guard_tool(self.client, "flight-purchase", nothing_ran, FLIGHT)("skyward-air", 10)

        asyncio.run(go())
        self.assertEqual(sorted(self.states()), ["captured", "voided"])

    def test_guard_agent_tool_settles_too(self) -> None:
        book = guard_agent_tool(self.client, "flight-purchase", lambda airline, amount: "ok", FLIGHT)
        book("skyward-air", 10)
        self.assertEqual(self.states(), ["captured"])

    def test_a_refusal_from_a_nested_guarded_call_keeps_the_outer_hold(self) -> None:
        raise_limit = guard_tool(self.client, "permissions.update", lambda: None, lambda: {"amount": 0, "context": {"riskLevel": "low"}})

        def books_then_asks_for_more(airline: str, amount: float) -> None:
            # ...the booking happened here, then the tool asks for something it was never granted...
            raise_limit()

        with self.assertRaises(GovernanceBlocked):
            guard_tool(self.client, "flight-purchase", books_then_asks_for_more, FLIGHT)("skyward-air", 30)
        self.assertEqual(self.states(), ["held"], "the outer tool may have acted: its hold is neither released nor captured")

    def test_bad_options_are_refused_at_wrap_time(self) -> None:
        with self.assertRaises(ValueError):
            guard_tool(self.client, "flight-purchase", lambda: None, settle="capturee")
        with self.assertRaises(ValueError):
            guard_tool(self.client, "flight-purchase", lambda: None, release_on_error="yes")


class Resume(unittest.TestCase):
    def setUp(self) -> None:
        key, seed = new_agent_key()
        self.gate = FakeGate(key.public_key())
        self.client = MetaMyndClient(self.gate.start(), "did:key:z6MkResume", seed, timeout=5)

    def tearDown(self) -> None:
        self.gate.stop()

    def test_an_approved_escalation_runs_once_with_a_fresh_signed_request_carrying_the_approval(self) -> None:
        seen = []

        def book_flight(airline: str, amount: float, risk: str) -> str:
            seen.append(governance_headers())
            return "booked"

        book = guard_tool(self.client, "flight-purchase", book_flight, FLIGHT, resume_timeout=5)
        with self.assertRaises(GovernanceBlocked) as held:
            book("skyward-air", 90, "high")
        esc = held.exception.verdict.escalation_id
        self.assertTrue(esc)
        self.assertEqual(seen, [], "nothing ran while held")
        threading.Timer(0.3, self.gate.approve, args=(esc,)).start()
        self.assertEqual(book.resume(esc, "skyward-air", 90, "high"), "booked")
        self.assertEqual(len(seen), 1)
        self.assertIn(self.gate.escalations[esc]["authorizationId"], seen[0]["x-magp-request"])
        self.assertEqual(self.gate.holds[self.gate.escalations[esc]["authorizationId"]]["state"], "captured")
        # Once only: the approval's authorization is used now, so a second resume never touches the tool.
        with self.assertRaises(GovernanceBlocked) as again:
            book.resume(esc, "skyward-air", 90, "high")
        self.assertEqual(again.exception.verdict.reason_code, "AUTHORIZATION_ALREADY_USED")
        self.assertEqual(len(seen), 1)

    def test_a_modified_or_undecided_escalation_never_runs_the_tool(self) -> None:
        ran = []
        book = guard_tool(self.client, "flight-purchase", lambda airline, amount, risk: ran.append(1), FLIGHT, resume_timeout=0.2)
        with self.assertRaises(GovernanceBlocked) as held:
            book("skyward-air", 90, "high")
        esc = held.exception.verdict.escalation_id
        with self.assertRaises(GovernanceBlocked) as pending:
            book.resume(esc, "skyward-air", 90, "high")
        self.assertEqual(pending.exception.verdict.decision, "escalate")
        self.gate.modify(esc)
        with self.assertRaises(GovernanceBlocked) as modified:
            book.resume(esc, "skyward-air", 90, "high")
        self.assertEqual(modified.exception.verdict.decision, "block")
        self.assertEqual(ran, [])

    def test_async_resume(self) -> None:
        async def book_flight(airline: str, amount: float, risk: str) -> str:
            return "booked"

        book = guard_tool(self.client, "flight-purchase", book_flight, FLIGHT, resume_timeout=5)

        async def go() -> str:
            try:
                await book("skyward-air", 90, "high")
            except GovernanceBlocked as held:
                esc = held.verdict.escalation_id
            self.gate.approve(esc)
            return await book.resume(esc, "skyward-air", 90, "high")

        self.assertEqual(asyncio.run(go()), "booked")



class OrphanAndRace(unittest.TestCase):
    """0.13.0: a hold minted for a request whose answer never came is found and released; concurrent resumes are refused."""

    def setUp(self) -> None:
        key, seed = new_agent_key()
        self.gate = FakeGate(key.public_key())
        self.base = self.gate.start()
        self.seed = seed

    def tearDown(self) -> None:
        self.gate.stop()

    def test_a_hold_the_gate_committed_after_the_client_timed_out_is_released(self) -> None:
        import time

        from metamynd_client import GateUnreachable

        client = MetaMyndClient(self.base, "did:key:z6MkOrphan", self.seed, timeout=0.3, orphan_release_delays=(0.6, 0.6, 1.0))
        self.gate.delay = 0.5  # the gate answers after the client has given up — and commits the hold anyway
        with self.assertRaises(GateUnreachable):
            client.authorize("flight-purchase", 40, merchant="skyward-air", context={"riskLevel": "low"})
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not any(h["state"] == "voided" for h in self.gate.holds.values()):
            time.sleep(0.1)
        self.assertEqual([h["state"] for h in self.gate.holds.values()], ["voided"], "the orphaned hold was released, signed")

    def test_orphan_release_can_be_turned_off(self) -> None:
        import time

        from metamynd_client import GateUnreachable

        client = MetaMyndClient(self.base, "did:key:z6MkOrphanOff", self.seed, timeout=0.3, orphan_release_delays=())
        self.gate.delay = 0.5
        with self.assertRaises(GateUnreachable):
            client.authorize("flight-purchase", 40, merchant="skyward-air", context={"riskLevel": "low"})
        time.sleep(1.0)
        self.assertEqual([h["state"] for h in self.gate.holds.values()], ["held"])

    def test_a_concurrent_resume_of_the_same_escalation_is_refused_in_use(self) -> None:
        client = MetaMyndClient(self.base, "did:key:z6MkRace", self.seed, timeout=5)
        started, release = threading.Event(), threading.Event()
        runs = []

        def slow_tool(airline: str, amount: float, risk: str) -> str:
            runs.append(1)
            started.set()
            release.wait(5)
            return "booked"

        book = guard_tool(client, "flight-purchase", slow_tool, FLIGHT, resume_timeout=5)
        with self.assertRaises(GovernanceBlocked) as held:
            book("skyward-air", 90, "high")
        esc = held.exception.verdict.escalation_id
        self.gate.approve(esc)
        first: dict = {}
        t = threading.Thread(target=lambda: first.setdefault("r", book.resume(esc, "skyward-air", 90, "high")))
        t.start()
        self.assertTrue(started.wait(5))
        with self.assertRaises(GovernanceBlocked) as second:
            book.resume(esc, "skyward-air", 90, "high")
        self.assertEqual(second.exception.verdict.reason_code, "AUTHORIZATION_IN_USE")
        release.set()
        t.join(5)
        self.assertEqual(first.get("r"), "booked")
        self.assertEqual(len(runs), 1)


if __name__ == "__main__":
    unittest.main()
