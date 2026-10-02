"""M-5: parallel SYNC tool calls, and `guard_tool(..., on_refusal=...)` (0.8.0).

PydanticAI and LangGraph's default `ToolNode` run the sync tool calls of one model turn in worker threads. A refused
call that RAISES aborts the turn, while the sibling calls already in their threads keep going: authorized, run, and
their results delivered to nobody. `on_refusal="return"` makes a refusal that call's RESULT instead, so the turn
completes and the model sees every outcome. Each test here pins one part of that; the LangGraph one runs the real
`ToolNode` when langgraph is installed.
"""

from __future__ import annotations

import asyncio
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor

from _support import new_agent_key
from fake_gate import FakeGate
from metamynd_client import GovernanceBlocked, GovernanceRefusal, MetaMyndClient, governance_headers, guard_tool

CTX = lambda vendor, amount: {"amount": amount, "merchant": vendor, "context": {"riskLevel": "low"}}  # noqa: E731
HIGH = lambda vendor, amount: {"amount": amount, "merchant": vendor, "context": {"riskLevel": "high"}}  # noqa: E731
NO_RISK = lambda vendor, amount: {"amount": amount, "merchant": vendor, "context": {"tool": "book-flight"}}  # noqa: E731


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        key, seed = new_agent_key()
        self.gate = FakeGate(key.public_key())
        self.client = MetaMyndClient(self.gate.start(), "did:key:z6MkParallel", seed, timeout=5)
        self.addCleanup(self.gate.stop)
        self.ran: list = []
        self._lock = threading.Lock()

    def tool(self, vendor: str, amount: float) -> dict:
        with self._lock:
            self.ran.append((vendor, amount, governance_headers().get("x-magp-request", "")))
        return {"pnr": "PNR-1", "vendor": vendor, "amount": amount}


class OnRefusalReturn(_Base):
    def test_a_sync_refusal_is_returned_as_a_json_ready_value_and_the_tool_never_runs(self) -> None:
        guarded = guard_tool(self.client, "permissions.update", self.tool, CTX, on_refusal="return")
        result = guarded("skyward-air", 100)
        self.assertIsInstance(result, GovernanceRefusal)
        self.assertIsInstance(result, dict)
        self.assertEqual(self.ran, [], "a refused tool must not run")
        self.assertEqual(result["refused"], True)
        self.assertEqual(result["action"], "permissions.update")
        self.assertEqual(result["decision"], "block")
        self.assertTrue(result["reasonCode"])
        self.assertFalse(result.verdict.permitted)
        # What a framework does with a tool result: serialise it. No signature, no verdict object, leaks into it.
        wire = json.loads(json.dumps(result))
        self.assertEqual(set(wire), {"refused", "action", "decision", "reasonCode", "escalationId", "message"})

    def test_an_escalate_is_returned_with_its_handle(self) -> None:
        result = guard_tool(self.client, "flight-purchase", self.tool, HIGH, on_refusal="return")("skyward-air", 100)
        self.assertIsInstance(result, GovernanceRefusal)
        self.assertEqual(result["decision"], "escalate")
        self.assertTrue(result["escalationId"], "an escalate carries its handle for wait_for_escalation")
        self.assertIn("held for a human", result["message"])
        self.assertEqual(self.ran, [])

    def test_a_call_that_states_no_risk_is_held_not_allowed(self) -> None:
        # M-4's counterpart: this client never invents a riskLevel, so a call without one reaches the gate as missing.
        result = guard_tool(self.client, "flight-purchase", self.tool, NO_RISK, on_refusal="return")("skyward-air", 100)
        self.assertIsInstance(result, GovernanceRefusal)
        self.assertEqual(result["decision"], "escalate")
        self.assertEqual(self.ran, [])

    def test_a_permit_still_runs_the_tool_and_returns_its_result(self) -> None:
        result = guard_tool(self.client, "flight-purchase", self.tool, CTX, on_refusal="return")("skyward-air", 100)
        self.assertEqual(result["pnr"], "PNR-1")
        self.assertNotIsInstance(result, GovernanceRefusal)
        self.assertEqual(len(self.ran), 1)
        self.assertIn("authorizationId", self.ran[0][2], "the handoff is unchanged on a permit")

    def test_an_async_refusal_is_returned_too(self) -> None:
        async def tool(vendor: str, amount: float) -> dict:
            self.ran.append(vendor)
            return {"ok": True}

        result = asyncio.run(guard_tool(self.client, "permissions.update", tool, CTX, on_refusal="return")("skyward-air", 100))
        self.assertIsInstance(result, GovernanceRefusal)
        self.assertEqual(self.ran, [])

    def test_the_default_still_raises(self) -> None:
        with self.assertRaises(GovernanceBlocked):
            guard_tool(self.client, "permissions.update", self.tool, CTX)("skyward-air", 100)
        self.assertEqual(self.ran, [])

    def test_a_callable_shapes_the_result(self) -> None:
        seen: list = []

        def explain(refused: GovernanceBlocked) -> str:
            seen.append(refused)
            return f"refused: {refused.verdict.reason_code}"

        result = guard_tool(self.client, "permissions.update", self.tool, CTX, on_refusal=explain)("skyward-air", 100)
        self.assertTrue(result.startswith("refused: "), result)
        self.assertIsInstance(seen[0], GovernanceBlocked)
        self.assertEqual(self.ran, [])

        async def explain_async(refused: GovernanceBlocked) -> str:
            return "async " + refused.verdict.decision

        async def tool(vendor: str, amount: float) -> dict:
            return {"ok": True}

        self.assertEqual(asyncio.run(guard_tool(self.client, "permissions.update", tool, CTX, on_refusal=explain_async)("skyward-air", 1)), "async block")

    def test_a_block_with_no_decision_from_the_gate_does_not_tell_the_model_never_to_retry(self) -> None:
        # A rate-limit or server error with a JSON body is read as block/UNKNOWN. That is "no decision", not a refusal of
        # this request, so the model must not be told the arguments were the problem.
        from metamynd_client import Verdict

        neutral = GovernanceRefusal(Verdict(decision="block", reason_code="UNKNOWN"), "book_flight")
        self.assertIn("did not give a decision", neutral["message"])
        self.assertNotIn("Do not retry", neutral["message"])
        real = GovernanceRefusal(Verdict(decision="block", reason_code="SOP_SPEND_CAP"), "book_flight")
        self.assertIn("Do not retry it with different arguments", real["message"])

    def test_an_unknown_mode_is_refused_at_wrap_time(self) -> None:
        with self.assertRaises(ValueError):
            guard_tool(self.client, "flight-purchase", self.tool, CTX, on_refusal="retrun")

    def test_an_unreachable_gate_still_raises_and_never_runs_the_tool(self) -> None:
        guarded = guard_tool(self.client, "flight-purchase", self.tool, CTX, on_refusal="return")
        self.gate.stop()
        with self.assertRaises(RuntimeError) as caught:
            guarded("skyward-air", 100)
        self.assertNotIsInstance(caught.exception, GovernanceBlocked)
        self.assertEqual(self.ran, [])


class ParallelSyncCalls(_Base):
    def test_parallel_sync_calls_all_complete_and_every_outcome_is_delivered(self) -> None:
        """The framework shape: one turn's calls mapped over a thread pool, results collected in order."""
        self.gate.delay = 0.2
        book = guard_tool(self.client, "flight-purchase", self.tool, CTX, on_refusal="return")
        raise_limit = guard_tool(self.client, "permissions.update", self.tool, CTX, on_refusal="return")
        calls = [(raise_limit, ("skyward-air", 100_000)), (book, ("skyward-air", 100)), (book, ("skyward-air", 150))]
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(lambda c: c[0](*c[1]), calls))  # pool.map re-raises the first exception: none here
        self.assertIsInstance(results[0], GovernanceRefusal)
        self.assertEqual([r["pnr"] for r in results[1:]], ["PNR-1", "PNR-1"])
        self.assertEqual(sorted(a for _, a, _ in self.ran), [100, 150], "the permitted siblings ran once each, and their results came back")

    def test_with_raise_the_first_refusal_aborts_collection_while_siblings_run_on(self) -> None:
        """The M-5 finding, pinned as the reason `on_refusal="return"` exists (default behaviour is unchanged)."""
        self.gate.delay = 0.2
        book = guard_tool(self.client, "flight-purchase", self.tool, CTX)
        raise_limit = guard_tool(self.client, "permissions.update", self.tool, CTX)
        with ThreadPoolExecutor(max_workers=2) as pool:
            with self.assertRaises(GovernanceBlocked):
                list(pool.map(lambda c: c[0](*c[1]), [(raise_limit, ("skyward-air", 1)), (book, ("skyward-air", 100))]))
        self.assertEqual([a for _, a, _ in self.ran], [100], "the sibling ran anyway; its result reached nobody")


class LangGraphToolNode(_Base):
    def test_toolnode_runs_parallel_sync_calls_and_returns_the_refusal_as_a_tool_message(self) -> None:
        try:
            from langchain_core.messages import AIMessage
            from langchain_core.tools import StructuredTool
            from langgraph.graph import END, START, MessagesState, StateGraph
            from langgraph.prebuilt import ToolNode
        except ImportError:
            self.skipTest("langgraph not installed")

        def book_flight(vendor: str, amount: float) -> dict:
            """Book a flight."""
            return self.tool(vendor, amount)

        def raise_own_limit(vendor: str, amount: float) -> dict:
            """Raise the agent's own limit."""
            return self.tool(vendor, amount)

        tools = [
            StructuredTool.from_function(guard_tool(self.client, "flight-purchase", book_flight, CTX, on_refusal="return")),
            StructuredTool.from_function(guard_tool(self.client, "permissions.update", raise_own_limit, CTX, on_refusal="return")),
        ]
        turn = AIMessage(content="", tool_calls=[
            {"name": "raise_own_limit", "args": {"vendor": "skyward-air", "amount": 100000}, "id": "c1"},
            {"name": "book_flight", "args": {"vendor": "skyward-air", "amount": 100}, "id": "c2"},
        ])
        graph = StateGraph(MessagesState)
        graph.add_node("tools", ToolNode(tools))  # default handle_tool_errors: a raised refusal would propagate out of invoke
        graph.add_edge(START, "tools")
        graph.add_edge("tools", END)
        out = graph.compile().invoke({"messages": [turn]})
        by_id = {m.tool_call_id: m for m in out["messages"] if getattr(m, "tool_call_id", None)}
        self.assertEqual(set(by_id), {"c1", "c2"}, "both calls answered")
        self.assertIn('"refused": true', by_id["c1"].content)
        self.assertIn("PNR-1", by_id["c2"].content)
        self.assertEqual([a for _, a, _ in self.ran], [100])


if __name__ == "__main__":
    unittest.main()
