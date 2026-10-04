"""An unreachable gate carries a machine-readable code (L-g, 2026-10-03 pre-beta rerun).

It used to be a bare RuntimeError("gate unreachable ...") with no reason code, so a framework tool crashed the turn and an
agent could not tell "the gate is down" from any other failure. It is now `GateUnreachable` (still a RuntimeError), and a
guarded tool treats it as what it is — a block, `GATE_UNREACHABLE`, fail closed — like the Node guard does.
"""

from __future__ import annotations

import asyncio
import socket
import unittest

from _support import new_agent_key
from metamynd_client import GateUnreachable, GovernanceBlocked, GovernanceRefusal, MetaMyndClient, guard_agent_tool, guard_tool


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class GateUnreachableCode(unittest.TestCase):
    def setUp(self) -> None:
        _key, seed = new_agent_key()
        self.client = MetaMyndClient(f"http://127.0.0.1:{_closed_port()}/api/v1", "did:key:z6MkDown", seed, timeout=2)
        self.ran = []

    def _tool(self, amount: float) -> dict:
        self.ran.append(amount)
        return {"ok": True}

    def test_authorize_raises_GateUnreachable_which_is_still_a_RuntimeError(self) -> None:
        with self.assertRaises(GateUnreachable) as ctx:
            self.client.authorize("flight-purchase", 10, merchant="skyward-air", context={"riskLevel": "low"})
        self.assertIsInstance(ctx.exception, RuntimeError)
        self.assertEqual(ctx.exception.reason_code, "GATE_UNREACHABLE")

    def test_guard_tool_raises_a_block_with_the_code(self) -> None:
        governed = guard_tool(self.client, "flight-purchase", self._tool, lambda amount: {"amount": amount, "merchant": "m"})
        with self.assertRaises(GovernanceBlocked) as ctx:
            governed(amount=10)
        self.assertEqual((ctx.exception.verdict.decision, ctx.exception.verdict.reason_code), ("block", "GATE_UNREACHABLE"))
        self.assertIsInstance(ctx.exception.__cause__, GateUnreachable)
        self.assertEqual(self.ran, [], "fail closed: the tool never ran")

    def test_an_agent_tool_returns_the_refusal_the_model_can_read(self) -> None:
        governed = guard_agent_tool(self.client, "flight-purchase", self._tool, lambda amount: {"amount": amount, "merchant": "m"})
        result = governed(amount=10)
        self.assertIsInstance(result, GovernanceRefusal)
        self.assertEqual(result["reasonCode"], "GATE_UNREACHABLE")
        self.assertIn("may be retried later", result["message"])
        self.assertEqual(self.ran, [])

    def test_the_async_path_too(self) -> None:
        async def tool(amount: float) -> dict:
            self.ran.append(amount)
            return {"ok": True}

        governed = guard_agent_tool(self.client, "flight-purchase", tool, lambda amount: {"amount": amount, "merchant": "m"})
        result = asyncio.run(governed(amount=10))
        self.assertEqual(result["reasonCode"], "GATE_UNREACHABLE")
        self.assertEqual(self.ran, [])


if __name__ == "__main__":
    unittest.main()
