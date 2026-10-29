"""The owner's argument policy in guard_tool (0.25.0, MAGP §8.3.14).

The gate names the action's policies on a permit (`argumentPolicies`) and on an approved escalation's status; guard_tool holds
the tool's arguments to them before the tool runs. A value outside `allow` is refused and the hold released; a `sensitive`
value reaches the tool redacted or keyed-hashed, with the same keyed hash the Node guards compute.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import shutil
import subprocess
import unittest

from _support import PACKAGE, new_agent_key
from fake_gate import FakeGate
from metamynd_client import (
    ArgumentRefusal,
    GovernanceBlocked,
    MetaMyndClient,
    canonical_payload,
    check_arguments,
    guard_tool,
    sanitize_arguments,
)

KEY = b"k" * 32
POLICY = {"allow": ["/to", "/lines/*/sku", "/lines/*/qty", "/note", "/iban"],
          "sensitive": [{"path": "/iban", "mode": "hmac"}, {"path": "/note", "mode": "redact"}]}
LOW = lambda *_a, **_kw: {"context": {"riskLevel": "low"}}  # noqa: E731
LINES = [{"sku": "X", "qty": 1}]
HIGH = lambda *_a, **_kw: {"context": {"riskLevel": "high"}}  # noqa: E731


def keyed(value: object) -> str:
    return "hmac-sha256:" + hmac.new(KEY, canonical_payload(value).encode("utf-8"), hashlib.sha256).hexdigest()


class PolicyFunctions(unittest.TestCase):
    def test_allowed_paths_pass_and_anything_else_names_its_path(self) -> None:
        check_arguments([POLICY], {"to": "a", "lines": [{"sku": "X", "qty": 1}]})
        with self.assertRaises(ArgumentRefusal) as ctx:
            check_arguments([POLICY], {"to": "a", "lines": [{"sku": "X", "price": 1}]})
        self.assertEqual((ctx.exception.reason_code, ctx.exception.path), ("ARGUMENT_NOT_ALLOWED", "/lines/0/price"))

    def test_every_policy_must_be_satisfied_and_a_malformed_one_is_uncheckable(self) -> None:
        with self.assertRaises(ArgumentRefusal) as ctx:
            check_arguments([POLICY, {"allow": ["/to"]}], {"to": "a", "note": "n"})
        self.assertEqual(ctx.exception.path, "/note")
        for bad in ({}, {"allow": []}, {"allow": [""]}, {"allow": ["/a"], "sensitive": None}, {"allow": ["/a"], "sensitive": [{"path": "/a", "mode": "hash"}]}):
            with self.assertRaises(ArgumentRefusal) as ctx:
                check_arguments([bad], {"a": 1})
            self.assertEqual(ctx.exception.reason_code, "ARGUMENTS_UNCHECKABLE", bad)

    def test_redact_wins_over_hmac_and_a_missing_key_refuses_rather_than_send_the_value(self) -> None:
        both = [POLICY, {"allow": ["/iban"], "sensitive": [{"path": "/iban", "mode": "redact"}]}]
        self.assertEqual(sanitize_arguments(both, {"iban": "GB00"}, KEY), {"iban": "[REDACTED]"})
        self.assertEqual(sanitize_arguments([POLICY], {"iban": {"n": 1, "a": [2]}}, KEY), {"iban": keyed({"a": [2], "n": 1})})
        with self.assertRaises(ArgumentRefusal) as ctx:
            sanitize_arguments([POLICY], {"iban": "GB00"})
        self.assertEqual((ctx.exception.reason_code, ctx.exception.path), ("SENSITIVE_ARGUMENT_UNPROTECTED", "/iban"))

    @unittest.skipUnless(shutil.which("node") and (PACKAGE.parent / "agentsafe-mcp-guard" / "policy-core.mjs").exists(), "needs node and the Node guard beside this package")
    def test_the_same_policy_sanitizes_byte_for_byte_as_the_node_guards_do(self) -> None:
        args = {"to": "ap@acme", "lines": [{"sku": "Ünï", "qty": 2.5}], "note": "card 4111", "iban": {"z": "GB00", "a": [1, True, None, " "]}}
        core = (PACKAGE.parent / "agentsafe-mcp-guard" / "policy-core.mjs").as_uri()
        script = (
            f"import {{ checkArguments, sanitizeArguments }} from {json.dumps(core)};"
            "import crypto from 'node:crypto';"
            "const [policy, args] = JSON.parse(process.argv[1]);"
            "const hmac = (c) => crypto.createHmac('sha256', 'k'.repeat(32)).update(c, 'utf8').digest('hex');"
            "process.stdout.write(JSON.stringify({ check: checkArguments([policy], args), clean: sanitizeArguments([policy], args, { hmac }) }));"
        )
        out = subprocess.run(["node", "--input-type=module", "-e", script, json.dumps([POLICY, args])], capture_output=True, text=True, encoding="utf-8", check=True)
        node = json.loads(out.stdout)
        self.assertEqual(node["check"], {"ok": True})
        self.assertEqual(node["clean"], {"ok": True, "value": sanitize_arguments([POLICY], json.loads(json.dumps(args)), KEY)})


class _Gate(unittest.TestCase):
    def setUp(self) -> None:
        key, seed = new_agent_key()
        self.gate = FakeGate(key.public_key(), grants={"send-invoice": 0.0}, merchants={})
        self.gate.argument_policies["send-invoice"] = [POLICY]
        self.client = MetaMyndClient(self.gate.start(), "did:key:z6MkArgs", seed, timeout=5, orphan_release_delays=(), argument_key=KEY)
        self.addCleanup(self.gate.stop)
        self.ran: list = []

    def tool(self, to: str, lines: list, note: str = "", **extra: object) -> str:
        self.ran.append({"to": to, "lines": lines, "note": note, **extra})
        return "sent"


class GuardTool(_Gate):
    def test_an_allowed_call_runs_with_the_sensitive_values_rewritten(self) -> None:
        governed = guard_tool(self.client, "send-invoice", self.tool, LOW)
        self.assertEqual(governed("ap@acme", ({"sku": "X", "qty": 2},), note="card 4111", iban="GB00"), "sent")
        self.assertEqual(self.ran, [{"to": "ap@acme", "lines": [{"sku": "X", "qty": 2}], "note": "[REDACTED]", "iban": keyed("GB00")}])

    def test_an_argument_outside_the_policy_is_refused_before_the_tool_and_its_hold_released(self) -> None:
        governed = guard_tool(self.client, "send-invoice", self.tool, LOW)
        with self.assertRaises(GovernanceBlocked) as ctx:
            governed("ap@acme", LINES, bcc="x@evil")
        self.assertEqual((ctx.exception.verdict.reason_code, ctx.exception.verdict.raw.get("path")), ("ARGUMENT_NOT_ALLOWED", "/bcc"))
        self.assertEqual(self.ran, [])
        self.assertEqual([h["state"] for h in self.gate.holds.values()], ["voided"])

    def test_a_returned_refusal_and_a_missing_key(self) -> None:
        refused = guard_tool(self.client, "send-invoice", self.tool, LOW, on_refusal="return")("ap@acme", [{"sku": "X", "price": 9}])
        self.assertEqual(refused["reasonCode"], "ARGUMENT_NOT_ALLOWED")
        self.client.argument_key = None
        with self.assertRaises(GovernanceBlocked) as ctx:
            guard_tool(self.client, "send-invoice", self.tool, LOW)("ap@acme", LINES, iban="GB00")
        self.assertEqual(ctx.exception.verdict.reason_code, "SENSITIVE_ARGUMENT_UNPROTECTED")
        self.assertEqual(self.ran, [])

    def test_a_value_json_cannot_carry_is_uncheckable_and_no_policy_leaves_the_call_alone(self) -> None:
        with self.assertRaises(GovernanceBlocked) as ctx:
            guard_tool(self.client, "send-invoice", self.tool, LOW)("ap@acme", [{"sku": object()}])
        self.assertEqual(ctx.exception.verdict.reason_code, "ARGUMENTS_UNCHECKABLE")
        self.gate.argument_policies.clear()
        marker = object()
        self.assertEqual(guard_tool(self.client, "send-invoice", self.tool, LOW)("ap@acme", [marker], bcc="x"), "sent")
        self.assertIs(self.ran[-1]["lines"][0], marker)

    def test_review_edges_refuse_and_release_rather_than_raise(self) -> None:
        # A non-ASCII digit in an owner's path, a keyword that shadows a positional-only parameter: refused, hold released.
        self.gate.argument_policies["send-invoice"] = [{"allow": ["/items"], "sensitive": [{"path": "/items/²", "mode": "redact"}]}]
        # "²" is not a list index (it was a ValueError, not a refusal): it matches nothing and the call runs.
        self.assertEqual(guard_tool(self.client, "send-invoice", lambda items: "ran", LOW)(["a", "b", "c"]), "ran")
        self.gate.argument_policies["send-invoice"] = [{"allow": ["/a"]}]

        def positional(a, /, **kw):  # noqa: ANN001, ANN003
            return "ran"

        with self.assertRaises(GovernanceBlocked) as clash:
            guard_tool(self.client, "send-invoice", positional, LOW)(1, a=2)
        self.assertEqual(clash.exception.verdict.reason_code, "ARGUMENTS_UNCHECKABLE")
        self.assertTrue(all(h["state"] == "voided" for h in self.gate.holds.values() if h["state"] != "captured"))

    def test_the_snapshot_is_plain_json(self) -> None:
        import enum

        class Qty(enum.IntEnum):
            TWO = 2

        governed = guard_tool(self.client, "send-invoice", self.tool, LOW)
        governed("ap@acme", [{"sku": "X", "qty": Qty.TWO}])
        self.assertIs(type(self.ran[-1]["lines"][0]["qty"]), int)

    def test_an_async_tool_is_held_to_it_too(self) -> None:
        async def tool(to: str, note: str = "") -> str:
            self.ran.append({"to": to, "note": note})
            return "sent"

        governed = guard_tool(self.client, "send-invoice", tool, LOW)
        self.assertEqual(asyncio.run(governed("ap@acme", note="secret")), "sent")
        self.assertEqual(self.ran, [{"to": "ap@acme", "note": "[REDACTED]"}])
        with self.assertRaises(GovernanceBlocked):
            asyncio.run(governed("ap@acme", cc="x"))

    def test_a_resume_is_held_to_it_before_the_one_resume_is_taken(self) -> None:
        governed = guard_tool(self.client, "send-invoice", self.tool, HIGH, resume_timeout=5)
        with self.assertRaises(GovernanceBlocked) as held:
            governed("ap@acme", LINES, bcc="x@evil")
        escalation_id = held.exception.verdict.escalation_id
        self.gate.approve(escalation_id)
        with self.assertRaises(GovernanceBlocked) as ctx:
            governed.resume(escalation_id, "ap@acme", LINES, bcc="x@evil")
        self.assertEqual(ctx.exception.verdict.reason_code, "ARGUMENT_NOT_ALLOWED")
        self.assertFalse(any(p.endswith("/resume-claim") for p in self.gate.paths), "a refused resume must not use up the approval")
        self.assertEqual(self.ran, [])


if __name__ == "__main__":
    unittest.main()
