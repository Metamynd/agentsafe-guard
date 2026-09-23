"""Every example runs, offline, end to end — and signs correctly.

Before this file the four framework examples were byte-compared to their published copies and nothing else: CI
never ran them, never even compiled them, and each built its client at import time, so with no credentials they
died with a stack trace before printing the message that says what is missing. They also called the live gate, so
"runs" meant "runs if you have an account".

Each example is run as a real subprocess against `fake_gate.py` (no account, no network, no LLM key). What is
checked: it exits 0; it prints the outcomes it promises; the gate saw EVERY request signed correctly (an
independent verifier, so a client that signs the wrong bytes fails here); every request for a granted action
carried a `riskLevel` (a request with none is escalated, so an example that omitted it would demonstrate the
wrong thing); and with no credentials it says what is missing instead of raising.

Frameworks are optional: the examples import them lazily and degrade to "install X to see the graph", so this
passes with none installed and exercises the framework wiring wherever one is.
"""

from __future__ import annotations

import os
import py_compile
import subprocess
import sys
import unittest

from _support import EXAMPLES, new_agent_key
from fake_gate import FakeGate

# example file -> substrings its output must contain. Only what each example PROMISES about governance; the
# framework-specific lines vary with what is installed.
EXPECTED = {
    "crewai_agent.py": ["booked QK7T2M", "block/SOP_SPEND_CAP", "block/MERCHANT_NOT_ALLOWED", "block/NO_PERMISSION_FOR_ACTION"],
    "langchain_agent.py": ["booked QK7T2M", "block/SOP_SPEND_CAP", "block/MERCHANT_NOT_ALLOWED", "block/NO_PERMISSION_FOR_ACTION"],
    "openai_agents_agent.py": ["booked QK7T2M", "block/SOP_SPEND_CAP", "block/MERCHANT_NOT_ALLOWED", "block/NO_PERMISSION_FOR_ACTION"],
    "pydantic_ai_agent.py": ["booked QK7T2M", "block/SOP_SPEND_CAP", "block/MERCHANT_NOT_ALLOWED", "block/NO_PERMISSION_FOR_ACTION"],
    "langgraph_agent.py": ["raised PO-10231", "block/SOP_SPEND_CAP", "block/NO_PERMISSION_FOR_ACTION"],
    "plain_python_agent.py": [
        "allow/AUTHORIZED", "capture ok=True", "settled (retry_safe=False)", "not_started: nothing_executed=True, retry_safe=False",
        "not_executed: retry_safe=True", "block/SOP_SPEND_CAP", "escalate/RISK_REVIEW", "pending (may_proceed=False)", "block/NO_PERMISSION_FOR_ACTION",
    ],
}


def _env(**extra: str) -> dict:
    env = {**os.environ, "PYTHONPATH": str(EXAMPLES), "PYTHONIOENCODING": "utf-8", "PYDANTIC_AI_NO_BANNER": "1", "NO_COLOR": "1"}
    for name in ("AGENT_DID", "AGENT_KEY", "METAMYND_API", "GATEWAY_URL"):
        env.pop(name, None)
    env.update(extra)
    return env


def _run(example: str, env: dict) -> "subprocess.CompletedProcess[str]":
    return subprocess.run([sys.executable, str(EXAMPLES / example)], env=env, capture_output=True, text=True, timeout=180, encoding="utf-8", errors="replace")


class Examples(unittest.TestCase):
    def test_every_example_is_covered_and_compiles(self) -> None:
        on_disk = sorted(p.name for p in EXAMPLES.glob("*_agent.py"))
        self.assertEqual(on_disk, sorted(EXPECTED), "a new example must be added to this test (and an old one must not go missing)")
        for name in on_disk:
            py_compile.compile(str(EXAMPLES / name), doraise=True)

    def test_each_example_runs_offline_and_signs_correctly(self) -> None:
        key, seed = new_agent_key()
        for example, expected in EXPECTED.items():
            with self.subTest(example):
                gate = FakeGate(key.public_key())
                url = gate.start()
                try:
                    done = _run(example, _env(METAMYND_API=url, AGENT_DID="did:key:z6MkExamples", AGENT_KEY=seed))
                finally:
                    gate.stop()
                self.assertEqual(done.returncode, 0, f"{example} exited {done.returncode}\n--- stdout\n{done.stdout[-1500:]}\n--- stderr\n{done.stderr[-1500:]}")
                self.assertNotIn("Traceback", done.stdout + done.stderr)
                for needle in expected:
                    self.assertIn(needle, done.stdout, f"{example} should print {needle!r}\n{done.stdout[-1500:]}")
                self.assertGreater(len(gate.requests), 0, "the example never reached the gate")
                self.assertEqual(gate.signature_failures, 0, f"{example}: the gate could not verify the client's signature on {gate.signature_failures} request(s)")
                # A request for a granted action states its risk (a request with none is escalated, not allowed).
                for req in gate.requests:
                    if req["action"] in gate.grants and req["action"] != "permissions.update":
                        self.assertIn("riskLevel", req.get("itinerary") or {}, f"{example}: a {req['action']} request carried no riskLevel: {req}")

    def test_without_credentials_each_example_says_what_is_missing_instead_of_crashing(self) -> None:
        for example in EXPECTED:
            with self.subTest(example):
                done = _run(example, _env())
                self.assertNotEqual(done.returncode, 0)
                self.assertIn("AGENT_DID", done.stderr + done.stdout, "it should name the missing variables")
                self.assertNotIn("Traceback", done.stderr, f"{example} must not die at import with a stack trace:\n{done.stderr[-800:]}")

    def test_importing_an_example_never_needs_credentials(self) -> None:
        for example in EXPECTED:
            with self.subTest(example):
                module = example[:-3]
                done = subprocess.run([sys.executable, "-c", f"import {module}"], env=_env(), capture_output=True, text=True, timeout=120)
                self.assertEqual(done.returncode, 0, done.stderr[-800:])


if __name__ == "__main__":
    unittest.main()
