"""Python SDK gaps from the 2026-10-09 pre-beta evaluation (L5), each pinned here.

  a. There was no loader for the agent.metamynd.json the deploy screen hands out: every example rebuilt the client
     from environment variables. `MetaMyndClient.from_config` reads it, a passphrase-encrypted key included.
  b. A permitted call through `guard_agent_tool` returned only the tool's result, so its authorization and event ids
     were lost. `on_verdict` sees every gate answer, and `current_verdict()` returns it inside the running tool.
  c. LangGraph turned `guard_agent_tool`'s refusal into a ToolMessage with status="success". `guard_langchain_tool`
     makes it status="error", and the turn still completes.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import tempfile
import unittest
import warnings
from pathlib import Path

from _support import REPO, new_agent_key
from fake_gate import FakeGate
from metamynd_client import (
    GovernanceRefusal,
    MetaMyndClient,
    current_verdict,
    decrypt_agent_key,
    guard_agent_tool,
    guard_langchain_tool,
)

FLIGHT = lambda vendor, amount: {"amount": amount, "merchant": vendor, "context": {"riskLevel": "low"}}  # noqa: E731


def encrypt_agent_key(plain: str, passphrase: str, salt: str) -> str:
    """The issuer's encryption (deriveKeyFromPassword + AES-256-GCM, AAD "hedera-data"), written independently here."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    key = PBKDF2HMAC(algorithm=hashes.SHA512(), length=32, salt=salt.encode("utf-8"), iterations=100_000).derive(passphrase.encode("utf-8"))
    iv = secrets.token_bytes(12)
    sealed = AESGCM(key).encrypt(iv, plain.encode("utf-8"), b"hedera-data")
    data, tag = sealed[:-16], sealed[-16:]
    return f"{iv.hex()}:{tag.hex()}:{data.hex()}"


class FromConfig(unittest.TestCase):
    def setUp(self) -> None:
        self.key, self.seed = new_agent_key()
        self.gate = FakeGate(self.key.public_key())
        self.base = self.gate.start()
        self.addCleanup(self.gate.stop)
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)

    def write(self, cfg: dict) -> Path:
        path = self.dir / "agent.metamynd.json"
        path.write_text(json.dumps(cfg), encoding="utf-8")
        return path

    def test_reads_the_deploy_screens_file_and_authorizes(self) -> None:
        client = MetaMyndClient.from_config(self.write({"apiBase": self.base, "agentDid": "did:key:z6MkFromFile", "agentKey": self.seed}))
        self.assertEqual((client.api, client.agent_did), (self.base, "did:key:z6MkFromFile"))
        self.assertEqual(client.authorize("flight-purchase", 10, merchant="skyward-air", context={"riskLevel": "low"}).decision, "allow")

    def test_a_mapping_and_an_api_response_are_accepted_and_overrides_win(self) -> None:
        cfg = {"success": True, "data": {"apiBase": "http://unused", "agentDid": "did:key:z6MkA", "agentKey": self.seed, "signContext": False}}
        client = MetaMyndClient.from_config(cfg, api=self.base, timeout=3)
        self.assertEqual((client.api, client.agent_did, client.timeout, client.sign_context), (self.base, "did:key:z6MkA", 3, False))

    def test_a_passphrase_encrypted_key(self) -> None:
        enc = {"ciphertext": encrypt_agent_key(self.seed, "correct horse", "a1b2c3"), "salt": "a1b2c3"}
        path = self.write({"apiBase": self.base, "agentDid": "did:key:z6MkEnc", "agentKeyEncrypted": enc})
        with self.assertRaisesRegex(ValueError, "passphrase"):
            MetaMyndClient.from_config(path)
        with self.assertRaisesRegex(ValueError, "wrong passphrase"):
            MetaMyndClient.from_config(path, passphrase="wrong")
        client = MetaMyndClient.from_config(path, passphrase="correct horse")
        self.assertEqual(client.authorize("flight-purchase", 10, merchant="skyward-air", context={"riskLevel": "low"}).decision, "allow")

    def test_a_daemon_config_selects_the_daemon(self) -> None:
        client = MetaMyndClient.from_config({"apiBase": self.base, "agentDid": "did:key:z6MkD", "keyProvider": "daemon", "daemonSocketPath": "/run/agentsafe/agent.sock"})
        self.assertEqual(type(client._signer).__name__, "_DaemonSigner")

    def test_a_file_missing_its_key_or_did_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            MetaMyndClient.from_config({"apiBase": self.base, "agentDid": "did:key:z6MkNoKey"})
        with self.assertRaises(ValueError):
            MetaMyndClient.from_config({"apiBase": self.base, "agentKey": self.seed})

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_the_node_guard_opens_what_this_test_sealed_and_this_client_opens_it_too(self) -> None:
        # Cross-language: the Node guard's own decryptAgentKeyWithPassword, on the ciphertext the Python test made.
        sealed = encrypt_agent_key(self.seed, "pw-123", "salt-xyz")
        module = (REPO / "integrations" / "agentsafe-guard" / "key-providers.mjs").as_uri()
        script = f"import {{ decryptAgentKeyWithPassword }} from {json.dumps(module)}; process.stdout.write(decryptAgentKeyWithPassword({json.dumps(sealed)}, 'pw-123', 'salt-xyz'));"
        out = subprocess.run(["node", "--input-type=module", "-e", script], capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout, self.seed)
        self.assertEqual(decrypt_agent_key(sealed, "pw-123", "salt-xyz"), self.seed)


class VerdictOfAPermittedCall(unittest.TestCase):
    def setUp(self) -> None:
        key, seed = new_agent_key()
        self.gate = FakeGate(key.public_key())
        self.client = MetaMyndClient(self.gate.start(), "did:key:z6MkVerdict", seed, timeout=5)
        self.addCleanup(self.gate.stop)

    def test_on_verdict_sees_the_permit_with_its_ids_and_the_tool_sees_it_too(self) -> None:
        seen, inside = [], []

        def book(vendor: str, amount: float) -> dict:
            inside.append(current_verdict())
            return {"pnr": "P1"}

        governed = guard_agent_tool(self.client, "flight-purchase", book, FLIGHT, on_verdict=seen.append)
        self.assertEqual(governed("skyward-air", 10), {"pnr": "P1"})
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].decision, "allow")
        self.assertTrue(seen[0].authorization_id)
        self.assertIs(inside[0], seen[0])
        self.assertIsNone(current_verdict(), "outside the tool there is none")

    def test_on_verdict_sees_a_refusal_too(self) -> None:
        seen = []
        governed = guard_agent_tool(self.client, "flight-purchase", lambda vendor, amount: {"pnr": "X"}, FLIGHT, on_verdict=seen.append)
        result = governed("skyward-air", 5000)
        self.assertIsInstance(result, GovernanceRefusal)
        self.assertEqual([v.decision for v in seen], ["block"])

    def test_a_raising_observer_is_a_warning_never_a_different_outcome(self) -> None:
        def broken(_verdict) -> None:
            raise RuntimeError("logging is down")

        governed = guard_agent_tool(self.client, "flight-purchase", lambda vendor, amount: {"pnr": "P2"}, FLIGHT, on_verdict=broken)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            self.assertEqual(governed("skyward-air", 10), {"pnr": "P2"})
        self.assertTrue(any("on_verdict raised" in str(w.message) for w in caught))

    def test_on_verdict_must_be_callable(self) -> None:
        with self.assertRaises(ValueError):
            guard_agent_tool(self.client, "flight-purchase", lambda vendor, amount: None, FLIGHT, on_verdict="log")


class LangGraphErrorStatus(unittest.TestCase):
    def test_a_refusal_is_an_error_tool_message_and_the_turn_completes(self) -> None:
        try:
            from langchain_core.messages import AIMessage
            from langgraph.graph import END, START, MessagesState, StateGraph
            from langgraph.prebuilt import ToolNode
        except ImportError:
            if os.environ.get("METAMYND_REQUIRE_LANGGRAPH"):
                raise
            self.skipTest("langgraph not installed")
        key, seed = new_agent_key()
        gate = FakeGate(key.public_key())
        client = MetaMyndClient(gate.start(), "did:key:z6MkGraph", seed, timeout=5)
        self.addCleanup(gate.stop)
        ran = []

        def book_flight(vendor: str, amount: float) -> dict:
            """Book a flight."""
            ran.append(amount)
            return {"pnr": f"PNR-{len(ran)}"}

        graph = StateGraph(MessagesState)
        graph.add_node("tools", ToolNode([guard_langchain_tool(client, "flight-purchase", book_flight, FLIGHT)]))
        graph.add_edge(START, "tools")
        graph.add_edge("tools", END)
        turn = AIMessage(content="", tool_calls=[
            {"name": "book_flight", "args": {"vendor": "skyward-air", "amount": 5000}, "id": "over"},
            {"name": "book_flight", "args": {"vendor": "skyward-air", "amount": 100}, "id": "ok"},
        ])
        out = graph.compile().invoke({"messages": [turn]})
        by_id = {m.tool_call_id: m for m in out["messages"] if getattr(m, "tool_call_id", None)}
        self.assertEqual(by_id["over"].status, "error")
        self.assertEqual(json.loads(by_id["over"].content)["reasonCode"], "SOP_SPEND_CAP")
        self.assertEqual(by_id["ok"].status, "success")
        self.assertIn("PNR-1", by_id["ok"].content)
        self.assertEqual(ran, [100], "the refused call never ran")


if __name__ == "__main__":
    unittest.main()
