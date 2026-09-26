"""The daemon-backed signer (0.5.0), verified against the REAL `agentsafe-signer` daemon.

`daemon_fixture.mjs` starts the actual `SignerDaemon` class from this repository, listening on a
real OS socket — a real named pipe on Windows, going through the same raw `ctypes`/kernel32 calls
`metamynd_client._connect_windows` uses in production, not a mock of them. If the wire format is
wrong, the pipe name hash disagrees with the daemon's own, or a ctypes signature is mistyped, this
fails the way a real integration would — it does not fall back to anything.

Skipped (loudly) when Node is not installed, same convention as test_real_guard.py.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
import uuid

from _support import TESTS, new_agent_key, public_hex  # noqa: F401
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import metamynd_client
from metamynd_client import DaemonError, MetaMyndClient, canonical_message, payload_binding_message, payload_digest, payload_rebind_message, utc_now_rfc3339

NODE = shutil.which("node")
FIXTURE = str(TESTS / "daemon_fixture.mjs")


class _RealDaemon:
    """Starts (and cleanly tears down) one real agentsafe-signer daemon, in its own temp state dir."""

    def __init__(self) -> None:
        self.state_dir = tempfile.mkdtemp(prefix="metamynd-daemon-")
        self.proc = subprocess.Popen([NODE, FIXTURE, self.state_dir], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
        line = None

        def _read_ready() -> None:
            nonlocal line
            line = self.proc.stdout.readline()

        reader = threading.Thread(target=_read_ready, daemon=True)
        reader.start()
        reader.join(timeout=20)
        if line is None or not line.strip():
            self.proc.kill()
            err = self.proc.stderr.read()
            raise RuntimeError(f"daemon_fixture.mjs did not become ready: {err[:2000]}")
        info = json.loads(line)
        self.socket_path: str = info["socketPath"]
        self.agent_did: str = info["agentDid"]
        self.public_key_hex: str = info["publicKeyHex"]

    def close(self) -> None:
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()
        shutil.rmtree(self.state_dir, ignore_errors=True)


def _public_key(daemon: "_RealDaemon") -> Ed25519PublicKey:
    # publicKeyHex is DER SubjectPublicKeyInfo (same shape load_key accepts for a managed key).
    return serialization.load_der_public_key(bytes.fromhex(daemon.public_key_hex))


@unittest.skipUnless(NODE, "node is not installed — the daemon-signer conformance test needs it (CI installs it)")
class DaemonSignerConformance(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.daemon = _RealDaemon()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.daemon.close()

    def _client(self) -> MetaMyndClient:
        return MetaMyndClient("http://127.0.0.1:1", self.daemon.agent_did, daemon_socket=self.daemon.socket_path)

    def test_sign_request_produces_a_signature_the_real_daemons_own_public_key_verifies(self) -> None:
        client = self._client()
        signed = client.sign_request("flight-purchase", 250, merchant="skyward-air", context={"riskLevel": "low"})
        message = canonical_message(signed.body["agentDid"], signed.body["action"], signed.body["amount"], signed.body["currency"], signed.body.get("merchant"), signed.body["nonce"], signed.body["issuedAt"], resource=signed.body.get("resource"))
        _public_key(self.daemon).verify(bytes.fromhex(signed.body["signature"]), message.encode("utf-8"))  # raises InvalidSignature on mismatch
        self.assertEqual(signed.body["agentDid"], self.daemon.agent_did)

    def test_a_jurisdiction_signed_by_the_real_daemon_verifies_as_the_v2_message(self) -> None:
        client = self._client()
        signed = client.sign_request("flight-purchase", 250, merchant="skyward-air", jurisdiction="sg")
        b = signed.body
        self.assertEqual(b["jurisdiction"], "SG")
        message = canonical_message(b["agentDid"], b["action"], b["amount"], b["currency"], b.get("merchant"), b["nonce"], b["issuedAt"], resource=b.get("resource"), jurisdiction=b["jurisdiction"])
        self.assertTrue(message.endswith("|MAGP-AUTH-v2|SG"))
        _public_key(self.daemon).verify(bytes.fromhex(b["signature"]), message.encode("utf-8"))  # raises InvalidSignature on mismatch

    def test_a_daemon_signed_request_does_not_verify_under_a_DIFFERENT_key_or_message(self) -> None:
        client = self._client()
        signed = client.sign_request("flight-purchase", 250, merchant="skyward-air")
        message = canonical_message(signed.body["agentDid"], signed.body["action"], signed.body["amount"], signed.body["currency"], signed.body.get("merchant"), signed.body["nonce"], signed.body["issuedAt"], resource=signed.body.get("resource"))
        other_daemon = _RealDaemon()
        try:
            with self.assertRaises(InvalidSignature):
                _public_key(other_daemon).verify(bytes.fromhex(signed.body["signature"]), message.encode("utf-8"))
        finally:
            other_daemon.close()
        with self.assertRaises(InvalidSignature):
            _public_key(self.daemon).verify(bytes.fromhex(signed.body["signature"]), (message + "x").encode("utf-8"))

    def test_authorize_time_payload_binding_verifies_under_the_MAGP_PAYLOAD_v1_domain(self) -> None:
        client = self._client()
        payload = {"payee": {"iban": "NL91ABNA0417164300"}, "reference": "INV-1042"}
        signed = client.sign_request("wire", 250, merchant="acme", payload=payload)
        digest = payload_digest(payload)
        self.assertEqual(signed.body["payloadDigest"], digest)
        message = payload_binding_message(signed.body["agentDid"], signed.body["action"], signed.body["nonce"], signed.body["issuedAt"], digest)
        _public_key(self.daemon).verify(bytes.fromhex(signed.body["payloadSignature"]), message.encode("utf-8"))

    def test_bind_payload_late_binding_verifies_under_the_MAGP_PAYLOAD_REBIND_v1_domain_and_names_the_hold(self) -> None:
        # bind_payload POSTs to a real gate, which this test has none of — call the daemon signer directly, the
        # same way MetaMyndClient.bind_payload does internally, and check what it PRODUCES (the message it is
        # about to send), not the gate's response.
        client = self._client()
        auth_id = str(uuid.uuid4())
        digest = payload_digest({"amount": 100})
        nonce = "n" * 16
        issued_at = utc_now_rfc3339()
        sig = client._signer.sign_payload_binding({"agentDid": self.daemon.agent_did, "action": "wire", "nonce": nonce, "issuedAt": issued_at, "payloadDigest": digest, "authorizationId": auth_id})
        message = payload_rebind_message(self.daemon.agent_did, "wire", auth_id, nonce, issued_at, digest)
        _public_key(self.daemon).verify(sig, message.encode("utf-8"))
        # ...and does NOT verify as an authorize-time binding (different domain, no authorizationId) — proves the
        # daemon really dispatches on authorizationId's presence, not just producing "a" valid signature.
        with self.assertRaises(InvalidSignature):
            _public_key(self.daemon).verify(sig, payload_binding_message(self.daemon.agent_did, "wire", nonce, issued_at, digest).encode("utf-8"))

    def test_an_unreachable_daemon_raises_DaemonError_DAEMON_UNREACHABLE_not_a_hang(self) -> None:
        bogus = MetaMyndClient("http://127.0.0.1:1", "did:key:zBogus", daemon_socket=str(TESTS / "no-such-daemon-here"))
        started = time.monotonic()
        with self.assertRaises(DaemonError) as ctx:
            bogus.sign_request("flight-purchase", 10)
        self.assertEqual(ctx.exception.code, "DAEMON_UNREACHABLE")
        self.assertLess(time.monotonic() - started, 10, "must fail within the connect timeout, never hang")

    def test_pipe_name_hash_is_a_pure_function_of_the_resolved_path(self) -> None:
        # The property the whole Windows transport rests on: client and server derive the SAME name
        # independently. Already proven end-to-end by every test above actually connecting; this pins the
        # function's own behaviour (stable, and sensitive to the path) so a future refactor cannot silently
        # change it without a matching change in daemon.mjs's windowsPipeName.
        name_a = metamynd_client._daemon_pipe_name(self.daemon.socket_path)
        name_b = metamynd_client._daemon_pipe_name(self.daemon.socket_path)
        self.assertEqual(name_a, name_b)
        self.assertTrue(name_a.startswith("agentsafe-signer-"))
        self.assertNotEqual(name_a, metamynd_client._daemon_pipe_name(self.daemon.socket_path + "-different"))

    def test_client_construction_requires_exactly_one_of_agent_key_or_daemon_socket(self) -> None:
        with self.assertRaises(ValueError):
            MetaMyndClient("http://127.0.0.1:1", "did:key:zBoth", "aa" * 32, daemon_socket=self.daemon.socket_path)
        with self.assertRaises(ValueError):
            MetaMyndClient("http://127.0.0.1:1", "did:key:zNeither")

class DaemonErrorMapping(unittest.TestCase):
    """Pure logic — no live daemon needed: `_DaemonSigner` translates whatever `_daemon_request`
    raises. `DAEMON_UNKNOWN_OPERATION` (an older daemon that predates `sign-payload`, signer <
    0.15.0) gets its own, more actionable code; every other `DaemonError` passes through unchanged."""

    def test_DAEMON_UNKNOWN_OPERATION_becomes_PAYLOAD_BINDING_UNSUPPORTED(self) -> None:
        signer = metamynd_client._DaemonSigner("unused-in-this-test")
        signer._request = lambda op, fields: (_ for _ in ()).throw(DaemonError("DAEMON_UNKNOWN_OPERATION"))
        with self.assertRaises(DaemonError) as ctx:
            signer.sign_payload_binding({"agentDid": "d", "action": "a", "nonce": "n", "issuedAt": "t", "payloadDigest": "sha256:" + "0" * 64})
        self.assertEqual(ctx.exception.code, "PAYLOAD_BINDING_UNSUPPORTED")

    def test_every_other_DaemonError_passes_through_unchanged(self) -> None:
        signer = metamynd_client._DaemonSigner("unused-in-this-test")
        signer._request = lambda op, fields: (_ for _ in ()).throw(DaemonError("DAEMON_MALFORMED_REQUEST", "bad nonce"))
        with self.assertRaises(DaemonError) as ctx:
            signer.sign_payload_binding({"agentDid": "d", "action": "a", "nonce": "n", "issuedAt": "t", "payloadDigest": "sha256:" + "0" * 64})
        self.assertEqual(ctx.exception.code, "DAEMON_MALFORMED_REQUEST")

    def test_sign_authorize_does_not_get_the_payload_specific_remap(self) -> None:
        signer = metamynd_client._DaemonSigner("unused-in-this-test")
        signer._call = lambda op, fields: (_ for _ in ()).throw(DaemonError("DAEMON_UNKNOWN_OPERATION"))
        with self.assertRaises(DaemonError) as ctx:
            signer.sign_authorize({"agentDid": "d", "action": "a", "amount": 1, "currency": "USD", "nonce": "n", "issuedAt": "t"})
        self.assertEqual(ctx.exception.code, "DAEMON_UNKNOWN_OPERATION")

    def test_a_daemon_that_does_not_echo_the_jurisdiction_is_refused(self) -> None:
        """A daemon older than signer 0.18.0 ignores `jurisdiction` and signs v1 — the gate would refuse the request
        SIGNATURE_INVALID. The client catches it first: a current daemon echoes the jurisdiction it signed."""
        signer = metamynd_client._DaemonSigner("unused-in-this-test")
        fields = {"agentDid": "d", "action": "a", "amount": 1, "currency": "USD", "nonce": "n", "issuedAt": "t", "jurisdiction": "SG"}
        signer._call = lambda op, f: {"signature": "aa"}
        with self.assertRaises(DaemonError) as ctx:
            signer.sign_authorize(fields)
        self.assertEqual(ctx.exception.code, "JURISDICTION_SIGNING_UNSUPPORTED")
        signer._call = lambda op, f: {"signature": "aa", "jurisdiction": f.get("jurisdiction")}
        self.assertEqual(signer.sign_authorize(fields), b"\xaa")
        signer._call = lambda op, f: {"signature": "bb"}
        self.assertEqual(signer.sign_authorize({k: v for k, v in fields.items() if k != "jurisdiction"}), b"\xbb", "no jurisdiction: no echo needed")


if __name__ == "__main__":
    unittest.main()
