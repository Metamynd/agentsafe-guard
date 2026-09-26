"""The Python client, verified by the REAL guard and the REAL HTTP gateway.

`fake_gate.py` checks the client's signing with a verifier written in Python. That catches a wrong message, but
it is still Python checking Python. This is the conformance test that is not: requests the client signs are
handed to the actual `agentsafe-mcp-guard` and `agentsafe-http-gateway` from this repository (Node), which
re-verify them the way a real service would — key-in-DID Ed25519, the eight-field message, the payload binding.

It is what "CI vs the live protocol" means without needing a database: the counterparty code is the code that
ships. Skipped (loudly) when Node is not installed; CI installs it.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import unittest

from _support import TESTS, new_agent_key, public_hex
from metamynd_client import MetaMyndClient, canonical_message

NODE = shutil.which("node")
SCRIPT = str(TESTS / "verify_with_real_guard.mjs")


def _node(*args: str, stdin: str = "") -> str:
    done = subprocess.run([NODE, SCRIPT, *args], input=stdin, capture_output=True, text=True, timeout=60, encoding="utf-8")
    if done.returncode != 0:
        raise AssertionError(f"node failed ({done.returncode}): {done.stderr.strip()[:600]}")
    return done.stdout


@unittest.skipUnless(NODE, "node is not installed — the real-guard conformance test needs it (CI installs it)")
class RealGuardConformance(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.key, cls.seed = new_agent_key()
        cls.pub = public_hex(cls.key)
        cls.did = _node("--did", cls.pub).strip()
        # Never contacted: `sign_request` signs without a gate, which is exactly what a counterparty needs.
        cls.client = MetaMyndClient("http://127.0.0.1:1", cls.did, cls.seed)

    def _verify(self, cases: list) -> dict:
        out = json.loads(_node("--verify", stdin=json.dumps({"publicKeyHex": self.pub, "cases": cases})))
        self.assertEqual(out["did"], self.did)
        return {r["name"]: r for r in out["results"]}

    def _guard(self, name: str, request: dict) -> dict:
        return {"name": name, "kind": "guard", "request": request}

    def test_signed_requests_verify_and_the_rules_apply(self) -> None:
        c = self.client
        honest = {"riskLevel": "low"}
        cases = [
            self._guard("honest", dict(c.sign_request("flight-purchase", 100, merchant="skyward-air", context=honest).body)),
            self._guard("float amount", dict(c.sign_request("flight-purchase", 150.0, merchant="skyward-air", context=honest).body)),
            self._guard("decimal amount", dict(c.sign_request("flight-purchase", 142.3, merchant="skyward-air", context=honest).body)),
            self._guard("resource signed", dict(c.sign_request("db-read", 0, resource="inspection-db", context=honest).body)),
            self._guard("over the cap", dict(c.sign_request("flight-purchase", 900, merchant="skyward-air", context=honest).body)),
            self._guard("high risk", dict(c.sign_request("flight-purchase", 100, merchant="skyward-air", context={"riskLevel": "high"}).body)),
            self._guard("no risk stated", dict(c.sign_request("flight-purchase", 100, merchant="skyward-air", context={"tool": "book-flight"}).body)),
            # a "|" in a field: the message is escaped, so the SIGNATURE verifies and the failure is the mandate's
            self._guard("pipe in merchant", dict(c.sign_request("flight-purchase", 100, merchant="sky|ward", context=honest).body)),
            # the amounts whose text Python's repr() spells differently from JavaScript's String()
            self._guard("sub-cent amount", dict(c.sign_request("flight-purchase", 0.00005, merchant="skyward-air", context=honest).body)),
            self._guard("tiny amount", dict(c.sign_request("flight-purchase", 1.5e-7, merchant="skyward-air", context=honest).body)),
            self._guard("int beyond 2**53", dict(c.sign_request("flight-purchase", 2**60 + 1, merchant="skyward-air", context=honest).body)),
        ]
        r = self._verify(cases)
        self.assertEqual((r["honest"]["decision"], r["honest"]["reasonCode"]), ("allow", "AUTHORIZED"), r["honest"])
        self.assertEqual(r["float amount"]["decision"], "allow", "String(150.0) is '150': a client that signs '150.0' fails here")
        self.assertEqual(r["decimal amount"]["decision"], "allow")
        self.assertEqual(r["resource signed"]["decision"], "allow", "resource is the eighth signed field")
        self.assertEqual(r["over the cap"]["reasonCode"], "SOP_SPEND_CAP")
        self.assertEqual((r["high risk"]["decision"], r["high risk"]["reasonCode"]), ("escalate", "RISK_REVIEW"))
        self.assertEqual((r["no risk stated"]["decision"], r["no risk stated"]["reasonCode"]), ("escalate", "CONTEXT_UNVERIFIABLE"), "an unstated risk is escalated, not allowed")
        self.assertEqual(r["pipe in merchant"]["reasonCode"], "MERCHANT_NOT_ALLOWED", "escaping is right: the signature verified and the MANDATE refused")
        for name in ("sub-cent amount", "tiny amount"):
            self.assertEqual(r[name]["decision"], "allow", f"{name}: the real guard must verify what the client signed — {r[name]}")
        # An amount this large is over the cap, but that is the MANDATE speaking: the signature verified.
        self.assertNotEqual(r["int beyond 2**53"]["reasonCode"], "SIGNATURE_INVALID", r["int beyond 2**53"])

    def test_tampering_and_the_seven_field_regression_are_refused(self) -> None:
        c = self.client
        good = dict(c.sign_request("db-read", 0, resource="inspection-db", context={"riskLevel": "low"}).body)
        amount_swapped = dict(c.sign_request("flight-purchase", 100, merchant="skyward-air", context={"riskLevel": "low"}).body)
        amount_swapped["amount"] = 1
        resource_swapped = {**good, "resource": "billing-db"}

        # The release that shipped to PyPI: a valid Ed25519 signature over the SEVEN-field message (no resource).
        req = dict(c.sign_request("flight-purchase", 100, merchant="skyward-air", context={"riskLevel": "low"}).body)
        legacy = "|".join([req["agentDid"], req["action"], "100", req["currency"], req["merchant"], req["nonce"], req["issuedAt"]])
        req_legacy = {**req, "signature": self.key.sign(legacy.encode("utf-8")).hex()}
        self.assertNotEqual(legacy, canonical_message(req["agentDid"], req["action"], 100, req["currency"], req["merchant"], req["nonce"], req["issuedAt"]))

        r = self._verify([
            self._guard("amount swapped", amount_swapped),
            self._guard("resource swapped", resource_swapped),
            self._guard("seven-field signature", req_legacy),
        ])
        for name in ("amount swapped", "resource swapped", "seven-field signature"):
            self.assertEqual((r[name]["decision"], r[name]["reasonCode"]), ("block", "SIGNATURE_INVALID"), f"{name}: {r[name]}")

    def test_a_signed_jurisdiction_verifies_as_v2_and_is_the_only_one_judged(self) -> None:
        """MAGP §8.3.12 against the real guard: the v2 message verifies, the mandate's allowed-jurisdictions term judges
        the SIGNED value, a context jurisdiction stands in for nothing, and stripping the field breaks the signature."""
        c = self.client
        low = {"riskLevel": "low"}
        allowed = dict(c.sign_request("visa-apply", 0, context=low, jurisdiction="sg").body)
        stripped = {k: v for k, v in allowed.items() if k != "jurisdiction"}
        r = self._verify([
            self._guard("signed SG", allowed),
            self._guard("signed DE", dict(c.sign_request("visa-apply", 0, context=low, jurisdiction="DE").body)),
            self._guard("none signed", dict(c.sign_request("visa-apply", 0, context=low).body)),
            self._guard("context only", dict(c.sign_request("visa-apply", 0, context={**low, "jurisdiction": "SG"}).body)),
            self._guard("stripped in transit", stripped),
            self._guard("changed in transit", {**allowed, "jurisdiction": "MY"}),
        ])
        self.assertEqual(allowed["jurisdiction"], "SG")
        self.assertEqual((r["signed SG"]["decision"], r["signed SG"]["reasonCode"]), ("allow", "AUTHORIZED"), r["signed SG"])
        self.assertEqual(r["signed DE"]["reasonCode"], "JURISDICTION_NOT_ALLOWED", r["signed DE"])
        self.assertEqual(r["none signed"]["reasonCode"], "JURISDICTION_REQUIRED", r["none signed"])
        self.assertEqual(r["context only"]["reasonCode"], "JURISDICTION_REQUIRED", "a context jurisdiction is unsigned and never judged")
        for name in ("stripped in transit", "changed in transit"):
            self.assertEqual(r[name]["reasonCode"], "SIGNATURE_INVALID", f"{name}: {r[name]}")

    def test_the_signed_request_handoff_works_through_the_real_gateway(self) -> None:
        """`verdict.signed.headers()` is what a Python tool attaches to a call to a protected service."""
        c = self.client
        signed = c.sign_request("flight-purchase", 100, merchant="skyward-air", context={"riskLevel": "low"}, authorization_id="auth-123")
        body = {"amount": 100, "merchant": "skyward-air"}
        cases = [
            {"name": "handoff", "kind": "gateway", "headers": signed.headers(), "body": body},
            {"name": "executed args differ from the signed ones", "kind": "gateway", "headers": signed.headers(), "body": {"amount": 5000, "merchant": "skyward-air"}},
            {"name": "no header", "kind": "gateway", "headers": {}, "body": body},
            {"name": "unknown field smuggled in", "kind": "gateway", "headers": signed.headers(), "body": {**body, "payee": "attacker-llc"}},
        ]
        r = self._verify(cases)
        self.assertEqual((r["handoff"]["status"], r["handoff"]["forwarded"]), (200, True), r["handoff"])
        self.assertEqual((r["executed args differ from the signed ones"]["status"], r["executed args differ from the signed ones"]["reasonCode"]), (403, "PAYLOAD_NOT_BOUND"))
        self.assertFalse(r["executed args differ from the signed ones"]["forwarded"], "the upstream must never see arguments the agent did not sign")
        self.assertEqual(r["no header"]["status"], 401, "a call without the signed request is refused (MISSING_GOVERNANCE)")
        self.assertFalse(r["no header"]["forwarded"])
        self.assertFalse(r["unknown field smuggled in"]["forwarded"], "an unsigned field is refused, not passed through")

    def test_payload_binding_is_verified_by_the_real_guard_and_gateway(self) -> None:
        """The digest the Python client signs is the digest the Node executor computes, for values where languages disagree."""
        c = self.client
        # Amounts and text where a Python and a JavaScript canonicaliser could disagree: an integral float, a sub-cent amount,
        # a number past 2**53, non-ASCII, a supplementary-plane character, a control character, and key order.
        payload = {
            "payee": {"name": "Zoë Müller 😀", "iban": "NL91ABNA0417164300", "note": "tab\there "},
            "amount": 250.0, "fee": 0.00005, "big": 2**60 + 1, "ref": "INV|1\\2", "passenger": ["A", "B"],
            "\U0001f600": 1, "￿": 2, "a": None, "z": True,
        }
        signed = c.sign_request("flight-purchase", 250, merchant="skyward-air", context={"riskLevel": "low"}, payload=payload)
        unbound = c.sign_request("flight-purchase", 250, merchant="skyward-air", context={"riskLevel": "low"})
        swapped = {**payload, "payee": {**payload["payee"], "iban": "XX99EVIL"}}
        # What the service RECEIVES is JSON text; the gateway digests the bytes it forwards.
        wire = json.loads(json.dumps(payload))
        cases = [
            self._guard("guard: executed == signed", dict(signed.body)) | {"executed": wire},
            self._guard("guard: executed swapped", dict(signed.body)) | {"executed": json.loads(json.dumps(swapped))},
            self._guard("guard: unbound, not required", dict(unbound.body)) | {"executed": wire},
            self._guard("guard: unbound, required", dict(unbound.body)) | {"executed": wire, "requirePayloadBinding": True},
            self._guard("guard: bad binding signature", {**signed.body, "payloadSignature": "00" * 64}) | {"executed": wire},
            self._guard("guard: digest without signature", {k: v for k, v in signed.body.items() if k != "payloadSignature"}),
            {"name": "gateway: honest", "kind": "gateway", "path": "/pay", "headers": signed.headers(), "body": {"amount": 250, "merchant": "skyward-air", "payee": "NL91", "passenger": ["A"]}},
        ]
        r = self._verify(cases)
        self.assertEqual(r["guard: executed == signed"]["decision"], "allow", f"the digests must agree across languages: {r['guard: executed == signed']}")
        self.assertEqual(r["guard: executed swapped"]["reasonCode"], "PAYLOAD_NOT_BOUND")
        self.assertEqual(r["guard: unbound, not required"]["decision"], "allow")
        self.assertEqual(r["guard: unbound, required"]["reasonCode"], "PAYLOAD_BINDING_REQUIRED")
        self.assertEqual(r["guard: bad binding signature"]["reasonCode"], "PAYLOAD_BINDING_INVALID")
        self.assertEqual(r["guard: digest without signature"]["reasonCode"], "PAYLOAD_BINDING_INVALID")
        # The gateway digests the body it forwards: this body is not the payload that was signed, so the request never reaches upstream.
        self.assertEqual((r["gateway: honest"]["status"], r["gateway: honest"]["reasonCode"]), (403, "PAYLOAD_NOT_BOUND"))
        self.assertFalse(r["gateway: honest"]["forwarded"])

    def test_the_gateway_forwards_exactly_the_payload_that_was_signed(self) -> None:
        c = self.client
        body = {"amount": 250, "merchant": "skyward-air", "payee": "NL91ABNA0417164300", "passenger": ["A. Traveller"]}
        signed = c.sign_request("flight-purchase", 250, merchant="skyward-air", context={"riskLevel": "low"}, payload=body)
        swapped = {**body, "payee": "XX99EVIL"}
        unbound = c.sign_request("flight-purchase", 250, merchant="skyward-air", context={"riskLevel": "low"})
        r = self._verify([
            {"name": "bound, honest", "kind": "gateway", "path": "/pay", "headers": signed.headers(), "body": body},
            {"name": "bound, payee swapped", "kind": "gateway", "path": "/pay", "headers": signed.headers(), "body": swapped},
            {"name": "unbound, default route", "kind": "gateway", "path": "/pay", "headers": unbound.headers(), "body": body},
            {"name": "unbound, strict route", "kind": "gateway", "path": "/pay-strict", "headers": unbound.headers(), "body": body},
        ])
        self.assertEqual((r["bound, honest"]["status"], r["bound, honest"]["forwarded"]), (200, True), r["bound, honest"])
        self.assertEqual((r["bound, payee swapped"]["status"], r["bound, payee swapped"]["reasonCode"]), (403, "PAYLOAD_NOT_BOUND"))
        self.assertFalse(r["bound, payee swapped"]["forwarded"], "a payee the agent never signed must not reach the upstream")
        self.assertTrue(r["unbound, default route"]["forwarded"], "without a binding the gateway behaves as it always did")
        self.assertEqual(r["unbound, strict route"]["reasonCode"], "PAYLOAD_BINDING_REQUIRED")
        self.assertFalse(r["unbound, strict route"]["forwarded"])

    def test_the_header_is_ascii_safe_even_for_unicode_fields(self) -> None:
        signed = self.client.sign_request("flight-purchase", 100, merchant="Café ✓", context={"riskLevel": "low", "note": "münchen"})
        signed.header_value().encode("ascii")  # would raise if a non-ASCII byte reached an HTTP header
        r = self._verify([self._guard("unicode", dict(signed.body))])
        self.assertEqual(r["unicode"]["reasonCode"], "MERCHANT_NOT_ALLOWED", "the signature over UTF-8 verified; only the mandate refused")


if __name__ == "__main__":
    unittest.main()
