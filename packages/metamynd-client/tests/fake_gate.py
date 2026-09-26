"""A TEST DOUBLE of the MetaMynd gate — enough of it to run the examples and the client offline.

This is not the gate and it is not policy. It exists so CI can run every example end to end with no account,
no network and no LLM, and so the client's signing is checked by a verifier that does NOT share its code:
the eight-field message is rebuilt here by hand, from the body received, and the Ed25519 signature is checked
against the agent's public key — exactly what the real gate does (MAGP section 8.3). A client that signs the
wrong bytes therefore fails in CI as SIGNATURE_INVALID instead of on the first real request.

What it decides is fixed and mirrors the starter rules a sandbox agent gets, so the examples' expected
outcomes hold:

    action not granted              -> block    NO_PERMISSION_FOR_ACTION
    merchant not on the allow-list  -> block    MERCHANT_NOT_ALLOWED
    amount over the action's cap    -> block    SOP_SPEND_CAP
    riskLevel missing/unrecognised  -> escalate CONTEXT_UNVERIFIABLE   (MAGP section 6.3)
    riskLevel high                  -> escalate RISK_REVIEW
    otherwise                       -> allow, with an authorizationId

Escalations stay `pending` until `approve()` is called. Endpoints: POST /policy/mandate/authorize, GET
/policy/escalations/{id}/status, POST /policy/mandate/authorize/{id}/capture|void, GET .../{id}/effect.
"""

from __future__ import annotations

import decimal
import json
import re
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Mapping, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

RISK_LEVELS = {"low", "medium", "high", "critical"}


def js_string(amount: Any) -> str:
    """JavaScript's String(Number) of the JSON amount — written differently from the client's version on purpose
    (a plain-decimal branch and an exponent branch, not the client's digits-and-position rules), and pinned to real
    JS output by the shared vectors, so a bug would have to be made twice, the same way."""
    x = float(amount)  # the gate's JSON.parse holds a double, even for an int past 2**53
    if x.is_integer() and abs(x) < 1e21:
        return str(int(x))
    r = repr(x)
    if 1e-6 <= abs(x) < 1e21:
        return format(decimal.Decimal(r), "f")
    mantissa, exponent = r.split("e")
    mantissa = mantissa[:-2] if mantissa.endswith(".0") else mantissa
    return f"{mantissa}e{'+' if int(exponent) >= 0 else '-'}{abs(int(exponent))}"


def rebuild_message(body: Mapping[str, Any]) -> str:
    """The signed message, rebuilt BY HAND from the wire body — deliberately not `canonical_message`."""

    def esc(v: str) -> str:
        return v.replace("\\", "\\\\").replace("|", "\\|")

    text = js_string(body["amount"])
    fields = [body["agentDid"], body["action"], text, body["currency"], body.get("merchant", ""), body.get("resource", ""), body["nonce"], body["issuedAt"]]
    return "|".join(esc(str(f)) for f in fields)


class FakeGate:
    def __init__(
        self,
        public_key: Ed25519PublicKey,
        grants: Optional[Mapping[str, float]] = None,
        merchants: Optional[Mapping[str, List[str]]] = None,
    ) -> None:
        self.public_key = public_key
        # action -> per-transaction cap. The starter sandbox grants flight-purchase; the LangGraph example's
        # procurement case grants purchase-order.
        self.grants: Dict[str, float] = dict(grants or {"flight-purchase": 500.0, "purchase-order": 10_000.0})
        # action -> merchants the mandate names. The starter sandbox names its airlines; an action with no entry
        # accepts any merchant.
        self.merchants: Dict[str, List[str]] = dict(merchants) if merchants is not None else {
            "flight-purchase": ["skyward-air", "northwind-rail", "globe-hotels"],
            "purchase-order": ["acme-supplies", "nusantara-office", "kl-industrial"],
        }
        self.requests: List[Dict[str, Any]] = []
        self.bind_requests: List[Dict[str, Any]] = []  # every late-binding request received
        self.signature_failures = 0  # requests whose eight-field signature did not verify
        self.payload_failures = 0  # requests whose payload-binding signature did not verify
        self.echo_payload_digest = True  # a gate that predates binding (or a proxy that strips it) does not acknowledge the digest
        self.holds: Dict[str, Dict[str, Any]] = {}
        self.escalations: Dict[str, Dict[str, Any]] = {}
        self.paths: List[str] = []  # every POST path received, as sent
        self.bodies: List[Dict[str, Any]] = []  # every POST body received, in the same order
        self.delay = 0.0  # seconds the gate takes to answer an authorize
        self.html_200 = False  # answer every POST with a non-JSON 200, like a CDN error page
        self._server: Optional[ThreadingHTTPServer] = None
        self.base_url = ""

    # ---- lifecycle -------------------------------------------------------------------------

    def start(self) -> str:
        gate = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_a: Any) -> None:
                pass

            def _send(self, code: int, payload: Any) -> None:
                raw = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self) -> None:  # noqa: N802
                gate.paths.append(self.path)
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                gate.bodies.append(body)
                if gate.delay and self.path == "/policy/mandate/authorize":
                    time.sleep(gate.delay)  # a slow gate, so a caller can be cancelled while the hold is being made
                if gate.html_200:
                    raw = b"<html>a CDN error page with a 200 status</html>"
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                    return
                code, payload = gate.post(self.path, body)
                self._send(code, payload)

            def do_GET(self) -> None:  # noqa: N802
                code, payload = gate.get(self.path)
                self._send(code, payload)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        self.base_url = f"http://127.0.0.1:{self._server.server_address[1]}"
        return self.base_url

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()

    def approve(self, escalation_id: str) -> None:
        self.escalations[escalation_id]["status"] = "approved"

    def modify(self, escalation_id: str) -> None:
        """A reviewer changed the action instead of approving it: terminal, with a follow-up hold."""
        self.escalations[escalation_id]["status"] = "modified"

    # ---- protocol --------------------------------------------------------------------------

    def post(self, path: str, body: Mapping[str, Any]) -> "tuple[int, Any]":
        if path == "/policy/mandate/authorize":
            return self._authorize(body)
        if path.endswith("/payload-binding"):
            return self._bind_payload(path.split("/")[-2], body)
        for verb in ("capture", "void"):
            if path.endswith("/" + verb):
                auth_id = path.split("/")[-2]
                return self._settle(verb, auth_id, body)
        return 404, {"success": False, "message": "no such route", "data": None}

    def _bind_payload(self, auth_id: str, body: Mapping[str, Any]) -> "tuple[int, Any]":
        """Late binding (MAGP 8.3.11): the rebind message rebuilt BY HAND, never with the client's own builder."""
        self.bind_requests.append({"authorizationId": auth_id, **dict(body)})
        hold = self.holds.get(auth_id)
        if not hold:
            return 404, {"success": False, "message": "AUTHORIZATION_NOT_FOUND", "data": {"reasonCode": "AUTHORIZATION_NOT_FOUND"}}
        try:
            digest = body["payloadDigest"]
            assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
            esc = lambda v: v.replace("\\", "\\\\").replace("|", "\\|")  # noqa: E731
            message = "|".join(esc(f) for f in ["MAGP-PAYLOAD-REBIND-v1", body["agentDid"], body["action"], auth_id, body["nonce"], body["issuedAt"], digest])
            self.public_key.verify(bytes.fromhex(body["payloadSignature"]), message.encode("utf-8"))
        except Exception:
            self.payload_failures += 1
            return 403, {"success": False, "message": "PAYLOAD_BINDING_INVALID", "data": {"reasonCode": "PAYLOAD_BINDING_INVALID"}}
        if hold.get("payloadDigest"):
            if hold["payloadDigest"] == digest:
                return 200, {"success": True, "message": "Payload already bound", "data": {"authorizationId": auth_id, "payloadDigest": digest, "alreadyBound": True}}
            return 409, {"success": False, "message": "PAYLOAD_ALREADY_BOUND", "data": {"reasonCode": "PAYLOAD_ALREADY_BOUND"}}
        hold["payloadDigest"] = digest
        # A gate that predates late binding would answer without echoing the digest; `echo_payload_digest = False` plays that gate.
        return 200, {"success": True, "message": "Payload bound", "data": {"authorizationId": auth_id, **self._ack(digest)}}

    def get(self, path: str) -> "tuple[int, Any]":
        if path.startswith("/policy/escalations/") and path.endswith("/status"):
            esc_id = path.split("/")[-2]
            e = self.escalations.get(esc_id)
            if not e:
                return 404, {"success": False, "message": "Not found", "data": None}
            data = {"status": e["status"], "reasonCode": "APPROVED" if e["status"] == "approved" else "ESCALATION_PENDING", "approvals": 1 if e["status"] == "approved" else 0, "required": 1}
            if e["status"] == "approved":
                data["authorizationId"] = e["authorizationId"]
            if e["status"] == "modified":
                data["reasonCode"] = "MODIFIED"
                data["nextEscalationId"] = "esc-next"
                data["modifiedAction"] = {"amount": 50}
            return 200, {"success": True, "data": data}
        if path.endswith("/effect"):
            auth_id = path.split("/")[-2]
            h = self.holds.get(auth_id)
            if not h:
                return 404, {"success": False, "message": "AUTHORIZATION_NOT_FOUND", "data": {"authorizationId": auth_id, "reasonCode": "AUTHORIZATION_NOT_FOUND", "detail": "AUTHORIZATION_NOT_FOUND: no authorization with this id"}}
            settled = h["state"] == "captured"
            return 200, {"success": True, "data": {
                "authorizationId": auth_id, "outcome": "settled" if settled else ("not_executed" if h["state"] == "voided" else "not_started"),
                "nothingExecuted": not settled, "retrySafe": h["state"] == "voided", "claimed": False, "spendStatus": h["state"],
                # As the real gate now reports it: the authorized amount survives settlement, and a settlement says what it
                # rests on (this double only accepts a capture at the full amount, so it is always the unattested kind).
                "currency": h["currency"], "authorizedAmount": h["amount"], "settledAmount": h["amount"] if settled else None,
                "settlementEvidence": "unattested" if settled else None,
            }}
        return 404, {"success": False, "message": "no such route", "data": None}

    def _authorize(self, body: Mapping[str, Any]) -> "tuple[int, Any]":
        self.requests.append(dict(body))
        try:
            self.public_key.verify(bytes.fromhex(body["signature"]), rebuild_message(body).encode("utf-8"))
        except Exception:
            self.signature_failures += 1
            return 403, {"success": False, "data": {"decision": "block", "reasonCode": "SIGNATURE_INVALID"}}
        # Payload binding (MAGP 8.3.9), checked with a message rebuilt by hand — never the client's own builder. A digest with no
        # valid signature over it binds nothing, so it is refused; a request that binds nothing is unchanged.
        digest, digest_sig = body.get("payloadDigest"), body.get("payloadSignature")
        if digest is not None or digest_sig is not None:
            try:
                assert isinstance(digest, str) and isinstance(digest_sig, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
                esc = lambda v: v.replace("\\", "\\\\").replace("|", "\\|")  # noqa: E731
                message = "|".join(esc(f) for f in ["MAGP-PAYLOAD-v1", body["agentDid"], body["action"], body["nonce"], body["issuedAt"], digest])
                self.public_key.verify(bytes.fromhex(digest_sig), message.encode("utf-8"))
            except Exception:
                self.payload_failures += 1
                return self._refuse("block", "PAYLOAD_BINDING_INVALID")
        action, amount = body["action"], float(body["amount"])
        risk = (body.get("itinerary") or {}).get("riskLevel")
        if action not in self.grants:
            return self._refuse("block", "NO_PERMISSION_FOR_ACTION")
        if body.get("merchant") and action in self.merchants and body["merchant"] not in self.merchants[action]:
            return self._refuse("block", "MERCHANT_NOT_ALLOWED")
        if amount > self.grants[action]:
            return self._refuse("block", "SOP_SPEND_CAP")
        norm = risk.strip().lower() if isinstance(risk, str) else None
        if norm not in RISK_LEVELS:
            return self._hold("CONTEXT_UNVERIFIABLE", digest)
        if norm in ("high", "critical"):
            return self._hold("RISK_REVIEW", digest)
        auth_id = str(uuid.uuid4())
        self.holds[auth_id] = {"state": "held", "amount": amount, "currency": body["currency"], "payloadDigest": digest}
        # A DIFFERENT id from auth_id — the real gate's anchored evidence event and the mandate hold are
        # never the same id; a test that only ever saw one value here could not catch the two being confused.
        self.last_event_id = str(uuid.uuid4())
        return 200, {"success": True, "data": {"decision": "allow", "reasonCode": "AUTHORIZED", "authorizationId": auth_id, "eventId": self.last_event_id, **self._ack(digest)}}

    def _refuse(self, decision: str, code: str) -> "tuple[int, Any]":
        return 403, {"success": False, "data": {"decision": decision, "reasonCode": code}}

    def _ack(self, digest: Optional[str]) -> Dict[str, Any]:
        """The gate ACKNOWLEDGES a binding by echoing the digest it stored (null when unbound)."""
        return {"payloadDigest": digest} if self.echo_payload_digest else {}

    def _hold(self, code: str, digest: Optional[str] = None) -> "tuple[int, Any]":
        esc_id = str(uuid.uuid4())
        self.escalations[esc_id] = {"status": "pending", "authorizationId": str(uuid.uuid4())}
        return 403, {"success": False, "data": {"decision": "escalate", "reasonCode": code, "escalationId": esc_id, **self._ack(digest)}}

    @staticmethod
    def _settlement_refusal(status: int, flag: str, auth_id: str, code: str, detail: str) -> "tuple[int, Any]":
        """The gate's one settlement-refusal shape (MAGP 8.7.8): the bare code as `message`, the sentence in `data.detail`,
        and the HTTP status the code always has."""
        return status, {"success": False, "message": code, "data": {flag: False, "authorizationId": auth_id, "reasonCode": code, "detail": f"{code}: {detail}"}}

    def _settle(self, verb: str, auth_id: str, body: Mapping[str, Any]) -> "tuple[int, Any]":
        flag = {"capture": "captured", "void": "voided"}.get(verb, "refunded")
        h = self.holds.get(auth_id)
        if not h:
            return self._settlement_refusal(404, flag, auth_id, "AUTHORIZATION_NOT_FOUND", "no authorization with this id")
        if h["state"] != "held":
            if verb == "void":  # repeating a void that already happened (or voiding a settled hold) is a 200, not an error
                return 200, {"success": False, "message": "Not voided (NOT_HELD)", "data": {"voided": False, "authorizationId": auth_id, "status": h["state"], "reasonCode": "NOT_HELD"}}
            return self._settlement_refusal(409, flag, auth_id, "NOT_HELD", "this hold is already settled or released — read GET .../effect")
        if verb == "capture":
            charged = float(body.get("amountCharged", -1))
            if charged > h["amount"]:
                return self._settlement_refusal(400, flag, auth_id, "AMOUNT_EXCEEDS_AUTHORIZED", "amountCharged is more than the authorized hold")
            if charged != h["amount"]:
                # This double treats every hold as claimed by a service, so an agent settling it below the authorization is
                # refused exactly as the real gate refuses a non-claimer's lowered capture.
                return self._settlement_refusal(403, flag, auth_id, "COUNTERPARTY_MISMATCH", "only the claimer of this hold may settle it below the authorized amount")
            h["state"] = "captured"
            return 200, {"success": True, "message": "Captured", "data": {"captured": True}}
        h["state"] = "voided"
        return 200, {"success": True, "message": "Hold voided", "data": {"voided": True}}
