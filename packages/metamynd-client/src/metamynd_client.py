"""
MetaMynd authorize-gate client for Python — the supported reference implementation.

MAGP is language-agnostic by design: the gate verifies an Ed25519 signature over a
canonical string (spec §8.3), and nothing about that is JavaScript-specific. This file is
the proof, and the shortest path for a Python team that does not want to read the Node
guard to find out what the protocol actually expects.

Three details cost a Python integration a day each, because all three fail identically
and silently as SIGNATURE_INVALID — the request is well-formed, the key is correct, and
the bytes that were signed are simply not the bytes the gate reconstructs:

  1. Private key encoding. The provisioning flow hands you a hex string that is DER
     PKCS#8, not a raw 32-byte seed. `load_key` accepts either.
  2. Number stringification. JavaScript's String(150.0) is "150"; Python's str(150.0) is
     "150.0". Different message, different signature. `js_number_to_string` normalises.
  3. Timestamp identity. issuedAt is signed as the literal string that goes on the wire,
     so the two must be byte-identical. The format itself does not matter — isoformat()
     verifies as happily as "...Z" does — but calling the clock twice, once for the
     message and once for the body, does not. With microseconds that fails every time;
     at second precision it fails only when a second ticks between the two calls, which
     is an intermittent SIGNATURE_INVALID under load. `authorize` formats once.

All three are now written down in MAGP §8.3 (the signed message), and the gate returns a
`hint` on a SIGNATURE_INVALID verdict naming them as the usual causes. The message is
EIGHT fields — `agentDid|action|amount|currency|merchant|resource|nonce|issuedAt`; an
earlier release of this file signed seven and every request from it was refused. The
shared vectors in `docs/protocol/authorize-vectors.json` are checked by BOTH this client's
tests and the gate's, so the two cannot drift apart again without a test failing.

SCOPE. This is the entry price, not an SDK: it signs and submits authorize requests,
returns the verdict, follows up an ESCALATE, wraps a tool so it only runs on a permit
(sync or async), hands the signed request to a gateway or MCP server that re-verifies it,
and settles or looks up a hold. Local bundle evaluation and evidence-proof fetch exist in
the protocol and in the Node guard (`integrations/agentsafe-guard`) and are deliberately
not reimplemented here.

Behind a gateway. A tool that calls a service protected by `@metamynd/agentsafe-http-gateway`
or an MCP server using `agentsafe-mcp-guard` must present the signed request so the
service can re-verify it and claim the hold. `guard_tool` does that for you: inside the
wrapped tool, `governance_headers()` returns the header to attach to the outbound call
(`x-magp-request`). Outside it, `verdict.signed.headers()` is the same thing.

Who settles. The service that executed the action settles or releases the hold it claimed
(`capture` / `void`); an agent normally does not. Once a service has claimed a hold, only
that service can settle it below the authorized amount or release it — the gate refuses
the agent's attempt, on purpose, because otherwise an agent could wait for a purchase to
happen and then take its budget back. `capture` at the full authorized amount, and `void`
of a hold nobody has claimed, are the cases an agent can do itself.

Risk. A rule that judges `riskLevel` escalates a request that carries none (or an
unrecognised one) — an agent that omits its risk is indistinguishable from one hiding it.
Send an honest `riskLevel` in `context`, or have your mandate's owner set a `riskTier` so
it does not depend on you (MAGP §6.3). `guard_tool` never invents one.

Requires: Python 3.9+. `pip install metamynd-client` pulls in the one runtime
dependency (`cryptography`) automatically; vendoring this file directly instead
needs `pip install cryptography` on its own.

Usage:

    pip install metamynd-client

    python -m metamynd_client --selftest      # offline: checks the three details

    export METAMYND_API=https://metamynd.ai/api/v1
    export AGENT_DID=did:hedera:testnet:...
    export AGENT_KEY=302e020100...            # as issued
    python -m metamynd_client                 # runs the demo below

or as a library:

    from metamynd_client import MetaMyndClient
    client = MetaMyndClient.from_env()
    verdict = client.authorize("flight-purchase", 150, merchant="skyward-air",
                               context={"tool": "book-flight", "riskLevel": "low"})
    if verdict.decision == "escalate":
        state = client.wait_for_escalation(verdict.escalation_id, timeout=600)
        # act only on state.may_proceed. Never self-approve, never treat `pending` as a yes.
    elif not verdict.permitted:
        raise RuntimeError(f"refused: {verdict.reason_code}")
    # permitted: verdict.signed.headers() is what a gateway needs to re-verify and claim it
"""

from __future__ import annotations

import asyncio
import contextvars
import decimal
import functools
import hashlib
import inspect
import json
import os
import secrets
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Optional, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

__all__ = [
    "MetaMyndClient",
    "Verdict",
    "SignedRequest",
    "EscalationStatus",
    "Outcome",
    "SettlementResult",
    "load_key",
    "js_number_to_string",
    "utc_now_rfc3339",
    "canonical_message",
    "canonical_payload",
    "payload_digest",
    "payload_binding_message",
    "payload_rebind_message",
    "NO_PAYLOAD",
    "BindResult",
    "PayloadNotCanonicalizable",
    "DaemonError",
    "guard_tool",
    "current_governance",
    "governance_headers",
    "GovernanceBlocked",
]

__version__ = "0.5.1"

DEFAULT_API = "http://localhost:9926/api/v1"

# Identify the client explicitly. urllib otherwise sends "Python-urllib/3.x", which the
# CDN in front of the production gate blocks outright: every call comes back
#
#     HTTP 403  error code: 1010
#
# and 403 is also how the gate returns an ordinary refusal, so the failure reads like a
# governance decision rather than a request that never arrived. Nothing in that error
# mentions user agents. Verified against metamynd.ai — curl, python-requests and a bare
# request all pass; "Python-urllib/*" is refused by name.
USER_AGENT = "metamynd-python-client/1.0 (+https://metamynd.ai/developers/python)"

# Only these two permit execution. Everything else — block, escalate, suspend, quarantine
# — must stop the action. `escalate` in particular is a HOLD, not a denial: a human owner
# decides, and the agent must never treat it as an allow.
PERMITTING_DECISIONS = frozenset({"allow", "observe"})

Number = Union[int, float]


# --------------------------------------------------------------------------------------
# The three details
# --------------------------------------------------------------------------------------


def load_key(raw: str) -> Ed25519PrivateKey:
    """Load an agent private key from either encoding MetaMynd hands out.

    Detail 1 of 3 (MAGP §8.3.3). The managed provisioning path returns a hex string that
    is DER PKCS#8 — Hedera's format, recognisable by the ASN.1 SEQUENCE tag `30` and the
    Ed25519 OID that follows (`302e020100300506032b657004220420...`). A BYOK agent that
    generated its own key may instead hold the raw 32-byte seed as 64 hex characters.
    Feeding raw bytes to a DER loader raises; feeding DER bytes to a raw loader raises on
    the length — so detect rather than guess.
    """
    hex_str = raw.strip()
    if hex_str.startswith(("0x", "0X")):
        hex_str = hex_str[2:]
    try:
        key_bytes = bytes.fromhex(hex_str)
    except ValueError as exc:
        raise ValueError("agent key must be hex (DER PKCS#8, or a raw 32-byte seed)") from exc

    if len(key_bytes) == 32:
        return Ed25519PrivateKey.from_private_bytes(key_bytes)

    loaded = serialization.load_der_private_key(key_bytes, password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise ValueError(f"expected an Ed25519 key, got {type(loaded).__name__}")
    return loaded


def js_number_to_string(value: Number) -> str:
    """Render a number the way JavaScript's String() would.

    Detail 2 of 3 (MAGP §8.3.4). The canonical message is a string join, so the amount has
    to become text — and the two languages disagree on how. JS String(150.0) is "150";
    Python str(150.0) is "150.0". One extra character, an entirely different signature,
    and a SIGNATURE_INVALID with nothing in it to suggest the amount was the problem.

    Integral floats collapse to their integer form, which is the whole of the disagreement
    for ordinary money. The rest is the ECMAScript Number::toString rules, applied to the
    shortest round-trip digits Python's repr() already computes (the same digits V8 picks):
    plain decimal for 1e-6 <= |x| < 1e21, exponent form outside it, and JavaScript's own
    spelling of the exponent ("1e-7", "1e+21" — not Python's "1e-07", "1e+21" only by luck).
    Python's repr() alone is NOT enough: repr(0.00005) is "5e-05" and JS writes "0.00005",
    a SIGNATURE_INVALID for any sub-cent amount (x402 micropayments live here).

    An int beyond 2**53 is signed as the double the gate will actually hold: the gate parses
    the JSON body with JSON.parse, which cannot represent it exactly.
    """
    if isinstance(value, bool):  # bool is an int subclass; a boolean amount is a bug
        raise TypeError("amount must be a number, not a bool")
    if isinstance(value, int) and abs(value) <= 2**53:
        return str(int(value))  # int(): an int SUBCLASS (an IntEnum) must render as its number, not its name

    try:
        as_float = float(value)
    except OverflowError:
        raise ValueError("amount is too large to be a JSON number the gate can read") from None
    if as_float != as_float or as_float in (float("inf"), float("-inf")):
        raise ValueError("amount must be finite")
    if as_float == 0:
        return "0"  # also -0.0: String(-0) is "0"

    sign = "-" if as_float < 0 else ""
    parts = decimal.Decimal(repr(abs(as_float))).as_tuple()
    raw_digits = "".join(str(d) for d in parts.digits)
    digits = raw_digits.rstrip("0")
    k = len(digits)  # number of significant digits
    n = k + parts.exponent + (len(raw_digits) - k)  # position of the decimal point: value = 0.DIGITS * 10**n

    if k <= n <= 21:
        text = digits + "0" * (n - k)
    elif 0 < n <= 21:
        text = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        text = "0." + "0" * (-n) + digits
    else:
        exponent = n - 1
        mantissa = digits if k == 1 else digits[0] + "." + digits[1:]
        text = f"{mantissa}e{'+' if exponent >= 0 else '-'}{abs(exponent)}"
    return sign + text


def utc_now_rfc3339() -> str:
    """Timestamp in the shape the spec's examples use (MAGP §8.3.5).

    Detail 3 of 3, and the one most often misdescribed. The gate parses whatever
    RFC 3339 string it receives, so "+00:00" and microseconds verify perfectly well —
    what it cannot tolerate is a DIFFERENT string in the signed message than in the body.
    Second precision is chosen here because it is what the spec's examples show and it
    reads cleanly in an evidence record, not because the gate demands it.

    The rule that actually matters lives at the call site: format once, use the result in
    both places. Calling this function twice for one request is the bug.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _escape_field(value: str) -> str:
    """Mirrors backend/src/policy-core/canonical.ts's escapeField exactly: `\\` and `|` in a
    field's string form must never be mistaken for the `|` delimiter or another escape."""
    return value.replace("\\", "\\\\").replace("|", "\\|")


def canonical_message(
    agent_did: str,
    action: str,
    amount: Number,
    currency: str,
    merchant: Optional[str],
    nonce: str,
    issued_at: str,
    *,
    resource: Optional[str] = None,
) -> str:
    """The UTF-8 string that gets signed (MAGP §8.3.1).

    EIGHT fields, "|"-delimited, in this order, each escaped so a field value can never be
    mistaken for the delimiter — mirrors backend/src/policy-core/canonical.ts's
    buildAuthMessage/escapeField exactly. `resource` was added between merchant and nonce by
    a later release; omit it (or pass None) for a non-resource-scoped request, the same ""
    a verifier defaults an absent one to. The verifier reconstructs this string from the
    fields it received rather than trusting a client-sent message (§8.3.2), which is why
    every field below must be sent exactly as it was signed.
    """
    return "|".join(
        _escape_field(v)
        for v in [
            agent_did,
            action,
            js_number_to_string(amount),
            currency,
            merchant or "",
            resource or "",
            nonce,
            issued_at,
        ]
    )


# --------------------------------------------------------------------------------------
# Payload binding (MAGP §8.3.9)
# --------------------------------------------------------------------------------------
#
# The eight signed fields do not cover a payee, an account number, a passenger list — anything else a real tool takes.
# `payload=` on `authorize` / `sign_request` (or "payload" from `guard_tool`'s `map_args`) signs a digest of the COMPLETE
# payload the tool will execute, bound to that one authorization. The service that executes it digests what it is about to
# run and the gate refuses to let it claim the hold on any difference. Both ends must compute the SAME digest, so the
# canonical form is RFC 8785 (JSON Canonicalization Scheme), reproduced here and pinned to the shared vectors in
# docs/protocol/payload-binding-vectors.json.

PAYLOAD_BINDING_PREFIX = "MAGP-PAYLOAD-v1"
PAYLOAD_REBIND_PREFIX = "MAGP-PAYLOAD-REBIND-v1"
PAYLOAD_DIGEST_PREFIX = "sha256:"
MAX_CANONICAL_PAYLOAD_BYTES = 256 * 1024
_MAX_PAYLOAD_DEPTH = 32


class PayloadNotCanonicalizable(ValueError):
    """The payload contains something JSON cannot carry, so it cannot be digested — refused, never normalised."""


class _NoPayload:
    """The default for `payload=` on `sign_request` / `authorize` / `bind_payload`'s callers: "nothing to bind" — as
    opposed to `None`, which is a real JSON value (`null`) and, since 0.4.0, CAN be bound. A dict has the identical
    problem (`.get("payload")` cannot tell "no such key" from "the key is None"), so `guard_tool`'s `map_args` uses the
    same sentinel: return `{"payload": NO_PAYLOAD}` (or omit the key) for "don't bind", `{"payload": None}` to bind
    literal `null`. Not constructible or comparable to anything else — `NO_PAYLOAD` is the only instance.
    """

    def __repr__(self) -> str:
        return "NO_PAYLOAD"


NO_PAYLOAD = _NoPayload()


def _has_lone_surrogate(text: str) -> bool:
    # A Python str holds code points; a valid pair from json.loads is already one code point, so ANY surrogate is unpaired.
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in text)


def _json_string(text: str, path: str) -> str:
    """ECMAScript JSON.stringify of a string: escape `"` `\\` and control characters; everything else is literal."""
    if _has_lone_surrogate(text):
        raise PayloadNotCanonicalizable(f"{path} contains an unpaired surrogate")
    out = ['"']
    for ch in text:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif code < 0x20:
            out.append({8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r"}.get(code) or f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _canonical(value: Any, depth: int, path: str) -> str:
    if depth > _MAX_PAYLOAD_DEPTH:
        raise PayloadNotCanonicalizable(f"payload is nested deeper than {_MAX_PAYLOAD_DEPTH} levels at {path}")
    if value is None:
        return "null"
    if isinstance(value, bool):  # before int: bool is an int subclass
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        try:
            return js_number_to_string(value)
        except ValueError as exc:
            raise PayloadNotCanonicalizable(f"{path} is not a finite number") from exc
    if isinstance(value, str):
        return _json_string(value, path)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical(v, depth + 1, f"{path}[{i}]") for i, v in enumerate(value)) + "]"
    if isinstance(value, Mapping):
        for k in value:
            if not isinstance(k, str):
                raise PayloadNotCanonicalizable(f"{path} has a non-string key ({type(k).__name__}); JSON object keys are strings")
        # RFC 8785 sorts keys by UTF-16 code unit — NOT by code point, which differs for anything beyond the BMP.
        # Big-endian UTF-16 bytes compare exactly as the code units do. (A lone surrogate does not encode: refused below.)
        try:
            ordered = sorted(value, key=lambda k: k.encode("utf-16-be"))
        except UnicodeEncodeError as exc:
            raise PayloadNotCanonicalizable(f"{path} has a key with an unpaired surrogate") from exc
        return "{" + ",".join(f"{_json_string(k, path)}:{_canonical(value[k], depth + 1, f'{path}.{k}')}" for k in ordered) + "}"
    raise PayloadNotCanonicalizable(f"{path} is a {type(value).__name__}, which JSON cannot represent")


def canonical_payload(value: Any) -> str:
    """The RFC 8785 canonical text of a JSON-shaped Python value (dict / list / str / int / float / bool / None).

    Anything JSON cannot carry — NaN, Infinity, bytes, datetime, Decimal, a set, a non-string key, a lone surrogate — raises
    `PayloadNotCanonicalizable` rather than being normalised: two implementations would normalise it differently, and a
    digest they compute differently is a binding that silently never matches. Convert such values yourself first, the same
    way you would before `json.dumps` — and to the form the SERVICE receives them in.
    """
    text = _canonical(value, 0, "$")
    if len(text.encode("utf-8")) > MAX_CANONICAL_PAYLOAD_BYTES:
        raise PayloadNotCanonicalizable(f"canonical payload exceeds {MAX_CANONICAL_PAYLOAD_BYTES} bytes")
    return text


def payload_digest(value: Any) -> str:
    """`sha256:` + the hex SHA-256 of the canonical text — what the agent signs and the executing service compares."""
    return PAYLOAD_DIGEST_PREFIX + hashlib.sha256(canonical_payload(value).encode("utf-8")).hexdigest()


def payload_binding_message(agent_did: str, action: str, nonce: str, issued_at: str, digest: str) -> str:
    """The UTF-8 string signed to bind `digest` to ONE authorization (MAGP §8.3.9): domain-separated from every other MAGP
    signature, and naming the agent, action, nonce and issuedAt of the authorize request it accompanies."""
    return "|".join(_escape_field(v) for v in [PAYLOAD_BINDING_PREFIX, agent_did, action, nonce, issued_at, digest])


def payload_rebind_message(agent_did: str, action: str, authorization_id: str, nonce: str, issued_at: str, digest: str) -> str:
    """The UTF-8 string signed to bind `digest` to a hold that ALREADY EXISTS and has none (MAGP §8.3.11) — what a reviewer's
    MODIFY leaves behind. Its own domain (a signature made for one message never verifies as the other) and it names the
    authorization id, so the digest is bound to THAT hold and cannot be lifted onto another."""
    return "|".join(_escape_field(v) for v in [PAYLOAD_REBIND_PREFIX, agent_did, action, authorization_id, nonce, issued_at, digest])


# --------------------------------------------------------------------------------------
# Verdict
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class SignedRequest:
    """A request this client signed — what a counterparty needs to re-verify it.

    The gate answers the agent; a SERVICE (an HTTP gateway, an MCP server) that is about to act
    on the agent's behalf answers to nobody unless it can check the agent's authority itself,
    so it asks for the signed request and re-verifies it against the agent's own policy. That
    is what makes "an agent that ignores its guard still cannot make the service act" true —
    and it is the part a Python client used to drop on the floor: `authorize()` signed a
    request, sent it, and threw it away, so a tool that called a gateway could only fail with
    `MISSING_GOVERNANCE`.

    `body` is exactly what was signed and sent, plus the `authorizationId` the gate issued
    (a permit only). It contains a signature, never the key. `headers()` is the supported way
    to attach it to an outbound call.
    """

    # repr=False: the body carries the live signature, and `logger.info("%r", verdict)` must not print it.
    body: Mapping[str, Any] = field(repr=False)

    @property
    def authorization_id(self) -> Optional[str]:
        return self.body.get("authorizationId")

    def header_value(self) -> str:
        """The `x-magp-request` header value: compact JSON, ASCII-only so it is HTTP-header safe."""
        return json.dumps(self.body, separators=(",", ":"), ensure_ascii=True)

    def headers(self) -> dict:
        """Headers to attach to a call to a MAGP-protected service."""
        return {"x-magp-request": self.header_value()}


@dataclass(frozen=True)
class Verdict:
    """The gate's answer. `raw` keeps everything, including fields added after this file.

    `signed` is the request that was signed and sent, with the `authorizationId` a permit
    carries — hand it to a gateway or MCP server with `signed.headers()`.
    """

    decision: str
    reason_code: str
    authorization_id: Optional[str] = None
    escalation_id: Optional[str] = None
    hint: Optional[str] = None
    # The id of the anchored evidence event THIS decision was recorded under (§10.3) — what
    # `GET /magp/evidence/{event_id}/proof` needs to serve this decision's own Merkle inclusion
    # proof. NOT the same id as `authorization_id` (the mandate hold); that id does not work
    # there. None only when the gate's own best-effort evidence write failed.
    event_id: Optional[str] = None
    raw: Mapping[str, Any] = field(default_factory=dict)
    signed: Optional[SignedRequest] = field(default=None, repr=False)

    @property
    def permitted(self) -> bool:
        """True only for the dispositions that permit execution. Fail closed on anything else."""
        return self.decision in PERMITTING_DECISIONS

    @classmethod
    def from_response(cls, body: Mapping[str, Any]) -> "Verdict":
        data = body.get("data") or {}
        return cls(
            decision=str(data.get("decision", "block")),
            reason_code=str(data.get("reasonCode", "UNKNOWN")),
            authorization_id=data.get("authorizationId"),
            # Set on an escalate verdict (§10) — the handle for escalation_status().
            escalation_id=data.get("escalationId"),
            # Diagnostic only, and present only on codes that have one — a
            # SIGNATURE_INVALID says which of the three details is the usual cause.
            hint=data.get("hint"),
            event_id=data.get("eventId"),
            raw=data,
        )


@dataclass(frozen=True)
class EscalationStatus:
    """Where a held action has got to."""

    status: str          # pending | approved | denied | expired | modified
    reason_code: str
    authorization_id: Optional[str] = None
    expires_at: Optional[str] = None
    approvals: int = 0
    required: int = 1
    raw: Mapping[str, Any] = field(default_factory=dict)

    @property
    def resolved(self) -> bool:
        """True once a human has decided, either way — the signal to stop polling.

        `modified` is terminal too: the reviewer changed the action instead of approving it as asked.
        It is NOT `may_proceed` — what was asked for is not what was approved — and `next_escalation_id`
        (when present) is the follow-up hold for the modified action.
        """
        return self.status in {"approved", "denied", "expired", "modified"}

    @property
    def next_escalation_id(self) -> Optional[str]:
        return self.raw.get("nextEscalationId")

    @property
    def modified_action(self) -> Optional[Mapping[str, Any]]:
        return self.raw.get("modifiedAction")

    @property
    def may_proceed(self) -> bool:
        """The ONLY condition under which the held action may run."""
        return self.status == "approved" and bool(self.authorization_id)


@dataclass(frozen=True)
class Outcome:
    """What became of an authorization — the answer to "did it happen, and may I try again?".

    `outcome` is one of not_started | expired | in_flight | settled | not_executed | unknown |
    reversing | reversed | reversal_failed. Two safety bits answer different questions:

      nothing_executed   nothing has run SO FAR.
      retry_safe         nothing can run LATER either, so a fresh authorization cannot duplicate
                         this one. Only `expired` and `not_executed`.

    Retry ONLY on `retry_safe`. `not_started` is nothing_executed but not retry_safe (a service
    queued behind a slow gateway can still claim it — void it first); `unknown` and `in_flight`
    are neither: an ambiguous outcome is reconciled, never retried blindly.
    """

    outcome: str
    nothing_executed: bool = False
    retry_safe: bool = False
    claimed: bool = False
    effect_state: Optional[str] = None
    spend_status: Optional[str] = None
    currency: Optional[str] = None
    # What the gate authorized — reported before AND after settlement. None means unknown (an authorization captured
    # before the gate kept it), which is not the same as zero or as the settled amount.
    authorized_amount: Optional[float] = None
    settled_amount: Optional[float] = None
    # What `settled_amount` rests on: unattested | unclaimed_lowered | counterparty_attested | independently_confirmed |
    # operator_resolved | reconciled_at_authorized (spec 8.7.9). Only `independently_confirmed` (and an operator's
    # decision) means anything beyond "the claiming service said so".
    settlement_evidence: Optional[str] = None
    raw: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SettlementResult:
    """The gate's answer to a capture or a void. `ok` is False for a refusal (`message` says why)."""

    ok: bool
    message: str = ""
    raw: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BindResult:
    """The gate's answer to `bind_payload`. `bound` is True only when the gate CONFIRMED the digest it now holds for the hold;
    anything else (`reason_code` says why) means the payload is NOT bound and the caller must not act as if it were."""

    bound: bool
    payload_digest: Optional[str] = None
    reason_code: Optional[str] = None
    already_bound: bool = False
    raw: Mapping[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------------------
# Remote signer daemon (agentsafe-signer, 0.5.0) — the key stays out of this process
# --------------------------------------------------------------------------------------
#
# `agentsafe-signer` (`integrations/agentsafe-signer`) is a SEPARATE local process holding the
# agent's key, reachable over a Unix domain socket (a Windows named pipe there — see below) with
# a tiny, closed, line-delimited JSON protocol (`daemon.mjs`, `daemon-client.mjs`). It never
# returns the key itself, under any request. It also never signs bytes a caller hands it — every
# op takes STRUCTURED fields and reconstructs the exact same canonical message this file builds
# locally, so a compromised or careless caller cannot trick it into signing something else under
# the agent's key. This client speaks the SAME protocol as the Node guards' daemon key providers
# (`agentsafe-guard`'s `key-providers.mjs`, `createDaemonKeyProvider`) — same socket, same wire
# format, same two ops (`sign-authorize`, `sign-payload`: the only two this client ever needs).
#
# `MetaMyndClient(api, agent_did, daemon_socket=path)` in place of `agent_key=` routes every
# signature through the daemon instead of a key held in this process's memory.

DAEMON_PROTOCOL_VERSION = 1
_DAEMON_ENOENT_RETRY_MS = 20


class DaemonError(RuntimeError):
    """The daemon rejected a request, or could not be reached. `code` is the daemon's own error
    code (`DAEMON_UNREACHABLE`, `DAEMON_MALFORMED_REQUEST`, `DAEMON_IDENTITY_MISMATCH`,
    `DAEMON_UNKNOWN_OPERATION` — an older daemon that predates an operation this client sent —
    and so on); never guess at its meaning from the message text alone."""

    def __init__(self, code: str, message: Optional[str] = None):
        super().__init__(message or code)
        self.code = code


def _daemon_pipe_name(socket_path: str) -> str:
    """The short name .NET's NamedPipeServerStream (and this client, on Windows) derive the
    `\\\\.\\pipe\\...` path from — MUST match `daemon.mjs`'s `windowsPipeName` byte-for-byte, since
    client and server compute this independently and never exchange it. `os.path.abspath` and
    Node's `path.resolve` agree for an already-well-formed path on the SAME machine/OS (both
    resolve relative to cwd and normalise separators to the platform's own) — this is exercised
    against the real daemon by `test_daemon_signer.py`'s live conformance test, not assumed."""
    digest = hashlib.sha256(os.path.abspath(socket_path).encode("utf-8")).hexdigest()[:32]
    return f"agentsafe-signer-{digest}"


class _PosixDaemonConn:
    """A connected AF_UNIX socket, wrapped to the tiny read/write surface `_daemon_request` needs
    (so the Windows named-pipe transport below can present the identical surface)."""

    def __init__(self, sock: "socket.socket"):
        self._sock = sock

    def sendall(self, data: bytes) -> None:
        self._sock.sendall(data)

    def recv(self, n: int) -> bytes:
        return self._sock.recv(n)

    def close(self) -> None:
        self._sock.close()


def _connect_posix(socket_path: str, deadline: float) -> _PosixDaemonConn:
    """Connect to the daemon's Unix domain socket, retrying a transient ENOENT the same way
    `daemon-client.mjs` does: `ENOENT` here does not mean "no daemon" — the daemon may be mid
    startup — but it is retried for progressively less time as `deadline` approaches, never past
    it, so a genuinely absent daemon still fails within `connect_timeout`."""
    while True:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(socket_path)
            return _PosixDaemonConn(sock)
        except FileNotFoundError:
            sock.close()
            if time.monotonic() >= deadline:
                raise
            time.sleep(_DAEMON_ENOENT_RETRY_MS / 1000)
        except OSError:
            sock.close()
            raise


_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_OPEN_EXISTING = 3
_ERROR_FILE_NOT_FOUND = 2
_ERROR_PIPE_BUSY = 231
_INVALID_HANDLE_VALUE = 0xFFFFFFFFFFFFFFFF  # what CreateFileW's HANDLE-typed return actually compares equal to on
# failure, verified empirically: `restype = wintypes.HANDLE` decodes it as this UNSIGNED 64-bit value here, not
# the signed `-1` the Win32 docs' `(HANDLE)(LONG_PTR)-1` cast suggests — comparing against the wrong one meant
# every genuine failure (including the routine `ERROR_PIPE_BUSY` the pool retry below exists for) was silently
# treated as a successful connect, on a handle that then failed the very next read or write.


def _kernel32():
    """`ctypes.windll.kernel32` with the handful of signatures this needs declared EXPLICITLY —
    left at ctypes' default (`c_int` args and return), `CreateFileW`'s HANDLE return is truncated
    to 32 bits on 64-bit Windows, so `INVALID_HANDLE_VALUE` never compares equal and every open
    looks like it succeeded with a garbage handle. Declared once, lazily (never touched at all on
    a non-Windows import), and memoized on the function object."""
    import ctypes
    import ctypes.wintypes

    k32 = getattr(_kernel32, "_cached", None)
    if k32 is not None:
        return k32
    k32 = ctypes.windll.kernel32
    k32.CreateFileW.restype = ctypes.wintypes.HANDLE
    k32.CreateFileW.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD, ctypes.wintypes.HANDLE]
    k32.ReadFile.restype = ctypes.wintypes.BOOL
    k32.ReadFile.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.DWORD), ctypes.c_void_p]
    k32.WriteFile.restype = ctypes.wintypes.BOOL
    k32.WriteFile.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.DWORD), ctypes.c_void_p]
    k32.CloseHandle.restype = ctypes.wintypes.BOOL
    k32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
    k32.WaitNamedPipeW.restype = ctypes.wintypes.BOOL
    k32.WaitNamedPipeW.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD]
    k32.GetLastError.restype = ctypes.wintypes.DWORD
    _kernel32._cached = k32
    return k32


class _WindowsDaemonConn:
    """A connected named-pipe HANDLE, opened via raw `kernel32` calls through `ctypes` — no extra
    package (e.g. `pywin32`) needed for the CLIENT side, which only opens an existing pipe the
    daemon already created and ACL-restricted (`windows-secure-pipe.mjs`); this never constructs a
    pipe or a security descriptor itself, so it needs none of that module's complexity."""

    def __init__(self, handle: int):
        self._handle = handle

    def sendall(self, data: bytes) -> None:
        import ctypes
        import ctypes.wintypes

        k32 = _kernel32()
        written = ctypes.wintypes.DWORD(0)
        buf = ctypes.create_string_buffer(data, len(data))
        ok = k32.WriteFile(self._handle, buf, len(data), ctypes.byref(written), None)
        if not ok:
            raise OSError(f"WriteFile to signer pipe failed (GetLastError={k32.GetLastError()})")

    def recv(self, n: int) -> bytes:
        import ctypes
        import ctypes.wintypes

        k32 = _kernel32()
        buf = ctypes.create_string_buffer(n)
        read = ctypes.wintypes.DWORD(0)
        ok = k32.ReadFile(self._handle, buf, n, ctypes.byref(read), None)
        if not ok:
            raise OSError(f"ReadFile from signer pipe failed (GetLastError={k32.GetLastError()})")
        return buf.raw[: read.value]

    def close(self) -> None:
        _kernel32().CloseHandle(self._handle)


def _connect_windows(socket_path: str, deadline: float) -> _WindowsDaemonConn:
    """Open the named pipe `daemon.mjs`'s Windows relay (`windows-secure-pipe.mjs`) hosts. Windows
    has no ENOENT-style transient error for "no free pipe instance right now" — it is
    `ERROR_PIPE_BUSY`, and the documented fix is `WaitNamedPipeW` (block until an instance frees or
    the wait itself times out) before retrying `CreateFileW`; `ERROR_FILE_NOT_FOUND` (the daemon is
    not up at all yet) gets the same short-sleep retry the POSIX path uses for ENOENT."""
    pipe_path = "\\\\.\\pipe\\" + _daemon_pipe_name(socket_path)
    k32 = _kernel32()
    while True:
        handle = k32.CreateFileW(pipe_path, _GENERIC_READ | _GENERIC_WRITE, 0, None, _OPEN_EXISTING, 0, None)
        if handle != _INVALID_HANDLE_VALUE:
            return _WindowsDaemonConn(handle)
        err = k32.GetLastError()
        remaining_ms = int((deadline - time.monotonic()) * 1000)
        if remaining_ms <= 0:
            raise OSError(f"agentsafe-signer daemon unreachable at {socket_path}: CreateFile failed (GetLastError={err})")
        if err == _ERROR_PIPE_BUSY:
            k32.WaitNamedPipeW(pipe_path, min(remaining_ms, 1000))
            continue
        if err == _ERROR_FILE_NOT_FOUND:
            time.sleep(_DAEMON_ENOENT_RETRY_MS / 1000)
            continue
        raise OSError(f"agentsafe-signer daemon unreachable at {socket_path}: CreateFile failed (GetLastError={err})")


def _daemon_request(socket_path: str, op: str, params: Mapping[str, Any], connect_timeout: float = 3.0) -> Mapping[str, Any]:
    """One request/response round trip: connect (platform-dispatched), write ONE line of JSON,
    read ONE line back. Same wire shape as `daemon-client.mjs`'s `daemonRequest`: `{protocolVersion,
    requestId, op, params}\\n` out, `{ok, result}` or `{ok:false, error:{code,message}}\\n` back."""
    deadline = time.monotonic() + connect_timeout
    try:
        conn = _connect_windows(socket_path, deadline) if sys.platform == "win32" else _connect_posix(socket_path, deadline)
    except OSError as exc:
        raise DaemonError("DAEMON_UNREACHABLE", f"agentsafe-signer daemon unreachable at {socket_path}: {exc}") from exc
    try:
        request_id = secrets.token_hex(16)
        conn.sendall((json.dumps({"protocolVersion": DAEMON_PROTOCOL_VERSION, "requestId": request_id, "op": op, "params": dict(params)}) + "\n").encode("utf-8"))
        buf = b""
        while b"\n" not in buf:
            if time.monotonic() >= deadline:
                raise DaemonError("DAEMON_UNREACHABLE", f"agentsafe-signer daemon at {socket_path} timed out waiting for a response")
            chunk = conn.recv(65536)
            if not chunk:
                raise DaemonError("DAEMON_UNREACHABLE", f"agentsafe-signer daemon at {socket_path} closed the connection")
            buf += chunk
    finally:
        conn.close()
    line, _, _rest = buf.partition(b"\n")
    res = json.loads(line.decode("utf-8"))
    if not res.get("ok"):
        err = res.get("error") or {}
        raise DaemonError(err.get("code", "DAEMON_ERROR"), err.get("message"))
    return res.get("result") or {}


class _LocalKeySigner:
    """Signs with the key held in THIS process (the pre-0.5.0 behaviour, unchanged)."""

    def __init__(self, key: Ed25519PrivateKey):
        self._key = key

    def sign_authorize(self, fields: Mapping[str, Any]) -> bytes:
        message = canonical_message(fields["agentDid"], fields["action"], fields["amount"], fields["currency"], fields.get("merchant"), fields["nonce"], fields["issuedAt"], resource=fields.get("resource"))
        return self._key.sign(message.encode("utf-8"))

    def sign_payload_binding(self, fields: Mapping[str, Any]) -> bytes:
        authorization_id = fields.get("authorizationId")
        if authorization_id is None:
            message = payload_binding_message(fields["agentDid"], fields["action"], fields["nonce"], fields["issuedAt"], fields["payloadDigest"])
        else:
            message = payload_rebind_message(fields["agentDid"], fields["action"], authorization_id, fields["nonce"], fields["issuedAt"], fields["payloadDigest"])
        return self._key.sign(message.encode("utf-8"))


class _DaemonSigner:
    """Signs by asking `agentsafe-signer` — the key never enters this process."""

    def __init__(self, socket_path: str, connect_timeout: float = 3.0):
        self._socket_path = socket_path
        self._connect_timeout = connect_timeout

    def _request(self, op: str, fields: Mapping[str, Any]) -> bytes:
        # A field this client treats as "absent" is `None` (Python has no separate undefined); the daemon's own
        # validation treats a PRESENT-but-non-string field as malformed and an ABSENT one as fine (JS `undefined`),
        # so an optional field genuinely absent — no merchant, no resource, no authorizationId — must be dropped
        # from `params` entirely rather than sent as JSON `null`, or the daemon refuses it as an invalid string.
        params = {k: v for k, v in fields.items() if v is not None}
        result = _daemon_request(self._socket_path, op, params, self._connect_timeout)
        signature = result.get("signature")
        if not isinstance(signature, str):
            raise DaemonError("DAEMON_MALFORMED_RESPONSE", f"{op} response carried no signature")
        return bytes.fromhex(signature)

    def sign_authorize(self, fields: Mapping[str, Any]) -> bytes:
        return self._request("sign-authorize", fields)

    def sign_payload_binding(self, fields: Mapping[str, Any]) -> bytes:
        try:
            return self._request("sign-payload", fields)
        except DaemonError as exc:
            if exc.code == "DAEMON_UNKNOWN_OPERATION":
                raise DaemonError("PAYLOAD_BINDING_UNSUPPORTED", "the agentsafe-signer daemon predates payload binding (sign-payload, signer 0.15.0); upgrade it, or omit `payload`") from exc
            raise


# --------------------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------------------


class MetaMyndClient:
    """Signs and submits authorize requests to the MetaMynd gate."""

    def __init__(self, api: str, agent_did: str, agent_key: Optional[str] = None, timeout: float = 15.0, *, daemon_socket: Optional[str] = None):
        """Exactly one of `agent_key` (the key lives in THIS process) or `daemon_socket` — a path
        to an `agentsafe-signer` daemon's socket (0.5.0) — must be given; the daemon signs without
        ever handing the key to this process. Everything else about the client is identical either
        way: every signing call already goes through `self._signer`, so nothing downstream needs
        to know or care which one is in use.
        """
        self.api = api.rstrip("/")
        self.agent_did = agent_did
        self.timeout = timeout
        if bool(agent_key) == bool(daemon_socket):
            raise ValueError("MetaMyndClient needs exactly one of agent_key or daemon_socket")
        self._signer = _LocalKeySigner(load_key(agent_key)) if agent_key else _DaemonSigner(daemon_socket)

    @classmethod
    def from_env(cls) -> "MetaMyndClient":
        """Build from METAMYND_API / AGENT_DID / AGENT_KEY, or — since 0.5.0 — AGENT_DID /
        AGENT_DAEMON_SOCKET when AGENT_KEY is unset, for a daemon-custody agent."""
        agent_did = os.environ.get("AGENT_DID", "")
        agent_key = os.environ.get("AGENT_KEY", "")
        daemon_socket = os.environ.get("AGENT_DAEMON_SOCKET", "")
        if not agent_did or not (agent_key or daemon_socket):
            raise RuntimeError("set AGENT_DID and (AGENT_KEY or AGENT_DAEMON_SOCKET) (see the provisioning docs)")
        api = os.environ.get("METAMYND_API", DEFAULT_API)
        if agent_key:
            return cls(api, agent_did, agent_key)
        return cls(api, agent_did, daemon_socket=daemon_socket)

    def sign_request(
        self,
        action: str,
        amount: Number,
        currency: str = "USD",
        merchant: Optional[str] = None,
        context: Optional[Mapping[str, Any]] = None,
        resource: Optional[str] = None,
        authorization_id: Optional[str] = None,
        payload: Any = NO_PAYLOAD,
    ) -> SignedRequest:
        """Sign a request WITHOUT sending it to the gate.

        `authorize()` uses this. Call it yourself when you need a fresh signed request for a
        service that re-verifies — most usefully after a human approved a held action: the
        original request is old by then and a service refuses one older than a few minutes, so
        sign again and attach the `authorization_id` the approval carries
        (`status.authorization_id`). `authorization_id` is not part of the signed message, so
        adding it needs no new signature.

        `payload` (optional) is the COMPLETE payload the tool will execute — a dict / list of
        JSON values. Omitted (the default, `NO_PAYLOAD`) means unbound, exactly as before. Since
        0.4.0, `None` is no longer synonymous with omitted: `payload=None` binds the literal JSON
        `null` (pass `NO_PAYLOAD` explicitly, or omit the argument, for "don't bind"). The eight
        signed fields do not cover a payee or an account number; this does: a digest of the
        payload is signed, bound to this one authorization, and the service that executes it is
        held to the same digest (MAGP §8.3.9). A payload JSON cannot carry (NaN, bytes, a
        datetime, a lone surrogate) raises `PayloadNotCanonicalizable` — it is never silently
        sent unbound.
        """
        nonce = secrets.token_hex(16)  # §8.2 — 8-128 chars, single use
        # Formatted ONCE and reused in both the signed message and the body (§8.3.5).
        # Two calls to the clock is the intermittent-SIGNATURE_INVALID bug.
        issued_at = utc_now_rfc3339()
        # `self._signer` builds the exact same canonical message from these fields whether it
        # signs locally or asks the daemon to (§8.3.9's "the daemon builds the message itself"
        # property extends here: this file never hands EITHER signer a pre-built string).
        auth_fields = {"agentDid": self.agent_did, "action": action, "amount": amount, "currency": currency, "merchant": merchant, "resource": resource, "nonce": nonce, "issuedAt": issued_at}

        body: dict[str, Any] = {
            "agentDid": self.agent_did,
            "action": action,
            # The amount is signed as text but sent as a number; the gate stringifies the
            # received value the same way to rebuild the message.
            "amount": amount,
            "currency": currency,
            "nonce": nonce,
            "issuedAt": issued_at,
            "signature": self._signer.sign_authorize(auth_fields).hex(),
        }
        if merchant:
            body["merchant"] = merchant
        # `resource` is a SIGNED, top-level field (§8.3.1) — not something to tuck into `context`,
        # where it is unsigned and, worse, silently ignored.
        if resource:
            body["resource"] = resource
        if context:
            body["itinerary"] = dict(context)
        if payload is not NO_PAYLOAD:
            digest = payload_digest(payload)
            body["payloadDigest"] = digest
            body["payloadSignature"] = self._signer.sign_payload_binding({"agentDid": self.agent_did, "action": action, "nonce": nonce, "issuedAt": issued_at, "payloadDigest": digest}).hex()
        if authorization_id:
            body["authorizationId"] = authorization_id
        return SignedRequest(body)

    def authorize(
        self,
        action: str,
        amount: Number,
        currency: str = "USD",
        merchant: Optional[str] = None,
        context: Optional[Mapping[str, Any]] = None,
        resource: Optional[str] = None,
        payload: Any = NO_PAYLOAD,
    ) -> Verdict:
        """Ask the gate whether this action may proceed (MAGP §8.1-§8.3).

        `context` carries the request context the Standard/SOP rules read — `tool`,
        `jurisdiction`, `riskLevel` and so on. Which fields your assigned rules need is
        discoverable: each atom at GET /standards/atoms lists its `requiredContext`. Send an
        honest `riskLevel`: a request with none is escalated, not allowed (MAGP §6.3).

        `resource` is what this specific action touches (a signed field, checked against the
        mandate's resource scope).

        `payload` binds everything ELSE the tool will execute (see `sign_request`, including the
        0.4.0 `NO_PAYLOAD` / `None` distinction): pass the arguments exactly as the service will
        receive them, and a service that claims the hold with a different payload is refused by
        the gate before it runs anything.

        A permit carries `verdict.signed` — the request exactly as signed, with the
        `authorizationId` the gate issued — for a gateway or MCP server that re-verifies it.
        """
        signed = self.sign_request(action, amount, currency, merchant, context, resource, payload=payload)
        # The gate is sent the request; the authorizationId only exists once it answers.
        verdict = Verdict.from_response(self._post("/policy/mandate/authorize", dict(signed.body)))
        if "payloadDigest" in signed.body and verdict.decision in ("allow", "observe", "escalate") and verdict.raw.get("payloadDigest") != signed.body["payloadDigest"]:
            # The gate ACKNOWLEDGES a binding by echoing the digest it stored. A permit or escalation that does not — a proxy
            # stripped the fields, or the backend predates payload binding and ignored them — was never bound: refuse it, and
            # release the hold just made (best effort; an unclaimed hold also lapses on its own). Never act on an unbound
            # authorization the caller believes is bound.
            if verdict.authorization_id:
                try:
                    self.void(verdict.authorization_id, reason="payload binding not confirmed by the gate")
                except Exception:  # noqa: BLE001 — best effort
                    pass
            return Verdict(
                decision="block",
                reason_code="PAYLOAD_BINDING_NOT_CONFIRMED",
                hint="the gate did not confirm the payload binding (an older backend, or the digest was stripped in transit)",
                event_id=verdict.event_id,
                raw={**verdict.raw, "decision": "block", "authorizationId": None},
            )
        handoff = SignedRequest({**signed.body, "authorizationId": verdict.authorization_id}) if verdict.authorization_id else signed
        return Verdict(
            decision=verdict.decision,
            reason_code=verdict.reason_code,
            authorization_id=verdict.authorization_id,
            escalation_id=verdict.escalation_id,
            hint=verdict.hint,
            event_id=verdict.event_id,
            raw=verdict.raw,
            signed=handoff,
        )

    def bind_payload(self, authorization_id: str, action: str, payload: Any) -> BindResult:
        """Bind a payload to a hold that ALREADY EXISTS and carries none (MAGP §8.3.11).

        A reviewer's MODIFY changes the action this agent signed, so the hold it mints — or the one minted when the re-entered
        review is approved — has no payload digest, and a service that requires binding could never claim it. This is how the
        agent binds the payload of the action that WILL run: it signs a message naming the authorization (so the digest cannot
        be lifted onto another hold) and the gate applies it only while the hold is live, unclaimed and unbound.

            status = client.escalation_status(escalation_id)           # approved, or modified
            client.bind_payload(status.authorization_id, "flight-purchase", payload)
            signed = client.sign_request("flight-purchase", amount, payload=payload, authorization_id=status.authorization_id)

        Returns a `BindResult`; a gate refusal is `bound=False` with its `reason_code`, never an exception. A payload JSON cannot
        carry raises `PayloadNotCanonicalizable` before anything is sent. An unreachable gate raises `RuntimeError`: the payload is
        NOT bound.
        """
        digest = payload_digest(payload)
        nonce = secrets.token_hex(16)
        issued_at = utc_now_rfc3339()
        body = {
            "agentDid": self.agent_did,
            "action": action,
            "nonce": nonce,
            "issuedAt": issued_at,
            "payloadDigest": digest,
            "payloadSignature": self._signer.sign_payload_binding({"agentDid": self.agent_did, "action": action, "nonce": nonce, "issuedAt": issued_at, "payloadDigest": digest, "authorizationId": authorization_id}).hex(),
        }
        result = self._post(
            f"/policy/mandate/authorize/{urllib.parse.quote(authorization_id, safe='')}/payload-binding",
            body,
            unreachable="the payload is NOT bound; do not execute this action as if it were",
        )
        # A gate (or a proxy in front of it) that answers with anything but a JSON object is not confirming a binding.
        if not isinstance(result, Mapping):
            raise RuntimeError("gate returned an unexpected body for a payload binding — the payload is NOT bound")
        data = result.get("data") or {}
        if not isinstance(data, Mapping):
            data = {}
        if result.get("success") is True and data.get("payloadDigest") == digest:
            return BindResult(bound=True, payload_digest=digest, already_bound=data.get("alreadyBound") is True, raw=data)
        # A success that does not echo the digest we sent is an issuer that predates late binding answering something else.
        reason = "PAYLOAD_BINDING_NOT_CONFIRMED" if result.get("success") is True else str(data.get("reasonCode") or result.get("message") or "REFUSED")
        return BindResult(bound=False, reason_code=reason, raw=data)

    def wait_for_escalation(
        self,
        escalation_id: str,
        timeout: float = 300.0,
        interval: float = 2.0,
        _sleep: Callable[[float], None] = time.sleep,
    ) -> EscalationStatus:
        """Poll a held action until a human decides, or `timeout` seconds pass.

        Returns the last status. It may STILL be `pending` if the timeout hit — check
        `may_proceed`, never `not denied`: a hold nobody has decided is a hold. An unreachable
        gate raises (the hold stands); it never resolves the wait in the action's favour.
        """
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            status = self.escalation_status(escalation_id)
            if status.resolved or time.monotonic() >= deadline:
                return status
            _sleep(max(0.05, min(interval, deadline - time.monotonic())))

    # ---- settlement and lookup ---------------------------------------------------------------

    def capture(
        self,
        authorization_id: str,
        amount_charged: Number,
        booking_ref: Optional[str] = None,
        settlement_tx_hash: Optional[str] = None,
    ) -> SettlementResult:
        """Report what was actually charged, committing the hold.

        Normally the SERVICE that executed the action does this, not the agent. The gate accepts
        an agent's capture at the FULL authorized amount, and refuses a LOWER amount once a
        service has claimed the hold (it would let an agent take its budget back after the
        purchase happened). A refusal comes back as `ok=False` with the gate's `message`.
        """
        body: dict[str, Any] = {"amountCharged": amount_charged}
        if booking_ref:
            body["bookingRef"] = booking_ref
        if settlement_tx_hash:
            body["settlementTxHash"] = settlement_tx_hash
        return self._settlement(f"/policy/mandate/authorize/{urllib.parse.quote(authorization_id, safe='')}/capture", body)

    def void(self, authorization_id: str, reason: Optional[str] = None) -> SettlementResult:
        """Release a hold nobody has claimed, returning its amount to the budget.

        Refused (`ok=False`) once a service has claimed the hold: only that service can release
        it, because it may already have executed the action.
        """
        body: dict[str, Any] = {}
        if reason:
            body["reason"] = reason
        return self._settlement(f"/policy/mandate/authorize/{urllib.parse.quote(authorization_id, safe='')}/void", body)

    def outcome(self, authorization_id: str) -> Outcome:
        """What became of an authorization — did it happen, and is a retry safe? See `Outcome`."""
        data = self._get_data(f"/policy/mandate/authorize/{urllib.parse.quote(authorization_id, safe='')}/effect")
        return Outcome(
            outcome=str(data.get("outcome", "unknown")),
            # Fail closed: anything the gate did not say plainly is "not safe".
            nothing_executed=data.get("nothingExecuted") is True,
            retry_safe=data.get("retrySafe") is True,
            claimed=data.get("claimed") is True,
            effect_state=data.get("effectState"),
            spend_status=data.get("spendStatus"),
            currency=data.get("currency"),
            authorized_amount=data.get("authorizedAmount"),
            settled_amount=data.get("settledAmount"),
            settlement_evidence=data.get("settlementEvidence"),
            raw=data,
        )

    def _settlement(self, path: str, body: Mapping[str, Any]) -> SettlementResult:
        # A lost response to a capture or void may already have committed, so "treat as block" would
        # be wrong here: the outcome is unknown, and `outcome()` is how to find out.
        payload = self._post(path, body, unreachable="the outcome is UNKNOWN — it may have been applied; check client.outcome() before retrying")
        data = payload.get("data") or {}
        message = str(payload.get("message") or data.get("reasonCode") or "")
        return SettlementResult(ok=payload.get("success") is True, message=message, raw=data)

    def _get_data(self, path: str) -> Mapping[str, Any]:
        """GET a public gate endpoint and return its `data`, with the same failure rules as authorize."""
        request = urllib.request.Request(f"{self.api}{path}", headers={"User-Agent": USER_AGENT}, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
            return (_loads(raw, "gate returned a non-JSON body") or {}).get("data") or {}
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            try:
                return (json.loads(payload) or {}).get("data") or {}
            except json.JSONDecodeError:
                raise RuntimeError(f"gate returned HTTP {exc.code}: {payload[:200]!r}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise RuntimeError(f"gate unreachable ({getattr(exc, 'reason', exc)}) — nothing is known about the outcome") from exc

    def escalation_status(self, escalation_id: str) -> EscalationStatus:
        """Follow up a held action (MAGP §10).

        ESCALATE is not a denial — the action is PARKED for a human owner, and roughly a
        third of what the demo below prints ends here. The endpoint is unauthenticated and
        keyed by the escalation id, which is itself the capability: an agent has no user
        token and needs none to ask about its own held action.

        Poll until `resolved`, then act only on `may_proceed`. Never self-approve, and
        never treat `pending` as permission to continue — a hold that has not been decided
        is a hold.
        """
        request = urllib.request.Request(
            f"{self.api}/policy/escalations/{urllib.parse.quote(escalation_id, safe='')}/status",
            headers={"User-Agent": USER_AGENT},
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
            data = (_loads(raw, "gate returned a non-JSON body") or {}).get("data") or {}
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            try:
                data = (json.loads(payload) or {}).get("data") or {}
            except json.JSONDecodeError:
                if exc.code == 403 and b"1010" in payload:
                    raise RuntimeError(
                        "gate returned HTTP 403 (CDN error 1010) — the request was refused "
                        "before it reached the gate, not by it. Something replaced the "
                        f"User-Agent: expected {USER_AGENT!r}."
                    ) from exc
                raise RuntimeError(f"gate returned HTTP {exc.code}: {payload[:200]!r}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            # Same rule as authorize: an unreachable gate is a hold, never a release.
            raise RuntimeError(f"gate unreachable ({getattr(exc, 'reason', exc)}) — the hold stands") from exc

        return EscalationStatus(
            status=str(data.get("status", "unknown")),
            reason_code=str(data.get("reasonCode", "UNKNOWN")),
            authorization_id=data.get("authorizationId"),
            expires_at=data.get("expiresAt"),
            approvals=int(data.get("approvals") or 0),
            required=int(data.get("required") or 1),
            raw=data,
        )

    def _post(self, path: str, body: Mapping[str, Any], *, unreachable: str = "treat as block") -> Mapping[str, Any]:
        request = urllib.request.Request(
            f"{self.api}{path}",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
            return _loads(raw, "gate returned a non-JSON body")
        except urllib.error.HTTPError as exc:
            # A refusal is a 403 carrying the verdict, so an HTTP error here is usually a
            # normal governance outcome rather than a transport failure.
            payload = exc.read()
            try:
                return json.loads(payload)
            except json.JSONDecodeError:
                raise RuntimeError(f"gate returned HTTP {exc.code}: {payload[:200]!r}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            # Rule 5 of the runtime contract: unreachable gate means BLOCK. Raising is how
            # a caller that follows the contract fails closed. (A read timeout is not a URLError.)
            reason = getattr(exc, "reason", exc)
            raise RuntimeError(f"gate unreachable ({reason}) — {unreachable}") from exc


def _loads(raw: bytes, what: str) -> Any:
    """json.loads that fails as the RuntimeError the rest of the client documents (a CDN's HTML error page
    with a 200 status would otherwise surface as a JSONDecodeError that `except RuntimeError` misses)."""
    try:
        return json.loads(raw)
    except ValueError as exc:
        raise RuntimeError(f"{what}: {raw[:200]!r}") from exc


class GovernanceBlocked(RuntimeError):
    """Raised instead of running a tool the gate did not permit."""

    def __init__(self, verdict: Verdict, action: str):
        super().__init__(f"{action} refused: {verdict.decision}/{verdict.reason_code}")
        self.verdict = verdict
        self.action = action


def guard_tool(
    client: "MetaMyndClient",
    action: str,
    fn: "Any",
    map_args: "Any" = None,
) -> "Any":
    """Wrap a callable so it runs ONLY on a permit.

    The Node guard's `guardTool()` has always had this; Python did not, and its absence was
    the real gap. A client that only returns verdicts leaves every caller to remember to
    check one — and the failure mode of forgetting is that the tool runs anyway, which is
    the exact thing this product exists to prevent. Wrapping inverts that: the unguarded
    path stops being the easy one.

    `map_args` turns your tool's arguments into the gate's inputs
    (`amount`, `currency`, `merchant`, `resource`, `context`). Without it the call is
    authorized with no amount, which is right for a tool that moves no money and wrong for
    one that does — so pass it whenever there is a value at stake. Put an honest `riskLevel`
    in `context`; a call with none is escalated (MAGP §6.3), and this function never invents one.

        book = guard_tool(client, "flight-purchase", raw_book,
                          lambda vendor, amount: {"amount": amount, "merchant": vendor,
                                                  "context": {"tool": "book-flight", "riskLevel": "low"}})

    `map_args` may also return `"payload"`: the complete payload the tool will send (a dict of
    JSON values). It is digested and signed with the request, so the service that executes it
    is held to exactly those arguments — a payee or account number the eight signed fields do
    not cover (MAGP §8.3.9). One a JSON payload cannot carry raises PayloadNotCanonicalizable
    before the tool is touched. Omitting `"payload"` (or returning `NO_PAYLOAD` for it) means
    unbound; returning `None` for it binds the literal JSON `null` (0.4.0).

    Raises GovernanceBlocked on anything that is not a permit, including an escalate: a
    held action has not happened yet, and returning normally would tell the caller it had.
    (`refused.verdict.escalation_id` is the handle for `client.wait_for_escalation`.)

    Async tools are supported: pass an `async def` and get an `async def` back.

    If the tool calls a service that re-verifies the agent (an HTTP gateway, an MCP server), it
    needs the signed request: inside the wrapped call, `governance_headers()` returns the
    `x-magp-request` header to attach. It is not a parameter, so the tool's signature — and
    the schema a framework builds from it — is unchanged.

    functools.wraps here is load-bearing, not tidiness. Frameworks that build a tool schema
    from your function read `inspect.signature` and `typing.get_type_hints`; a wrapper that
    copies only __name__ and __doc__ presents itself as `(*args, **kwargs)` with no hints at
    all. The OpenAI Agents SDK then refuses the tool with

        UserError: additionalProperties should not be set for object types.
                   This could be because you're using an older version of Pydantic

    which sends you to your dependency versions, where the problem is not. `wraps` sets
    __wrapped__ and copies __annotations__, so the schema comes out identical to the
    unguarded function and the wrapper is invisible to the framework — which is the only
    way "wrap the tool" can be advice we give people.
    """

    def _gate(*args: "Any", **kwargs: "Any") -> "Verdict":
        payload = map_args(*args, **kwargs) if map_args else {}
        verdict = client.authorize(
            action,
            payload.get("amount", 0),
            currency=payload.get("currency", "USD"),
            merchant=payload.get("merchant", ""),
            context=payload.get("context", {}),
            resource=payload.get("resource"),
            payload=payload.get("payload", NO_PAYLOAD),
        )
        if not verdict.permitted:
            # Fail closed, loudly, and before the tool is touched.
            raise GovernanceBlocked(verdict, action)
        return verdict

    if inspect.isasyncgenfunction(fn):
        # One authorization covers one action; a generator would yield many results over time, after the
        # signed request had been reset. Refusing at wrap time beats a tool that silently loses its handoff.
        raise TypeError("guard_tool does not support async generator tools; wrap a coroutine function")

    def _release_if_cancelled(task: "Any") -> None:
        # The caller cancelled (a timeout, a framework abort) while the gate call was in a worker thread.
        # The thread cannot be stopped, so if the gate PERMITTED, a hold now exists that nothing holds a
        # handle to: release it, best effort (the hold's TTL is the backstop), off the event loop.
        if task.cancelled() or task.exception() is not None:
            return
        held = task.result()

        def _void() -> None:
            try:
                client.void(held.authorization_id, reason="caller cancelled before the tool ran")
            except Exception:  # noqa: BLE001 — best effort
                pass

        if held.authorization_id:
            threading.Thread(target=_void, daemon=True).start()

    if inspect.iscoroutinefunction(fn) or inspect.iscoroutinefunction(getattr(fn, "__call__", None)):
        # An async tool (the OpenAI Agents SDK and PydanticAI are async-first). Two things a
        # naive wrapper gets wrong: it must STAY a coroutine function — frameworks decide how to
        # call a tool by asking — and the gate call is blocking I/O, which must not stall the
        # event loop, so it runs in a worker thread.
        @functools.wraps(fn)
        async def governed_async(*args: "Any", **kwargs: "Any") -> "Any":
            gate_call = asyncio.ensure_future(asyncio.to_thread(_gate, *args, **kwargs))
            try:
                verdict = await asyncio.shield(gate_call)
            except asyncio.CancelledError:
                gate_call.add_done_callback(_release_if_cancelled)
                raise
            token = _GOVERNANCE.set(verdict.signed)
            try:
                return await fn(*args, **kwargs)
            finally:
                _GOVERNANCE.reset(token)

        return governed_async

    @functools.wraps(fn)
    def governed(*args: "Any", **kwargs: "Any") -> "Any":
        verdict = _gate(*args, **kwargs)
        # While the tool runs, the signed request is available to it WITHOUT appearing in its
        # signature (which frameworks read to build the tool's schema): a tool that calls a
        # gateway does `headers=governance_headers()`. Reset afterwards so it can never leak into
        # an unrelated call.
        token = _GOVERNANCE.set(verdict.signed)
        try:
            result = fn(*args, **kwargs)
        except BaseException:
            _GOVERNANCE.reset(token)
            raise
        if inspect.isawaitable(result):
            # A sync function that RETURNS a coroutine (a lambda over an async tool, an `functools.partial`
            # of one): the body has not run yet, so hold the signed request across the await instead of
            # resetting it before the tool can read it. (The gate call above was blocking; an `async def`
            # gets the worker-thread path.)
            _GOVERNANCE.reset(token)

            async def _await_with_governance() -> "Any":
                inner = _GOVERNANCE.set(verdict.signed)
                try:
                    return await result
                finally:
                    _GOVERNANCE.reset(inner)

            return _await_with_governance()
        _GOVERNANCE.reset(token)
        return result

    return governed


# The signed request of the guarded tool call currently running, if any. A ContextVar, so it is
# per-thread and per-asyncio-task: two tools running concurrently never see each other's.
_GOVERNANCE: "contextvars.ContextVar[Optional[SignedRequest]]" = contextvars.ContextVar("metamynd_governance", default=None)


def current_governance() -> Optional[SignedRequest]:
    """The signed request of the `guard_tool` call this code is running inside, or None."""
    return _GOVERNANCE.get()


def governance_headers() -> dict:
    """Headers to attach to a call to a MAGP-protected service, from inside a guarded tool.

    Returns `{}` outside one — calling a protected service without them is refused by the
    service (`MISSING_GOVERNANCE`), which is the safe failure.
    """
    signed = _GOVERNANCE.get()
    return signed.headers() if signed is not None else {}


# --------------------------------------------------------------------------------------
# Demo
# --------------------------------------------------------------------------------------


def _show(label: str, verdict: Verdict) -> None:
    mark = {"allow": "OK  ", "observe": "OBS ", "block": "DENY", "escalate": "HOLD"}.get(verdict.decision, "??  ")
    print(f"  {mark}  {verdict.decision.upper():<9} {verdict.reason_code:<24} {label}")
    if verdict.hint:
        print(f"        hint: {verdict.hint}")


def _demo() -> None:
    client = MetaMyndClient.from_env()
    print(f"\nMetaMynd gate, from Python — agent {client.agent_did[:38]}…\n")

    flight = {"tool": "book-flight", "jurisdiction": "SG", "riskLevel": "low"}
    _show("$150 flight, low risk", client.authorize("flight-purchase", 150, merchant="skyward-air", context=flight))
    _show("$600 flight, over the SOP cap", client.authorize("flight-purchase", 600, merchant="skyward-air", context=flight))
    held = client.authorize("flight-purchase", 150, merchant="skyward-air", context={**flight, "riskLevel": "high"})
    _show("$150 flight, high risk", held)
    # ESCALATE is a HOLD, not a denial. Follow it up rather than stopping here — this is
    # the one verdict a naive integration mishandles, usually by treating it as failure.
    if held.escalation_id:
        state = client.escalation_status(held.escalation_id)
        print(f"        held for review: {state.status} ({state.approvals}/{state.required} approvals)"
              f"{' — may proceed' if state.may_proceed else ''}")
    _show(
        "$150 flight, unapproved tool",
        client.authorize("flight-purchase", 150, merchant="skyward-air", context={**flight, "tool": "wire-transfer"}),
    )

    # Tamper check: sign one amount, send another. The gate reconstructs the message from
    # what it received (§8.3.2), so the signature cannot cover the amount that arrived.
    print()
    nonce = secrets.token_hex(16)
    issued_at = utc_now_rfc3339()
    signed_for_50 = canonical_message(client.agent_did, "flight-purchase", 50, "USD", "skyward-air", nonce, issued_at)
    forged = {
        "agentDid": client.agent_did,
        "action": "flight-purchase",
        "amount": 5000,
        "currency": "USD",
        "merchant": "skyward-air",
        "nonce": nonce,
        "issuedAt": issued_at,
        "signature": client._key.sign(signed_for_50.encode("utf-8")).hex(),
    }
    _show("signed $50, sent $5000", Verdict.from_response(client._post("/policy/mandate/authorize", forged)))
    print()


def _selftest() -> None:
    """Check the three details without touching the network.

    A reference implementation that can only be exercised against a running gate with a
    provisioned agent is one nobody checks before copying. These assertions cover exactly
    the parts that are easy to get wrong and impossible to debug from the verdict.
    """
    from cryptography.hazmat.primitives import serialization as _ser

    # §8.3.3 — both encodings load, and to the same key.
    der = (
        "302e020100300506032b657004220420"
        "1a89c8f14ad24e63f616a4e0b9270f866ec19e2f7436c68bd3e168b594f09837"
    )
    key = load_key(der)
    seed = key.private_bytes(_ser.Encoding.Raw, _ser.PrivateFormat.Raw, _ser.NoEncryption()).hex()
    assert load_key(seed).sign(b"x") == key.sign(b"x"), "raw seed must load to the same key as DER"
    assert load_key("0x" + der).sign(b"x") == key.sign(b"x"), "0x prefix must be tolerated"

    # §8.3.4 — parity with ECMAScript String().
    for value, expected in [
        (150, "150"),
        (150.0, "150"),          # the whole trap, in one line
        (142.3, "142.3"),
        (0.1, "0.1"),
        (-5.5, "-5.5"),
        (0, "0"),
        (1e20, "100000000000000000000"),
        # Below 1e-4 Python's repr() switches to an exponent JavaScript does not use until 1e-7 — sub-cent
        # amounts (micropayments) signed the wrong text and failed as SIGNATURE_INVALID.
        (0.00005, "0.00005"),
        (0.000001, "0.000001"),
        (1e-7, "1e-7"),
        (1.5e-7, "1.5e-7"),
        (-0.00005, "-0.00005"),
        (1e21, "1e+21"),
        (1.5e25, "1.5e+25"),
        (2**60 + 1, "1152921504606847000"),   # an int past 2**53: the gate holds the double, so that is what is signed
        (2**53, "9007199254740992"),
        (-0.0, "0"),
    ]:
        got = js_number_to_string(value)
        assert got == expected, f"String({value!r}) should be {expected!r}, got {got!r}"
    for bad in (float("nan"), float("inf"), True, 10**400):
        try:
            js_number_to_string(bad)
            raise AssertionError(f"{bad!r} should have been rejected")
        except (ValueError, TypeError):
            pass

    # §8.3.5 — second precision, Z designator, no offset and no fractional part.
    stamp = utc_now_rfc3339()
    assert stamp.endswith("Z") and "+" not in stamp and "." not in stamp, stamp
    assert len(stamp) == 20, stamp

    # §8.3.1 — eight fields, "|"-delimited, empty string for an absent merchant/resource.
    msg = canonical_message("did:x", "act", 150.0, "USD", None, "n0nce", stamp)
    assert msg == f"did:x|act|150|USD|||n0nce|{stamp}", msg

    # resource, when given, slots between merchant and nonce.
    msg_with_resource = canonical_message("did:x", "act", 150.0, "USD", "acme", "n0nce", stamp, resource="res-1")
    assert msg_with_resource == f"did:x|act|150|USD|acme|res-1|n0nce|{stamp}", msg_with_resource

    # a literal "|" or "\\" in a field must be escaped, never mistaken for the delimiter.
    msg_escaped = canonical_message("did:x", "act", 150.0, "USD", "a|b\\c", "n0nce", stamp)
    assert msg_escaped == f"did:x|act|150|USD|a\\|b\\\\c||n0nce|{stamp}", msg_escaped

    # guard_tool must be invisible to a framework building a tool schema. This is not a
    # style assertion: without it the OpenAI Agents SDK rejects the tool and blames Pydantic.
    import inspect as _inspect
    import typing as _typing

    def _sample(vendor: str, amount: float, items: str) -> dict:
        """A tool with a real signature."""
        return {}

    _guarded = guard_tool(None, "x", _sample)  # never called, so the client may be None
    assert str(_inspect.signature(_guarded)) == str(_inspect.signature(_sample)), _inspect.signature(_guarded)
    assert _typing.get_type_hints(_guarded) == _typing.get_type_hints(_sample)
    assert _guarded.__name__ == "_sample" and _guarded.__doc__ == _sample.__doc__

    _selftest_gate()

    print(
        "selftest ok — key encodings, number stringification, timestamp shape, canonical join, tool signature, "
        "signed handoff, escalation wait, settlement, outcome, sync + async guard_tool"
    )


def _selftest_gate() -> None:
    """Drive the client against an in-process STUB of the gate (127.0.0.1, no network, no account).

    The stub is an independent verifier: it rebuilds the eight-field message by hand from the body it
    received and checks the Ed25519 signature, so a client that signs the wrong bytes fails HERE, offline,
    instead of as SIGNATURE_INVALID against a live gate. It is a test double, not policy: what it decides
    is fixed by the action name.
    """
    import http.server
    import threading

    key = load_key("302e020100300506032b6570042204201a89c8f14ad24e63f616a4e0b9270f866ec19e2f7436c68bd3e168b594f09837")
    pub = key.public_key()
    seen: list = []
    polls = {"n": 0}

    class Gate(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_a: "Any") -> None:  # keep the selftest output clean
            pass

        def _send(self, code: int, payload: "Any") -> None:
            raw = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self) -> None:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            seen.append((self.path, dict(body), self.headers.get("User-Agent")))
            if self.path == "/policy/mandate/authorize":
                message = "|".join([body["agentDid"], body["action"], js_number_to_string(body["amount"]), body["currency"], body.get("merchant", ""), body.get("resource", ""), body["nonce"], body["issuedAt"]])
                try:
                    pub.verify(bytes.fromhex(body["signature"]), message.encode("utf-8"))
                except Exception:  # a wrong message: refuse it the way the real gate does, so the assert below names the cause
                    return self._send(403, {"success": False, "data": {"decision": "block", "reasonCode": "SIGNATURE_INVALID"}})
                if body["action"] == "hold":
                    return self._send(403, {"success": False, "data": {"decision": "escalate", "reasonCode": "RISK_REVIEW", "escalationId": "esc-1"}})
                if body["action"] == "deny":
                    return self._send(403, {"success": False, "data": {"decision": "block", "reasonCode": "SOP_SPEND_CAP"}})
                return self._send(200, {"success": True, "data": {"decision": "allow", "reasonCode": "AUTHORIZED", "authorizationId": f"auth-{int(body['amount'])}"}})
            if self.path.endswith("/capture"):
                if body.get("amountCharged") == 100:
                    return self._send(200, {"success": True, "message": "Captured", "data": {"captured": True}})
                return self._send(400, {"success": False, "message": "amountCharged (0) is below the claimed hold (100)", "data": None})
            if self.path.endswith("/void"):
                if "claimed-1" in self.path:
                    return self._send(400, {"success": False, "message": "Authorization has been claimed for execution", "data": None})
                return self._send(200, {"success": True, "message": "Hold voided", "data": {"voided": True}})
            return self._send(404, {"success": False, "message": "no such route", "data": None})

        def do_GET(self) -> None:
            seen.append((self.path, None, self.headers.get("User-Agent")))
            if self.path == "/policy/escalations/esc-1/status":
                polls["n"] += 1
                if polls["n"] < 3:
                    return self._send(200, {"success": True, "data": {"status": "pending", "reasonCode": "ESCALATION_PENDING"}})
                return self._send(200, {"success": True, "data": {"status": "approved", "reasonCode": "APPROVED", "authorizationId": "auth-approved"}})
            if self.path.endswith("/auth-100/effect"):
                return self._send(200, {"success": True, "data": {"outcome": "settled", "nothingExecuted": False, "retrySafe": False, "claimed": True, "authorizedAmount": 250, "settledAmount": 100, "settlementEvidence": "independently_confirmed", "currency": "USD"}})
            if self.path.endswith("/auth-weird/effect"):  # flags that are not literally `true` must read as NOT safe
                return self._send(200, {"success": True, "data": {"outcome": "expired", "nothingExecuted": "yes", "retrySafe": 1}})
            return self._send(404, {"success": False, "message": "Not found", "data": None})

    # The stub is on loopback, but urllib sends even 127.0.0.1 through HTTP(S)_PROXY unless NO_PROXY says
    # otherwise — so the selftest (and the publish gate that runs it) died behind a corporate proxy with
    # "gate unreachable". Exempt loopback for the duration of the stub run only.
    saved_no_proxy = {k: os.environ.get(k) for k in ("NO_PROXY", "no_proxy")}
    exempt = ",".join(filter(None, [saved_no_proxy["NO_PROXY"] or saved_no_proxy["no_proxy"], "127.0.0.1,localhost"]))
    os.environ["NO_PROXY"] = os.environ["no_proxy"] = exempt

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Gate)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
        client = MetaMyndClient(f"http://127.0.0.1:{server.server_address[1]}", "did:key:z6MkSelftest", seed)

        # authorize: the eight-field message verifies (the stub would have raised), resource is signed and sent top-level.
        v = client.authorize("flight-purchase", 100, merchant="skyward-air", context={"riskLevel": "low"}, resource="inspection-db")
        assert v.permitted and v.authorization_id == "auth-100", v
        sent = seen[-1][1]
        assert sent["resource"] == "inspection-db" and sent["itinerary"] == {"riskLevel": "low"}, sent
        assert "authorizationId" not in sent, "the authorizationId only exists once the gate answers; it is never sent to it"
        assert seen[-1][2] == USER_AGENT, "the client must identify itself (the CDN blocks urllib's default)"

        # the handoff: exactly what was signed + the issued authorizationId, header-safe.
        assert v.signed is not None and v.signed.authorization_id == "auth-100"
        assert {k: val for k, val in v.signed.body.items() if k != "authorizationId"} == sent
        header = v.signed.headers()
        assert list(header) == ["x-magp-request"] and json.loads(header["x-magp-request"]) == dict(v.signed.body)
        header["x-magp-request"].encode("ascii")  # non-ASCII must be escaped, or an HTTP stack rejects the header
        wire = client.authorize("flight-purchase", 5, merchant="Café ✓").signed
        wire.header_value().encode("ascii")

        # sign_request signs WITHOUT calling the gate, and can attach an authorizationId (post-approval).
        before = len(seen)
        again = client.sign_request("flight-purchase", 100, merchant="skyward-air", authorization_id="auth-approved")
        assert len(seen) == before, "sign_request must not touch the network"
        assert again.authorization_id == "auth-approved" and again.body["signature"] != sent["signature"], "fresh nonce, fresh signature"

        # a refusal / hold: not permitted, and a hold's signed request carries no authorizationId.
        held = client.authorize("hold", 100)
        assert held.decision == "escalate" and not held.permitted and held.escalation_id == "esc-1" and held.signed.authorization_id is None
        denied = client.authorize("deny", 100)
        assert denied.decision == "block" and not denied.permitted

        # wait_for_escalation polls until a human decides, and returns rather than hanging on a timeout.
        sleeps: list = []
        status = client.wait_for_escalation("esc-1", timeout=30, interval=0.5, _sleep=sleeps.append)
        assert status.may_proceed and status.authorization_id == "auth-approved" and len(sleeps) == 2, (status, sleeps)
        polls["n"] = 0
        pending = client.wait_for_escalation("esc-1", timeout=0, _sleep=sleeps.append)
        assert not pending.resolved and not pending.may_proceed, "a hold nobody has decided is a hold"

        # settlement: full-amount capture ok; a lower one is REFUSED and says why; void of a claimed hold is refused.
        assert client.capture("auth-100", 100, booking_ref="PNR1").ok
        refused = client.capture("auth-100", 0)
        assert not refused.ok and "below the claimed hold" in refused.message, refused
        assert client.void("auth-9").ok and not client.void("claimed-1").ok
        assert seen[-1][1] == {} or "reason" not in seen[-1][1]

        # outcome: read tolerantly, but a safety flag is True ONLY when the gate said literally true.
        out = client.outcome("auth-100")
        assert out.outcome == "settled" and out.claimed and not out.retry_safe and out.settled_amount == 100
        # the authorized amount survives settlement, and what the settled amount rests on is reported (spec 8.7.9)
        assert out.authorized_amount == 250 and out.settlement_evidence == "independently_confirmed", out
        weird = client.outcome("auth-weird")
        assert weird.outcome == "expired" and weird.nothing_executed is False and weird.retry_safe is False, weird
        missing = client.outcome("nope")
        assert missing.outcome == "unknown" and not missing.retry_safe and not missing.nothing_executed

        # guard_tool (sync): the tool sees the signed request while it runs and not a moment after; a refusal never runs it.
        ran: list = []

        def book(vendor: str, amount: float) -> dict:
            hdr = governance_headers()
            ran.append(json.loads(hdr["x-magp-request"])["authorizationId"])
            return {"ok": True}

        ctx = lambda vendor, amount: {"amount": amount, "merchant": vendor, "context": {"riskLevel": "low"}}  # noqa: E731
        guarded = guard_tool(client, "flight-purchase", book, ctx)
        assert guarded("acme", 11) == {"ok": True} and ran == ["auth-11"]
        assert governance_headers() == {} and current_governance() is None, "the handoff must not outlive the call"
        try:
            guard_tool(client, "hold", book, ctx)("acme", 1)
            raise AssertionError("an escalate must raise, not run the tool")
        except GovernanceBlocked as blocked:
            assert blocked.verdict.escalation_id == "esc-1" and ran == ["auth-11"]

        # guard_tool (async): stays a coroutine function, hands off per task, and does not block the event loop.
        async_ran: list = []

        async def book_async(vendor: str, amount: float) -> dict:
            await asyncio.sleep(0.01)  # yield, so the two tasks below interleave
            async_ran.append(json.loads(governance_headers()["x-magp-request"])["authorizationId"])
            return {"ok": True}

        guarded_async = guard_tool(client, "flight-purchase", book_async, ctx)
        assert inspect.iscoroutinefunction(guarded_async), "an async tool must stay async"

        async def _both() -> "Any":
            return await asyncio.gather(guarded_async("a", 22), guarded_async("b", 33))

        assert asyncio.run(_both()) == [{"ok": True}, {"ok": True}]
        assert sorted(async_ran) == ["auth-22", "auth-33"], f"each task must see its OWN signed request: {async_ran}"
        assert governance_headers() == {}

        # An async callable that is not an `async def` (an object with an async __call__, a sync function
        # returning a coroutine) must hand off too, not silently lose the signed request.
        class AsyncCallable:
            async def __call__(self, vendor: str, amount: float) -> dict:
                async_ran.append(json.loads(governance_headers()["x-magp-request"])["authorizationId"])
                return {"ok": True}

        async def _odd_callables() -> "Any":
            via_object = guard_tool(client, "flight-purchase", AsyncCallable(), ctx)
            via_sync = guard_tool(client, "flight-purchase", lambda vendor, amount: AsyncCallable()(vendor, amount), ctx)
            return [await via_object("c", 44), await via_sync("d", 55)]

        assert asyncio.run(_odd_callables()) == [{"ok": True}, {"ok": True}]
        assert async_ran[-2:] == ["auth-44", "auth-55"], async_ran
        assert governance_headers() == {}
    finally:
        for name, prior in saved_no_proxy.items():
            if prior is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = prior
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        _selftest()
    else:
        _demo()
