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
it does not depend on you (MAGP §6.3). `guard_tool` never invents one. Whatever you send is
the agent's OWN claim: signing the context proves who said it, not that it is true, so it
can only RAISE the risk. The gate derives a floor the agent cannot lower (MAGP 6.4.3): a
payment at or above 70% of the per-transaction cap is high, as is the first payment to a
merchant that is not on the mandate's list, not a registered payee and never paid before,
and anything at or above an owner-set `riskTier`. A "low" call can still be held: the
verdict names the cause (`verdict.risk_signals`). Never default a missing one to "low" in
a `map_args` — pass it through, so a call that does not say is sent for review.

In-process, cooperative. `guard_tool` runs in YOUR process: it is the agent declining to
call a tool the gate refused, which stops a well-behaved agent and records every decision,
but anything that can import the raw function (or the credential it uses) can still call it
directly. The enforcement boundary is a SEPARATE process that holds the tool and its
credentials and re-verifies the signed request itself — `@metamynd/agentsafe-http-gateway`
or an MCP server using `agentsafe-mcp-guard`.

Tools you hand to an agent framework: wrap them with `guard_agent_tool` (0.9.0). A refused
tool wrapped with plain `guard_tool` RAISES `GovernanceBlocked` — the right default for code
that calls a tool itself, where an exception can never be mistaken for a result. But
frameworks that run several SYNC tool calls of one model turn in worker threads (PydanticAI,
LangGraph's `ToolNode`) abort the turn on that exception while sibling calls already in their
threads keep going — authorized and run, with results that reach nobody, so a retried turn can
do them twice. `guard_agent_tool` returns the refusal instead (a `GovernanceRefusal`, a dict the
framework hands to the model as that call's result), so the turn completes and the model sees
every outcome. `async def` tools are safe either way (a cancelled async call is cancelled, and
a hold it was granted is released).

Jurisdiction (0.6.0). Pass `jurisdiction="SG"` (ISO 3166-1 alpha-2) to `authorize` /
`sign_request`: it is sent as a top-level field and SIGNED (the v2 message, MAGP §8.3.12 —
the eight fields, then `MAGP-AUTH-v2`, then the jurisdiction). A jurisdiction in `context` is
unsigned and the gate ignores it. When the payee is registered with a country, that country
wins; a signed value that differs is refused `JURISDICTION_MISMATCH`. The other two refusals
are `JURISDICTION_REQUIRED` (the mandate or a rule needs one and none was signed) and
`JURISDICTION_NOT_ALLOWED` (outside the mandate's list). See `JURISDICTION_REASON_CODES`.

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
import errno
import functools
import hashlib
import inspect
import json
import math
import os
import secrets
import selectors
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings
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
    "normalize_jurisdiction",
    "AUTH_MESSAGE_V2_TAG",
    "JURISDICTION_REASON_CODES",
    "canonical_payload",
    "payload_digest",
    "payload_binding_message",
    "payload_rebind_message",
    "envelope_hash",
    "NO_PAYLOAD",
    "BindResult",
    "PayloadNotCanonicalizable",
    "DaemonError",
    "GateUnreachable",
    "agent_settle_message",
    "guard_tool",
    "guard_agent_tool",
    "current_governance",
    "governance_headers",
    "GovernanceBlocked",
    "GovernanceRefusal",
    "ToolNotExecuted",
]

__version__ = "0.22.0"

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
    jurisdiction: Optional[str] = None,
) -> str:
    """The UTF-8 string that gets signed (MAGP §8.3.1).

    EIGHT fields, "|"-delimited, in this order, each escaped so a field value can never be
    mistaken for the delimiter — mirrors backend/src/policy-core/canonical.ts's
    buildAuthMessage/escapeField exactly. `resource` was added between merchant and nonce by
    a later release; omit it (or pass None) for a non-resource-scoped request, the same ""
    a verifier defaults an absent one to. The verifier reconstructs this string from the
    fields it received rather than trusting a client-sent message (§8.3.2), which is why
    every field below must be sent exactly as it was signed.

    `jurisdiction` (0.6.0, MAGP §8.3.12): None = the v1 message above, byte for byte. A value =
    the v2 message: the eight fields, then the literal tag `MAGP-AUTH-v2`, then the
    jurisdiction, every one escaped the same way. It is signed as given — pass the value you
    send (`normalize_jurisdiction` produces it); the gate picks v1 or v2 from the field's
    presence on the wire and never tries the other.
    """
    fields = [
        agent_did,
        action,
        js_number_to_string(amount),
        currency,
        merchant or "",
        resource or "",
        nonce,
        issued_at,
    ]
    if jurisdiction is not None:
        fields += [AUTH_MESSAGE_V2_TAG, jurisdiction]
    return "|".join(_escape_field(v) for v in fields)


AUTH_MESSAGE_V2_TAG = "MAGP-AUTH-v2"

# The jurisdiction refusals the gate can answer (MAGP §8.3.12), all hard blocks: none signed where the mandate or an
# enforced rule needs one; the signed one outside the mandate's list; the payee's REGISTERED country differs from it.
JURISDICTION_REASON_CODES = frozenset({"JURISDICTION_REQUIRED", "JURISDICTION_NOT_ALLOWED", "JURISDICTION_MISMATCH"})


def normalize_jurisdiction(value: Optional[str]) -> Optional[str]:
    """A caller's jurisdiction as it is signed and sent: trimmed, exactly two ASCII letters, upper-cased. None = none
    (the v1 message). Anything else raises ValueError — refused here, never sent. The ASCII check comes BEFORE
    upper-casing, because "ß".upper() is "SS"."""
    if value is None:
        return None
    trimmed = value.strip() if isinstance(value, str) else ""
    if not (len(trimmed) == 2 and trimmed.isascii() and trimmed.isalpha()):
        raise ValueError(f"jurisdiction must be an ISO 3166-1 alpha-2 country code (two letters), got {str(value)[:16]!r}")
    return trimmed.upper()


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
AGENT_SETTLE_PREFIX = "MAGP-SETTLE-v1"
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


# Effect outcomes after which a hold is final: nothing is left for an agent to capture (F-3).
_SETTLED_OUTCOMES = frozenset({"settled", "not_executed", "expired", "reversing", "reversed", "reversal_failed"})

RESUME_BINDING_PREFIX = "MAGP-RESUME-BIND-v1"


def _resume_amount(amount: Any) -> str:
    """The amount as the resume binding spells it: JavaScript number text, empty for none or 0, other text kept as is."""
    if amount is None or amount == "" or isinstance(amount, bool):
        return "" if amount is None or amount == "" else str(amount)
    try:
        number = float(amount)
    except (TypeError, ValueError):
        return str(amount)
    if not math.isfinite(number):
        return str(amount)
    if number == 0:
        return ""
    return js_number_to_string(int(number) if number.is_integer() and abs(number) <= 2**53 else number)


RESUME_CLAIM_PREFIX = "MAGP-RESUME-CLAIM-v1"
# v2 (0.19.0, pre-beta rerun 6 F-1-NF-R): the claim also signs the digests of the request and context about to run, so the gate
# itself refuses a resume of anything but what the person approved — not only this SDK, which an outdated copy cannot apply.
RESUME_CLAIM_V2_PREFIX = "MAGP-RESUME-CLAIM-v2"


def resume_claim_message(escalation_id: str, authorization_id: str, agent_did: str, nonce: str, issued_at: str,
                         request_digest: Optional[str] = None, context_digest: Optional[str] = None) -> str:
    """The agent's claim of the ONE resume of an approved escalation (MAGP 9a.6) — byte-for-byte the gate's builder.

    v2 with both digests, v1 with neither; one without the other is refused (the gate could not reproduce it)."""
    if (request_digest is None) != (context_digest is None):
        raise ValueError("a resume claim carries both request_digest and context_digest (v2), or neither (v1)")
    fields = ([RESUME_CLAIM_V2_PREFIX, escalation_id, authorization_id, agent_did, request_digest, context_digest, nonce, issued_at]
              if request_digest is not None else [RESUME_CLAIM_PREFIX, escalation_id, authorization_id, agent_did, nonce, issued_at])
    return "|".join(_escape_field(str(f)) for f in fields)


def _int_or_zero(value: Any) -> int:
    """A status field read as an int, 0 when it is absent or not a number (an older gate, or a malformed answer)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def resume_request_digest(authorization_id: str, action: str, amount: Any = None, currency: Optional[str] = None,
                          merchant: Optional[str] = None, resource: Optional[str] = None, payload_digest_value: Optional[str] = None) -> str:
    """The digest of the request an approval's hold authorizes (MAGP 9a.5), byte-for-byte the gate's `resumeRequestDigest`.

    The escalation status returns it as `requestDigest`; `resume()` recomputes it from the call it is about to run and refuses
    a mismatch, so an owner's approval runs only what the owner approved. Pinned by docs/protocol/resume-binding-vectors.json.
    """
    amount_text = _resume_amount(amount)
    fields = [RESUME_BINDING_PREFIX, authorization_id, action, amount_text, (currency or "") if amount_text else "",
              merchant or "", resource or "", payload_digest_value or ""]
    message = "|".join(_escape_field(str(f)) for f in fields)
    return "sha256:" + hashlib.sha256(message.encode("utf-8")).hexdigest()


APPROVED_CONTEXT_DOMAIN = "MAGP-APPROVED-CONTEXT-v1"


def approved_context_digest(context: Any) -> str:
    """The digest of the context (itinerary) an approval was given for (MAGP 9a.5), byte-for-byte the gate's
    `approvedContextDigest`: RFC 8785 canonical JSON of {"MAGP-APPROVED-CONTEXT-v1": context}, an absent context being {}.

    The request digest binds what an approval SPENDS — for an action that spends nothing, little more than its name — so an
    approval of {"target": "record-A", "op": "read"} could otherwise run as {"target": "record-B", "op": "delete-all"}. The
    escalation status returns this as `contextDigest`, and `resume()` refuses a call whose context differs. Pinned by
    docs/protocol/resume-binding-vectors.json (`contextVectors`).
    """
    return payload_digest({APPROVED_CONTEXT_DOMAIN: {} if context is None else context})


ENVELOPE_VERSION = "1.0"


def envelope_hash(request: Mapping[str, Any]) -> str:
    """The envelope hash a context signature covers (MAGP §8.3.13) — byte-for-byte the gate's `envelopeHashFor`.

    `request` is the wire request (the dict this client sends): the GovernanceEnvelope is built from it exactly as the gate
    builds it — no defaults applied, `context` = the `itinerary` when present (an empty dict included), `merchant` null when
    absent — then serialised with object keys sorted by UTF-16 code unit and ECMAScript number/string forms, which for JSON
    values is the gate's `stableStringify` and RFC 8785 alike, and hashed: lower-case hex SHA-256. Checked against
    docs/protocol/context-signature-vectors.json (tests/test_context_signature.py). A value JSON cannot carry raises
    `PayloadNotCanonicalizable`.
    """
    nonce = request["nonce"]
    action: dict[str, Any] = {"actionId": f"act:{nonce}", "actionType": request["action"], "merchant": request.get("merchant")}
    for key in ("amount", "currency"):
        if request.get(key) is not None:
            action[key] = request[key]
    if request.get("materiality") is not None:
        action["materiality"] = request["materiality"]
    envelope: dict[str, Any] = {
        "envelopeId": f"env:{nonce}",
        "version": ENVELOPE_VERSION,
        "createdAt": request["issuedAt"],
        "agent": {"did": request["agentDid"]},
        "action": action,
    }
    if request.get("trace") is not None:
        envelope["trace"] = request["trace"]
    if request.get("itinerary") is not None:
        envelope["context"] = request["itinerary"]
    return hashlib.sha256(_canonical(envelope, 0, "$").encode("utf-8")).hexdigest()


def payload_binding_message(agent_did: str, action: str, nonce: str, issued_at: str, digest: str) -> str:
    """The UTF-8 string signed to bind `digest` to ONE authorization (MAGP §8.3.9): domain-separated from every other MAGP
    signature, and naming the agent, action, nonce and issuedAt of the authorize request it accompanies."""
    return "|".join(_escape_field(v) for v in [PAYLOAD_BINDING_PREFIX, agent_did, action, nonce, issued_at, digest])


def payload_rebind_message(agent_did: str, action: str, authorization_id: str, nonce: str, issued_at: str, digest: str) -> str:
    """The UTF-8 string signed to bind `digest` to a hold that ALREADY EXISTS and has none (MAGP §8.3.11) — what a reviewer's
    MODIFY leaves behind. Its own domain (a signature made for one message never verifies as the other) and it names the
    authorization id, so the digest is bound to THAT hold and cannot be lifted onto another."""
    return "|".join(_escape_field(v) for v in [PAYLOAD_REBIND_PREFIX, agent_did, action, authorization_id, nonce, issued_at, digest])


def agent_settle_message(verb: str, agent_did: str, authorization_id: str, nonce: str, issued_at: str, fields: list[str]) -> str:
    """The UTF-8 string an agent signs to capture or void its OWN hold that nobody has claimed (MAGP §8.7.4). `fields`:
    capture → amountCharged (as JS prints it), bookingRef, settlementTxHash; void → reason ('' when absent). Domain-separated
    (MAGP-SETTLE-v1), naming the verb and the authorization, so it cannot be replayed as any other call."""
    return "|".join(_escape_field(v) for v in [AGENT_SETTLE_PREFIX, verb, agent_did, authorization_id, nonce, issued_at, *fields])


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

    @property
    def risk_signals(self) -> "list[Mapping[str, Any]]":
        """The risk the ISSUER derived and the agent cannot lower (MAGP 6.4.3; gate v1.82+), on an escalate: `owner-tier`,
        `amount-share` (at or above the owner's share of the per-transaction cap) or `new-merchant`, each with a `detail`.
        Empty when none applied: then a RISK_REVIEW came from the agent's own riskLevel claim."""
        signals = self.raw.get("riskSignals") if isinstance(self.raw, Mapping) else None
        return [s for s in signals if isinstance(s, Mapping)] if isinstance(signals, list) else []

    @property
    def jurisdiction_refused(self) -> bool:
        """True when the gate refused on jurisdiction (0.6.0, MAGP §8.3.12): `JURISDICTION_REQUIRED`,
        `JURISDICTION_NOT_ALLOWED` or `JURISDICTION_MISMATCH` (a registered payee's country differs from
        the signed one). None of them is retryable by resending the same request."""
        return self.reason_code in JURISDICTION_REASON_CODES

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

    @property
    def executed(self) -> Optional[bool]:
        """Whether something ran, or may have run, under the approval (0.21.0, pre-beta rerun 6 resume-status nit). `status`
        stays `approved` after the action ran, so this says it. None from a gate that predates the field."""
        value = self.raw.get("executed")
        return value if isinstance(value, bool) else None

    @property
    def executed_at(self) -> Optional[str]:
        return self.raw.get("executedAt")

    @property
    def outcome(self) -> Optional[str]:
        """The approval's hold outcome, as `client.outcome()` reports it (not_started, settled, ...), or None."""
        return self.raw.get("outcome")


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
    """The gate's answer to a capture or a void. `ok` is False for a refusal, and `reason_code` says why.

    Branch on `reason_code` — the stable code (MAGP §8.7.8), e.g. `COUNTERPARTY_MISMATCH`, `NOT_HELD`,
    `AUTHORIZATION_NOT_FOUND` — never on `detail`, which is a sentence for people and may change. A refused
    call's `message` is that same bare code; the one exception is a void of a hold that is already settled or
    released, which the gate answers `200` with the message `Not voided (NOT_HELD)` and `reason_code` `NOT_HELD`
    (usually an earlier void landed — read `outcome()`)."""

    ok: bool
    message: str = ""
    raw: Mapping[str, Any] = field(default_factory=dict)
    # Added in 0.5.3 (after `raw`, so positional construction is unchanged). On success, the gate's code when it gives one
    # (`HOLD_VOIDED` for a void, since 0.17.1), else empty (a capture). Branch on `ok`, not on this being empty.
    reason_code: str = ""
    detail: str = ""


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
        message = canonical_message(fields["agentDid"], fields["action"], fields["amount"], fields["currency"], fields.get("merchant"), fields["nonce"], fields["issuedAt"], resource=fields.get("resource"), jurisdiction=fields.get("jurisdiction"))
        return self._key.sign(message.encode("utf-8"))

    def sign_payload_binding(self, fields: Mapping[str, Any]) -> bytes:
        authorization_id = fields.get("authorizationId")
        if authorization_id is None:
            message = payload_binding_message(fields["agentDid"], fields["action"], fields["nonce"], fields["issuedAt"], fields["payloadDigest"])
        else:
            message = payload_rebind_message(fields["agentDid"], fields["action"], authorization_id, fields["nonce"], fields["issuedAt"], fields["payloadDigest"])
        return self._key.sign(message.encode("utf-8"))

    def sign_envelope(self, fields: Mapping[str, Any]) -> bytes:
        return self._key.sign(envelope_hash(fields).encode("utf-8"))

    def sign_settle(self, fields: Mapping[str, Any]) -> bytes:
        message = agent_settle_message(fields["verb"], fields["agentDid"], fields["authorizationId"], fields["nonce"], fields["issuedAt"], list(fields["fields"]))
        return self._key.sign(message.encode("utf-8"))

    def sign_resume_claim(self, fields: Mapping[str, Any]) -> bytes:
        message = resume_claim_message(fields["escalationId"], fields["authorizationId"], fields["agentDid"], fields["nonce"], fields["issuedAt"],
                                       fields.get("requestDigest"), fields.get("contextDigest"))
        return self._key.sign(message.encode("utf-8"))


class _DaemonSigner:
    """Signs by asking `agentsafe-signer` — the key never enters this process."""

    def __init__(self, socket_path: str, connect_timeout: float = 3.0):
        self._socket_path = socket_path
        self._connect_timeout = connect_timeout

    def _call(self, op: str, fields: Mapping[str, Any]) -> Mapping[str, Any]:
        # A field this client treats as "absent" is `None` (Python has no separate undefined); the daemon's own
        # validation treats a PRESENT-but-non-string field as malformed and an ABSENT one as fine (JS `undefined`),
        # so an optional field genuinely absent — no merchant, no resource, no authorizationId — must be dropped
        # from `params` entirely rather than sent as JSON `null`, or the daemon refuses it as an invalid string.
        params = {k: v for k, v in fields.items() if v is not None}
        result = _daemon_request(self._socket_path, op, params, self._connect_timeout)
        if not isinstance(result.get("signature"), str):
            raise DaemonError("DAEMON_MALFORMED_RESPONSE", f"{op} response carried no signature")
        return result

    def _request(self, op: str, fields: Mapping[str, Any]) -> bytes:
        return bytes.fromhex(self._call(op, fields)["signature"])

    def sign_authorize(self, fields: Mapping[str, Any]) -> bytes:
        result = self._call("sign-authorize", fields)
        jurisdiction = fields.get("jurisdiction")
        # A daemon older than agentsafe-signer 0.18.0 ignores `jurisdiction` and signs the v1 message; the gate would refuse
        # that request SIGNATURE_INVALID. A current daemon echoes the jurisdiction it signed, so anything else is caught here.
        if jurisdiction is not None and result.get("jurisdiction") != jurisdiction:
            raise DaemonError("JURISDICTION_SIGNING_UNSUPPORTED", "the agentsafe-signer daemon cannot sign a jurisdiction (it predates signer 0.18.0); upgrade it, or omit `jurisdiction`")
        return bytes.fromhex(result["signature"])

    def sign_payload_binding(self, fields: Mapping[str, Any]) -> bytes:
        try:
            return self._request("sign-payload", fields)
        except DaemonError as exc:
            if exc.code == "DAEMON_UNKNOWN_OPERATION":
                raise DaemonError("PAYLOAD_BINDING_UNSUPPORTED", "the agentsafe-signer daemon predates payload binding (sign-payload, signer 0.15.0); upgrade it, or omit `payload`") from exc
            raise

    def sign_settle(self, fields: Mapping[str, Any]) -> bytes:
        try:
            return self._request("sign-settle", fields)
        except DaemonError as exc:
            if exc.code == "DAEMON_UNKNOWN_OPERATION":
                raise DaemonError("SETTLE_SIGNING_UNSUPPORTED", "the agentsafe-signer daemon predates sign-settle (signer 0.20.0); upgrade it to settle an unclaimed hold as the agent") from exc
            raise

    def sign_envelope(self, fields: Mapping[str, Any]) -> bytes:
        # The daemon builds the envelope itself from these fields (`sign-envelope`, every signer version). This client always
        # sends amount and currency, so even a daemon older than signer 0.19.0 (which defaulted an omitted currency) hashes
        # the same envelope the gate does. Fails closed: no signature → an error, never an unsigned context.
        params = {k: v for k, v in fields.items() if v is not None}
        try:
            result = _daemon_request(self._socket_path, "sign-envelope", params, self._connect_timeout)
        except DaemonError as exc:
            if exc.code == "DAEMON_UNKNOWN_OPERATION":
                raise DaemonError("CONTEXT_SIGNING_UNSUPPORTED", "the agentsafe-signer daemon cannot sign the context (no sign-envelope); upgrade it, or pass sign_context=False") from exc
            raise
        if not isinstance(result.get("envelopeSignature"), str):
            raise DaemonError("CONTEXT_SIGNING_UNSUPPORTED", "the agentsafe-signer daemon returned no envelopeSignature; upgrade it, or pass sign_context=False")
        return bytes.fromhex(result["envelopeSignature"])


# --------------------------------------------------------------------------------------
# Transport
# --------------------------------------------------------------------------------------

# The production gate sits behind a CDN that answers on two IPv6 and two IPv4 addresses. urllib connects through
# socket.create_connection, which tries them ONE AT A TIME, IPv6 first, each with the full client timeout. On a network
# that drops some IPv6 SYNs, a call stalled for 15 s or 30 s (one or two dead IPv6 attempts) before IPv4 answered in
# 80 ms: 6 of 29 authorize calls in the 2026-10-09 pre-beta evaluation (M1). The Node guard never stalled because Node
# races address families (Happy Eyeballs). So does this, after RFC 8305: start the next address 250 ms after the last
# one if nothing has connected yet, keep every attempt running, take the first that connects. The whole connect phase
# stays inside the client's `timeout`.
_CONNECTION_ATTEMPT_DELAY = 0.25  # RFC 8305 section 5
_CONNECT_IN_PROGRESS = {code for code in (errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EAGAIN, getattr(errno, "WSAEWOULDBLOCK", None)) if code is not None}


def _interleave_families(infos: "list[tuple]") -> "list[tuple]":
    """getaddrinfo's order, with the families alternated (RFC 8305 section 4): the first family first, then the other."""
    first = [info for info in infos if info[0] == infos[0][0]]
    rest = [info for info in infos if info[0] != infos[0][0]]
    ordered = []
    for i in range(max(len(first), len(rest))):
        ordered.extend(group[i] for group in (first, rest) if i < len(group))
    return ordered


def _happy_eyeballs_connect(address: "tuple[str, int]", timeout: Any = None, source_address: Any = None, *, _getaddrinfo: Callable[..., list] = socket.getaddrinfo) -> socket.socket:
    """socket.create_connection, racing the host's addresses instead of trying them in turn."""
    host, port = address
    seconds = timeout if isinstance(timeout, (int, float)) else socket.getdefaulttimeout()
    infos = _interleave_families(list(_getaddrinfo(host, port, 0, socket.SOCK_STREAM)))
    if not infos:
        raise OSError(f"getaddrinfo returned no addresses for {host!r}")
    deadline = None if seconds is None else time.monotonic() + seconds
    selector = selectors.DefaultSelector()
    pending: "dict[socket.socket, Any]" = {}
    errors: "list[OSError]" = []
    next_start = time.monotonic()
    winner: Optional[socket.socket] = None
    try:
        while winner is None:
            now = time.monotonic()
            if infos and (now >= next_start or not pending):
                family, kind, proto, _canon, sockaddr = infos.pop(0)
                sock = socket.socket(family, kind, proto)
                try:
                    sock.setblocking(False)
                    if source_address:
                        sock.bind(source_address)
                    code = sock.connect_ex(sockaddr)
                except OSError as exc:
                    sock.close()
                    errors.append(exc)
                    continue
                if code == 0:
                    winner = sock
                    break
                if code not in _CONNECT_IN_PROGRESS:
                    sock.close()
                    errors.append(OSError(code, os.strerror(code)))
                    continue
                selector.register(sock, selectors.EVENT_WRITE)
                pending[sock] = sockaddr
                next_start = now + _CONNECTION_ATTEMPT_DELAY
                continue
            if not pending:
                raise errors[-1] if errors else OSError(f"could not connect to {host!r}")
            if deadline is not None and now >= deadline:
                raise socket.timeout("timed out")
            waits = [w for w in (None if deadline is None else deadline - now, next_start - now if infos else None) if w is not None]
            for key, _events in selector.select(max(0.0, min(waits)) if waits else None):
                sock = key.fileobj  # type: ignore[assignment]
                selector.unregister(sock)
                pending.pop(sock, None)
                code = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if code == 0:
                    winner = sock
                    break
                sock.close()
                errors.append(OSError(code, os.strerror(code)))
                next_start = time.monotonic()  # a refusal is an answer: try the next address now, not in 250 ms
    finally:
        for sock in pending:
            if sock is not winner:
                sock.close()
        selector.close()
    winner.settimeout(seconds)
    return winner


def _racing(connection_class: Callable[..., Any]) -> Callable[..., Any]:
    def build(host: str, **kwargs: Any) -> Any:
        connection = connection_class(host, **kwargs)
        connection._create_connection = _happy_eyeballs_connect  # what HTTPConnection.connect opens its socket with
        return connection

    return build


class _RacingHTTPHandler(urllib.request.HTTPHandler):
    def do_open(self, http_class, req, **http_conn_args):  # type: ignore[override]
        return super().do_open(_racing(http_class), req, **http_conn_args)


class _RacingHTTPSHandler(urllib.request.HTTPSHandler):
    def do_open(self, http_class, req, **http_conn_args):  # type: ignore[override]
        return super().do_open(_racing(http_class), req, **http_conn_args)


_opener: Optional[urllib.request.OpenerDirector] = None


def _urlopen(request: urllib.request.Request, timeout: float) -> Any:
    """urllib.request.urlopen (proxies, redirects, HTTPError for a non-2xx answer), with racing connects."""
    global _opener
    if _opener is None:
        _opener = urllib.request.build_opener(_RacingHTTPHandler, _RacingHTTPSHandler)
    return _opener.open(request, timeout=timeout)


# --------------------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------------------


class MetaMyndClient:
    """Signs and submits authorize requests to the MetaMynd gate."""

    def __init__(self, api: str, agent_did: str, agent_key: Optional[str] = None, timeout: float = 15.0, *, daemon_socket: Optional[str] = None, sign_context: bool = True, orphan_release_delays: "tuple[float, ...]" = (2.0, 10.0, 30.0)):
        """Exactly one of `agent_key` (the key lives in THIS process) or `daemon_socket` — a path
        to an `agentsafe-signer` daemon's socket (0.5.0) — must be given; the daemon signs without
        ever handing the key to this process. Everything else about the client is identical either
        way: every signing call already goes through `self._signer`, so nothing downstream needs
        to know or care which one is in use.

        `sign_context` (0.7.0, default True): every request also carries `envelopeSignature`, this
        agent's signature over its context (MAGP §8.3.13), so the gate and any re-verifying service
        refuse a context altered in transit (`CONTEXT_SIGNATURE_INVALID`). `False` sends the request
        exactly as 0.6.x did. Services that predate it ignore the field.

        `orphan_release_delays` (0.13.0): when an authorize call is sent but its answer never arrives (a timeout, a dropped
        connection), the gate may still have committed a hold nobody can use or settle. After each of these delays (seconds)
        the client looks it up by the request's nonce and releases it with this agent's signed void; `()` turns it off.
        """
        # Pre-beta rerun 6 FW N-4: refuse a missing api or agent DID here, at construction, as the Node
        # guard's createGuard does (`if (!api || !agentDid) throw`) — the same rule, no stricter, so the two
        # languages agree. Before this, Python built the client and sent an empty DID to the gate, which
        # refused it MALFORMED_REQUEST: fail-closed either way, but a different place and a different error.
        # A non-empty but malformed DID still goes to the gate in both languages (NO_MANDATE).
        if not api or not agent_did:
            raise ValueError("MetaMyndClient requires api and agent_did (the agent's DID from provisioning, e.g. "
                             "AGENT_DID) — or use MetaMyndClient.from_env() — plus exactly one of agent_key or daemon_socket")
        self.orphan_release_delays = tuple(orphan_release_delays)
        self._resumes_in_flight: "set[str]" = set()
        self._resumes_lock = threading.Lock()
        self.api = api.rstrip("/")
        self.agent_did = agent_did
        self.timeout = timeout
        self.sign_context = sign_context
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
        # METAMYND_SIGN_CONTEXT=false opts out of context signing (0.7.0; on by default).
        sign_context = os.environ.get("METAMYND_SIGN_CONTEXT", "true").strip().lower() not in ("false", "0", "no", "off")
        if agent_key:
            return cls(api, agent_did, agent_key, sign_context=sign_context)
        return cls(api, agent_did, daemon_socket=daemon_socket, sign_context=sign_context)

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
        jurisdiction: Optional[str] = None,
    ) -> SignedRequest:
        """Sign a request WITHOUT sending it to the gate.

        `jurisdiction` (0.6.0, optional): ISO 3166-1 alpha-2, e.g. "SG". Normalised (trimmed,
        upper-cased), SIGNED (the v2 message, MAGP §8.3.12) and sent as a top-level field; a
        malformed one raises ValueError. Omitted = the v1 message, exactly as before.

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
        signed_jurisdiction = normalize_jurisdiction(jurisdiction)  # raises before anything is signed
        nonce = secrets.token_hex(16)  # §8.2 — 8-128 chars, single use
        # Formatted ONCE and reused in both the signed message and the body (§8.3.5).
        # Two calls to the clock is the intermittent-SIGNATURE_INVALID bug.
        issued_at = utc_now_rfc3339()
        # `self._signer` builds the exact same canonical message from these fields whether it
        # signs locally or asks the daemon to (§8.3.9's "the daemon builds the message itself"
        # property extends here: this file never hands EITHER signer a pre-built string).
        # `jurisdiction` is a key only when it is also sent (below), so signed and sent cannot differ.
        auth_fields = {"agentDid": self.agent_did, "action": action, "amount": amount, "currency": currency, "merchant": merchant, "resource": resource, "nonce": nonce, "issuedAt": issued_at}
        if signed_jurisdiction is not None:
            auth_fields["jurisdiction"] = signed_jurisdiction

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
        # The signed jurisdiction (§8.3.12) — top-level, exactly the value in the signed message.
        if signed_jurisdiction is not None:
            body["jurisdiction"] = signed_jurisdiction
        if context:
            body["itinerary"] = dict(context)
        if payload is not NO_PAYLOAD:
            digest = payload_digest(payload)
            body["payloadDigest"] = digest
            body["payloadSignature"] = self._signer.sign_payload_binding({"agentDid": self.agent_did, "action": action, "nonce": nonce, "issuedAt": issued_at, "payloadDigest": digest}).hex()
        if self.sign_context:
            # MAGP §8.3.13 (0.7.0, on by default): sign the envelope built from exactly the fields sent, so the gate's
            # envelopeHashFor over the received body is the hash signed. Fails closed — an error, never an unsigned context.
            envelope_fields = {k: body.get(k) for k in ("agentDid", "action", "amount", "currency", "merchant", "itinerary", "nonce", "issuedAt")}
            body["envelopeSignature"] = self._signer.sign_envelope(envelope_fields).hex()
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
        jurisdiction: Optional[str] = None,
    ) -> Verdict:
        """Ask the gate whether this action may proceed (MAGP §8.1-§8.3).

        `context` carries the request context the Standard/SOP rules read — `tool`,
        `riskLevel` and so on. Which fields your assigned rules need is
        discoverable: each atom at GET /standards/atoms lists its `requiredContext`. Send an
        honest `riskLevel`: a request with none is escalated, not allowed (MAGP §6.3).

        `jurisdiction` is NOT context: pass it here (ISO 3166-1 alpha-2) and it is signed
        (MAGP §8.3.12); the gate ignores a jurisdiction in `context`. A registered payee's
        country wins over it. Refusals: `JURISDICTION_REQUIRED`, `JURISDICTION_NOT_ALLOWED`,
        `JURISDICTION_MISMATCH` (`JURISDICTION_REASON_CODES`). A malformed value raises
        ValueError before anything is sent.

        `resource` is what this specific action touches (a signed field, checked against the
        mandate's resource scope).

        `payload` binds everything ELSE the tool will execute (see `sign_request`, including the
        0.4.0 `NO_PAYLOAD` / `None` distinction): pass the arguments exactly as the service will
        receive them, and a service that claims the hold with a different payload is refused by
        the gate before it runs anything.

        A permit carries `verdict.signed` — the request exactly as signed, with the
        `authorizationId` the gate issued — for a gateway or MCP server that re-verifies it.
        """
        signed = self.sign_request(action, amount, currency, merchant, context, resource, payload=payload, jurisdiction=jurisdiction)
        # The gate is sent the request; the authorizationId only exists once it answers.
        try:
            verdict = Verdict.from_response(self._post("/policy/mandate/authorize", dict(signed.body)))
        except GateUnreachable:
            # Sent, but the answer never came: the gate may have committed a hold anyway. Find and release it in the
            # background (0.13.0), then fail closed as before.
            self._release_orphan(str(signed.body.get("nonce", "")))
            raise
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
        pay_to: Optional[str] = None,
    ) -> SettlementResult:
        """Report what was actually charged, committing the hold.

        Normally the SERVICE that executed the action does this, not the agent. The gate accepts
        an agent's capture at the FULL authorized amount, and refuses a LOWER amount once a
        service has claimed the hold (it would let an agent take its budget back after the
        purchase happened: `403 COUNTERPARTY_MISMATCH`). A refusal comes back as `ok=False` with its
        `reason_code` — e.g. `NOT_HELD` (409: already settled or released, usually an earlier capture
        landed; read `outcome()` before retrying), `AUTHORIZATION_EXPIRED`, `AMOUNT_EXCEEDS_AUTHORIZED`,
        `AUTHORIZATION_NOT_FOUND` (404). The full table is MAGP §8.7.8.

        `pay_to` is the account the service paid (a Hedera account id or an EVM address). A
        settlement BELOW the authorization needs it when the owner lists the merchant's accounts
        (MAGP 8.7.14, refused `PAYEE_NOT_REGISTERED` otherwise), and the settlement observer only
        counts a credit to that account.
        """
        body: dict[str, Any] = {"amountCharged": amount_charged}
        if booking_ref:
            body["bookingRef"] = booking_ref
        if settlement_tx_hash:
            body["settlementTxHash"] = settlement_tx_hash
        if pay_to:
            body["payTo"] = pay_to
        proof = self._settle_proof("capture", authorization_id, [js_number_to_string(amount_charged), booking_ref or "", settlement_tx_hash or ""])
        if proof:
            body["agentProof"] = proof
        return self._settlement(f"/policy/mandate/authorize/{urllib.parse.quote(authorization_id, safe='')}/capture", body)

    def void(self, authorization_id: str, reason: Optional[str] = None) -> SettlementResult:
        """Release a hold nobody has claimed, returning its amount to the budget.

        Refused (`ok=False`, `reason_code` `COUNTERPARTY_MISMATCH`) once a service has claimed the
        hold: only that service can release it, because it may already have executed the action.
        A hold already settled or released is `ok=False` with `reason_code` `NOT_HELD` — not an
        error, usually an earlier void landed.
        """
        body: dict[str, Any] = {}
        if reason:
            body["reason"] = reason
        proof = self._settle_proof("void", authorization_id, [reason or ""])
        if proof:
            body["agentProof"] = proof
        return self._settlement(f"/policy/mandate/authorize/{urllib.parse.quote(authorization_id, safe='')}/void", body)

    def _release_orphan(self, nonce: str) -> None:
        """Release the hold an unanswered authorize may have minted (0.13.0; pre-beta rerun 3, D-7). Looked up by the request's
        nonce (GET .../authorize/by-request), retried after each of `orphan_release_delays`, released with this agent's signed
        void. Best effort, on a daemon thread: the hold's TTL is the backstop."""
        if not nonce or not self.orphan_release_delays:
            return

        def _run() -> None:
            query = urllib.parse.urlencode({"agentDid": self.agent_did, "nonce": nonce})
            for delay in self.orphan_release_delays:
                time.sleep(delay)
                try:
                    found = self._get_data(f"/policy/mandate/authorize/by-request?{query}").get("authorizationId")
                except Exception:  # noqa: BLE001 — still unreachable, or an issuer without the route: try again
                    continue
                if found:
                    try:
                        self.void(str(found), reason="ORPHANED: the agent never received this authorization")
                    except Exception:  # noqa: BLE001 — best effort
                        pass
                    return

        threading.Thread(target=_run, daemon=True).start()

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

    def claim_resume(self, escalation_id: str, authorization_id: str, request_digest: Optional[str] = None, context_digest: Optional[str] = None) -> str:
        """Take the ONE resume of an approved escalation at the gate (0.17.0, MAGP 9a.6) before running a tool under it.

        Returns "claimed"; "unsupported" when this signer cannot sign the claim (a daemon) or the gate predates it (the
        resume then runs unclaimed, as before); or the refusal code, e.g. AUTHORIZATION_IN_USE when another process took
        it first. Raises GateUnreachable when the gate cannot be reached — never run a resume the gate was not told about.

        With `request_digest` and `context_digest` (0.19.0, pre-beta rerun 6 F-1-NF-R) — the digests of the call about to run —
        the claim is signed as MAGP-RESUME-CLAIM-v2 and the gate refuses it unless they are the approved request and context.
        """
        self._resume_refusal_detail = None
        if not hasattr(self._signer, "sign_resume_claim"):
            return "unsupported"
        nonce = secrets.token_hex(16)
        issued_at = utc_now_rfc3339()
        bound = {"requestDigest": request_digest, "contextDigest": context_digest} if request_digest is not None or context_digest is not None else {}
        signature = self._signer.sign_resume_claim({"escalationId": escalation_id, "authorizationId": authorization_id, "agentDid": self.agent_did, "nonce": nonce, "issuedAt": issued_at, **bound})
        request = urllib.request.Request(
            f"{self.api}/policy/escalations/{urllib.parse.quote(escalation_id, safe='')}/resume-claim",
            data=json.dumps({"agentDid": self.agent_did, "nonce": nonce, "issuedAt": issued_at, "signature": signature.hex(), **bound}).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
            method="POST",
        )
        try:
            with _urlopen(request, self.timeout):
                return "claimed"
        except urllib.error.HTTPError as exc:
            try:
                body = json.loads(exc.read())
            except ValueError:
                body = None
            # A gate that predates the route answers the framework's own 404 page, not JSON. A JSON 404 (an escalation the gate
            # does not know, or a proxy's error body) is a refusal: never run unclaimed on an ambiguous answer.
            if exc.code == 404 and body is None:
                if not getattr(self, "_warned_no_resume_claim", False):
                    self._warned_no_resume_claim = True
                    warnings.warn("this gate has no resume claim (it predates MAGP 9a.6): resume() runs unclaimed, so two processes "
                                  "resuming one approval could both run it", stacklevel=3)
                return "unsupported"
            data = body.get("data") if isinstance(body, dict) else None
            code = data.get("reasonCode") if isinstance(data, dict) else None
            # The gate's sentence for the refusal (0.20.0): resume() puts it on the GovernanceBlocked's hint.
            detail = data.get("detail") if isinstance(data, dict) else None
            self._resume_refusal_detail = detail if isinstance(detail, str) and detail else None
            return code if isinstance(code, str) and code else f"GATE_HTTP_{exc.code}"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise GateUnreachable(f"gate unreachable ({getattr(exc, 'reason', exc)}) — the resume was not claimed, so it did not run") from exc

    def _settle_proof(self, verb: str, authorization_id: str, fields: list[str]) -> Optional[dict[str, str]]:
        """This agent's MAGP-SETTLE-v1 signature over settling its own unclaimed hold (MAGP §8.7.4). The gate accepts a
        settlement of a hold nobody has claimed only from its agent or a counterparty the owner registered — on every owner,
        an open testnet one included: an authorizationId alone settles nothing (COUNTERPARTY_AUTH_REQUIRED). None when the
        signer cannot sign one (a daemon older than signer 0.20.0): the call then goes unsigned, and the gate refuses it."""
        nonce = secrets.token_hex(16)
        issued_at = utc_now_rfc3339()
        try:
            signature = self._signer.sign_settle({"verb": verb, "agentDid": self.agent_did, "authorizationId": authorization_id, "nonce": nonce, "issuedAt": issued_at, "fields": fields})
        except DaemonError as exc:
            if exc.code == "SETTLE_SIGNING_UNSUPPORTED":
                return None
            raise
        return {"agentDid": self.agent_did, "nonce": nonce, "issuedAt": issued_at, "signature": signature.hex()}

    def _settlement(self, path: str, body: Mapping[str, Any]) -> SettlementResult:
        # A lost response to a capture or void may already have committed, so "treat as block" would
        # be wrong here: the outcome is unknown, and `outcome()` is how to find out.
        payload = self._post(path, body, unreachable="the outcome is UNKNOWN — it may have been applied; check client.outcome() before retrying")
        data = payload.get("data") or {}
        ok = payload.get("success") is True
        message = str(payload.get("message") or data.get("reasonCode") or "")
        # The code, never the sentence: `data.reasonCode` first (the one field every refusal carries, and the only place
        # the code is on a 200 NOT_HELD void), then the bare-code `message` of the standard refusal body (MAGP §8.7.8).
        # On success, the code the gate gave (a void's `HOLD_VOIDED`, as the Node guard reports it; pre-beta rerun 4, F-10), or
        # "" when it gave none (a capture).
        reason_code = str(data.get("reasonCode") or "") if ok else str(data.get("reasonCode") or payload.get("message") or "REFUSED")
        return SettlementResult(ok=ok, message=message, raw=data, reason_code=reason_code, detail=str(data.get("detail") or ""))

    def _get_data(self, path: str) -> Mapping[str, Any]:
        """GET a public gate endpoint and return its `data`, with the same failure rules as authorize."""
        request = urllib.request.Request(f"{self.api}{path}", headers={"User-Agent": USER_AGENT}, method="GET")
        try:
            with _urlopen(request, self.timeout) as response:
                raw = response.read()
            return (_loads(raw, "gate returned a non-JSON body") or {}).get("data") or {}
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            try:
                return (json.loads(payload) or {}).get("data") or {}
            except json.JSONDecodeError:
                raise RuntimeError(f"gate returned HTTP {exc.code}: {payload[:200]!r}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise GateUnreachable(f"gate unreachable ({getattr(exc, 'reason', exc)}) — nothing is known about the outcome") from exc

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
            with _urlopen(request, self.timeout) as response:
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
            raise GateUnreachable(f"gate unreachable ({getattr(exc, 'reason', exc)}) — the hold stands") from exc

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
            with _urlopen(request, self.timeout) as response:
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
            raise GateUnreachable(f"gate unreachable ({reason}) — {unreachable}") from exc


def _loads(raw: bytes, what: str) -> Any:
    """json.loads that fails as the RuntimeError the rest of the client documents (a CDN's HTML error page
    with a 200 status would otherwise surface as a JSONDecodeError that `except RuntimeError` misses)."""
    try:
        return json.loads(raw)
    except ValueError as exc:
        raise RuntimeError(f"{what}: {raw[:200]!r}") from exc


class GateUnreachable(RuntimeError):
    """The gate could not be reached (0.11.0). Still a RuntimeError, so `except RuntimeError` keeps working; it adds the
    machine-readable code every other refusal has (L-g, 2026-10-03 pre-beta rerun), the one the Node guard reports.
    Fail closed: nothing was decided, so nothing may run."""

    reason_code = "GATE_UNREACHABLE"


class GovernanceBlocked(RuntimeError):
    """Raised instead of running a tool the gate did not permit."""

    def __init__(self, verdict: Verdict, action: str):
        # Name the risk the issuer derived, as the Node guard's message does (0.18.1; pre-beta rerun 5, FW N-1): a $200
        # "low" booking held for review otherwise reads as an unexplained RISK_REVIEW.
        derived = "; ".join(f"{s.get('signal')}: {s.get('detail') or s.get('level')}" for s in (verdict.risk_signals or []))
        why = f" (risk derived by the issuer: {derived})" if derived else ""
        super().__init__(f"{action} refused: {verdict.decision}/{verdict.reason_code}{why}")
        self.verdict = verdict
        self.action = action


class ToolNotExecuted(Exception):
    """Raise from a guarded tool when it failed BEFORE it did anything (0.12.0): input validation, a missing credential, an
    upstream that answered "not processed". `guard_tool` then releases the hold the call was granted instead of keeping it
    reserved. Any other exception keeps the hold, because a tool that raised may still have acted. An exception of your own
    can say the same with an attribute: `nothing_executed = True`."""

    nothing_executed = True


# What a gateway older than the approved-context binding (MAGP 9a.5) answers when asked to run an approval: its claim states
# no context, and the gate refuses it AUTHORIZATION_CONTEXT_REQUIRED with the hold untouched (pre-beta rerun 6 FW6-1).
OUTDATED_GATEWAY_CODE = "AUTHORIZATION_CONTEXT_REQUIRED"
OUTDATED_GATEWAY_HINT = (
    "the gateway this tool called predates the approved-context binding (MAGP 9a.5), so it could not claim the approval and ran "
    "nothing. Upgrade it (@metamynd/agentsafe-mcp-guard >= 0.27.0, @metamynd/agentsafe-http-gateway >= 0.26.0, "
    "@metamynd/agentsafe-a2a-guard >= 0.18.0) and resume() again: the approval is kept, not voided"
)


def _error_reason_code(exc: BaseException) -> Optional[str]:
    """The reason code a tool's exception carries, however the tool attached it (a relayed GovernanceBlocked, or a field)."""
    verdict = getattr(exc, "verdict", None)
    code = getattr(verdict, "reason_code", None) or getattr(exc, "reason_code", None) or getattr(exc, "code", None)
    return code if isinstance(code, str) else None


def _is_outdated_gateway_refusal(exc: BaseException) -> bool:
    return _error_reason_code(exc) == OUTDATED_GATEWAY_CODE


def _explain_outdated_gateway(exc: BaseException) -> None:
    """Say on the exception (and in one warning) which gateway to upgrade: the bare code said nothing a developer could act on."""
    verdict = getattr(exc, "verdict", None)
    raw = getattr(verdict, "raw", None)
    relayed = (raw.get("detail") if isinstance(raw, Mapping) else None) or getattr(verdict, "hint", None) or getattr(exc, "detail", None)
    detail = relayed if isinstance(relayed, str) and relayed and relayed != OUTDATED_GATEWAY_CODE else OUTDATED_GATEWAY_HINT
    try:
        exc.upgrade_required = True  # type: ignore[attr-defined]
        exc.hold_kept = True  # type: ignore[attr-defined]
        exc.detail = detail  # type: ignore[attr-defined]
        if hasattr(exc, "add_note"):
            exc.add_note(OUTDATED_GATEWAY_HINT)
    except Exception:  # noqa: BLE001 — an exception that takes no attributes: the warning below still says it
        pass
    warnings.warn(f"{OUTDATED_GATEWAY_CODE}: {detail}", stacklevel=4)


# Reason codes that mean "the gate gave no decision" (a rate-limit or server error with a JSON body is read as a block
# with one of these), not "the gate refused this request". Telling the model never to retry those would be wrong.
_NO_DECISION_REASONS = frozenset({"", "UNKNOWN", "REFUSED", "GATE_UNREACHABLE"})

# Refusals by a limit that frees itself over time: the same request can pass later, though no change of arguments makes
# it pass now. "Do not retry" was wrong for these (pre-beta evaluation 2026-10-03, L-a: the shared sandbox's per-caller
# share refills as its window rolls).
_TIME_BOUND_REASONS = frozenset({"SANDBOX_CALLER_SHARE_EXCEEDED", "RATE_LIMIT_EXCEEDED", "CIRCUIT_BREAKER_OPEN"})


def _refusal_message(verdict: Verdict, action: str) -> str:
    """The text a model reads for a refusal: what happened, and whether retrying could ever help."""
    if verdict.decision == "escalate":
        derived = "; ".join(f"{s.get('signal')}: {s.get('detail') or s.get('level')}" for s in verdict.risk_signals)
        why = f" Risk derived by the issuer: {derived}." if derived else ""
        return f"Held for human review: {verdict.reason_code}.{why} {action} did not run. It is held for a human; do not retry it."
    if (verdict.reason_code or "") in _NO_DECISION_REASONS:
        return f"The governance gate did not give a decision, so {action} did not run. It may be retried later."
    if verdict.reason_code in _TIME_BOUND_REASONS:
        return (f"Refused by governance: {verdict.decision}/{verdict.reason_code}. {action} did not run. This limit is "
                "temporary: the same request may pass later, but changing its arguments will not make it pass now.")
    return f"Refused by governance: {verdict.decision}/{verdict.reason_code}. {action} did not run. Do not retry it with different arguments."


class GovernanceRefusal(dict):
    """What a `guard_tool(..., on_refusal="return")` tool returns instead of raising (0.8.0).

    A plain dict, so every framework can hand it to the model as the tool's result (JSON-serialisable as is):
    `refused` (always True), `action`, `decision` (`block` / `escalate` / ...), `reasonCode`, `escalationId`
    (an escalate's handle for `client.wait_for_escalation`, else None) and `message`. The full verdict is on
    `.verdict` (an attribute, never serialised). The tool did NOT run. Test for it with
    `isinstance(result, GovernanceRefusal)`, never by truthiness: a non-empty dict is truthy.
    """

    def __init__(self, verdict: Verdict, action: str):
        super().__init__(
            refused=True,
            action=action,
            decision=verdict.decision,
            reasonCode=verdict.reason_code,
            escalationId=verdict.escalation_id,
            message=_refusal_message(verdict, action),
        )
        # Only when the issuer derived the risk (0.15.0), so every other refusal keeps its shape.
        if verdict.risk_signals:
            self["riskSignals"] = verdict.risk_signals
        self.verdict = verdict
        self.action = action


_ON_REFUSAL_MODES = ("raise", "return")


def guard_tool(
    client: "MetaMyndClient",
    action: str,
    fn: "Any",
    map_args: "Any" = None,
    *,
    on_refusal: "Any" = "raise",
    settle: str = "capture",
    release_on_error: "Any" = False,
    resume_timeout: float = 600.0,
) -> "Any":
    """Wrap a callable so it runs ONLY on a permit.

    What becomes of the hold a permitted call was granted (0.12.0; before, nothing — an unclaimed hold lapses with its
    TTL, so a tool that RAN handed its budget back after 15 minutes, and one that FAILED kept it reserved until then):
      - the tool returns → the hold is CAPTURED at the authorized amount (`settle="none"` opts out). Where a gateway
        claimed it, the gateway has already settled it and the gate refuses the agent's capture — harmless, ignored.
      - the tool raises `GovernanceBlocked` (a service that re-verifies the request refused it) or `ToolNotExecuted`, or
        an exception with `nothing_executed = True` → the hold is RELEASED (`client.void`).
      - it raises anything else → the hold is KEPT: a tool that raised may still have acted. `release_on_error=True`, or a
        callable `release_on_error(exc) -> bool`, says otherwise. The gate never lets the agent release a hold a service
        has CLAIMED, because that service may already have acted.

    An escalated call (an ESCALATE refusal carries `verdict.escalation_id`) is resumed with
    `governed.resume(escalation_id, *args, **kwargs)` and the SAME arguments: it waits up to `resume_timeout` seconds
    for the owner's decision, then runs the tool exactly once under the approval's authorization (a fresh signed request
    carrying it is what `governance_headers()` returns inside), settled as above. Not approved → `GovernanceBlocked`.

    The Node guard's `guardTool()` has always had this; Python did not, and its absence was
    the real gap. A client that only returns verdicts leaves every caller to remember to
    check one — and the failure mode of forgetting is that the tool runs anyway, which is
    the exact thing this product exists to prevent. Wrapping inverts that: the unguarded
    path stops being the easy one.

    `map_args` turns your tool's arguments into the gate's inputs
    (`amount`, `currency`, `merchant`, `resource`, `jurisdiction`, `context`). Without it the call is
    authorized with no amount, which is right for a tool that moves no money and wrong for
    one that does — so pass it whenever there is a value at stake. Put an honest `riskLevel`
    in `context`; a call with none is escalated (MAGP §6.3), and this function never invents one —
    nor should your `map_args` (pass the tool's own value through; never `or "low"`). It is the
    agent's own claim unless the mandate's owner configures provenance for it.

        book = guard_tool(client, "flight-purchase", raw_book,
                          lambda vendor, amount: {"amount": amount, "merchant": vendor,
                                                  "context": {"tool": "book-flight", "riskLevel": "low"}})

    This wrapper is IN-PROCESS and cooperative: it makes the governed path the easy one for
    your agent, but code that can reach `raw_book` itself can still call it. The boundary is a
    separate process holding the tool and its credentials that re-verifies the signed request
    (`@metamynd/agentsafe-http-gateway`, or an MCP server using `agentsafe-mcp-guard`).

    `map_args` may also return `"payload"`: the complete payload the tool will send (a dict of
    JSON values). It is digested and signed with the request, so the service that executes it
    is held to exactly those arguments — a payee or account number the eight signed fields do
    not cover (MAGP §8.3.9). One a JSON payload cannot carry raises PayloadNotCanonicalizable
    before the tool is touched. Omitting `"payload"` (or returning `NO_PAYLOAD` for it) means
    unbound; returning `None` for it binds the literal JSON `null` (0.4.0).

    Raises GovernanceBlocked on anything that is not a permit, including an escalate: a
    held action has not happened yet, and returning normally would tell the caller it had.
    (`refused.verdict.escalation_id` is the handle for `client.wait_for_escalation`.)

    `on_refusal` (0.8.0, keyword-only) chooses what a refusal does. An unreachable gate is a refusal
    like any other since 0.11.0 — a block with reason code `GATE_UNREACHABLE` (it used to be a bare
    RuntimeError); a payload that cannot be bound still raises, and the tool never runs in any case:
      - `"raise"` (default): raise `GovernanceBlocked`, as above.
      - `"return"`: return a `GovernanceRefusal` (a JSON-ready dict) instead — what
        `guard_agent_tool` does, and what a tool handed to an agent framework should do. When a
        framework runs several SYNC tool calls of one model turn in parallel threads (PydanticAI,
        LangGraph's `ToolNode`), one raised refusal aborts the turn while the sibling calls
        already in their threads go on — authorized and run, with results nobody receives. A
        returned refusal is just that call's result; the turn completes and the model sees every
        outcome.
      - a callable: `on_refusal(refused: GovernanceBlocked)` is called and its return value is
        the tool's result (e.g. a string for the model). Whatever it raises propagates. An
        `async def` handler needs an `async def` tool (it is awaited there); given a SYNC tool it
        raises TypeError at wrap time (0.8.1) — a sync tool would hand the framework an un-awaited
        coroutine as its result.

    Async tools are supported: pass an `async def` and get an `async def` back. They are the
    better fit for parallel tool calls: a cancelled async call is cancelled (and a hold it had
    already been granted is released), where a sync call already in a worker thread cannot be.

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

    if not (callable(on_refusal) or on_refusal in _ON_REFUSAL_MODES):
        # Refused at wrap time: a typo here ("retrun") must not silently fall back to either behaviour.
        raise ValueError(f'on_refusal must be "raise", "return" or a callable, not {on_refusal!r}')
    if settle not in ("capture", "none"):
        raise ValueError(f'settle must be "capture" or "none", not {settle!r}')
    if not (isinstance(release_on_error, bool) or callable(release_on_error)):
        raise ValueError(f"release_on_error must be a bool or a callable, not {release_on_error!r}")

    def _is_async_callable(f: "Any") -> bool:
        return inspect.iscoroutinefunction(f) or inspect.iscoroutinefunction(getattr(f, "__call__", None))

    if callable(on_refusal) and _is_async_callable(on_refusal) and not _is_async_callable(fn):
        # A sync tool returns the handler's result as-is, so an async handler's coroutine would reach the framework
        # un-awaited: the model gets "<coroutine object ...>" and Python warns it was never awaited. Refused at wrap time.
        raise TypeError(
            "on_refusal is an async function but the tool is sync: pass an async def tool, or a sync on_refusal handler"
        )

    def _refused(refused: "GovernanceBlocked") -> "Any":
        """The tool's result for a governance refusal when it is not raised. The tool has NOT run."""
        if on_refusal == "return":
            return GovernanceRefusal(refused.verdict, refused.action)
        return on_refusal(refused)

    def _gate(*args: "Any", **kwargs: "Any") -> "tuple[Verdict, Mapping[str, Any]]":
        payload = map_args(*args, **kwargs) if map_args else {}
        try:
            verdict = client.authorize(
                action,
                payload.get("amount", 0),
                currency=payload.get("currency", "USD"),
                merchant=payload.get("merchant", ""),
                context=payload.get("context", {}),
                resource=payload.get("resource"),
                payload=payload.get("payload", NO_PAYLOAD),
                jurisdiction=payload.get("jurisdiction"),
            )
        except GateUnreachable as exc:
            # No decision is a block (rule 5), and a block with its code like any other (L-g): raised as GovernanceBlocked
            # (still a RuntimeError), or under on_refusal="return" handed to the model as a GovernanceRefusal that says
            # the gate gave no decision and the call may be retried later — not a bare framework error.
            raise _guard_refusal(Verdict(decision="block", reason_code=GateUnreachable.reason_code, hint=str(exc))) from exc
        if not verdict.permitted:
            # Fail closed, loudly, and before the tool is touched.
            raise _guard_refusal(verdict)
        return verdict, payload

    def _guard_refusal(verdict: "Verdict") -> "GovernanceBlocked":
        """This wrapper's own refusal, marked as such: raised inside an ENCLOSING guarded tool it says nothing about what
        that tool had already done, so it must never release the enclosing call's hold (see _nothing_ran)."""
        refused = GovernanceBlocked(verdict, action)
        refused.raised_by_guard = True  # type: ignore[attr-defined]
        return refused

    def _resume_digest_for(state: "EscalationStatus", payload: "Mapping[str, Any]") -> str:
        """The resume binding of the call these args map to. The payload counts only when the hold carries one."""
        bound_payload = ""
        if state.raw.get("payloadBound") and payload.get("payload", NO_PAYLOAD) is not NO_PAYLOAD:
            try:
                bound_payload = payload_digest(payload["payload"])
            except PayloadNotCanonicalizable:
                bound_payload = "unbindable"
        return resume_request_digest(state.authorization_id or "", action, payload.get("amount"), payload.get("currency") or "USD",
                                     payload.get("merchant", ""), payload.get("resource"), bound_payload)

    def _approved(escalation_id: str, *args: "Any", **kwargs: "Any") -> "tuple[Verdict, Mapping[str, Any]]":
        """The permit an owner's approval minted, as if the gate had allowed the call itself — or GovernanceBlocked."""
        payload = map_args(*args, **kwargs) if map_args else {}
        try:
            state = client.wait_for_escalation(escalation_id, timeout=resume_timeout)
            if not state.may_proceed:
                # Pending at the timeout is still a hold; denied / expired / modified is not this action, approved.
                decision = "escalate" if state.status == "pending" else "block"
                code = state.reason_code or f"ESCALATION_{state.status.upper()}"
                raise _guard_refusal(Verdict(decision=decision, reason_code=code, escalation_id=escalation_id, raw=state.raw))
            # Once only: run while the approved authorization is still unused. A second resume — after a settled run, a
            # gateway's claim, an expiry — is refused without touching the tool. (Two resumes RACING in one in-process agent
            # can both pass this before either settles; a claiming gateway is what makes concurrent resumes exactly-once.)
            used = client.outcome(state.authorization_id)
        except GateUnreachable as exc:
            raise _guard_refusal(Verdict(decision="block", reason_code=GateUnreachable.reason_code, escalation_id=escalation_id, hint=str(exc))) from exc
        if used.outcome != "not_started":
            # A VOIDED hold was never used: it was released (by this agent after a failed run, its owner, a revoke…) and nothing
            # can run under it. AUTHORIZATION_ALREADY_USED sent the developer looking for a run that never happened (0.20.0,
            # pre-beta rerun 6 FW6-1): say what became of it, and that the owner must approve again.
            if used.spend_status == "voided":
                raise _guard_refusal(Verdict(decision="block", reason_code="AUTHORIZATION_VOIDED", authorization_id=state.authorization_id,
                                             escalation_id=escalation_id,
                                             hint="the approval's hold was voided, so nothing can run under it — its owner must approve the request again"))
            raise _guard_refusal(Verdict(decision="block", reason_code="AUTHORIZATION_ALREADY_USED", authorization_id=state.authorization_id,
                                         escalation_id=escalation_id, hint=f"outcome: {used.outcome}"))
        # Only what was approved (0.14.0, MAGP 9a.5): the approval's hold is for ONE request. A gateway re-verifies it, but an
        # in-process tool has nothing else between these args and the tool, so they must reproduce the hold's requestDigest.
        expected = state.raw.get("requestDigest")
        if not expected and not getattr(client, "_warned_no_request_digest", False):
            client._warned_no_request_digest = True
            warnings.warn("this gate returns no requestDigest (it predates MAGP 9a.5): resume() cannot check its arguments against the "
                          "approved request, so pass the SAME args; a gateway still re-verifies them", stacklevel=3)
        if expected and _resume_digest_for(state, payload) != expected:
            raise _guard_refusal(Verdict(decision="block", reason_code="ESCALATION_REQUEST_MISMATCH", authorization_id=state.authorization_id,
                                         escalation_id=escalation_id, hint="these arguments are not the request the owner approved"))
        # And only the CONTEXT that was approved (0.18.0, MAGP 9a.5): the digest above binds what the approval spends, which for
        # an action that spends nothing is little more than its name. The status carries a digest of the approved itinerary.
        expected_context = state.raw.get("contextDigest")
        if expected and not expected_context and not getattr(client, "_warned_no_context_digest", False):
            client._warned_no_context_digest = True
            warnings.warn("this gate returns no contextDigest (it predates the approved-context binding, MAGP 9a.5): resume() cannot "
                          "check the context against the approval, so pass the SAME args", stacklevel=3)
        if expected_context:
            try:
                actual_context = approved_context_digest(payload.get("context", {}))
            except PayloadNotCanonicalizable:
                actual_context = "unbindable"
            if actual_context != expected_context:
                raise _guard_refusal(Verdict(decision="block", reason_code="ESCALATION_REQUEST_MISMATCH", authorization_id=state.authorization_id,
                                             escalation_id=escalation_id, hint="this context is not the one the owner approved"))
        # The original signed request is old by now (a service refuses one older than a few minutes): sign the SAME
        # request again, carrying the approval's authorization, for governance_headers() to hand to a gateway.
        signed = client.sign_request(
            action,
            payload.get("amount", 0),
            currency=payload.get("currency", "USD"),
            merchant=payload.get("merchant", ""),
            context=payload.get("context", {}),
            resource=payload.get("resource"),
            authorization_id=state.authorization_id,
            payload=payload.get("payload", NO_PAYLOAD),
            jurisdiction=payload.get("jurisdiction"),
        )
        # The ONE resume (0.17.0, MAGP 9a.6): taken at the gate, atomically, so a second PROCESS resuming the same escalation
        # is refused AUTHORIZATION_IN_USE instead of running an in-process tool twice (the in-process lock covers one process
        # only). Taken last, right before the tool runs: it is at most once, so nothing that could still fail locally comes after.
        try:
            # v2 (0.19.0, F-1-NF-R): a gate that asks for it gets the digests of THIS call, computed from its args (never echoed
            # from the status), so the gate itself refuses anything but the approved request and context. An older gate gets v1.
            digests: "dict[str, str]" = {}
            if _int_or_zero(state.raw.get("resumeClaimVersion")) >= 2:
                try:
                    claim_context = approved_context_digest(payload.get("context", {}))
                except PayloadNotCanonicalizable:
                    claim_context = "unbindable"
                digests = {"request_digest": _resume_digest_for(state, payload), "context_digest": claim_context}
            claim = client.claim_resume(escalation_id, state.authorization_id or "", **digests)
        except GateUnreachable as exc:
            raise _guard_refusal(Verdict(decision="block", reason_code=GateUnreachable.reason_code, escalation_id=escalation_id, hint=str(exc))) from exc
        if claim not in ("claimed", "unsupported"):
            refusal_detail = getattr(client, "_resume_refusal_detail", None)
            raise _guard_refusal(Verdict(decision="block", reason_code=claim, authorization_id=state.authorization_id, escalation_id=escalation_id,
                                         hint=refusal_detail if isinstance(refusal_detail, str) and refusal_detail
                                         else "another process took this approval's one resume" if claim == "AUTHORIZATION_IN_USE" else None))
        verdict = Verdict(decision="allow", reason_code=state.reason_code or "ESCALATION_APPROVED", authorization_id=state.authorization_id,
                          escalation_id=escalation_id, raw=state.raw, signed=signed)
        return verdict, payload

    def _take_resume(escalation_id: str) -> None:
        """One resume of an escalation at a time per client (0.13.0): a second, concurrent one is refused AUTHORIZATION_IN_USE
        instead of racing the first past the "still unused?" check. Separate PROCESSES need a lock of their own, or a gateway."""
        if not hasattr(client, "_resumes_lock"):  # a client not built by __init__ (a test double, a subclass)
            client._resumes_lock = threading.Lock()
            client._resumes_in_flight = set()
        with client._resumes_lock:
            if escalation_id in client._resumes_in_flight:
                raise _guard_refusal(Verdict(decision="block", reason_code="AUTHORIZATION_IN_USE", escalation_id=escalation_id))
            client._resumes_in_flight.add(escalation_id)

    def _drop_resume(escalation_id: str) -> None:
        with client._resumes_lock:
            client._resumes_in_flight.discard(escalation_id)

    def _nothing_ran(exc: BaseException) -> bool:
        if not isinstance(exc, Exception):
            return False  # a cancellation or an interpreter exit says nothing about what the tool did
        if isinstance(exc, GovernanceBlocked) and getattr(exc, "raised_by_guard", False) is True:
            return False  # a NESTED guarded call's refusal: this tool may have acted before it
        if isinstance(exc, (GovernanceBlocked, ToolNotExecuted)) or getattr(exc, "nothing_executed", False) is True:
            return True
        if release_on_error is True:
            return True
        return callable(release_on_error) and release_on_error(exc) is True

    def _after_failure(verdict: "Verdict", exc: BaseException) -> None:
        """Release the hold of a call that cannot have run; keep it otherwise. Best effort: the TTL is the backstop."""
        # A gateway that predates the approved-context binding refused to claim the approval (0.20.0, pre-beta rerun 6 FW6-1):
        # nothing ran there and the hold is unclaimed, so it is KEPT. Voiding it left the owner to approve the same request
        # again, and the next resume misreported it as AUTHORIZATION_ALREADY_USED. The gate re-opens the one resume for it, so
        # resume() works again once the gateway is upgraded. The exception says which gateway to upgrade.
        if verdict.authorization_id and isinstance(exc, Exception) and _is_outdated_gateway_refusal(exc):
            _explain_outdated_gateway(exc)
            return
        if not verdict.authorization_id or not _nothing_ran(exc):
            return
        code = exc.verdict.reason_code if isinstance(exc, GovernanceBlocked) else str(getattr(exc, "code", "") or type(exc).__name__)
        try:
            client.void(verdict.authorization_id, reason=f"tool did not run: {code}"[:200])
        except Exception:  # noqa: BLE001 — best effort
            pass

    def _after_success(verdict: "Verdict", payload: "Mapping[str, Any]") -> None:
        """Commit the hold of a call that ran, at the authorized amount. Best effort; a gateway may already have."""
        # A call that names no amount was authorized at 0 (_gate sends `payload.get("amount", 0)`), and the gate holds it all
        # the same: settled here at 0 — "it ran, it spent nothing" — or it sat `held` until its TTL and then read as `expired`,
        # an action that never ran (0.19.2, pre-beta rerun 6 FW6-4). A zero capture of an unclaimed hold commits no spend.
        amount = payload.get("amount", 0)
        if settle != "capture" or not verdict.authorization_id or isinstance(amount, bool) or not isinstance(amount, (int, float)):
            return
        # A hold a counterparty CLAIMED is not this agent's to settle (0.16.0, pre-beta rerun 4 F-3): the gateway that ran the
        # tool claimed it before executing and settles it itself, at what it really charged. Capturing here raced that and
        # left the settlement `unattested`. Only when the gate cannot be asked does the agent capture (the safe side).
        try:
            state = client.outcome(verdict.authorization_id)
            if state.claimed or state.outcome in _SETTLED_OUTCOMES:
                return
        except Exception:  # noqa: BLE001 — unreachable or unreadable: fall through and count the spend
            pass
        # Retried briefly when the gate cannot be reached: a capture that never lands lets the hold of an action that RAN
        # lapse with its TTL, and its spend stop counting. A refusal (a gateway already settled it) is an answer, not retried.
        for wait in (0.0, 0.25, 1.0):
            if wait:
                time.sleep(wait)
            try:
                client.capture(verdict.authorization_id, amount)
                return
            except GateUnreachable:
                continue
            except Exception:  # noqa: BLE001 — best effort
                return

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
        held, _payload = task.result()

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
        async def _run_async(gate: "Any", args: "tuple", kwargs: "dict") -> "Any":
            gate_call = asyncio.ensure_future(asyncio.to_thread(gate, *args, **kwargs))
            try:
                verdict, payload = await asyncio.shield(gate_call)
            except asyncio.CancelledError:
                gate_call.add_done_callback(_release_if_cancelled)
                raise
            except GovernanceBlocked as refused:
                if on_refusal == "raise":
                    raise
                result = _refused(refused)
                return (await result) if inspect.isawaitable(result) else result
            token = _GOVERNANCE.set(verdict.signed)
            try:
                out = await fn(*args, **kwargs)
            except Exception as exc:  # a cancellation is not evidence of anything: it propagates at once, hold kept
                await asyncio.to_thread(_after_failure, verdict, exc)
                raise
            finally:
                _GOVERNANCE.reset(token)
            # The tool RAN. A cancellation from here on cannot stop the capture: it runs in its own thread to completion.
            await asyncio.to_thread(_after_success, verdict, payload)
            return out

        @functools.wraps(fn)
        async def governed_async(*args: "Any", **kwargs: "Any") -> "Any":
            return await _run_async(_gate, args, kwargs)

        async def resume_async(escalation_id: str, *args: "Any", **kwargs: "Any") -> "Any":
            _take_resume(escalation_id)
            try:
                return await _run_async(lambda *a, **k: _approved(escalation_id, *a, **k), args, kwargs)
            finally:
                _drop_resume(escalation_id)

        governed_async.resume = resume_async  # type: ignore[attr-defined]
        return governed_async

    def _run(gate: "Any", args: "tuple", kwargs: "dict") -> "Any":
        try:
            verdict, payload = gate(*args, **kwargs)
        except GovernanceBlocked as refused:
            if on_refusal == "raise":
                raise
            # Returned, not raised: a framework running sibling sync calls in parallel threads would otherwise abort the
            # turn on this exception while those siblings run on unobserved (M-5). The tool has not been touched.
            return _refused(refused)
        # While the tool runs, the signed request is available to it WITHOUT appearing in its
        # signature (which frameworks read to build the tool's schema): a tool that calls a
        # gateway does `headers=governance_headers()`. Reset afterwards so it can never leak into
        # an unrelated call.
        token = _GOVERNANCE.set(verdict.signed)
        try:
            result = fn(*args, **kwargs)
        except BaseException as exc:
            _GOVERNANCE.reset(token)
            _after_failure(verdict, exc)
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
                    out = await result
                except Exception as exc:  # a cancellation propagates at once, hold kept
                    await asyncio.to_thread(_after_failure, verdict, exc)
                    raise
                finally:
                    _GOVERNANCE.reset(inner)
                await asyncio.to_thread(_after_success, verdict, payload)
                return out

            return _await_with_governance()
        _GOVERNANCE.reset(token)
        _after_success(verdict, payload)
        return result

    @functools.wraps(fn)
    def governed(*args: "Any", **kwargs: "Any") -> "Any":
        return _run(_gate, args, kwargs)

    def resume(escalation_id: str, *args: "Any", **kwargs: "Any") -> "Any":
        _take_resume(escalation_id)
        try:
            return _run(lambda *a, **k: _approved(escalation_id, *a, **k), args, kwargs)
        finally:
            _drop_resume(escalation_id)

    governed.resume = resume  # type: ignore[attr-defined]
    return governed


def guard_agent_tool(
    client: "MetaMyndClient",
    action: str,
    fn: "Any",
    map_args: "Any" = None,
    *,
    settle: str = "capture",
    release_on_error: "Any" = False,
    resume_timeout: float = 600.0,
) -> "Any":
    """Wrap a tool you hand to an AGENT FRAMEWORK so it runs ONLY on a permit (0.9.0).

    Exactly `guard_tool(client, action, fn, map_args, on_refusal="return")`: a refusal comes back as a
    `GovernanceRefusal` — a JSON-ready dict the framework gives the model as that call's result (`refused`,
    `decision`, `reasonCode`, `escalationId`, `message`) — instead of an exception. The tool still never runs on
    a refusal, and an unreachable gate comes back the same way, with reason code `GATE_UNREACHABLE` (0.11.0).

    Why a separate name rather than a different default: code that calls a guarded tool ITSELF should get an
    exception for a refusal, because a returned value can be mistaken for the tool's result — so `guard_tool`
    keeps raising. A framework is the opposite case. PydanticAI and LangGraph's `ToolNode` run the SYNC tool calls
    of one model turn in parallel threads; a raised refusal aborts the turn while the sibling calls already running
    go on — authorized and executed, with results nobody receives, so a retried turn can do them twice. A returned
    refusal is just one call's result: the turn completes, the model sees every outcome, and it can explain the
    refusal or ask for approval (an escalate carries `escalationId` for `client.wait_for_escalation`).

        agent.tool_plain(guard_agent_tool(client, "flight-purchase", book_flight, map_args))   # PydanticAI
        ToolNode([guard_agent_tool(client, "purchase-order", raise_po, map_args)])              # LangGraph

    Signature, type hints and sync/async-ness are preserved, so a framework builds the same tool schema it would
    for `fn` unguarded.
    """
    return guard_tool(client, action, fn, map_args, on_refusal="return", settle=settle, release_on_error=release_on_error, resume_timeout=resume_timeout)


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

    # The jurisdiction is SIGNED (a top-level argument, MAGP §8.3.12) — never context, which the gate ignores for it.
    flight = {"tool": "book-flight", "riskLevel": "low"}
    _show("$150 flight, low risk", client.authorize("flight-purchase", 150, merchant="skyward-air", context=flight, jurisdiction="SG"))
    _show("$600 flight, over the SOP cap", client.authorize("flight-purchase", 600, merchant="skyward-air", context=flight, jurisdiction="SG"))
    held = client.authorize("flight-purchase", 150, merchant="skyward-air", context={**flight, "riskLevel": "high"}, jurisdiction="SG")
    _show("$150 flight, high risk", held)
    # ESCALATE is a HOLD, not a denial. Follow it up rather than stopping here — this is
    # the one verdict a naive integration mishandles, usually by treating it as failure.
    if held.escalation_id:
        state = client.escalation_status(held.escalation_id)
        print(f"        held for review: {state.status} ({state.approvals}/{state.required} approvals)"
              f"{' — may proceed' if state.may_proceed else ''}")
    _show(
        "$150 flight, unapproved tool",
        client.authorize("flight-purchase", 150, merchant="skyward-air", context={**flight, "tool": "wire-transfer"}, jurisdiction="SG"),
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

    # §8.3.12 — a signed jurisdiction appends the version tag and the value (the v2 message); none is v1 exactly.
    msg_v2 = canonical_message("did:x", "act", 150.0, "USD", None, "n0nce", stamp, jurisdiction="SG")
    assert msg_v2 == f"did:x|act|150|USD|||n0nce|{stamp}|MAGP-AUTH-v2|SG", msg_v2
    assert canonical_message("did:x", "act", 150.0, "USD", None, "n0nce", stamp, jurisdiction=None) == msg
    assert normalize_jurisdiction(" sg ") == "SG" and normalize_jurisdiction(None) is None
    for bad_jurisdiction in ("", "S", "SGP", "S1", "ß", "é1", "EU-1"):
        try:
            normalize_jurisdiction(bad_jurisdiction)
            raise AssertionError(f"{bad_jurisdiction!r} should have been rejected")
        except ValueError:
            pass

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
        "selftest ok — key encodings, number stringification, timestamp shape, canonical join (v1 + v2), tool signature, "
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
                parts = [body["agentDid"], body["action"], js_number_to_string(body["amount"]), body["currency"], body.get("merchant", ""), body.get("resource", ""), body["nonce"], body["issuedAt"]]
                if "jurisdiction" in body:  # the v2 message (§8.3.12): chosen by the field's presence, never tried both ways
                    parts += ["MAGP-AUTH-v2", body["jurisdiction"]]
                message = "|".join(parts)
                try:
                    pub.verify(bytes.fromhex(body["signature"]), message.encode("utf-8"))
                except Exception:  # a wrong message: refuse it the way the real gate does, so the assert below names the cause
                    return self._send(403, {"success": False, "data": {"decision": "block", "reasonCode": "SIGNATURE_INVALID"}})
                if body["action"] == "hold":
                    return self._send(403, {"success": False, "data": {"decision": "escalate", "reasonCode": "RISK_REVIEW", "escalationId": "esc-1"}})
                if body["action"] == "deny":
                    return self._send(403, {"success": False, "data": {"decision": "block", "reasonCode": "SOP_SPEND_CAP"}})
                return self._send(200, {"success": True, "data": {"decision": "allow", "reasonCode": "AUTHORIZED", "authorizationId": f"auth-{int(body['amount'])}"}})
            # Settlement refusals in the gate's one refusal shape (MAGP §8.7.8): the bare code as `message`, the sentence in
            # `data.detail`, and the status the code always has.
            def refusal(status: int, flag: str, code: str, detail: str) -> None:
                auth_id = self.path.split("/")[-2]
                self._send(status, {"success": False, "message": code, "data": {flag: False, "authorizationId": auth_id, "reasonCode": code, "detail": f"{code}: {detail}"}})

            if self.path.endswith("/capture"):
                if "/missing/" in self.path:
                    return refusal(404, "captured", "AUTHORIZATION_NOT_FOUND", "no authorization with this id")
                if "/settled-1/" in self.path:
                    return refusal(409, "captured", "NOT_HELD", "this hold is already settled or released")
                if body.get("amountCharged") == 100:
                    return self._send(200, {"success": True, "message": "Captured", "data": {"captured": True}})
                return refusal(403, "captured", "COUNTERPARTY_MISMATCH", "only the claimer of this hold may settle it below the authorized amount")
            if self.path.endswith("/void"):
                if "claimed-1" in self.path:
                    return refusal(403, "voided", "COUNTERPARTY_MISMATCH", "only the claimer of this hold may release it")
                if "settled-1" in self.path:  # repeating a void that already happened is a 200, not an error
                    return self._send(200, {"success": False, "message": "Not voided (NOT_HELD)", "data": {"voided": False, "authorizationId": "settled-1", "status": "captured", "reasonCode": "NOT_HELD"}})
                return self._send(200, {"success": True, "message": "Hold voided", "data": {"voided": True, "authorizationId": self.path.split("/")[-2], "reasonCode": "HOLD_VOIDED"}})
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
            if self.path.endswith("/effect"):  # an unknown id: 404 AUTHORIZATION_NOT_FOUND in the refusal shape, no outcome
                auth_id = self.path.split("/")[-2]
                return self._send(404, {"success": False, "message": "AUTHORIZATION_NOT_FOUND", "data": {"authorizationId": auth_id, "reasonCode": "AUTHORIZATION_NOT_FOUND", "detail": "AUTHORIZATION_NOT_FOUND: no authorization with this id"}})
            return self._send(404, {"success": False, "message": "no such route", "data": None})

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

        # jurisdiction: normalised, sent top-level, and signed as the v2 message (the stub verifies it that way).
        vj = client.authorize("flight-purchase", 100, merchant="skyward-air", context={"riskLevel": "low"}, jurisdiction=" sg ")
        assert vj.permitted, vj
        sent_j = seen[-1][1]
        assert sent_j["jurisdiction"] == "SG" and "jurisdiction" not in sent_j["itinerary"], sent_j
        assert "jurisdiction" not in sent, "no jurisdiction given, none sent: the v1 message, as before"
        before_bad = len(seen)
        try:
            client.authorize("flight-purchase", 100, jurisdiction="SGP")
            raise AssertionError("a malformed jurisdiction must be refused locally")
        except ValueError:
            pass
        assert len(seen) == before_bad, "a malformed jurisdiction must never reach the gate"

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

        # settlement: full-amount capture ok; a lower one is REFUSED with its code; void of a claimed hold is refused.
        captured = client.capture("auth-100", 100, booking_ref="PNR1")
        assert captured.ok and captured.reason_code == "" and captured.detail == "", captured
        refused = client.capture("auth-100", 0)
        assert not refused.ok and refused.reason_code == "COUNTERPARTY_MISMATCH" and refused.message == "COUNTERPARTY_MISMATCH", refused
        assert refused.detail.startswith("COUNTERPARTY_MISMATCH: "), refused
        again_captured = client.capture("settled-1", 100)
        assert not again_captured.ok and again_captured.reason_code == "NOT_HELD", "a repeat capture is 409 NOT_HELD — read outcome()"
        assert client.capture("missing", 100).reason_code == "AUTHORIZATION_NOT_FOUND"
        voided = client.void("auth-9")
        assert voided.ok and voided.reason_code == "HOLD_VOIDED", "a void says HOLD_VOIDED, as the Node guard does (F-10)"
        claimed = client.void("claimed-1")
        assert not claimed.ok and claimed.reason_code == "COUNTERPARTY_MISMATCH", claimed
        assert seen[-1][1] == {} or "reason" not in seen[-1][1]
        # a void of a hold already settled is a 200 with success false: the code is in data.reasonCode, not the message
        not_held = client.void("settled-1")
        assert not not_held.ok and not_held.reason_code == "NOT_HELD" and not_held.message == "Not voided (NOT_HELD)", not_held

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
