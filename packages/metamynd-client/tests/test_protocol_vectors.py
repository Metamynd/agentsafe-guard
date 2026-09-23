"""The Python client reproduces the shared protocol vectors (docs/protocol/authorize-vectors.json).

This is the half of the fix that would have caught the seven-field bug. The client used to be tested only against
hand-written strings; nothing compared it to the gate's own message builder, so a release that signed SEVEN fields
sailed through every check and every request from the published package was refused. The vectors are generated
from the TypeScript `buildAuthMessage` (the source of truth) and checked by BOTH suites: the backend's
`authorize-vectors.test.ts` and this file. Change the message format and both fail until the vectors are
regenerated, so the two implementations cannot drift apart silently again.

Run:  python -m unittest discover -s integrations/metamynd-client/tests
"""

from __future__ import annotations

import json
import shutil
import subprocess
import unittest

from _support import VECTORS  # noqa: F401  (also puts src/ on sys.path)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from metamynd_client import canonical_message, js_number_to_string, load_key

DOC = json.loads(VECTORS.read_text(encoding="utf-8"))
KEY = load_key(DOC["seed"])
PUBLIC = Ed25519PublicKey.from_public_bytes(bytes.fromhex(DOC["publicKey"]))


class ProtocolVectors(unittest.TestCase):
    def test_the_file_pins_the_eight_field_protocol(self) -> None:
        self.assertEqual(DOC["algorithm"], "Ed25519")
        self.assertEqual(DOC["fieldOrder"], ["agentDid", "action", "amount", "currency", "merchant", "resource", "nonce", "issuedAt"])
        self.assertGreaterEqual(len(DOC["vectors"]), 10)

    def test_the_seed_derives_the_published_public_key(self) -> None:
        derived = KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.assertEqual(derived, DOC["publicKey"])

    def test_every_vector(self) -> None:
        for vector in DOC["vectors"]:
            with self.subTest(vector["name"]):
                f = vector["fields"]
                message = canonical_message(
                    f["agentDid"], f["action"], f["amount"], f["currency"], f["merchant"], f["nonce"], f["issuedAt"], resource=f["resource"]
                )
                self.assertEqual(message, vector["message"], "the client must reproduce the gate's message byte for byte")
                self.assertEqual(len(_split_unescaped(message)), 8, "eight fields, always")
                signature = KEY.sign(message.encode("utf-8")).hex()
                self.assertEqual(signature, vector["signature"], "Ed25519 is deterministic: same bytes, same signature")
                PUBLIC.verify(bytes.fromhex(vector["signature"]), message.encode("utf-8"))  # raises if it does not verify

    def test_an_integral_float_is_signed_as_javascript_writes_it(self) -> None:
        # JSON cannot tell 150.0 from 150, so the vector file holds 150. Python's float is where the trap is.
        vector = next(v for v in DOC["vectors"] if v["name"] == "integral float")
        f = vector["fields"]
        message = canonical_message(f["agentDid"], f["action"], 150.0, f["currency"], None, f["nonce"], f["issuedAt"])
        self.assertEqual(message, vector["message"])
        self.assertNotIn("150.0", message)
        self.assertEqual(js_number_to_string(150.0), "150")

    def test_a_seven_field_message_does_not_verify_against_the_vectors(self) -> None:
        """The exact regression: drop `resource` (the seventh-of-eight field) and the vector signature fails."""
        vector = next(v for v in DOC["vectors"] if v["name"] == "merchant and resource")
        f = vector["fields"]
        legacy = "|".join([f["agentDid"], f["action"], js_number_to_string(f["amount"]), f["currency"], f["merchant"], f["nonce"], f["issuedAt"]])
        self.assertNotEqual(legacy, vector["message"])
        with self.assertRaises(Exception):
            PUBLIC.verify(bytes.fromhex(vector["signature"]), legacy.encode("utf-8"))


@unittest.skipUnless(shutil.which("node"), "node is not installed — the JavaScript parity check needs it (CI installs it)")
class JavaScriptNumberParity(unittest.TestCase):
    """The amount is signed as text, and the gate rebuilds that text with JavaScript's String(). Ask Node itself.

    The first cut of 0.2.0 used Python's repr(), which spells 0.00005 as "5e-05" where JavaScript writes "0.00005":
    every sub-cent amount failed as SIGNATURE_INVALID, and no fixed list of examples caught it. So this compares the
    client against real JavaScript over the exponent boundaries and a few thousand random magnitudes.
    """

    def test_js_number_to_string_equals_node_string_of_the_parsed_number(self) -> None:
        import random

        rng = random.Random(20260921)
        values = [0.5, 1e-4, 9.99e-5, 1e-5, 1.5e-5, 5e-5, 1e-6, 9.99e-7, 1e-7, 1.5e-7, 1.2345e-9, 1e-300, 5e-324, 1e15, 1e16, 123456789012345680.0, 1e20, 1.5e20, 1e21, 1.5e21, 1.7976931348623157e308, 0.1 + 0.2, 142.3, 2**53, 2**53 + 2.0]
        values += [rng.uniform(1, 10) * 10 ** rng.randint(-30, 30) for _ in range(3000)]
        values += [rng.randint(1, 10**6) / 10 ** rng.randint(0, 9) for _ in range(1000)]
        values += [2**60 + 1, 2**64, 10**21, 10**30, 987654321987654321]  # ints beyond 2**53
        script = "const t=require('fs').readFileSync(0,'utf8').split('\\n').filter(Boolean);console.log(JSON.stringify(t.map(s=>String(Number(s)))))"
        # ship the values as JSON number text (what the gate's JSON.parse reads), never as Python's str()
        texts = [json.dumps(v) for v in values]
        done = subprocess.run([shutil.which("node"), "-e", script], input="\n".join(texts), capture_output=True, text=True, timeout=60, encoding="utf-8")
        self.assertEqual(done.returncode, 0, done.stderr[-400:])
        expected = json.loads(done.stdout)
        self.assertEqual(len(expected), len(values))
        wrong = [(t, js_number_to_string(v), e) for t, v, e in zip(texts, values, expected) if js_number_to_string(v) != e]
        self.assertEqual(wrong, [], f"{len(wrong)} amounts signed as different text than JavaScript's String(); first: {wrong[:5]}")


def _split_unescaped(message: str) -> list:
    out, cur, i = [], "", 0
    while i < len(message):
        c = message[i]
        if c == "\\":
            cur += message[i : i + 2]
            i += 2
            continue
        if c == "|":
            out.append(cur)
            cur = ""
        else:
            cur += c
        i += 1
    out.append(cur)
    return out


if __name__ == "__main__":
    unittest.main()
