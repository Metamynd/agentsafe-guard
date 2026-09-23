"""Shared paths and fixtures for the client's tests. Standard library + `cryptography` only (no pytest)."""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Every test talks to a gate on loopback. urllib routes even 127.0.0.1 through HTTP(S)_PROXY unless NO_PROXY says
# otherwise, so on a machine behind a proxy the whole suite failed with "gate unreachable".
os.environ["NO_PROXY"] = os.environ["no_proxy"] = ",".join(filter(None, [os.environ.get("NO_PROXY") or os.environ.get("no_proxy"), "127.0.0.1,localhost"]))

TESTS = Path(__file__).resolve().parent
PACKAGE = TESTS.parent
REPO = PACKAGE.parent.parent
SRC = PACKAGE / "src"
EXAMPLES = REPO / "docs" / "integration" / "examples"
VECTORS = REPO / "docs" / "protocol" / "authorize-vectors.json"

for path in (str(SRC), str(TESTS)):
    if path not in sys.path:
        sys.path.insert(0, path)

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402


def new_agent_key() -> "tuple[Ed25519PrivateKey, str]":
    """A fresh Ed25519 key and its raw-seed hex — the BYOK shape `load_key` accepts."""
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()).hex()
    return key, seed


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
