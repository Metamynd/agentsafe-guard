"""Authorize calls do not stall on a dead address, and a timed-out authorize never runs twice (M1, 2026-10-09 pre-beta).

6 of 29 authorize calls took 15-32 s: whole multiples of the 15 s timeout. Not a retry: the client never retries an
authorize. urllib tried the CDN's two IPv6 addresses before IPv4, one at a time, each with the full timeout, and the
evaluation's network dropped about one IPv6 SYN in three. The client now races addresses (RFC 8305), so a dead address
costs 250 ms. The second half pins the property the stall raised a doubt about: an authorize whose answer never arrives
is not resent, the tool does not run, and the hold the gate made anyway is released.
"""

from __future__ import annotations

import socket
import time
import unittest

from _support import new_agent_key
from fake_gate import FakeGate
from metamynd_client import GovernanceBlocked, MetaMyndClient, _happy_eyeballs_connect, guard_tool

# TEST-NET-1 (RFC 5737): never routed. A connect to it hangs (or fails at once), like the evaluation's dropped IPv6 SYNs.
BLACKHOLE = "192.0.2.1"


class _Listener:
    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]

    def close(self) -> None:
        self.sock.close()


def _addresses(*hosts: str):
    def getaddrinfo(_host, port, *_args):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (h, port)) for h in hosts]

    return getaddrinfo


class RacingConnect(unittest.TestCase):
    def setUp(self) -> None:
        self.listener = _Listener()
        self.addCleanup(self.listener.close)

    def test_a_dead_first_address_costs_a_fraction_of_a_second_not_the_timeout(self) -> None:
        started = time.monotonic()
        sock = _happy_eyeballs_connect(("gate", self.listener.port), 15, _getaddrinfo=_addresses(BLACKHOLE, BLACKHOLE, "127.0.0.1"))
        elapsed = time.monotonic() - started
        sock.close()
        self.assertLess(elapsed, 2.0, f"took {elapsed:.2f}s; the old sequential connect took 30 s here")

    def test_the_connected_socket_carries_the_client_timeout(self) -> None:
        sock = _happy_eyeballs_connect(("gate", self.listener.port), 7, _getaddrinfo=_addresses("127.0.0.1"))
        self.addCleanup(sock.close)
        self.assertEqual(sock.gettimeout(), 7)

    def test_every_address_refusing_raises_promptly(self) -> None:
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()
        started = time.monotonic()
        with self.assertRaises(OSError):
            _happy_eyeballs_connect(("gate", port), 15, _getaddrinfo=_addresses("127.0.0.1", "127.0.0.1"))
        self.assertLess(time.monotonic() - started, 5.0)

    def test_the_whole_connect_stays_inside_the_timeout(self) -> None:
        started = time.monotonic()
        with self.assertRaises(OSError):  # socket.timeout, or an immediate "unreachable" on a host with no route
            _happy_eyeballs_connect(("gate", 443), 0.6, _getaddrinfo=_addresses(BLACKHOLE, BLACKHOLE, BLACKHOLE))
        self.assertLess(time.monotonic() - started, 2.0)


class TimedOutAuthorizeRunsOnce(unittest.TestCase):
    def setUp(self) -> None:
        key, seed = new_agent_key()
        self.gate = FakeGate(key.public_key())
        base = self.gate.start()
        self.addCleanup(self.gate.stop)
        self.client = MetaMyndClient(base, "did:key:z6MkSlowGate", seed, timeout=0.3, orphan_release_delays=(0.6, 0.6, 1.0))

    def _authorize_posts(self) -> int:
        return sum(1 for path in self.gate.paths if path == "/policy/mandate/authorize")

    def test_the_tool_never_runs_the_request_is_sent_once_and_the_hold_is_released(self) -> None:
        client = self.client
        self.gate.delay = 0.5  # the gate commits the hold, then answers after the client has given up
        ran = []
        governed = guard_tool(client, "flight-purchase", lambda amount: ran.append(amount), lambda amount: {"amount": amount, "merchant": "skyward-air", "context": {"riskLevel": "low"}})
        with self.assertRaises(GovernanceBlocked) as ctx:
            governed(amount=10)
        self.assertEqual(ctx.exception.verdict.reason_code, "GATE_UNREACHABLE")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and [h["state"] for h in self.gate.holds.values()] != ["voided"]:
            time.sleep(0.1)
        self.assertEqual(ran, [], "fail closed: the tool did not run")
        self.assertEqual(self._authorize_posts(), 1, "the authorize was not resent")
        self.assertEqual([h["state"] for h in self.gate.holds.values()], ["voided"], "the one hold it made was released")


if __name__ == "__main__":
    unittest.main()
