"""The egress allowlist proxy — the only route off the sandbox network.

`pyhunt-internal` is created with ``internal: true``, so nothing attached to it
has a route off the box. That is the right default and it is also too strong:
there is normally exactly one host anything in the sandbox legitimately needs to
reach (``api.anthropic.com:443``). Punching a hole by attaching the sandbox to a
routed network would give target-controlled code the whole internet.

So the hole is a *process*, not a route. This proxy container is the single
thing attached to BOTH `pyhunt-internal` and a routed network; everything else
stays on the internal side and can only get out by asking this program, which
answers for allowlisted `host:port` pairs and refuses everything else with 403.

Deliberate limits, each of which is a security property rather than an omission:

* **CONNECT only.** A plain-HTTP absolute-URI proxy would have to parse and
  forward request bodies, which turns this into a protocol-aware intermediary
  with a much larger bug surface. CONNECT is an opaque byte pump: it decides
  once, at connect time, then copies. Anything else gets 501.
* **The allowlist is matched before the upstream socket is created**, so a
  denied host is never even resolved from inside the proxy.
* **No logging of tunnelled bytes.** The proxy sees TLS ciphertext and must
  keep it that way; it logs only the decision and the target.
* **Stdlib only, no writes to disk.** It runs on a `--read-only` rootfs with
  `--cap-drop ALL`, like everything else PyHunt starts.

Run it with ``python3 egress_proxy.py``; configuration is environment-only
(``PYHUNT_EGRESS_ALLOW``, ``PYHUNT_EGRESS_PORT``, ``PYHUNT_EGRESS_BIND``) so the
container needs no mounted config file.

The matching helpers are pure functions with no I/O precisely so the allowlist
can be tested without ever starting a listener — see
`tests/test_sandbox_tiers.py`.
"""

from __future__ import annotations

import logging
import os
import select
import socket
import socketserver
import sys
from dataclasses import dataclass

log = logging.getLogger("pyhunt.egress")

# The one host the harness legitimately needs. Kept as a tuple (not a mutable
# module global) so nothing can widen it at runtime by accident.
DEFAULT_ALLOWLIST: tuple[str, ...] = ("api.anthropic.com:443",)

DEFAULT_PORT = 3128
DEFAULT_BIND = "0.0.0.0"

# Upstream connect timeout. Short: the allowlisted host is either reachable in
# a couple of seconds or the sandbox has no egress at all, and a long hang here
# looks to the caller exactly like a silent failure.
CONNECT_TIMEOUT = 10.0

# Idle timeout on an established tunnel. A tunnel that has said nothing for this
# long is finished; without it a wedged PoC could pin a thread indefinitely.
IDLE_TIMEOUT = 300.0

PUMP_CHUNK = 65536

# Longest request line we will read before giving up. A CONNECT line is tiny;
# anything larger is either not HTTP or is trying to make us buffer.
MAX_REQUEST_BYTES = 8192


@dataclass(frozen=True)
class Rule:
    """One allowlist entry.

    `wildcard` is the ``*.example.com`` form, which matches any strict subdomain
    but NOT the bare parent — `*.example.com` does not admit `example.com`. That
    asymmetry is intentional: an allowlist that silently widens by one label is
    how these things leak.
    """

    host: str
    port: int
    wildcard: bool = False

    def matches(self, host: str, port: int) -> bool:
        if port != self.port:
            return False
        host = host.lower().rstrip(".")
        if self.wildcard:
            return host.endswith("." + self.host) and len(host) > len(self.host) + 1
        return host == self.host


def parse_allowlist(spec: str | None) -> tuple[Rule, ...]:
    """Parse ``host:port[,host:port...]`` into rules, dropping malformed entries.

    A malformed entry is dropped rather than widened into "allow anything" — the
    failure mode of a security list must always be *more* restrictive.
    """
    rules: list[Rule] = []
    for raw in (spec or "").split(","):
        entry = raw.strip()
        if not entry:
            continue
        host, sep, port_s = entry.rpartition(":")
        if not sep or not host:
            log.warning("[egress] ignoring allowlist entry without a port: %r", entry)
            continue
        try:
            port = int(port_s)
        except ValueError:
            log.warning("[egress] ignoring allowlist entry with a bad port: %r", entry)
            continue
        if not (0 < port < 65536):
            log.warning("[egress] ignoring allowlist entry with a bad port: %r", entry)
            continue
        host = host.strip().lower().rstrip(".")
        wildcard = host.startswith("*.")
        if wildcard:
            host = host[2:]
        if not host or host == "*":
            log.warning("[egress] ignoring allowlist entry that matches everything: %r", entry)
            continue
        rules.append(Rule(host=host, port=port, wildcard=wildcard))
    return tuple(rules)


def is_allowed(host: str, port: int, rules: tuple[Rule, ...]) -> bool:
    """True only if some rule admits this exact host/port. Empty list denies."""
    return any(r.matches(host, port) for r in rules)


def parse_connect_target(request_line: str) -> tuple[str, int] | None:
    """``CONNECT host:port HTTP/1.1`` -> (host, port); None for anything else.

    Handles the bracketed IPv6 literal form. Returns None (rather than raising)
    for every malformed input, so the caller has exactly one rejection path.
    """
    parts = request_line.split()
    if len(parts) < 2 or parts[0].upper() != "CONNECT":
        return None
    target = parts[1]
    if target.startswith("["):                       # [2606:4700::1111]:443
        close = target.find("]")
        if close < 0 or not target[close + 1:].startswith(":"):
            return None
        host, port_s = target[1:close], target[close + 2:]
    else:
        host, sep, port_s = target.rpartition(":")
        if not sep or not host:
            return None
    try:
        port = int(port_s)
    except ValueError:
        return None
    if not (0 < port < 65536):
        return None
    return host.lower().rstrip("."), port


def _pump(a: socket.socket, b: socket.socket) -> None:
    """Copy bytes both ways until either side closes or the tunnel goes idle."""
    socks = [a, b]
    try:
        while True:
            readable, _, errored = select.select(socks, [], socks, IDLE_TIMEOUT)
            if errored or not readable:
                return
            for src in readable:
                dst = b if src is a else a
                try:
                    chunk = src.recv(PUMP_CHUNK)
                except OSError:
                    return
                if not chunk:
                    return
                try:
                    dst.sendall(chunk)
                except OSError:
                    return
    finally:
        for s in socks:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


class _Handler(socketserver.StreamRequestHandler):
    """One client connection. `server.rules` is the allowlist."""

    timeout = CONNECT_TIMEOUT

    def _refuse(self, status: str, reason: str) -> None:
        try:
            self.wfile.write(
                f"HTTP/1.1 {status}\r\nContent-Length: 0\r\n"
                f"X-PyHunt-Egress: {reason}\r\nConnection: close\r\n\r\n".encode()
            )
            self.wfile.flush()
        except OSError:
            pass

    def handle(self) -> None:  # noqa: D102 - socketserver contract
        try:
            line = self.rfile.readline(MAX_REQUEST_BYTES)
        except OSError:
            return
        request_line = line.decode("latin-1", "replace").strip()
        if not request_line:
            return

        target = parse_connect_target(request_line)
        if target is None:
            log.warning("[egress] REFUSED non-CONNECT request: %.80r", request_line)
            self._refuse("501 Not Implemented", "connect-only")
            return
        host, port = target

        # Drain the (empty-bodied) CONNECT headers so the client's writes do not
        # sit in our buffer and get replayed into the tunnel.
        while True:
            try:
                header = self.rfile.readline(MAX_REQUEST_BYTES)
            except OSError:
                return
            if not header or header in (b"\r\n", b"\n"):
                break

        rules: tuple[Rule, ...] = self.server.rules  # type: ignore[attr-defined]
        if not is_allowed(host, port, rules):
            log.warning("[egress] DENIED %s:%d (not on the allowlist)", host, port)
            self._refuse("403 Forbidden", "not-allowlisted")
            return

        try:
            upstream = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        except OSError as e:
            log.warning("[egress] upstream %s:%d unreachable: %s", host, port, e)
            self._refuse("502 Bad Gateway", "upstream-unreachable")
            return

        log.info("[egress] ALLOWED %s:%d", host, port)
        try:
            self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.wfile.flush()
        except OSError:
            upstream.close()
            return

        upstream.settimeout(None)
        self.connection.settimeout(None)
        try:
            _pump(self.connection, upstream)
        finally:
            upstream.close()


class EgressProxy(socketserver.ThreadingTCPServer):
    """Threaded CONNECT proxy bound to `rules`."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], rules: tuple[Rule, ...]) -> None:
        self.rules = rules
        super().__init__(address, _Handler)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO, stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    spec = os.environ.get("PYHUNT_EGRESS_ALLOW")
    rules = parse_allowlist(spec) if spec else parse_allowlist(",".join(DEFAULT_ALLOWLIST))
    if not rules:
        # No usable rule means no egress at all. Say so and keep running: a proxy
        # that denies everything is a correct, safe proxy, and exiting would look
        # to Docker like a crash loop.
        log.warning("[egress] allowlist is EMPTY — every CONNECT will be refused")

    try:
        port = int(os.environ.get("PYHUNT_EGRESS_PORT", DEFAULT_PORT))
    except ValueError:
        port = DEFAULT_PORT
    bind = os.environ.get("PYHUNT_EGRESS_BIND", DEFAULT_BIND)

    log.info("[egress] listening on %s:%d, allowlist=%s", bind, port,
             ", ".join(f"{'*.' if r.wildcard else ''}{r.host}:{r.port}" for r in rules) or "(empty)")
    with EgressProxy((bind, port), rules) as server:
        try:
            server.serve_forever(poll_interval=0.5)
        except KeyboardInterrupt:
            log.info("[egress] shutting down")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
