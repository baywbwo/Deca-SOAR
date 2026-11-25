"""Outbound HTTPS guard for integrations: which hosts each integration may call, and a transport that
only connects to public addresses.

A host must match its integration's allowlist (an IP literal never does). At connect time the name is
resolved once, every address must be public (no private, loopback, link-local, CGNAT or cloud metadata
address), and the socket goes to that checked address while TLS still verifies the hostname, so a DNS
answer that changes between the check and the connect cannot point the call inward.

  HYPERSOAR_AI_HOSTS   comma-separated exact hostnames of the designated 9router; empty = live AI refused
"""

from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlsplit

import httpcore
import httpx

# Exact hosts, or ".suffix" for any subdomain of it.
ALLOW = {
    "lark": ("open.larksuite.com",),
    "jira": (".atlassian.net",),
    "sls": (".log.aliyuncs.com",),
}
METADATA = frozenset(ipaddress.ip_address(a) for a in ("169.254.169.254", "100.100.100.200", "fd00:ec2::254"))
_getaddrinfo = socket.getaddrinfo  # patched in tests


class EgressDenied(ValueError):
    pass


def allowed(integration: str) -> tuple[str, ...]:
    if integration == "ai":
        return tuple(h.strip().lower() for h in os.environ.get("HYPERSOAR_AI_HOSTS", "").split(",") if h.strip())
    return ALLOW.get(integration, ())


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        # "1.2.3.4." / "0x7f.1" style names: a numeric last label is never a real public hostname.
        last = host.rstrip(".").rsplit(".", 1)[-1]
        return not last or not last[0].isalpha()


def check_host(integration: str, host: str) -> str:
    host = (host or "").lower()
    if not host or _is_ip(host):
        raise EgressDenied(f"{integration}: an IP address is not allowed as the host, use the service hostname")
    rules = allowed(integration)
    if not rules:
        raise EgressDenied(f"{integration}: no host is allowed (set the designated host first)")
    if not any(host == r or (r.startswith(".") and host.endswith(r) and len(host) > len(r)) for r in rules):
        raise EgressDenied(f"{integration}: host {host[:80]!r} is not on the allowlist {list(rules)}")
    return host


def host_of(integration: str, url: str) -> str:
    """The checked hostname of an https URL with no user info and the default port."""
    try:
        u = urlsplit(url)
        port = u.port
    except ValueError:
        raise EgressDenied(f"{integration}: not a valid URL") from None
    if u.scheme != "https" or u.username or u.password or port not in (None, 443):
        raise EgressDenied(f"{integration}: only https on port 443 without user info is allowed")
    return check_host(integration, u.hostname or "")


def public(ip: str) -> bool:
    a = ipaddress.ip_address(ip.split("%", 1)[0])
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a.is_global and a not in METADATA


def resolve(host: str, port: int = 443) -> list[str]:
    """Every address the name resolves to; all of them must be public."""
    try:
        infos = _getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        raise EgressDenied(f"{host[:80]!r} does not resolve") from None
    ips = list(dict.fromkeys(i[4][0] for i in infos))
    if not ips:
        raise EgressDenied(f"{host[:80]!r} does not resolve")
    bad = [ip for ip in ips if not public(ip)]
    if bad:
        raise EgressDenied(f"{host[:80]!r} resolves to a non-public address")
    return ips


class _PinnedBackend(httpcore.NetworkBackend):
    def __init__(self, integration: str):
        self.integration = integration
        self._sync = httpcore.SyncBackend()

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        try:
            check_host(self.integration, host)
            ips = resolve(host, port)
        except EgressDenied as e:
            raise httpcore.ConnectError(f"egress denied: {e}") from None
        last: Exception | None = None
        for ip in ips:
            try:
                return self._sync.connect_tcp(ip, port, timeout, local_address, socket_options)
            except httpcore.ConnectError as e:
                last = e
        raise last or httpcore.ConnectError("no address")

    def connect_unix_socket(self, *a, **kw):
        raise httpcore.ConnectError("egress denied: unix sockets are not allowed")

    def sleep(self, seconds: float) -> None:
        self._sync.sleep(seconds)


class GuardedTransport(httpx.HTTPTransport):
    def __init__(self, integration: str):
        super().__init__(trust_env=False)
        self.integration = integration
        self._pool._network_backend = _PinnedBackend(integration)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        try:
            host_of(self.integration, str(request.url))
        except EgressDenied as e:
            raise httpx.ConnectError(f"egress denied: {e}", request=request) from None
        return super().handle_request(request)


def transport(integration: str) -> httpx.BaseTransport:
    return GuardedTransport(integration)
