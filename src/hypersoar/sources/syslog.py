"""Syslog/CEF listener (UDP and TCP, newline-framed). Syslog has no sender authentication, so only
the networks in allowed_senders are accepted; anything else is dropped and counted. Keep the port
on a private network or behind a TLS-terminating forwarder (rsyslog/syslog-ng) in production."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from collections.abc import Callable

from hypersoar.sources.cef import MAX_LINE

log = logging.getLogger("hypersoar.sources.syslog")
MAX_CONNECTIONS = 32
IDLE_S = 120

# on_line(sender_ip, line) -> None; it decides (allowed sender? parse, spool) and never raises.
OnLine = Callable[[str, str], None]


def allowed(sender: str, cidrs: tuple[str, ...]) -> bool:
    try:
        ip = ipaddress.ip_address(sender)
    except ValueError:
        return False
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    return any(ip in ipaddress.ip_network(c) for c in cidrs)


class _Udp(asyncio.DatagramProtocol):
    def __init__(self, on_line: OnLine) -> None:
        self.on_line = on_line

    def datagram_received(self, data: bytes, addr) -> None:
        if len(data) > MAX_LINE:
            return
        for line in data.decode("utf-8", "replace").splitlines():
            if line.strip():
                asyncio.get_running_loop().run_in_executor(None, self.on_line, addr[0], line)


async def serve(host: str, port: int, on_line: OnLine) -> list:
    """Start both listeners; returns the server objects to close on shutdown."""
    loop = asyncio.get_running_loop()
    udp, _ = await loop.create_datagram_endpoint(lambda: _Udp(on_line), local_addr=(host, port))
    active = 0

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal active
        peer = (writer.get_extra_info("peername") or ("",))[0]
        if active >= MAX_CONNECTIONS:
            writer.close()
            return
        active += 1
        try:
            while True:
                try:
                    line = await asyncio.wait_for(reader.readuntil(b"\n"), IDLE_S)
                except asyncio.LimitOverrunError:
                    break  # a line longer than MAX_LINE: drop the connection
                except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
                    break
                text = line.decode("utf-8", "replace").strip()
                if text:
                    await asyncio.to_thread(on_line, peer, text)
        finally:
            active -= 1
            writer.close()

    tcp = await asyncio.start_server(handle, host, port, limit=MAX_LINE)
    log.info("syslog listening on %s:%d (udp, tcp)", host, port)
    return [udp, tcp]
