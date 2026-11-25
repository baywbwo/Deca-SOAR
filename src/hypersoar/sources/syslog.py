"""Syslog/CEF listener (TCP newline-framed, optionally TLS; UDP only where allowed). Syslog has no sender
authentication, so only the networks in allowed_senders are accepted: a connection or datagram from
anywhere else is refused before any of its data is read or queued, and counted.

Production listens on TCP with TLS only (HYPERSOAR_SYSLOG_TLS_CERT_FILE / _KEY_FILE); UDP cannot be
turned on there. A sandbox may add plain TCP or UDP (HYPERSOAR_SYSLOG_UDP=1) for test senders.

Accepted lines go through one bounded queue to the worker that parses and spools them, so a flood
cannot grow memory or threads; when the queue is full, lines are dropped and counted.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import ssl
from collections.abc import Callable
from dataclasses import dataclass

from hypersoar.common.config import ConfigError
from hypersoar.sources.cef import MAX_LINE

log = logging.getLogger("hypersoar.sources.syslog")
MAX_CONNECTIONS = 32
IDLE_S = 120
QUEUE_MAX = 2000

# on_line(sender_ip, line) -> None; it decides (allowed sender? parse, spool) and never raises.
OnLine = Callable[[str, str], None]
# accept(sender_ip) -> bool; must not block (it runs on the event loop).
Accept = Callable[[str], bool]


def allowed(sender: str, cidrs: tuple[str, ...]) -> bool:
    try:
        ip = ipaddress.ip_address(sender)
    except ValueError:
        return False
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    return any(ip in ipaddress.ip_network(c) for c in cidrs)


@dataclass(frozen=True)
class Listen:
    host: str
    port: int
    tls: ssl.SSLContext | None
    udp: bool


def listen_config(mode: str, env=os.environ) -> Listen | None:
    """The listener this install may open, or None when HYPERSOAR_SYSLOG_PORT is unset."""
    if not env.get("HYPERSOAR_SYSLOG_PORT"):
        return None
    cert, key = env.get("HYPERSOAR_SYSLOG_TLS_CERT_FILE"), env.get("HYPERSOAR_SYSLOG_TLS_KEY_FILE")
    udp = env.get("HYPERSOAR_SYSLOG_UDP") == "1"
    if mode == "production":
        if udp:
            raise ConfigError("syslog over UDP is not allowed in production (TCP with TLS only)")
        if not (cert and key):
            raise ConfigError("production syslog needs TLS: set HYPERSOAR_SYSLOG_TLS_CERT_FILE and _KEY_FILE")
    tls = None
    if cert and key:
        tls = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(cert, key)
    elif cert or key:
        raise ConfigError("set both HYPERSOAR_SYSLOG_TLS_CERT_FILE and HYPERSOAR_SYSLOG_TLS_KEY_FILE")
    return Listen(env.get("HYPERSOAR_SYSLOG_HOST", "0.0.0.0"), int(env["HYPERSOAR_SYSLOG_PORT"]), tls, udp)


class Pipe:
    """The bounded queue between the listeners and the worker that runs on_line in a thread."""

    def __init__(self, on_line: OnLine, counters: dict, maxsize: int | None = None) -> None:
        self.on_line = on_line
        self.counters = counters
        self.queue: asyncio.Queue[tuple[str, str]] = asyncio.Queue(maxsize or QUEUE_MAX)
        for k in ("denied", "queue_full"):
            counters.setdefault(k, 0)

    def offer(self, sender: str, line: str) -> None:
        try:
            self.queue.put_nowait((sender, line))
        except asyncio.QueueFull:
            self.counters["queue_full"] += 1

    async def run(self) -> None:
        while True:
            sender, line = await self.queue.get()
            try:
                await asyncio.to_thread(self.on_line, sender, line)
            except Exception as e:  # on_line should never raise; keep draining if it does
                log.error("syslog handler error: %s", type(e).__name__)


class _Udp(asyncio.DatagramProtocol):
    def __init__(self, pipe: Pipe, accept: Accept) -> None:
        self.pipe, self.accept = pipe, accept

    def datagram_received(self, data: bytes, addr) -> None:
        if not self.accept(addr[0]):
            self.pipe.counters["denied"] += 1
            return
        if len(data) > MAX_LINE:
            return
        for line in data.decode("utf-8", "replace").splitlines():
            if line.strip():
                self.pipe.offer(addr[0], line)


async def serve(cfg: Listen, on_line: OnLine, accept: Accept, counters: dict) -> list:
    """Start the listeners and the queue worker; returns the objects to close on shutdown."""
    loop = asyncio.get_running_loop()
    pipe = Pipe(on_line, counters)
    worker = asyncio.create_task(pipe.run(), name="syslog-pipe")
    active = 0

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal active
        peer = (writer.get_extra_info("peername") or ("",))[0]
        if not accept(peer):
            counters["denied"] += 1
            writer.close()
            return
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
                except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, ssl.SSLError):
                    break
                text = line.decode("utf-8", "replace").strip()
                if text:
                    pipe.offer(peer, text)
        finally:
            active -= 1
            writer.close()

    out: list = [_Task(worker)]
    # The TLS handshake runs before handle(); a refused sender still costs one handshake, bounded by the
    # handshake timeout. Keep the port on a private network as well.
    tcp = await asyncio.start_server(handle, cfg.host, cfg.port, limit=MAX_LINE, ssl=cfg.tls,
                                     ssl_handshake_timeout=10 if cfg.tls else None)
    out.append(tcp)
    if cfg.udp:
        udp, _ = await loop.create_datagram_endpoint(lambda: _Udp(pipe, accept), local_addr=(cfg.host, cfg.port))
        out.append(udp)
    log.info("syslog listening on %s:%d (tcp%s%s)", cfg.host, cfg.port, "+tls" if cfg.tls else "",
             ", udp" if cfg.udp else "")
    return out


class _Task:
    def __init__(self, task: asyncio.Task) -> None:
        self.task = task

    def close(self) -> None:
        self.task.cancel()
