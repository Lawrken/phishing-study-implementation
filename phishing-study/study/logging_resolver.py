#!/usr/bin/env python3
"""Unprivileged logged DNS service with explicit owned-only/public-web modes.

The root controller supplies the mode and phase file, grants only bind-service
capability, and freezes service-owned logs after shutdown. Public-web mode is a
public-answer forwarder, not independent authoritative-DNS or label verification.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import socketserver
import stat
import struct
import threading
import time
from typing import Callable

import dns.exception
import dns.flags
import dns.message
import dns.opcode
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.svcbbase


LISTEN = "127.0.0.153"
UPSTREAM = "127.0.0.53"
MAX_QUERY = 4096
IO_TIMEOUT = 2.0
MAX_HANDLERS = 16
MAX_HEALTH_HANDLERS = 1
HEALTH_NAME = 'health.controls.test.'
MAX_LOG_BYTES = 64 * 1024 * 1024
MODES = ('owned-only', 'public-web')
SPECIAL_SUFFIXES = ('.test', '.invalid', '.localhost', '.local', '.internal',
                    '.example', '.home.arpa', '.onion', '.lan', '.corp')
QUERY_TYPES = frozenset(
    (dns.rdatatype.A, dns.rdatatype.AAAA, dns.rdatatype.CNAME,
     dns.rdatatype.NS, dns.rdatatype.HTTPS)
)


class InvalidResponse(ValueError):
    """An upstream response must not be delivered to the browser."""


class LoggingFailure(RuntimeError):
    """Evidence is unavailable: never return a successful workload reply."""


def normalize_hosts(values) -> frozenset[str]:
    """Only explicit DNS names: no IPs, wildcards, search or special-use names."""
    if not values:
        raise ValueError("owned_host_allowlist_required")
    result = set()
    for value in values:
        if not isinstance(value, str):
            raise ValueError("invalid_owned_hostname")
        host = value.lower().rstrip(".")
        if not public_dns_name(host):
            raise ValueError("invalid_owned_hostname")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError("owned_hostname_must_not_be_ip")
        result.add(host + ".")
    return frozenset(result)


def public_dns_name(value: str) -> bool:
    """Public syntactic DNS names only; address reachability is checked separately."""
    if not isinstance(value, str) or value != value.strip():
        return False
    host = value.lower().rstrip('.')
    if (not host or len(host) > 253 or '.' not in host or host.endswith(SPECIAL_SUFFIXES)
            or host in {'localhost', 'home.arpa', 'invalid', 'test', 'example', 'local', 'internal'}
            or host.split('.')[-1].isdigit()
            or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.'))):
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return True
    return False


def validate_endpoints(listen: str, upstream: str) -> None:
    # The upstream is an explicit IP, never resolved through this listener.
    if listen == upstream:
        raise ValueError("resolver_forwarding_loop")
    if listen != LISTEN or upstream != UPSTREAM:
        raise ValueError("preview_requires_fixed_local_dns_route")


def validate_upstream_config(text: str) -> None:
    """Inspect systemd-resolved's upstream snapshot without issuing any query."""
    nameservers = []
    for raw in text.splitlines():
        pieces = raw.split("#", 1)[0].split()
        if pieces and pieces[0] == "nameserver":
            if len(pieces) != 2:
                raise ValueError("invalid_system_stub_upstream_snapshot")
            nameservers.append(ipaddress.ip_address(pieces[1]))
    if not nameservers:
        raise ValueError("system_stub_upstream_snapshot_required")
    if any(str(address) in {LISTEN, UPSTREAM, "127.0.0.54"} for address in nameservers):
        raise ValueError("system_stub_forwarding_loop")


def root_readonly_file(path: Path) -> bool:
    try:
        path = path.absolute()
        for item in (path, *path.parents):
            info = item.lstat()
            if (stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022):
                return False
        return path.is_file()
    except OSError:
        return False


def validate_output_parent(path: Path, uid: int) -> None:
    """A service-owned private leaf beneath protected root-owned ancestors."""
    parent = path.absolute().parent
    info = parent.lstat()
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != uid or info.st_mode & 0o077):
        raise ValueError("private_service_output_directory_required")
    for item in parent.parents:
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("protected_root_output_ancestors_required")


def public_address(value: str) -> bool:
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped.is_global
    return address.is_global


def validate_response(
    query: dns.message.Message, response: dns.message.Message
) -> list[str]:
    """Validate the envelope and every address, without modifying DNS data."""
    if response.id != query.id:
        raise InvalidResponse("response_id_mismatch")
    if not response.flags & dns.flags.QR:
        raise InvalidResponse("response_not_answer")
    if response.opcode() != query.opcode():
        raise InvalidResponse("response_opcode_mismatch")
    if len(response.question) != 1 or response.question != query.question:
        raise InvalidResponse("response_question_mismatch")
    if response.flags & dns.flags.TC:
        raise InvalidResponse("response_still_truncated")
    addresses = []
    for section in (response.answer, response.authority, response.additional):
        for rrset in section:
            if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                for item in rrset:
                    if not public_address(item.address):
                        raise InvalidResponse("nonpublic_address")
                    addresses.append(item.address)
            elif rrset.rdtype in (dns.rdatatype.HTTPS, dns.rdatatype.SVCB):
                for item in rrset:
                    for key in (dns.rdtypes.svcbbase.ParamKey.IPV4HINT,
                                dns.rdtypes.svcbbase.ParamKey.IPV6HINT):
                        parameter = item.params.get(key)
                        if parameter is not None:
                            for address in parameter.addresses:
                                if not public_address(address):
                                    raise InvalidResponse("nonpublic_service_hint")
                                addresses.append(address)
    return addresses


def forward_query(query: dns.message.Message, upstream: str) -> dns.message.Message:
    """One UDP attempt, with the standard TCP retry only for truncation."""
    result = dns.query.udp(query, upstream, port=53, timeout=IO_TIMEOUT)
    if result.flags & dns.flags.TC:
        result = dns.query.tcp(query, upstream, port=53, timeout=IO_TIMEOUT)
    return result


def error_response(raw: bytes, code: int) -> bytes:
    # A malformed packet still receives a small, categorical DNS error when its
    # two-byte transaction ID exists; packets without an ID are discarded.
    if len(raw) < 2:
        return b""
    response = dns.message.Message(id=struct.unpack("!H", raw[:2])[0])
    response.flags = dns.flags.QR
    response.set_rcode(code)
    return response.to_wire()


def process_query(
    raw: bytes,
    *,
    upstream: str = "127.0.0.53",
    allowed_hosts: frozenset[str] = frozenset(),
    mode: str = 'owned-only',
    forwarder: Callable[[dns.message.Message, str], dns.message.Message] = forward_query,
) -> tuple[bytes, dict]:
    """Return reply bytes and a bounded event; no logging or network side effects
    occur when a test supplies a forwarder.
    """
    event = {
        "hostname": None, "question_type": None, "status": "malformed",
        "query_id": None,
        "error": None, "rcode": "FORMERR", "public_address_count": 0,
        "public_addresses": [], "upstream": upstream,
    }
    try:
        if not 12 <= len(raw) <= MAX_QUERY:
            raise ValueError("query_size")
        query = dns.message.from_wire(raw, ignore_trailing=False)
        if query.flags & dns.flags.QR or query.opcode() != dns.opcode.QUERY:
            raise ValueError("query_envelope")
        if len(query.question) != 1 or query.answer or query.authority or query.additional:
            raise ValueError("query_sections")
        question = query.question[0]
        event['query_id'] = query.id
        event["question_type"] = dns.rdatatype.to_text(question.rdtype)
        if question.rdclass != dns.rdataclass.IN:
            raise ValueError("question_class")
    except (dns.exception.DNSException, ValueError, IndexError, struct.error):
        event["error"] = "malformed_query"
        return error_response(raw, dns.rcode.FORMERR), event

    if mode not in MODES:
        raise ValueError('explicit_resolver_mode_required')
    name = question.name.to_text().lower()
    owned = name in allowed_hosts if mode == 'owned-only' else public_dns_name(name)
    event["hostname"] = name.rstrip(".") if owned else "<refused>"
    if not owned or question.rdtype not in QUERY_TYPES:
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.REFUSED)
        event.update(status="refused", error="hostname_or_type_not_allowed", rcode="REFUSED")
        return response.to_wire(), event

    try:
        response = forwarder(query, upstream)
        addresses = validate_response(query, response)
        wire = response.to_wire(max_size=65535)
        event.update(
            status="forwarded", rcode=dns.rcode.to_text(response.rcode()),
            public_address_count=len(addresses), public_addresses=sorted(set(addresses)),
        )
        return wire, event
    except InvalidResponse as exc:
        reason = str(exc)
    except (dns.exception.DNSException, OSError, ValueError, TypeError, AttributeError):
        reason = "upstream_failure"
    response = dns.message.make_response(query)
    response.set_rcode(dns.rcode.SERVFAIL)
    event.update(status="failed", error=reason, rcode="SERVFAIL")
    return response.to_wire(), event


def fresh_file(path: Path):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    return os.fdopen(fd, "w", encoding="utf-8", buffering=1)


def phase_label(path: Path | None) -> str:
    if path is None:
        return "preparation"
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "r", encoding="ascii") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                return "invalid_phase_file"
            result = handle.read(129).strip()
        return result if re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", result) else "invalid_phase_file"
    except (OSError, UnicodeError):
        return "unavailable_phase_file"


class EventLog:
    def __init__(self, handle, phase_file: Path | None, stop: threading.Event | None = None,
                 max_bytes: int = MAX_LOG_BYTES):
        self.handle = handle
        self.phase_file = phase_file
        self.lock = threading.Lock()
        self.stop = stop if stop is not None else threading.Event()
        self.failed = threading.Event()
        if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_LOG_BYTES:
            raise ValueError('bounded_log_budget_required')
        self.max_bytes = max_bytes
        self.bytes_written = 0

    def write(self, event: dict) -> None:
        payload = dict(event)
        payload.setdefault("timestamp_utc", dt.datetime.now(dt.timezone.utc).isoformat())
        payload.setdefault("monotonic_ns", time.monotonic_ns())
        payload.setdefault("phase", phase_label(self.phase_file))
        try:
            if payload["phase"] in {"invalid_phase_file", "unavailable_phase_file"}:
                raise ValueError("phase_evidence_unavailable")
            if self.failed.is_set():
                raise ValueError("logging_already_failed")
            with self.lock:
                try:
                    if self.failed.is_set():
                        raise ValueError('logging_already_failed')
                    line = json.dumps(payload, sort_keys=True) + "\n"
                    byte_count = len(line.encode('utf-8'))
                    if self.bytes_written + byte_count > self.max_bytes:
                        raise ValueError('query_log_budget_exhausted')
                    self.handle.write(line)
                    self.handle.flush()
                    os.fsync(self.handle.fileno())
                    self.bytes_written += byte_count
                except (OSError, ValueError, TypeError):
                    # Keep the failed marker under the same lock as writes so
                    # a queued request cannot race a failed durable write.
                    self.failed.set()
                    self.stop.set()
                    raise
        except (OSError, ValueError, TypeError):
            self.failed.set()
            self.stop.set()
            raise LoggingFailure("durable_query_logging_failed") from None


def health_request(raw: bytes) -> bool:
    """Recognize only the local refused health probe; never forward this name."""
    if not isinstance(raw, bytes) or not 12 <= len(raw) <= MAX_QUERY:
        return False
    try:
        query = dns.message.from_wire(raw, ignore_trailing=False)
        return (not query.flags & dns.flags.QR and query.opcode() == dns.opcode.QUERY
                and len(query.question) == 1 and not (query.answer or query.authority or query.additional)
                and query.question[0].name.to_text().lower() == HEALTH_NAME
                and query.question[0].rdtype == dns.rdatatype.A
                and query.question[0].rdclass == dns.rdataclass.IN)
    except (dns.exception.DNSException, ValueError, IndexError, struct.error):
        return False


class LimitedThreadingMixIn(socketserver.ThreadingMixIn):
    daemon_threads = True
    block_on_close = False

    def verify_request(self, request, client_address):
        return ipaddress.ip_address(client_address[0]).is_loopback and not self.log.stop.is_set()

    def process_request(self, request, client_address):
        # A page's parallel DNS burst must not consume the health probe's slot.
        # The extra pool is one bounded thread and still uses durable logging.
        health = (self.transport == 'udp' and getattr(self, 'health_semaphore', None) is not None
                  and health_request(request[0]))
        slots = self.health_semaphore if health else self.semaphore
        if not slots.acquire(blocking=False):
            self.log.write({"event": "capacity_rejected", "transport": self.transport,
                            'pool': 'health' if health else 'workload'})
            self.shutdown_request(request)
            return
        try:
            thread = threading.Thread(target=self.process_request_thread,
                args=(request, client_address, slots), daemon=self.daemon_threads)
            thread.start()
        except BaseException:
            slots.release()
            raise

    def process_request_thread(self, request, client_address, slots=None):
        try:
            super().process_request_thread(request, client_address)
        finally:
            (self.semaphore if slots is None else slots).release()


class UDPServer(LimitedThreadingMixIn, socketserver.UDPServer):
    max_packet_size = MAX_QUERY + 1
    allow_reuse_address = False
    transport = "udp"


class TCPServer(LimitedThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = False
    request_queue_size = MAX_HANDLERS
    transport = "tcp"


def recv_exact(connection: socket.socket, count: int) -> bytes:
    result = bytearray()
    deadline = time.monotonic() + IO_TIMEOUT
    while len(result) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("frame_read_timeout")
        connection.settimeout(remaining)
        chunk = connection.recv(count - len(result))
        if not chunk:
            raise EOFError("frame_incomplete")
        result.extend(chunk)
    return bytes(result)


def handle_wire(server, raw: bytes, peer: tuple, transport: str) -> bytes:
    started_ns = time.monotonic_ns()
    received_at = dt.datetime.now(dt.timezone.utc).isoformat()
    received_phase = phase_label(server.log.phase_file)
    if received_phase in {"invalid_phase_file", "unavailable_phase_file"}:
        server.log.failed.set()
        server.log.stop.set()
        raise LoggingFailure("phase_evidence_unavailable")
    reply, event = process_query(raw, upstream=server.upstream, allowed_hosts=server.allowed_hosts,
                                mode=getattr(server, 'mode', 'owned-only'))
    event.update(event="query", transport=transport, peer_ip=peer[0], peer_port=peer[1],
                 timestamp_utc=received_at, monotonic_ns=started_ns, phase=received_phase,
                 duration_seconds=(time.monotonic_ns() - started_ns) / 1_000_000_000)
    server.log.write(event)
    # A large DNS reply uses normal truncation on UDP; TCP preserves the full
    # response. dnspython includes the question and the original transaction ID.
    if transport == "udp" and len(reply) > 512:
        request = dns.message.from_wire(raw)
        permitted_size = max(512, min(MAX_QUERY, request.payload if request.edns >= 0 else 512))
        if len(reply) > permitted_size:
            parsed = dns.message.from_wire(reply)
            reply = parsed.to_wire(max_size=permitted_size, prefer_truncation=True)
    return reply


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        raw, connection = self.request
        try:
            reply = handle_wire(self.server, raw, self.client_address, "udp")
            if reply:
                connection.sendto(reply, self.client_address)
        except (OSError, dns.exception.DNSException):
            self.server.log.write({"event": "transport_error", "transport": "udp"})


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            length = struct.unpack("!H", recv_exact(self.request, 2))[0]
            if not 12 <= length <= MAX_QUERY:
                self.server.log.write({"event": "malformed_frame", "transport": "tcp"})
                return
            raw = recv_exact(self.request, length)
            reply = handle_wire(self.server, raw, self.client_address, "tcp")
            if reply:
                self.request.settimeout(IO_TIMEOUT)
                self.request.sendall(struct.pack("!H", len(reply)) + reply)
        except (OSError, EOFError, struct.error, dns.exception.DNSException):
            self.server.log.write({"event": "transport_error", "transport": "tcp"})


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="127.0.0.153")
    parser.add_argument("--upstream", default="127.0.0.53")
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--ready", type=Path, required=True)
    parser.add_argument("--phase-file", type=Path, required=True)
    parser.add_argument('--mode', choices=MODES, default='owned-only')
    parser.add_argument("--allowed-host", action="append")
    parser.add_argument('--max-log-bytes', type=int, default=MAX_LOG_BYTES)
    args = parser.parse_args(argv)
    try:
        validate_endpoints(args.listen, args.upstream)
        if args.mode == 'owned-only':
            allowed_hosts = normalize_hosts(args.allowed_host)
        else:
            if args.allowed_host:
                raise ValueError('public_web_mode_forbids_ambiguous_owned_allowlist')
            allowed_hosts = frozenset()
        if type(args.max_log_bytes) is not int or not 1 <= args.max_log_bytes <= MAX_LOG_BYTES:
            raise ValueError('bounded_log_budget_required')
        uid = os.geteuid() if hasattr(os, "geteuid") else 0
        if uid <= 0 or os.name != "posix":
            raise ValueError("dedicated_nonroot_linux_service_required")
        if not root_readonly_file(args.phase_file):
            raise ValueError("protected_root_phase_file_required")
        validate_upstream_config(Path("/run/systemd/resolve/resolv.conf").read_text())
        validate_output_parent(args.log, uid)
        validate_output_parent(args.ready, uid)
        if args.log.absolute() == args.ready.absolute():
            raise ValueError("log_and_ready_paths_must_differ")
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stop.set())
    servers = []
    threads = []
    with fresh_file(args.log) as handle:
        event_log = EventLog(handle, args.phase_file, stop, max_bytes=args.max_log_bytes)
        semaphore = threading.BoundedSemaphore(MAX_HANDLERS)
        health_semaphore = threading.BoundedSemaphore(MAX_HEALTH_HANDLERS)
        try:
            for cls, handler in ((UDPServer, UDPHandler), (TCPServer, TCPHandler)):
                server = cls((args.listen, 53), handler)
                servers.append(server)
                server.upstream = args.upstream
                server.allowed_hosts = allowed_hosts
                server.mode = args.mode
                server.log = event_log
                server.semaphore = semaphore
                server.health_semaphore = health_semaphore
                thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
                thread.start()
                threads.append(thread)
            event_log.write({"event": "ready", "listen": args.listen, "port": 53,
                             "upstream": args.upstream, "allowed_hostnames": sorted(allowed_hosts),
                             "mode": args.mode, "max_log_bytes": args.max_log_bytes,
                             'workload_handler_limit': MAX_HANDLERS,
                             'health_handler_limit': MAX_HEALTH_HANDLERS,
                             "dnssec_verified": False, "research_eligible": False})
            with fresh_file(args.ready) as ready:
                json.dump({"pid": os.getpid(), "listen": args.listen, "upstream": args.upstream,
                           "port": 53, "transports": ["udp", "tcp"], "uid": uid,
                           "mode": args.mode, "max_log_bytes": args.max_log_bytes,
                           "allowed_hostnames": sorted(allowed_hosts)}, ready)
                ready.write("\n")
                ready.flush()
                os.fsync(ready.fileno())
            while not stop.wait(0.2):
                pass
        finally:
            started = time.monotonic()
            for server in servers:
                server.shutdown()
                server.server_close()
            # Active handlers have bounded reads/forwards and are daemon threads.
            # The entire process exits after both listener loops have stopped.
            for thread in threads:
                thread.join(timeout=0.5)
            # Do not describe shutdown as graceful while request workers remain.
            # A single shared semaphore bounds both transport pools together.
            drain_deadline = time.monotonic() + 6.0
            for slots, count in ((semaphore, MAX_HANDLERS), (health_semaphore, MAX_HEALTH_HANDLERS)):
                for _ in range(count):
                    if not slots.acquire(timeout=max(0.0, drain_deadline - time.monotonic())):
                        event_log.failed.set()
                        break
            if not event_log.failed.is_set():
                event_log.write({"event": "stopped", "duration_seconds": time.monotonic() - started})
    return 1 if event_log.failed.is_set() else 0


if __name__ == "__main__":
    raise SystemExit(main())
