"""Meaningful local tests; DNS forwarding is mocked and uses no network."""

from __future__ import annotations

import io
from pathlib import Path
import stat
import struct
from types import SimpleNamespace
import unittest
from unittest import mock

import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rrset


from study import logging_resolver as resolver

HOSTS = resolver.normalize_hosts(["d-tx-t.vercel.app"])


def process(*args, **kwargs):
    return resolver.process_query(*args, allowed_hosts=HOSTS, **kwargs)


def query(name="d-tx-t.vercel.app", kind="A"):
    result = dns.message.make_query(name, kind)
    result.id = 12345
    return result


def answer(request, address="64.29.17.67", ttl=47, kind="A"):
    result = dns.message.make_response(request)
    result.answer.append(dns.rrset.from_text(request.question[0].name, ttl, "IN", kind, address))
    return result


class ResolverTests(unittest.TestCase):
    def process(self, request, reply):
        forward = mock.Mock(return_value=reply)
        wire, event = process(request.to_wire(), forwarder=forward)
        return dns.message.from_wire(wire), event, forward

    def test_public_answer_preserves_id_question_ttl_and_flags(self):
        request = query()
        reply = answer(request)
        reply.flags |= dns.flags.RA | dns.flags.AD
        result, event, forward = self.process(request, reply)
        self.assertEqual(result.id, request.id)
        self.assertEqual(result.question, request.question)
        self.assertEqual(result.answer[0].ttl, 47)
        self.assertEqual(result.flags, reply.flags)
        self.assertEqual(event["status"], "forwarded")
        self.assertEqual(event["public_addresses"], ["64.29.17.67"])
        self.assertEqual(forward.call_count, 1)

    def test_hostname_match_is_case_insensitive_but_exact(self):
        request = query("D-TX-T.Vercel.APP.")
        result, event, _ = self.process(request, answer(request))
        self.assertEqual(result.rcode(), dns.rcode.NOERROR)
        self.assertEqual(event["hostname"], "d-tx-t.vercel.app")
        for host in ("other.vercel.app", "d-tx-t.vercel.app.example.com", "credentials.controls.test"):
            forward = mock.Mock()
            wire, event = process(query(host).to_wire(), forwarder=forward)
            self.assertEqual(dns.message.from_wire(wire).rcode(), dns.rcode.REFUSED)
            self.assertEqual(event["hostname"], "<refused>")
            forward.assert_not_called()

    def test_unsupported_query_type_never_forwarded(self):
        forward = mock.Mock()
        wire, event = process(query(kind="TXT").to_wire(), forwarder=forward)
        self.assertEqual(dns.message.from_wire(wire).rcode(), dns.rcode.REFUSED)
        forward.assert_not_called()

    def test_nxdomain_preserved_without_fabricated_addresses(self):
        request = query()
        reply = dns.message.make_response(request)
        reply.set_rcode(dns.rcode.NXDOMAIN)
        result, event, _ = self.process(request, reply)
        self.assertEqual(result.rcode(), dns.rcode.NXDOMAIN)
        self.assertEqual(event["status"], "forwarded")
        self.assertEqual(event["public_address_count"], 0)

    def test_cname_ns_and_https_records_preserved(self):
        for kind, value in (("CNAME", "alias.vercel.app."),
                            ("NS", "ns.vercel.app."),
                            ("HTTPS", '1 . alpn="h2"')):
            with self.subTest(kind=kind):
                request = query(kind=kind)
                reply = answer(request, value, kind=kind)
                result, event, _ = self.process(request, reply)
                self.assertEqual(result.answer, reply.answer)
                self.assertEqual(event["status"], "forwarded")

    def test_public_ipv6_is_accepted(self):
        request = query(kind="AAAA")
        result, event, _ = self.process(request, answer(request, "2606:4700:4700::1111", kind="AAAA"))
        self.assertEqual(result.rcode(), dns.rcode.NOERROR)
        self.assertEqual(event["public_address_count"], 1)

    def test_private_addresses_rejected_in_every_section(self):
        for section in ("answer", "authority", "additional"):
            for address, kind in (("10.0.0.1", "A"), ("127.0.0.1", "A"),
                                  ("169.254.169.254", "A"), ("100.64.0.1", "A"),
                                  ("192.0.2.1", "A"), ("::1", "AAAA"),
                                  ("fc00::1", "AAAA"), ("fe80::1", "AAAA"),
                                  ("::ffff:127.0.0.1", "AAAA")):
                with self.subTest(section=section, address=address):
                    request = query()
                    reply = dns.message.make_response(request)
                    getattr(reply, section).append(dns.rrset.from_text(
                        "alias.vercel.app", 30, "IN", kind, address))
                    result, event, _ = self.process(request, reply)
                    self.assertEqual(result.rcode(), dns.rcode.SERVFAIL)
                    self.assertEqual(event["error"], "nonpublic_address")
                    self.assertEqual(event["public_addresses"], [])

    def test_response_id_question_and_envelope_must_match(self):
        request = query()
        for problem in ("id", "question", "not_answer", "truncated"):
            with self.subTest(problem=problem):
                reply = answer(request)
                if problem == "id":
                    reply.id += 1
                elif problem == "question":
                    reply.question = query("other.vercel.app").question
                elif problem == "not_answer":
                    reply.flags &= ~dns.flags.QR
                else:
                    reply.flags |= dns.flags.TC
                result, event, _ = self.process(request, reply)
                self.assertEqual(result.rcode(), dns.rcode.SERVFAIL)
                self.assertTrue(event["error"].startswith("response_"))

    def test_upstream_failure_becomes_servfail_with_categorical_error(self):
        for error in (dns.exception.Timeout(), OSError("sensitive upstream detail"), ValueError("private data")):
            with self.subTest(error=type(error).__name__):
                forward = mock.Mock(side_effect=error)
                wire, event = process(query().to_wire(), forwarder=forward)
                self.assertEqual(dns.message.from_wire(wire).rcode(), dns.rcode.SERVFAIL)
                self.assertEqual(event["error"], "upstream_failure")
                self.assertNotIn("sensitive", str(event))

    def test_malformed_queries_do_not_reach_upstream(self):
        for raw in (b"", b"x", b"xy", b"not a DNS packet", query().to_wire() + b"trailing",
                    b"x" * (resolver.MAX_QUERY + 1)):
            with self.subTest(size=len(raw)):
                forward = mock.Mock()
                wire, event = process(raw, forwarder=forward)
                self.assertEqual(event["error"], "malformed_query")
                forward.assert_not_called()
                if len(raw) >= 2:
                    self.assertEqual(dns.message.from_wire(wire).rcode(), dns.rcode.FORMERR)

    def test_more_than_one_question_rejected(self):
        request = query()
        request.question += query("other.vercel.app").question
        forward = mock.Mock()
        wire, event = process(request.to_wire(), forwarder=forward)
        self.assertEqual(dns.message.from_wire(wire).rcode(), dns.rcode.FORMERR)
        forward.assert_not_called()

    def test_udp_truncation_uses_one_tcp_fallback(self):
        request = query()
        truncated = dns.message.make_response(request)
        truncated.flags |= dns.flags.TC
        with mock.patch.object(resolver.dns.query, "udp", return_value=truncated) as udp, \
             mock.patch.object(resolver.dns.query, "tcp", return_value=answer(request)) as tcp:
            result = resolver.forward_query(request, "127.0.0.53")
            self.assertEqual(result.answer[0].ttl, 47)
            self.assertEqual(udp.call_count, 1)
            self.assertEqual(tcp.call_count, 1)

    def test_successful_udp_never_uses_tcp(self):
        request = query()
        with mock.patch.object(resolver.dns.query, "udp", return_value=answer(request)), \
             mock.patch.object(resolver.dns.query, "tcp") as tcp:
            resolver.forward_query(request, "127.0.0.53")
            tcp.assert_not_called()

    def test_partial_tcp_frame_is_rejected(self):
        connection = mock.Mock()
        connection.recv.side_effect = [b"a", b""]
        with self.assertRaises(EOFError):
            resolver.recv_exact(connection, 2)

    def test_partial_tcp_frame_can_be_reassembled(self):
        connection = mock.Mock()
        connection.recv.side_effect = [b"a", b"b"]
        self.assertEqual(resolver.recv_exact(connection, 2), b"ab")

    def test_slow_tcp_frame_has_an_absolute_read_deadline(self):
        connection = mock.Mock()
        with mock.patch.object(resolver.time, "monotonic", side_effect=[10.0, 12.1]):
            with self.assertRaises(TimeoutError):
                resolver.recv_exact(connection, 2)
        connection.recv.assert_not_called()

    def test_oversized_udp_reply_respects_client_payload(self):
        for payload in (None, 640):
            with self.subTest(payload=payload):
                request = query()
                if payload:
                    request.use_edns(payload=payload)
                reply = dns.message.make_response(request)
                reply.answer.append(dns.rrset.from_text(
                    "d-tx-t.vercel.app.", 42, "IN", "A",
                    *[f"64.29.17.{index}" for index in range(1, 100)]))
                log = mock.Mock()
                log.phase_file = None
                server = SimpleNamespace(upstream="127.0.0.53", log=log, allowed_hosts=HOSTS)
                with mock.patch.object(resolver, "process_query", return_value=(reply.to_wire(max_size=65535), {})):
                    raw = resolver.handle_wire(server, request.to_wire(), ("127.0.0.1", 12345), "udp")
                result = dns.message.from_wire(raw)
                self.assertLessEqual(len(raw), payload or 512)
                self.assertTrue(result.flags & dns.flags.TC)
                self.assertEqual(result.id, request.id)
                self.assertEqual(result.question, request.question)
                event = log.write.call_args.args[0]
                self.assertEqual(event["phase"], "preparation")
                self.assertGreaterEqual(event["duration_seconds"], 0)

    def test_configured_allowlist_can_change_without_changing_source(self):
        request = query("owned.example.org")
        allowed = resolver.normalize_hosts(["OWNED.example.org."])
        forward = mock.Mock(return_value=answer(request))
        wire, event = resolver.process_query(request.to_wire(), allowed_hosts=allowed, forwarder=forward)
        self.assertEqual(dns.message.from_wire(wire).rcode(), dns.rcode.NOERROR)
        self.assertEqual(event["hostname"], "owned.example.org")
        forward.assert_called_once()

    def test_allowlist_rejects_ip_wildcard_special_use_and_empty_names(self):
        for hosts in ([], ["127.0.0.1"], ["*.example.org"], ["localhost"],
                      ["example.test"], ["user@example.org"], ["-bad.example.org"], ["a..org"]):
            with self.subTest(hosts=hosts), self.assertRaises(ValueError):
                resolver.normalize_hosts(hosts)

    def test_direct_and_system_stub_forwarding_loops_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "forwarding_loop"):
            resolver.validate_endpoints("127.0.0.153", "127.0.0.153")
        for upstream in ("127.0.0.153", "127.0.0.53", "127.0.0.54"):
            with self.subTest(upstream=upstream), self.assertRaisesRegex(ValueError, "forwarding_loop"):
                resolver.validate_upstream_config("nameserver " + upstream + "\n")
        resolver.validate_upstream_config("# actual existing upstream\nnameserver 10.0.2.3\n")
        for text in ("", "nameserver\n", "nameserver not-an-ip\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                resolver.validate_upstream_config(text)

    def test_wrong_endpoints_cannot_create_an_open_resolver(self):
        for listen, upstream in (("0.0.0.0", "127.0.0.53"), ("127.0.0.153", "8.8.8.8")):
            with self.subTest(listen=listen), self.assertRaises(ValueError):
                resolver.validate_endpoints(listen, upstream)

    def test_service_hints_reject_private_addresses_in_all_sections(self):
        for kind in ("HTTPS", "SVCB"):
            for section in ("answer", "authority", "additional"):
                for hint in ('ipv4hint="10.0.0.1"', 'ipv6hint="::ffff:127.0.0.1"'):
                    with self.subTest(kind=kind, section=section, hint=hint):
                        request = query(kind="HTTPS")
                        reply = dns.message.make_response(request)
                        getattr(reply, section).append(dns.rrset.from_text(
                            request.question[0].name, 67, "IN", kind, "1 . " + hint))
                        result, event, _ = self.process(request, reply)
                        self.assertEqual(result.rcode(), dns.rcode.SERVFAIL)
                        self.assertEqual(event["error"], "nonpublic_service_hint")

    def test_public_service_hints_preserve_records_and_ttl(self):
        request = query(kind="HTTPS")
        reply = answer(request, '1 . ipv4hint="64.29.17.67" ipv6hint="2606:4700:4700::1111"', kind="HTTPS")
        result, event, _ = self.process(request, reply)
        self.assertEqual(result.answer, reply.answer)
        self.assertEqual(result.answer[0].ttl, 47)
        self.assertEqual(event["status"], "forwarded")
        self.assertEqual(event["public_address_count"], 2)

    def test_logging_failure_marks_service_failed_and_requests_stop(self):
        handle = mock.Mock()
        handle.write.side_effect = OSError("disk full with private detail")
        log = resolver.EventLog(handle, None)
        with self.assertRaisesRegex(resolver.LoggingFailure, "durable_query_logging_failed"):
            log.write({"event": "query"})
        self.assertTrue(log.failed.is_set())
        self.assertTrue(log.stop.is_set())
        self.assertFalse(handle.flush.called)

    def test_fsync_failure_is_also_fatal(self):
        handle = mock.Mock()
        log = resolver.EventLog(handle, None)
        with mock.patch.object(resolver.os, "fsync", side_effect=OSError("storage error")):
            with self.assertRaises(resolver.LoggingFailure):
                log.write({"event": "query"})
        self.assertTrue(log.failed.is_set())
        self.assertTrue(log.stop.is_set())

    def test_invalid_phase_stops_service_before_successful_reply(self):
        request = query()
        log = resolver.EventLog(mock.Mock(), Path("unavailable-phase-file"))
        server = SimpleNamespace(upstream="127.0.0.53", log=log, allowed_hosts=HOSTS)
        with mock.patch.object(resolver, "phase_label", return_value="invalid_phase_file"), \
             mock.patch.object(resolver, "process_query", return_value=(answer(request).to_wire(), {})) as process_query:
            with self.assertRaises(resolver.LoggingFailure):
                resolver.handle_wire(server, request.to_wire(), ("127.0.0.1", 1234), "udp")
        self.assertTrue(log.failed.is_set())
        self.assertTrue(log.stop.is_set())
        process_query.assert_not_called()

    def test_non_loopback_clients_and_stopping_service_are_refused(self):
        log = resolver.EventLog(mock.Mock(), None)
        server = SimpleNamespace(log=log)
        verify = resolver.LimitedThreadingMixIn.verify_request
        self.assertFalse(verify(server, None, ("10.0.2.15", 123)))
        self.assertTrue(verify(server, None, ("127.0.0.1", 123)))
        log.stop.set()
        self.assertFalse(verify(server, None, ("127.0.0.1", 123)))

    def test_root_cli_is_refused_before_opening_files_or_sockets(self):
        argv = ["--allowed-host", "d-tx-t.vercel.app", "--log", "/owned/log",
                "--ready", "/owned/ready", "--phase-file", "/root/phase"]
        with mock.patch.object(resolver.os, "geteuid", return_value=0, create=True), \
             mock.patch.object(resolver, "fresh_file") as fresh, \
             mock.patch.object(resolver, "UDPServer") as udp, \
             mock.patch("sys.stderr", new=io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                resolver.main(argv)
        self.assertEqual(error.exception.code, 2)
        fresh.assert_not_called()
        udp.assert_not_called()

    def test_output_directory_requires_service_private_leaf_and_root_ancestors(self):
        def info(mode, uid):
            return SimpleNamespace(st_mode=mode, st_uid=uid)
        private = info(stat.S_IFDIR | 0o700, 900)
        root = info(stat.S_IFDIR | 0o755, 0)
        with mock.patch.object(Path, "lstat", side_effect=[private, root, root]):
            resolver.validate_output_parent(Path("/base/service/log"), 900)
        for bad in (info(stat.S_IFDIR | 0o777, 900), info(stat.S_IFDIR | 0o700, 901),
                    info(stat.S_IFLNK | 0o700, 900)):
            with self.subTest(mode=bad.st_mode, uid=bad.st_uid), \
                 mock.patch.object(Path, "lstat", return_value=bad), self.assertRaises(ValueError):
                resolver.validate_output_parent(Path("/base/service/log"), 900)

    def test_occupied_tcp_port_never_publishes_readiness_and_closes_udp(self):
        argv = ["--allowed-host", "d-tx-t.vercel.app", "--log", "/owned/log",
                "--ready", "/owned/ready", "--phase-file", "/root/phase"]
        handle = mock.MagicMock()
        handle.__enter__.return_value = handle
        udp = mock.Mock()
        with mock.patch.object(resolver.os, "name", "posix"), \
             mock.patch.object(resolver.os, "geteuid", return_value=900, create=True), \
             mock.patch.object(resolver, "root_readonly_file", return_value=True), \
             mock.patch.object(resolver, "phase_label", return_value="preparation"), \
             mock.patch.object(resolver, "validate_output_parent"), \
             mock.patch.object(Path, "read_text", return_value="nameserver 10.0.2.3\n"), \
             mock.patch.object(resolver, "fresh_file", return_value=handle) as fresh, \
             mock.patch.object(resolver, "UDPServer", return_value=udp), \
             mock.patch.object(resolver, "TCPServer", side_effect=OSError("address already in use")), \
             mock.patch.object(resolver.threading, "Thread"), \
             mock.patch.object(resolver.os, "fsync"), \
             mock.patch.object(resolver.signal, "signal"):
            with self.assertRaises(OSError):
                resolver.main(argv)
        self.assertEqual(fresh.call_count, 1)
        self.assertEqual(fresh.call_args.args[0], Path("/owned/log"))
        udp.shutdown.assert_called_once()
        udp.server_close.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
