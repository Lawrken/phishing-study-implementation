"""General DNS forwarding never means an open, unlogged or private resolver."""
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import dns.flags
import dns.message
import dns.rcode
import dns.rrset

from study import logging_resolver as resolver


def query(name='resource.ordinary.org', kind='A'):
    return dns.message.make_query(name, kind)


def reply(request, address='93.184.216.34', kind='A'):
    result = dns.message.make_response(request)
    result.answer.append(dns.rrset.from_text(request.question[0].name, 37, 'IN', kind, address))
    return result


class PublicResolverTests(unittest.TestCase):
    def test_public_mode_accepts_new_resource_domain_without_owned_allowlist(self):
        request = query()
        forward = mock.Mock(return_value=reply(request))
        wire, event = resolver.process_query(request.to_wire(), mode='public-web', forwarder=forward)
        answer = dns.message.from_wire(wire)
        self.assertEqual(answer.rcode(), dns.rcode.NOERROR)
        self.assertEqual(answer.answer[0].ttl, 37)
        self.assertEqual(event['hostname'], 'resource.ordinary.org')
        forward.assert_called_once()

    def test_owned_default_stays_exact_allowlisted_and_does_not_forward_new_domains(self):
        forward = mock.Mock()
        wire, _ = resolver.process_query(query().to_wire(), allowed_hosts=frozenset({'owned.org.'}), forwarder=forward)
        self.assertEqual(dns.message.from_wire(wire).rcode(), dns.rcode.REFUSED)
        forward.assert_not_called()

    def test_general_mode_refuses_special_names_addresses_wildcards_and_malformed_names(self):
        for name in ('localhost', 'abc.local', 'a.internal', 'a.test', 'a.invalid',
                     'a.home.arpa', 'a.onion', 'a.example', '127.0.0.1', '192.0.2.1',
                     '*.ordinary.org', 'a..org', 'x.123', '_service.ordinary.org'):
            with self.subTest(name=name):
                self.assertFalse(resolver.public_dns_name(name))
        for name in ('ordinary.org', 'CDN.ordinary.org.', 'xn--caf-dma.org'):
            self.assertTrue(resolver.public_dns_name(name))
        forward = mock.Mock()
        for name in ('secret.internal', 'metadata.home.arpa', '127.0.0.1', 'a.test'):
            wire, _ = resolver.process_query(query(name).to_wire(), mode='public-web', forwarder=forward)
            self.assertEqual(dns.message.from_wire(wire).rcode(), dns.rcode.REFUSED)
        forward.assert_not_called()

    def test_public_names_do_not_admit_rebinding_to_private_answers_or_hints(self):
        request = query()
        for kind, value in (('A', '10.0.0.2'), ('AAAA', '::ffff:127.0.0.1'),
                            ('HTTPS', '1 . ipv4hint="192.168.1.1"')):
            result = dns.message.make_response(request)
            result.additional.append(dns.rrset.from_text(request.question[0].name, 10, 'IN', kind, value))
            wire, event = resolver.process_query(request.to_wire(), mode='public-web', forwarder=lambda *_: result)
            self.assertEqual(dns.message.from_wire(wire).rcode(), dns.rcode.SERVFAIL)
            self.assertIn(event['error'], {'nonpublic_address', 'nonpublic_service_hint'})

    def test_log_budget_stops_service_before_an_unlogged_success(self):
        handle = io.StringIO()
        log = resolver.EventLog(handle, None, max_bytes=1)
        with self.assertRaises(resolver.LoggingFailure):
            log.write({'event': 'query'})
        self.assertEqual(handle.getvalue(), '')
        self.assertTrue(log.failed.is_set())
        self.assertTrue(log.stop.is_set())

    def test_log_budget_counts_utf8_bytes_and_does_not_allow_bigger_or_boolean_limit(self):
        for value in (0, -1, True, resolver.MAX_LOG_BYTES + 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                resolver.EventLog(io.StringIO(), None, max_bytes=value)
        handle = mock.Mock()
        log = resolver.EventLog(handle, None, max_bytes=4096)
        with mock.patch.object(resolver.os, 'fsync'):
            log.write({'event': 'query', 'name': 'é'})
        self.assertEqual(log.bytes_written, len(handle.write.call_args.args[0].encode('utf-8')))
        log.max_bytes = log.bytes_written
        with self.assertRaises(resolver.LoggingFailure): log.write({'event': 'query'})

    def test_explicit_unknown_mode_cannot_be_inferred_from_empty_allowlist(self):
        with self.assertRaises(ValueError):
            resolver.process_query(query().to_wire(), mode='anything', forwarder=mock.Mock())

    def test_service_cli_refuses_combined_public_and_owned_configuration_before_network(self):
        argv = ['--mode', 'public-web', '--allowed-host', 'owned.org', '--log', '/owned/log',
                '--ready', '/owned/ready', '--phase-file', '/owned/phase']
        with mock.patch.object(resolver, 'UDPServer') as udp, mock.patch('sys.stderr', new=io.StringIO()):
            with self.assertRaises(SystemExit): resolver.main(argv)
        udp.assert_not_called()


if __name__ == '__main__':
    unittest.main()
