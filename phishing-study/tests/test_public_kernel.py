"""Pure policy/controller regressions. These do not claim kernel verification."""
import errno
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from study import public_kernel as kernel
from study import public_kernel_worker as worker
from study.public_web import KERNEL_CASES, KERNEL_CHECKS


NONCE = '1234567890abcdef1234567890abcdef'
SOURCE = 'a' * 64
DNS_AVAILABLE = importlib.util.find_spec('dns') is not None


def temporary():
    return tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)


def snapshot(**values):
    return {'inode': 42, 'interfaces': ['lo'], 'addresses': [],
            'ipv4_routes': [], 'ipv6_routes': [], 'ipv4_defaults': [],
            'ipv6_defaults': [], **values}


def rule(chain, transport, field, packets, reject=False, upstream=None):
    expr = [{'match': {'left': {'payload': {'protocol': transport, 'field': field}}, 'right': 53}}]
    if upstream:
        expr.append({'match': {'right': upstream}})
    if field == 'sport':
        expr.append({'match': {'right': 'established'}})
    expr += [{'counter': {'packets': packets, 'bytes': 90 * packets}}, {'reject': None} if reject else {'accept': None}]
    return {'rule': {'chain': chain, 'expr': expr}}


class KernelPureTests(unittest.TestCase):
    def test_dns_sockets_are_created_after_uid_drop_with_only_temporary_bind_capability(self):
        events = []
        libc = Mock()
        libc.prctl.side_effect = lambda *args: events.append(('prctl', *args)) or 0
        libc.capset.side_effect = lambda header, data: events.append(('caps', data._obj[0].effective)) or 0
        sockets = []
        def create(*args):
            events.append(('socket', *args))
            item = Mock()
            item.bind.side_effect = lambda address: events.append(('bind', address))
            sockets.append(item)
            return item
        with patch('ctypes.CDLL', return_value=libc), \
             patch.object(kernel.os, 'setgroups', side_effect=lambda groups: events.append(('groups', groups))), \
             patch.object(kernel.os, 'setgid', side_effect=lambda gid: events.append(('gid', gid))), \
             patch.object(kernel.os, 'setuid', side_effect=lambda uid: events.append(('uid', uid))), \
             patch.object(kernel.socket, 'socket', side_effect=create):
            result = kernel.bind_dns_as_account(994, 985)
        self.assertEqual(result, sockets)
        uid_index = events.index(('uid', 994))
        self.assertTrue(all(index > uid_index for index, event in enumerate(events) if event[0] == 'socket'))
        self.assertEqual([event for event in events if event[0] == 'caps'], [('caps', 1024), ('caps', 0)])
        self.assertEqual(events[-1], ('prctl', 38, 1, 0, 0, 0))
        sockets[1].listen.assert_called_once_with(16)

    def test_namespace_requires_separate_loopback_without_routes(self):
        self.assertTrue(kernel.disconnected(snapshot(), 99))
        for value in (snapshot(inode=99), snapshot(inode=None), snapshot(interfaces=['eth0', 'lo']),
                      snapshot(ipv4_defaults=[{'dev': 'eth0'}]),
                      snapshot(ipv6_defaults=[{'dev': 'eth0'}]),
                      snapshot(ipv4_routes=[{'dev': 'eth0', 'dst': '192.0.2.0/24'}])):
            self.assertFalse(kernel.disconnected(value, 99))
        value = snapshot()
        del value['ipv4_routes']
        self.assertFalse(kernel.disconnected(value, 99))
        self.assertFalse(kernel.disconnected(snapshot(), True))

    def test_network_normalization_retains_addresses_and_routes(self):
        before = snapshot(addresses=[{'ifname': 'lo', 'addr_info': [
            {'local': '127.0.0.1', 'valid_life_time': 123, 'preferred_life_time': 123}]}])
        after = snapshot(addresses=[{'ifname': 'lo', 'addr_info': [
            {'local': '127.0.0.1', 'valid_life_time': 122, 'preferred_life_time': 122}]}])
        self.assertEqual(kernel.normalized_network(before), kernel.normalized_network(after))
        after['addresses'][0]['addr_info'][0]['local'] = kernel.PUBLIC
        self.assertNotEqual(kernel.normalized_network(before), kernel.normalized_network(after))

    def test_counter_proof_separates_dns_reply_and_stub_rules(self):
        data = {'nftables': [rule('resolver', 'udp', 'sport', 3),
            rule('resolver', 'tcp', 'sport', 4),
            rule('resolver', 'udp', 'dport', 5, upstream=kernel.STUB),
            rule('resolver', 'tcp', 'dport', 6, upstream=kernel.STUB),
            rule('workload', 'udp', 'sport', 17),
            rule('workload', 'tcp', 'dport', 9, reject=True)]}
        self.assertEqual(kernel.counter_receipt(data), {'reject_packets': 9,
            'resolver_reply_udp': 3, 'resolver_reply_tcp': 4,
            'resolver_stub_udp': 5, 'resolver_stub_tcp': 6})

    @unittest.skipUnless(DNS_AVAILABLE, 'pinned dnspython required in the complete Linux suite')
    def test_fixture_dns_never_forwards_or_answers_external_names(self):
        import dns.message
        import dns.rcode
        for hostname, allowed in [('normal' + NONCE + '.controls.test', True),
                ('example.org', False), ('normal' + 'f' * 32 + '.controls.test', False),
                ('sub.normal' + NONCE + '.controls.test', False)]:
            reply, evidence = kernel.fixture_dns(dns.message.make_query(hostname, 'A').to_wire(), NONCE)
            response = dns.message.from_wire(reply)
            self.assertEqual(evidence['fixture_name_allowed'], allowed)
            self.assertEqual(response.rcode(), dns.rcode.NOERROR if allowed else dns.rcode.NXDOMAIN)
            if allowed:
                self.assertEqual([item.address for item in response.answer[0]], [kernel.PUBLIC])
            else:
                self.assertFalse(response.answer)

    @unittest.skipUnless(DNS_AVAILABLE, 'pinned dnspython required in the complete Linux suite')
    def test_fixture_dns_no_ipv6_answers(self):
        import dns.message
        reply, _ = kernel.fixture_dns(dns.message.make_query('normal' + NONCE + '.controls.test', 'AAAA').to_wire(), NONCE)
        self.assertFalse(dns.message.from_wire(reply).answer)

    def test_socket_timeout_is_inconclusive(self):
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=None)
        connection.connect.side_effect = TimeoutError()
        with patch.object(worker.socket, 'socket', return_value=connection):
            result = worker.socket_attempt('negative', kernel.PRIVATE, 8443, 'tcp', b'x')
        self.assertFalse(result['categorical_denial'])
        self.assertEqual(result['reason'], 'timeout_is_inconclusive')

    def test_native_socket_reject_requires_socket_to_exist(self):
        with patch.object(worker.socket, 'socket', side_effect=OSError(errno.EAFNOSUPPORT, 'synthetic')):
            unavailable = worker.socket_attempt('ipv6', kernel.V6, 443, 'tcp', b'x')
        self.assertFalse(unavailable['categorical_denial'])
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=None)
        connection.connect.side_effect = OSError(errno.ECONNREFUSED, 'synthetic')
        with patch.object(worker.socket, 'socket', return_value=connection):
            rejected = worker.socket_attempt('private', kernel.PRIVATE, 8443, 'tcp', b'x')
        self.assertTrue(rejected['categorical_denial'])

    def test_positive_socket_connection_cannot_count_as_denied(self):
        connection = Mock()
        connection.__enter__ = Mock(return_value=connection)
        connection.__exit__ = Mock(return_value=None)
        with patch.object(worker.socket, 'socket', return_value=connection):
            result = worker.socket_attempt('negative', kernel.PRIVATE, 8443, 'tcp', b'x')
        self.assertFalse(result['categorical_denial'])
        self.assertTrue(result['connected'])

    def test_same_pid_different_start_never_authorizes_signal(self):
        identity = {'pid': 77, 'start_time': '100', 'uid': 123, 'netns': 'net:[42]'}
        with patch.object(kernel, 'read_process_identity', return_value={**identity, 'start_time': '101'}):
            self.assertFalse(kernel.same_process(identity))
        with patch.object(kernel, 'same_process', return_value=False), \
                patch.object(kernel, 'process_identity_state', return_value={'gone': False}), \
                patch.object(kernel.signal, 'SIGKILL', kernel.signal.SIGTERM, create=True), \
                patch.object(kernel.os, 'kill') as kill:
            receipt = kernel.bounded_stop(identity)
        kill.assert_not_called()
        self.assertFalse(receipt['gone'])
        self.assertEqual(receipt['reason'], 'identity_changed_signal_refused')

    def test_existing_output_is_preserved(self):
        with temporary() as temp:
            output = Path(temp) / 'existing'
            output.mkdir()
            marker = output / 'evidence.txt'
            marker.write_text('original evidence')
            with self.assertRaises(SystemExit):
                kernel.main(['--bundle', temp, '--output', str(output), '--private', temp,
                             '--outer-inode', '99', '--nonce', NONCE])
            self.assertEqual(marker.read_text(), 'original evidence')


class FakeLog:
    def __init__(self, *_):
        self.rows, self.phase = [], 'preparation'
        FakeLog.current = self

    def set_phase(self, value):
        self.phase = value

    def add(self, endpoint, **values):
        self.rows.append({'phase': self.phase, 'endpoint': endpoint, **values})

    def snapshot(self):
        return self.rows[:]


class ControllerUnitTests(unittest.TestCase):
    def simulate(self, root, fail_key=None, inconclusive=False, unproved_worker=False):
        """No sockets, interfaces, subprocesses or firewall are touched."""
        output = root / 'output'
        output.mkdir()
        args = SimpleNamespace(output=output, private=root / 'private', bundle=root / 'bundle',
                               outer_inode=99, nonce=NONCE)
        manifest = {'study_uid': 998, 'resolver': {'uid': 997}, 'source_hash': SOURCE,
                    'firewall_hash': 'b' * 64, 'service_hash': 'c' * 64}
        report = {'checks': {key: False for key in KERNEL_CHECKS}}
        counters = {'reject_packets': 0, 'resolver_reply_udp': 0, 'resolver_reply_tcp': 0,
                    'resolver_stub_udp': 0, 'resolver_stub_tcp': 0, 'rules': {'nftables': []}}
        calls, workers = [], []

        def preflight(a, result):
            result.update(network_before=snapshot(), source_hash=SOURCE)
            result['checks']['namespace_disconnected'] = True
            return manifest

        def command(*values):
            calls.append(values)
            return json.dumps({'nftables': []})

        def positives(_):
            for endpoint, *_ in kernel.FIXTURES:
                FakeLog.current.add(endpoint)
            return [{'endpoint': f[0], 'ok': True} for f in kernel.FIXTURES]

        def worker(a, _manifest, key, phase, case, role):
            workers.append((key, phase, role))
            if key == fail_key:
                if unproved_worker:
                    a.process_receipts.append({'all_owned_processes_gone': False})
                raise RuntimeError('retained_synthetic_failure')
            result = {'status': 'passed', 'worker_exit': 0, 'report_sha256': 'd' * 64,
                'source_hash': SOURCE, 'phase': phase, 'lifecycle': {},
                'dns_hostname': key + NONCE + '.controls.test', 'navigation': {'status': 200},
                'checks': {'native_dns_failure': {'ok': True}}}
            if phase in {'normal', 'restored', 'redirect'}:
                FakeLog.current.add('http')
            if phase in {'normal', 'restored'}:
                for transport in ('udp', 'tcp'):
                    FakeLog.current.add('approved_dns_' + transport, server_uid=997,
                        socket_uid=997, query_name=result['dns_hostname'] + '.')
                    counters['resolver_reply_' + transport] += 1
            elif phase == 'resolver':
                for transport in ('udp', 'tcp'):
                    FakeLog.current.add('stub_dns_' + transport)
                    counters['resolver_stub_' + transport] += 1
            elif phase == 'blocked' or case:
                counters['reject_packets'] += 0 if inconclusive else 1
            return result

        fake_server, fake_thread = Mock(), Mock()
        fake_thread.is_alive.return_value = False
        with patch.object(kernel, 'preflight', side_effect=preflight), \
                patch.object(kernel, 'network', return_value=snapshot()), \
                patch.object(kernel, 'command', side_effect=command), \
                patch.object(kernel, 'file_hash', return_value='e' * 64), \
                patch.object(kernel, 'source_hash', return_value=SOURCE), \
                patch.object(kernel, 'ReceiverLog', FakeLog), \
                patch.object(kernel, 'start_dns', return_value={'identity': {'pid': 123}}), \
                patch.object(kernel, 'bounded_stop', return_value={'gone': True, 'wait_status': 0, 'signals': ['SIGTERM']}), \
                patch.object(kernel, 'positive_controls', side_effect=positives), \
                patch.object(kernel, 'run_worker', side_effect=worker), \
                patch.object(kernel, 'nft_snapshot', side_effect=lambda: json.loads(json.dumps(counters))), \
                patch.object(kernel, 'TCP', return_value=fake_server), \
                patch.object(kernel, 'TCP6', return_value=fake_server), \
                patch.object(kernel, 'UDP', return_value=fake_server), \
                patch.object(kernel.threading, 'Thread', return_value=fake_thread), \
                patch.object(kernel.time, 'sleep'), \
                patch.dict(sys.modules, {'pwd': SimpleNamespace(getpwuid=lambda uid: SimpleNamespace(pw_gid=uid))}):
            error = None
            try:
                kernel.run(args, report)
            except Exception as exc:
                error = exc
        return output, report, calls, workers, error

    def test_exact_artifact_complete_case_matrix_and_ten_fresh_trials(self):
        with temporary() as temp:
            output, report, calls, workers, error = self.simulate(Path(temp))
            self.assertIsNone(error)
            self.assertEqual(set(report['checks']), KERNEL_CHECKS)
            self.assertTrue(all(report['checks'].values()))
            self.assertEqual(set(report['cases']), KERNEL_CASES)
            self.assertTrue(all(report['cleanup'].values()))
            trials = json.loads((output / 'lifecycle-trials.json').read_text())['trials']
            self.assertEqual(len(trials), 10)
            self.assertEqual([t['phase'] for t in trials], ['normal'] * 6 + ['redirect'] * 4)
            self.assertEqual(len({key for key, *_ in workers}), len(workers))
            bundle_file = str(Path(temp) / 'bundle' / 'collector.nft')
            self.assertIn(('nft', '-c', '-f', bundle_file), calls)
            self.assertIn(('nft', '-f', bundle_file), calls)
            self.assertFalse(any('ruleset' in c and 'flush' in c for c in calls))
            for case, receipt in report['cases'].items():
                self.assertGreater(receipt['positive_control_hits'], 0)
                self.assertEqual(receipt['workload_hits'], 0)
                if case != 'redirect':
                    self.assertGreater(receipt['reject_counter_delta'], 0)

    def test_failure_stops_sequence_and_preserves_receipts_and_cleanup(self):
        with temporary() as temp:
            output, report, calls, workers, error = self.simulate(Path(temp), fail_key='alternate_dns_tcp')
            self.assertIsInstance(error, RuntimeError)
            self.assertEqual([key for key, *_ in workers], ['normal', 'alternate_dns_tcp'])
            self.assertTrue((output / 'alternate_dns_tcp-before-counters.json').is_file())
            self.assertTrue((output / 'alternate_dns_tcp-after-counters.json').is_file())
            self.assertTrue((output / 'alternate_dns_tcp-receipt.json').is_file())
            self.assertTrue((output / 'fixture-receiver-logs.json').is_file())
            self.assertEqual(json.loads((output / 'lifecycle-trials.json').read_text()), {'trials': []})
            self.assertTrue(all(report['cleanup'].values()))

    def test_receiver_zero_hits_without_measured_rejection_fails(self):
        with temporary() as temp:
            output, report, _, workers, error = self.simulate(Path(temp), inconclusive=True)
            self.assertIsInstance(error, RuntimeError)
            self.assertIn('inconclusive', str(error))
            self.assertLess(len(workers), 10)
            self.assertEqual(report['cases']['alternate_dns_tcp']['reject_counter_delta'], 0)

    def test_containment_is_retained_when_worker_exit_is_not_proved(self):
        with temporary() as temp:
            output, report, calls, _, error = self.simulate(Path(temp),
                fail_key='alternate_dns_tcp', unproved_worker=True)
            self.assertIsInstance(error, RuntimeError)
            self.assertFalse(report['cleanup']['accounts_idle'])
            self.assertFalse(report['cleanup']['own_firewall_removed'])
            self.assertTrue(report['cleanup']['listeners_stopped'])
            self.assertNotIn(('nft', 'delete', 'table', 'inet', kernel.NFT_TABLE), calls)
            self.assertTrue((output / 'lifecycle-trials.json').is_file())

    def test_worker_uses_manifest_uid_and_actual_primary_group(self):
        with temporary() as temp:
            root = Path(temp)
            private, output = root / 'private', root / 'output'
            output.mkdir()
            (private / 'normal').mkdir(parents=True)
            report = {'status': 'passed', 'source_hash': SOURCE, 'checks': {'native': {'ok': True}}}
            (private / 'normal' / 'report.json').write_text(json.dumps(report))
            args = SimpleNamespace(private=private, resolver_private=root / 'dns', output=output,
                nonce=NONCE, bundle=root / 'bundle', process_receipts=[])
            manifest = {'study_uid': 998, 'resolver': {'uid': 997}, 'source_hash': SOURCE}
            process = Mock(pid=777)
            process.poll.return_value = 0
            identity = {'pid': 777, 'start_time': '100', 'uid': 998}
            with patch.dict(sys.modules, {'pwd': SimpleNamespace(getpwuid=lambda uid: SimpleNamespace(pw_gid=1234))}), \
                    patch.object(kernel.subprocess, 'Popen', return_value=process) as popen, \
                    patch.object(kernel, 'read_process_identity', return_value=identity), \
                    patch.object(kernel, 'process_identity_state', return_value={'gone': True}), \
                    patch.object(kernel, '_lifecycle') as lifecycle:
                result = kernel.run_worker(args, manifest, 'normal', 'normal')
            self.assertEqual(result['status'], 'passed')
            self.assertEqual(popen.call_args.kwargs['user'], 998)
            self.assertEqual(popen.call_args.kwargs['group'], 1234)
            self.assertEqual(popen.call_args.kwargs['extra_groups'], [])
            self.assertIn('study.public_kernel_worker', popen.call_args.args[0])
            lifecycle.assert_called_once_with(result, 998)


if __name__ == '__main__':
    unittest.main()
