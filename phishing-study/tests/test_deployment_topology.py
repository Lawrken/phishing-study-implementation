"""Current topology must remain inside the verified deployment deny set."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from study.deployment import (ROOT, check_network_snapshot, network_snapshot,
                              parse_network_snapshot)


spec = importlib.util.spec_from_file_location('study_topology_gate_test', ROOT / 'deployment' / 'linux' / 'gate.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def addresses():
    return [{'ifname': 'lo', 'addr_info': [{'family': 'inet', 'local': '127.0.0.1'},
                                        {'family': 'inet6', 'local': '::1'}]},
            {'ifname': 'eth0', 'addr_info': [{'family': 'inet', 'local': '93.184.216.35'}]}]


def routes():
    return [{'dst': 'default', 'gateway': '93.184.216.36', 'dev': 'eth0'},
            {'dst': '93.184.216.0/24', 'dev': 'eth0', 'scope': 'link'}]


def manifest():
    return {'local_ipv4': ['127.0.0.1', '93.184.216.35'],
            'gateways_ipv4': ['93.184.216.36']}


class DeploymentTopologyTests(unittest.TestCase):
    def test_snapshot_deduplicates_interfaces_and_multipath_gateways(self):
        interfaces = addresses()
        interfaces[1]['addr_info'].append({'family': 'inet', 'local': '93.184.216.35'})
        multipath = [{'dst': 'default', 'nexthops': [{'gateway': '93.184.216.36', 'dev': 'eth0'},
                                                  {'gateway': '93.184.216.37', 'dev': 'eth1'}]}]
        self.assertEqual(parse_network_snapshot(interfaces, routes() + multipath),
                         {'local_ipv4': manifest()['local_ipv4'],
                          'gateways_ipv4': ['93.184.216.36', '93.184.216.37']})

    def test_read_only_snapshot_matches_current_interfaces_and_routes(self):
        with patch('study.deployment.subprocess.check_output',
                   side_effect=[json.dumps(addresses()), json.dumps(routes())]) as read:
            self.assertEqual(check_network_snapshot(manifest()), manifest())
        self.assertEqual([call.args[0] for call in read.call_args_list],
                         [['ip', '-j', 'address', 'show'], ['ip', '-j', 'route', 'show']])
        self.assertTrue(all(call.kwargs.get('timeout') == 5 for call in read.call_args_list))

    def test_actual_on_link_route_allows_an_empty_gateway_list(self):
        configured = dict(manifest(), gateways_ipv4=[])
        on_link = [{'dst': 'default', 'dev': 'eth0'}]
        with patch('study.deployment.subprocess.check_output',
                   side_effect=[json.dumps(addresses()), json.dumps(on_link)]):
            self.assertEqual(check_network_snapshot(configured), configured)

    def test_added_removed_or_changed_local_and_gateway_addresses_reject_evidence(self):
        for current in (dict(manifest(), local_ipv4=['127.0.0.1', '93.184.216.35', '93.184.216.37']),
                        dict(manifest(), local_ipv4=['127.0.0.1']),
                        dict(manifest(), gateways_ipv4=['93.184.216.37']),
                        dict(manifest(), gateways_ipv4=[])):
            with self.subTest(current=current), patch('study.deployment.network_snapshot', return_value=current):
                with self.assertRaisesRegex(ValueError, 'interfaces/gateways changed'):
                    check_network_snapshot(manifest())

    def test_missing_expected_topology_rejects_current_snapshot(self):
        for configured in ({}, {'local_ipv4': manifest()['local_ipv4']},
                           dict(manifest(), gateways_ipv4=None), dict(manifest(), local_ipv4=[])):
            with self.subTest(configured=configured), patch('study.deployment.network_snapshot', return_value=manifest()):
                with self.assertRaises(ValueError):
                    check_network_snapshot(configured)

    def test_missing_or_malformed_interface_and_route_snapshots_fail_closed(self):
        invalid = [(None, routes()), ({}, routes()), ([], routes()),
                   ([{'ifname': 'eth0'}], routes()), ([{'addr_info': None}], routes()),
                   ([{'addr_info': [{'family': 'inet', 'local': None}]}], routes()),
                   ([{'addr_info': [{'family': 'inet', 'local': True}]}], routes()),
                   ([{'addr_info': [{'family': 'inet', 'local': '::1'}]}], routes()),
                   ([{'addr_info': [{'family': {}, 'local': '1.1.1.1'}]}], routes()),
                   ([{'addr_info': [{'family': 'inet6', 'local': '::1'}]}], routes()),
                   (addresses() + [{'addr_info': [{'family': 'inet6'}]}], routes()),
                   (addresses() + [{'addr_info': [{'family': 'inet6', 'local': 'invalid'}]}], routes()),
                   (addresses(), None), (addresses(), {}), (addresses(), [None]),
                   (addresses(), [{}]), (addresses(), [{'dst': 'default', 'gateway': None}]),
                   (addresses(), [{'dst': 'invalid'}]),
                   (addresses(), [{'dst': 'default', 'gateway': '::1'}]),
                   (addresses(), [{'dst': 'default', 'nexthops': None}]),
                   (addresses(), [{'dst': 'default', 'nexthops': [None]}]),
                   (addresses(), [{'dst': 'default', 'nexthops': [{}]}]),
                   (addresses(), [{'dst': 'default', 'via': {'family': 'inet6', 'host': '::1'}}]),
                   (addresses(), [{'dst': 'default', 'nhid': 1}])]
        for interfaces, paths in invalid:
            with self.subTest(interfaces=interfaces, routes=paths), self.assertRaises(ValueError):
                parse_network_snapshot(interfaces, paths)

    def test_failed_or_invalid_iproute_output_cannot_pass(self):
        for output in ('', 'not json', 'null', '{}'):
            with self.subTest(output=output), patch('study.deployment.subprocess.check_output', return_value=output):
                with self.assertRaises(ValueError):
                    network_snapshot()
        for error in (OSError('ip not installed'), subprocess.CalledProcessError(1, ['ip']),
                      subprocess.TimeoutExpired(['ip'], 5)):
            with self.subTest(error=type(error).__name__), patch('study.deployment.subprocess.check_output', side_effect=error):
                with self.assertRaisesRegex(ValueError, 'snapshots are unavailable'):
                    network_snapshot()

    def test_root_activation_and_service_prestart_reject_changed_topology_before_writes(self):
        configured = dict(manifest(), nsswitch_hash='same')
        changed = addresses()
        changed[1]['addr_info'].append({'family': 'inet', 'local': '93.184.216.37'})
        for arguments in (['gate.py', '--activate'], ['gate.py', '--service']):
            with self.subTest(arguments=arguments), patch('sys.argv', arguments), \
                 patch.object(gate, 'read', return_value=deepcopy(configured)), \
                 patch.object(gate, 'load'), patch.object(gate, 'secure_root_file'), \
                 patch.object(gate, 'file_hash', return_value='same'), \
                 patch.object(gate, 'fixture_gate'), \
                 patch('study.deployment.subprocess.check_output', side_effect=[json.dumps(changed), json.dumps(routes())]), \
                 patch.object(Path, 'write_text', side_effect=AssertionError('must not activate')):
                with self.assertRaisesRegex(ValueError, 'interfaces/gateways changed'):
                    gate.main()


if __name__ == '__main__':
    unittest.main()
