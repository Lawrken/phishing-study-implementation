"""Deployment preparation and stale-evidence gates, without host changes."""
from copy import deepcopy
from contextlib import closing
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import sqlite3
import unittest
from unittest.mock import patch

from study.config import load
from study.deployment import (ROOT, allowed_egress, check_evidence, digest_json,
                              firewall_state_hash, manifest_hash, prepare,
                              public_ipv4, render_firewall, source_hash)

spec = importlib.util.spec_from_file_location('study_prepare_pilot_test', ROOT / 'deployment' / 'linux' / 'prepare-pilot.py')
pilot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pilot)


def controls():
    return {'owned_controls': {'http_url': 'http://controls.owned.example/',
                              'https_url': 'https://controls.owned.example/',
                              'dns_template': '{nonce}.controls.owned.example',
                              'redirect_url': 'https://controls.owned.example/deny'},
            'expected_deny': {'owned_ipv4': '10.20.30.40', 'owned_ipv6': '2001:db8::10',
                              'owned_public_ipv4': '93.184.216.34', 'owned_port': 8443}}


class DeploymentTests(unittest.TestCase):
    def test_missing_inputs_emit_only_inert_template(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'bundle'
            manifest = prepare(output)
            config = load(output / 'pilot.template.toml')
            self.assertEqual(manifest['status'], 'incomplete')
            self.assertIn('region', manifest['required_inputs'])
            self.assertIn('approved_resolver', manifest['required_inputs'])
            self.assertIn('study_uid', manifest['required_inputs'])
            self.assertFalse(config.network_isolation_verified)
            self.assertFalse((output / 'collector.nft').exists())
            self.assertTrue((output / 'collector.nft.incomplete').exists())

    def test_complete_bundle_has_finite_passive_config_and_no_activation(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'bundle'
            manifest = prepare(output, 'operator-supplied-region', '1.1.1.1', 1001, controls(), ['93.184.216.35'], ['93.184.216.36'])
            config = load(output / 'pilot.template.toml')
            self.assertEqual(manifest['status'], 'configured')
            self.assertEqual(manifest['required_inputs'], [])
            self.assertEqual(manifest['configuration_hash'], manifest_hash(manifest))
            self.assertEqual(config.fingerprint, manifest['pilot_config_hash'])
            self.assertEqual((config.workers, config.max_attempts, config.max_hours, config.usable_per_class), (2, 400, 2, 50))
            self.assertEqual((config.route_id, config.interaction), ('direct-ipv4', 'none'))
            self.assertFalse(config.network_isolation_verified)
            self.assertFalse((output / 'pilot.toml').exists())
            self.assertEqual((output / 'resolver' / 'resolv.conf').read_text().splitlines()[0], 'nameserver 1.1.1.1')
            self.assertIn('hosts: files dns', (output / 'resolver' / 'nsswitch.conf').read_text())

    def test_existing_output_and_evidence_are_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'bundle'
            prepare(output)
            original = (output / 'deployment.json').read_bytes()
            with self.assertRaises(ValueError):
                prepare(output)
            self.assertEqual((output / 'deployment.json').read_bytes(), original)

    def test_approved_resolver_rejects_local_private_ipv6_and_mapped(self):
        for address in ('127.0.0.53', '10.0.0.1', '169.254.1.1', '100.64.0.1', '::1', '2606:4700:4700::1111', '::ffff:1.1.1.1'):
            with self.subTest(address=address), tempfile.TemporaryDirectory() as temp, self.assertRaises(ValueError):
                prepare(Path(temp) / 'bundle', resolver=address)
        self.assertFalse(public_ipv4(16843009))

    def test_non_root_uid_and_resolver_cannot_equal_gateway(self):
        for uid in (0, -1, True):
            with self.subTest(uid=uid), tempfile.TemporaryDirectory() as temp, self.assertRaises(ValueError):
                prepare(Path(temp) / 'bundle', uid=uid)
        with self.assertRaises(ValueError):
            render_firewall(1001, '1.1.1.1', gateways_ipv4=['1.1.1.1'])

    def test_control_destinations_and_non_web_receiver_port_are_validated(self):
        for key, value in (('https_url', 'http://owned.example/'), ('http_url', 'http://secret@owned.example/'),
                           ('dns_template', '{nonce}.local'), ('dns_template', '{nonce}.a..example')):
            data = controls()
            data['owned_controls'][key] = value
            with self.subTest(key=key, value=value), tempfile.TemporaryDirectory() as temp, self.assertRaises(ValueError):
                prepare(Path(temp) / 'bundle', controls=data)
        for port in (53, 80, 443, 0, True, '8443'):
            data = controls()
            data['expected_deny']['owned_port'] = port
            with self.subTest(port=port), tempfile.TemporaryDirectory() as temp, self.assertRaises(ValueError):
                prepare(Path(temp) / 'bundle', controls=data)

    def test_firewall_denies_non_public_local_gateway_and_ipv6_before_web_allow(self):
        for address in ('0.0.0.0', '127.0.0.1', '10.0.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254',
                        '100.64.0.1', '198.18.1.1', '224.0.0.1', '255.255.255.255', '::1', '2606:4700::1111',
                        '::ffff:10.0.0.1', '::ffff:1.1.1.1', '93.184.216.35', '93.184.216.36'):
            with self.subTest(address=address):
                self.assertFalse(allowed_egress(address, 'tcp', 443, '1.1.1.1', ['93.184.216.35'], ['93.184.216.36']))
        rules = render_firewall(1001, '1.1.1.1', ['93.184.216.35'], ['93.184.216.36'])
        self.assertNotIn('flush ruleset', rules)
        self.assertLess(rules.index('ip daddr @denied_v4'), rules.index('jump dns_allow'))
        self.assertIn('meta skuid 1001 jump workload', rules)
        self.assertIn('93.184.216.35', rules)
        self.assertIn('93.184.216.36', rules)

    def test_firewall_only_permits_public_web_and_exact_resolver(self):
        self.assertTrue(allowed_egress('93.184.216.34', 'tcp', 80, '1.1.1.1'))
        self.assertTrue(allowed_egress('93.184.216.34', 'tcp', 443, '1.1.1.1'))
        for protocol in ('tcp', 'udp'):
            self.assertTrue(allowed_egress('1.1.1.1', protocol, 53, '1.1.1.1'))
            self.assertFalse(allowed_egress('8.8.8.8', protocol, 53, '1.1.1.1'))
            self.assertFalse(allowed_egress('1.1.1.1', protocol, 53, '1.1.1.1', dns_blocked=True))
        for protocol, port in (('tcp', 22), ('tcp', 8443), ('udp', 443), ('udp', 80), ('icmp', 0)):
            self.assertFalse(allowed_egress('93.184.216.34', protocol, port, '1.1.1.1'))

    def test_state_hash_ignores_handles_and_counters_but_not_policy(self):
        rules = {'nftables': [{'metainfo': {'version': 'x'}}, {'rule': {'handle': 2, 'expr': [{'counter': {'packets': 1, 'bytes': 42}}, {'reject': None}]}}]}
        changed = deepcopy(rules)
        changed['nftables'][1]['rule']['handle'] = 200
        changed['nftables'][1]['rule']['expr'][0]['counter']['packets'] = 999
        self.assertEqual(firewall_state_hash(rules), firewall_state_hash(changed))
        changed['nftables'][1]['rule']['expr'][1] = {'accept': None}
        self.assertNotEqual(firewall_state_hash(rules), firewall_state_hash(changed))

    def test_source_hash_excludes_datasets_and_detects_source_change(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'study').mkdir()
            (root / 'study' / 'example.py').write_text('a = 1\n')
            original = source_hash(root)
            (root / 'data').mkdir()
            (root / 'data' / 'private.txt').write_text('not-source')
            self.assertEqual(source_hash(root), original)
            (root / 'study' / 'example.py').write_text('a = 2\n')
            self.assertNotEqual(source_hash(root), original)

    def test_evidence_must_match_every_current_input(self):
        with tempfile.TemporaryDirectory() as temp:
            manifest = prepare(Path(temp) / 'bundle', 'real-region', '1.1.1.1', 1001, controls())
            config = load(Path(temp) / 'bundle' / 'pilot.template.toml')
        evidence = {'status': 'passed', 'network_isolation_verified': True,
                    'configuration_hash': manifest['configuration_hash'], 'pilot_config_hash': config.fingerprint,
                    'source_hash': manifest['source_hash'], 'firewall_hash': 'rules',
                    'normal_firewall_state_hash': 'live-rules', 'resolver_hash': 'resolver'}
        self.assertTrue(check_evidence(manifest, evidence, manifest['source_hash'], 'rules', 'live-rules', 'resolver', config))
        for key in ('configuration_hash', 'pilot_config_hash', 'source_hash', 'firewall_hash', 'normal_firewall_state_hash', 'resolver_hash'):
            changed = dict(evidence)
            changed[key] = 'stale'
            with self.subTest(key=key), self.assertRaises(ValueError):
                check_evidence(manifest, changed, manifest['source_hash'], 'rules', 'live-rules', 'resolver', config)
        changed = dict(evidence, status='incomplete')
        with self.assertRaises(ValueError):
            check_evidence(manifest, changed, manifest['source_hash'], 'rules', 'live-rules', 'resolver', config)
        manifest['owned_controls']['http_url'] = 'http://changed.owned.example/'
        with self.assertRaises(ValueError):
            check_evidence(manifest, evidence, manifest['source_hash'], 'rules', 'live-rules', 'resolver', config)

    def test_local_feed_receipt_requires_actual_hash_and_fresh_utc_time(self):
        with tempfile.TemporaryDirectory() as temp:
            feed = Path(temp) / 'feed.txt'
            path = Path(temp) / 'receipt.json'
            feed.write_text('https://fixture.example/\n')
            from study.deployment import file_hash
            timestamp = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
            metadata = {'source': 'openphish', 'sha256': file_hash(feed), 'retrieved_at': timestamp}
            path.write_text(json.dumps(metadata))
            with patch.object(pilot, 'secure_root_file', side_effect=lambda value: Path(value)):
                self.assertEqual(pilot.receipt('openphish', feed, path)['retrieved_at'], timestamp)
                for changed in (dict(metadata, sha256='wrong'), dict(metadata, source='phishtank'),
                                dict(metadata, retrieved_at='2026-01-01T00:00:00'),
                                dict(metadata, retrieved_at='2026-01-01T08:00:00+08:00'),
                                dict(metadata, retrieved_at=(datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()),
                                dict(metadata, retrieved_at=(datetime.now(timezone.utc) - timedelta(hours=13)).isoformat())):
                    path.write_text(json.dumps(changed))
                    with self.assertRaises(ValueError):
                        pilot.receipt('openphish', feed, path)

    def test_interrupted_intake_is_archived_intact_before_retry(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data, etc = root / 'dataset', root / 'etc'
            data.mkdir(); etc.mkdir(); (etc / 'intake').mkdir()
            (data / 'retained.txt').write_text('retained')
            (etc / 'intake' / 'review-audit.json').write_text('retained review')
            (etc / 'pilot-intake-state.json').write_text(json.dumps({'status': 'preparing'}))
            with closing(sqlite3.connect(data / 'study.sqlite')) as connection:
                connection.execute('CREATE TABLE runs(id TEXT)')
            with patch.object(pilot, 'secure_root_file', side_effect=lambda value: Path(value)):
                archive = pilot.archive_unstarted_preparation(data, etc)
            self.assertFalse(data.exists())
            self.assertEqual((archive / 'retained.txt').read_text(), 'retained')
            retained = next(etc.glob('intake.preparation-*'))
            self.assertEqual((retained / 'review-audit.json').read_text(), 'retained review')
            self.assertTrue(list(etc.glob('pilot-intake-state.preparation-*.json')))

    def test_intake_retry_never_archives_a_dataset_with_an_existing_run(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            data, etc = root / 'dataset', root / 'etc'
            data.mkdir(); etc.mkdir()
            (etc / 'pilot-intake-state.json').write_text(json.dumps({'status': 'prepared'}))
            with closing(sqlite3.connect(data / 'study.sqlite')) as connection:
                connection.execute('CREATE TABLE runs(id TEXT)')
                connection.execute("INSERT INTO runs VALUES('original-run')")
                connection.commit()
            with patch.object(pilot, 'secure_root_file', side_effect=lambda value: Path(value)), self.assertRaises(ValueError):
                pilot.archive_unstarted_preparation(data, etc)
            self.assertTrue(data.exists())
            self.assertFalse(list(root.glob('dataset.preparation-*')))


if __name__ == '__main__':
    unittest.main()
