"""Fresh root health and bounded stopping are prerequisites to capture."""
import asyncio
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from study.deployment import file_hash
from study.public_pilot import (atomic_root_json, frozen_service_references,
                                measured_storage, summarize_dataset)
from study.runtime_lifecycle import observe_until_stop, ObservationStopped


class HealthReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / 'root-health.json'
        self.identity = {'schema_version': 3, 'verification_profile': 'local-public-web-v1',
                         'source_hash': '1' * 64}
        self.value = {'identity': self.identity, 'healthy': True, 'timestamp': 100.0,
                      'checks': {'durable_dns_logging': True, 'collector_service': True}}

    def receipt(self, value=None, now=103):
        # Windows has no pwd; this pure receipt helper does not use account APIs.
        if os.name == 'nt':
            import sys
            from types import ModuleType
            with patch.dict(sys.modules, {'pwd': ModuleType('pwd')}):
                from study.public_collect import health_receipt
        else:
            from study.public_collect import health_receipt
        self.path.write_text(json.dumps(self.value if value is None else value))
        with patch('study.public_collect.secure_root_file', side_effect=lambda path: Path(path)):
            return health_receipt(self.path, self.identity, now=now)

    def test_current_matching_root_receipt_accepts_only_complete_boolean_success(self):
        self.assertTrue(self.receipt())
        self.assertTrue(self.receipt(now=105))
        for changes in ({'healthy': 1}, {'checks': {}}, {'checks': {'logging': 1}},
                        {'checks': {'logging': False}}, {'timestamp': True}):
            value = {**self.value, **changes}
            with self.subTest(changes=changes):
                self.assertFalse(self.receipt(value))

    def test_stale_future_and_wrong_source_identity_cannot_authorize_visits(self):
        self.assertFalse(self.receipt(now=105.001))
        self.assertFalse(self.receipt(now=99.999))
        value = deepcopy(self.value)
        value['identity']['source_hash'] = '2' * 64
        self.assertFalse(self.receipt(value))

    def test_altered_receipt_revokes_health_and_protected_path_failure_propagates(self):
        self.assertTrue(self.receipt())
        self.assertFalse(self.receipt({**self.value, 'healthy': False}))
        from study.public_collect import health_receipt
        with patch('study.public_collect.secure_root_file', side_effect=ValueError('not_root_owned')):
            with self.assertRaisesRegex(ValueError, 'not_root_owned'):
                health_receipt(self.path, self.identity, now=103)


class PublicControllerFilesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1])
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_atomic_receipt_replaces_complete_json_and_preserves_nonfinite_failure(self):
        path = self.root / 'health.json'
        atomic_root_json(path, {'healthy': False})
        atomic_root_json(path, {'healthy': True, 'checks': {'logging': True}})
        self.assertTrue(json.loads(path.read_text())['healthy'])
        previous = path.read_bytes()
        with self.assertRaises(ValueError): atomic_root_json(path, {'timestamp': float('nan')})
        self.assertEqual(path.read_bytes(), previous)
        self.assertFalse(path.with_name(path.name + '.tmp').exists())

    def test_storage_includes_dns_and_dataset_regular_files(self):
        private, dns = self.root / 'private', self.root / 'dns'
        private.mkdir()
        dns.mkdir()
        (private / 'capture').write_bytes(b'x' * 11)
        (dns / 'queries.jsonl').write_bytes(b'y' * 17)
        self.assertEqual(measured_storage(private, dns), 28)

    def test_atomic_observation_rename_is_remeasured_with_final_bytes(self):
        observations=self.root/'observations';observations.mkdir()
        temporary=observations/('a'*32+'.tmp');temporary.write_bytes(b'x'*17)
        final=temporary.with_suffix('.json')
        original=Path.lstat
        renamed=False
        def stat_with_rename(path,*args,**kwargs):
            nonlocal renamed
            if path==temporary and not renamed:
                renamed=True
                temporary.replace(final)
            return original(path,*args,**kwargs)
        with patch.object(Path,'lstat',stat_with_rename):
            self.assertEqual(measured_storage(self.root),17)
        self.assertTrue(renamed)

    def test_missing_dns_log_is_not_hidden_as_an_atomic_rename(self):
        log=self.root/'queries.jsonl';log.write_bytes(b'x')
        original=Path.lstat
        def disappear(path,*args,**kwargs):
            if path==log:raise FileNotFoundError('logging lost')
            return original(path,*args,**kwargs)
        with patch.object(Path,'lstat',disappear),self.assertRaises(FileNotFoundError):
            measured_storage(self.root)

    def test_storage_race_retry_is_finite_and_fails_closed(self):
        path=self.root/'status.tmp'
        with patch.object(Path,'rglob',side_effect=lambda *_:iter([path])):
            with self.assertRaisesRegex(ValueError,'snapshot_unstable'):
                measured_storage(self.root)

    def test_attempts_distinct_urls_and_usable_rows_are_separate(self):
        from study.queue import Queue
        from study.config import Config
        queue = Queue(self.root / 'dataset')
        queue.ingest([{'url': 'https://example.com/a', 'label': 'legitimate', 'confidence': 'dataset',
            'source': 'phiusiil-dataset', 'source_id': 'a' * 64, 'observed_at': 'unknown'}])
        config = Config(retry_base_seconds=0, domain_cooldown_seconds=0)
        rid = queue.start_run(config)
        item = queue.claim(rid, config)
        queue.finish(item, 'dns_error', False, None, config, transient=True)
        item = queue.claim(rid, config)
        queue.finish(item, 'captured', True, 'synthetic-record.json', config)
        queue.finish_run(rid, 'queue_exhausted')
        summary = summarize_dataset(queue.root)
        self.assertEqual((summary['attempts'], summary['distinct_urls_attempted'], summary['failed_attempts']), (2, 1, 1))
        self.assertEqual(summary['usable_per_class'], {'legitimate': 1, 'phishing': 0})
        self.assertEqual(summary['collector_stop_reason'], 'queue_exhausted')

    def service_evidence(self):
        result = {'evidence_files': {}}
        for role, filename, hash_key, key in (
            ('collector', 'collector.service', 'runtime_service_hash', 'connected_collector_service'),
            ('resolver', 'resolver.service', 'runtime_resolver_service_hash', 'connected_resolver_service')):
            template = '[Service]\nUser=997\nMemoryMax=2G\nNoNewPrivileges=yes\nExecStart=@@PYTHON@@ @@RUNNER@@\n'
            (self.root / filename).write_text(template)
            path = self.root / (role + '-runtime.service')
            path.write_text(template.replace('@@PYTHON@@ @@RUNNER@@', '/bin/python /owned/control.py')
                            + 'ReadWritePaths=/var/lib/new-run\n')
            result[hash_key] = file_hash(path)
            result['evidence_files'][key] = {'path': str(path), 'sha256': file_hash(path)}
        return result

    def test_frozen_service_hashes_and_immutable_properties_must_match_template(self):
        evidence = self.service_evidence()
        with patch('study.public_pilot.secure_root_file', side_effect=lambda path: Path(path)):
            self.assertEqual(set(frozen_service_references(self.root, evidence)), {'collector', 'resolver'})
            entry = evidence['evidence_files']['connected_collector_service']
            path = Path(entry['path'])
            path.write_text(path.read_text().replace('MemoryMax=2G', 'MemoryMax=4G'))
            with self.assertRaises(ValueError): frozen_service_references(self.root, evidence)
            entry['sha256'] = evidence['runtime_service_hash'] = file_hash(path)
            with self.assertRaises(ValueError): frozen_service_references(self.root, evidence)


class StopWinsRaceTests(unittest.IsolatedAsyncioTestCase):
    async def test_preexisting_stop_cannot_commit_already_completed_capture(self):
        stop = asyncio.Event()
        stop.set()
        async def completed():
            return {'capture_eligible': True}
        with self.assertRaises(ObservationStopped):
            await observe_until_stop(completed(), stop, timeout=1)

    async def test_same_tick_health_failure_and_completed_capture_is_interrupted(self):
        stop = asyncio.Event()
        async def completed():
            stop.set()
            return {'capture_eligible': True}
        with self.assertRaises(ObservationStopped):
            await observe_until_stop(completed(), stop, timeout=1)


if __name__ == '__main__':
    unittest.main()
