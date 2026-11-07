"""Capture success never turns a historical dataset label into current verification."""
import csv
import json
from pathlib import Path
import tempfile
from types import ModuleType
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlsplit

from study.config import Config
from study.queue import Queue
from study.export import export
from study.analysis import analyze, dataset_label_report
from study.urls import digest


class DatasetLabelTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.root = Path(self.temp.name)
        self.groups = patch('study.queue.domain_group', side_effect=lambda url: urlsplit(url).hostname)
        self.groups.start()
        self.queue = Queue(self.root / 'dataset')
        self.config = Config(workers=1, network_isolation_verified=True)

    def tearDown(self):
        self.groups.stop()
        self.temp.cleanup()

    def row(self, name, label='legitimate'):
        return {'url': 'https://' + name + '.example/login?secret=PRIVATE', 'label': label,
                'confidence': 'dataset', 'source': 'phiusiil-dataset', 'source_id': digest('row:' + name),
                'observed_at': 'unknown'}

    def capture(self, profile='live', eligible=True, outcome='captured', artifact=True, config_hash=None):
        rid = self.queue.start_run(self.config)
        item = self.queue.claim(rid, self.config)
        filename = None
        if artifact:
            filename = item['attempt_id'] + '.json'
            record = {'captured_at': '2026-10-20T00:00:00Z', 'config_hash': config_hash or self.config.fingerprint,
                      'profile': profile, 'route_id': 'direct-ipv4', 'region': 'Laoag City, Philippines',
                      'groups': {'dom': {'measured': True, 'form_count': 0}}}
            (self.queue.root / filename).write_text(json.dumps(record))
        self.queue.finish(item, outcome, eligible, filename, self.config)
        self.queue.finish_run(rid, 'test')
        return item

    def exported(self, name='export'):
        destination = self.root / name
        manifest = export(self.queue, destination, fmt='csv')
        with (destination / 'features.csv').open(newline='') as stream:
            rows = list(csv.DictReader(stream))
        return destination, manifest, rows

    def test_active_capture_preserves_dataset_confidence_and_unknown_label_time(self):
        self.queue.ingest([self.row('one')])
        item = self.capture()
        self.queue.review(item['id'], 'active')
        destination, manifest, rows = self.exported()
        self.assertEqual(manifest['dataset_label_capture_eligible'], 1)
        self.assertEqual(manifest['research_eligible'], 0)
        self.assertEqual(rows[0]['label_confidence'], 'dataset')
        self.assertEqual(rows[0]['research_eligible'], 'False')
        self.assertEqual(rows[0]['label_source'], 'phiusiil-dataset')
        self.assertEqual(rows[0]['label_source_id'], digest('row:one'))
        self.assertEqual(rows[0]['label_observed_at'], 'unknown')
        self.assertNotIn('PRIVATE', (destination / 'features.csv').read_text())
        self.assertNotIn('url', rows[0])

    def test_fixture_or_failed_capture_cannot_be_dataset_usable(self):
        for profile, eligible in (('fixture', True), ('live', False)):
            with self.subTest(profile=profile, eligible=eligible):
                self.queue = Queue(self.root / ('dataset-' + profile))
                self.queue.ingest([self.row(profile)])
                self.capture(profile=profile, eligible=eligible)
                _, manifest, _ = self.exported('export-' + profile)
                self.assertEqual(manifest['dataset_label_capture_eligible'], 0)
                self.assertEqual(manifest['research_eligible'], 0)

    def test_dataset_confidence_requires_provenance_and_unknown_label_time(self):
        for changes in ({'source': 'local'}, {'source_id': 'not-a-row-hash'}, {'observed_at': '2026-10-20T00:00:00Z'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.queue.ingest([{**self.row('bad'), **changes}])
        self.assertEqual(self.queue.status()['states'], [])

    def test_only_actual_verified_provenance_can_upgrade_dataset_label(self):
        row = self.row('one')
        self.queue.ingest([row])
        self.queue.ingest([{**row, 'confidence': 'feed', 'source': 'openphish-community'}])
        with self.queue.connect() as db:
            self.assertEqual(db.execute('SELECT confidence FROM candidates').fetchone()[0], 'dataset')
        self.queue.ingest([{**row, 'confidence': 'verified', 'source': 'phishtank', 'observed_at': '2026-10-20T00:00:00Z'}])
        item = self.capture()
        self.queue.review(item['id'], 'active')
        _, manifest, rows = self.exported()
        self.assertEqual(rows[0]['label_confidence'], 'verified')
        self.assertEqual(manifest['research_eligible'], 1)
        self.assertEqual(manifest['dataset_label_capture_eligible'], 0)

    def test_opposite_label_conflict_is_preserved(self):
        row = self.row('one')
        self.queue.ingest([row])
        self.queue.ingest([{**row, 'label': 'phishing'}])
        self.assertEqual(self.queue.status()['states'][0]['state'], 'conflict')
        self.assertEqual(self.queue.status()['usable'], 0)

    def test_report_preserves_failed_attempts_and_unattempted_denominators(self):
        self.queue.ingest([self.row('legit'), self.row('failed', 'phishing'), self.row('reserve', 'phishing')])
        self.capture()
        self.capture(eligible=False, outcome='worker_error', artifact=False)
        destination, _, _ = self.exported()
        report = dataset_label_report(self.queue, destination / 'features.csv', self.root / 'report')
        self.assertEqual(report['analysis_scope'], 'phiusiil-historical-label-revisit')
        self.assertEqual(report['reserve_candidates_by_label'], {'legitimate': 1, 'phishing': 2})
        self.assertEqual(report['attempted_unique_candidates_by_label'], {'legitimate': 1, 'phishing': 1})
        self.assertEqual(report['unattempted_candidates_by_label']['phishing'], 1)
        self.assertEqual(report['attempts_by_label'], {'legitimate': 1, 'phishing': 1})
        self.assertEqual(report['dataset_label_usable_by_label'], {'legitimate': 1, 'phishing': 0})
        self.assertIn({'label': 'phishing', 'outcome': 'worker_error', 'count': 1}, report['attempt_outcomes'])
        self.assertFalse(report['new_model_trained'])
        self.assertFalse(report['dataset_labels_currently_verified'])
        self.assertEqual(report['independently_verified_research_rows'], 0)
        self.assertNotIn('accuracy', report)

    def test_standard_analysis_still_excludes_dataset_only_captures(self):
        self.queue.ingest([self.row('one')])
        self.capture()
        destination, _, _ = self.exported()
        stats = ModuleType('scipy.stats')
        stats.mannwhitneyu = Mock(side_effect=AssertionError('dataset labels must not trigger verified-label comparisons'))
        with patch.dict('sys.modules', {'scipy.stats': stats}):
            report = analyze(destination / 'features.csv', self.root / 'standard-report', bootstrap=2)
        stats.mannwhitneyu.assert_not_called()
        self.assertEqual(report['real_reviewed_rows'], 0)
        self.assertEqual(report['status'], 'insufficient_reviewed_live_data')

    def test_report_rejects_existing_output_and_flags_mixed_configs(self):
        self.queue.ingest([self.row('one'), self.row('two', 'phishing')])
        self.capture(config_hash='a' * 64)
        self.capture(config_hash='b' * 64)
        destination, _, _ = self.exported()
        out = self.root / 'report'
        report = dataset_label_report(self.queue, destination / 'features.csv', out)
        self.assertEqual(report['status'], 'mixed_configurations_report_separately')
        with self.assertRaisesRegex(ValueError, 'fresh'):
            dataset_label_report(self.queue, destination / 'features.csv', out)


if __name__ == '__main__':
    unittest.main()
