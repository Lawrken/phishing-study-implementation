"""Local file-only intake tests: no websites, training, or DNS requests."""
from collections import Counter
from copy import deepcopy
import csv
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

from study import phiusiil_intake as intake
from study.phiusiil import EXPECTED_COLUMNS
from study.sources import read_dataset_intake
from study.urls import canonical_url, digest


def group(url):
    return '.'.join(urlsplit(url).hostname.split('.')[-2:])


def write_csv(path, fields, rows):
    with path.open('w', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)


def fixture(directory, per_class=6):
    source, member, audit = [directory / name for name in ('source.csv', 'split-membership.csv', 'audit.json')]
    entries = []
    for label, prefix in ((1, 'legit'), (0, 'phish')):
        entries.extend((f'https://{prefix}{number}.example/login?q=preserved', label, 'train', True)
                       for number in range(per_class))
    for partition in ('validation', 'test'):
        entries.extend((f'https://{partition}-{label}.example/', label, partition, True) for label in (0, 1))
    entries += [('https://mixed.example/legit', 1, 'train', True),
                ('https://mixed.example/phish', 0, 'train', True),
                ('https://conflict.example/', 0, 'train', False),
                ('https://conflict.example/#fragment', 1, 'train', False),
                ('https://legit0.example/login?q=preserved#copy', 1, 'train', False),
                ('file:///not-an-endpoint', 0, 'train', False)]
    rows = []
    for url, label, _, _ in entries:
        values = dict.fromkeys(EXPECTED_COLUMNS, '0')
        values.update(URL=url, label=str(label), FILENAME='fixture', Domain=urlsplit(url).hostname or '', TLD='example', Title='fixture')
        rows.append(values)
    write_csv(source, EXPECTED_COLUMNS, rows)
    source_hash = intake.sha256_file(source)
    kept = []
    for number, (url, label, partition, keep) in enumerate(entries, 1):
        if keep:
            url = canonical_url(url)
            kept.append({'source_row': number, 'row_id': digest(source_hash + ':' + str(number)),
                'url_hash': digest(url), 'domain_group_hash': digest(group(url)),
                'component_id': digest('component:' + url), 'page_vector_hash': digest('features:' + url),
                'split': partition, 'truth_phishing': 1 - label})
    write_csv(member, intake.MEMBERSHIP_FIELDS, kept)
    data = {'status': 'baseline_complete', 'external_dataset_only': True, 'source_unchanged_after_run': True,
            'source': {'sha256': source_hash, 'bytes': source.stat().st_size,
                       'label_mapping': {'source_0': 'phishing', 'source_1': 'legitimate'}},
            'artifact_hashes': {'split-membership.csv': intake.sha256_file(member)},
            'rows': len(rows), 'retained_rows': len(kept),
            'source_label_counts': dict(sorted(Counter(str(label) for _, label, _, _ in entries).items())),
            'retained_class_counts': dict(sorted(Counter(intake.LABELS[label] for _, label, _, keep in entries if keep).items())),
            'exclusion_counts': {'invalid_canonical_url': 1, 'canonical_url_label_conflict': 2, 'duplicate_url_same_label': 1}}
    audit.write_text(json.dumps(data))
    return source, member, audit


def rewrite_manifest(path, data):
    data['selection_sha256'] = intake.digest_json(data['selected'])
    data['manifest_sha256'] = intake.manifest_hash(data)
    path.write_text(json.dumps(data))


class PhiusiilPilotIntakeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.root = Path(self.temp.name)
        self.inputs = fixture(self.root)
        self.groups = patch.object(intake, 'domain_group', side_effect=group)
        self.groups.start()

    def tearDown(self):
        self.groups.stop()
        self.temp.cleanup()

    def build(self, name='out', reserve=2, seed=intake.SEED):
        destination = self.root / name
        manifest = intake.prepare(*self.inputs, destination, reserve_per_class=reserve, seed=seed)
        return destination, manifest

    def test_cleaning_labels_and_training_only_reserve(self):
        output, manifest = self.build()
        self.assertEqual(manifest['census']['exclusion_counts'], {'invalid_canonical_url': 1,
            'canonical_url_label_conflict': 2, 'duplicate_url_same_label': 1})
        self.assertEqual(manifest['census']['mixed_label_groups_excluded'], 1)
        self.assertEqual(manifest['census']['homogeneous_train_groups'], {'legitimate': 6, 'phishing': 6})
        self.assertEqual([row['label'] for row in manifest['selected']], ['legitimate', 'phishing'] * 2)
        self.assertEqual(len({row['domain_group_hash'] for row in manifest['selected']}), 4)
        self.assertTrue(all(row['split'] == 'train' and row['domain_group'] != 'mixed.example' for row in manifest['selected']))
        self.assertEqual(manifest['endpoint_visits'], 0)
        self.assertFalse(manifest['reachability_screened'])
        for row in manifest['selected']:
            self.assertEqual(row['label'], 'legitimate' if row['source_label'] == 1 else 'phishing')
            self.assertIn('?q=preserved', row['url'])
        with (output / 'candidates.csv').open(newline='') as stream:
            rows = list(csv.DictReader(stream))
        self.assertTrue(all(row['confidence'] == 'dataset' and row['observed_at'] == 'unknown' for row in rows))
        self.assertTrue(all(row['source'] == 'phiusiil-dataset' for row in rows))
        self.assertEqual(intake.validate_intake(output / 'candidates.csv', output / 'intake-manifest.json', *self.inputs), manifest)

    def test_same_input_seed_identical_selection_csv_and_different_seed_changes_order(self):
        first, a = self.build('first')
        second, b = self.build('second')
        self.assertEqual(a['selected'], b['selected'])
        self.assertEqual(a['selection_sha256'], b['selection_sha256'])
        self.assertEqual((first / 'candidates.csv').read_bytes(), (second / 'candidates.csv').read_bytes())
        _, other = self.build('third', seed=2)
        self.assertNotEqual(a['selection_sha256'], other['selection_sha256'])

    def test_existing_output_and_original_bytes_are_preserved(self):
        hashes = [intake.sha256_file(path) for path in self.inputs]
        output, _ = self.build()
        before = (output / 'intake-manifest.json').read_bytes()
        with self.assertRaisesRegex(ValueError, 'fresh output'):
            intake.prepare(*self.inputs, output, reserve_per_class=2)
        self.assertEqual((output / 'intake-manifest.json').read_bytes(), before)
        self.assertEqual([intake.sha256_file(path) for path in self.inputs], hashes)

    def test_source_and_membership_must_match_frozen_audit(self):
        for position in (0, 1):
            original = self.inputs[position].read_bytes()
            self.inputs[position].write_bytes(original + b'\n')
            with self.assertRaisesRegex(ValueError, 'does not match'):
                self.build('failure-' + str(position))
            self.inputs[position].write_bytes(original)

    def test_invalid_label_even_with_rehashed_source_is_rejected(self):
        source, _, audit = self.inputs
        with source.open(newline='') as stream:
            rows = list(csv.DictReader(stream))
        rows[0]['label'] = 'legitimate'
        write_csv(source, EXPECTED_COLUMNS, rows)
        data = json.loads(audit.read_text())
        data['source'].update(sha256=intake.sha256_file(source), bytes=source.stat().st_size)
        audit.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'original token'):
            self.build()

    def test_reversed_audit_label_convention_is_rejected(self):
        audit = self.inputs[2]
        data = json.loads(audit.read_text())
        data['source']['label_mapping']['source_0'] = 'legitimate'
        audit.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'label convention'):
            self.build()

    def test_reconstructed_cleaning_must_agree_with_frozen_counts(self):
        audit = self.inputs[2]
        data = json.loads(audit.read_text())
        data['retained_rows'] += 1
        audit.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'cleaning differs'):
            self.build()

    def test_ledger_label_tampering_cannot_be_hidden_by_rehash(self):
        _, member, audit = self.inputs
        with member.open(newline='') as stream:
            rows = list(csv.DictReader(stream))
        rows[0]['truth_phishing'] = str(1 - int(rows[0]['truth_phishing']))
        write_csv(member, intake.MEMBERSHIP_FIELDS, rows)
        data = json.loads(audit.read_text())
        data['artifact_hashes']['split-membership.csv'] = intake.sha256_file(member)
        audit.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'identity or label'):
            self.build()

    def test_group_crossing_frozen_partitions_is_rejected(self):
        _, member, audit = self.inputs
        with member.open(newline='') as stream:
            rows = list(csv.DictReader(stream))
        rows[-1]['split'] = 'test'
        write_csv(member, intake.MEMBERSHIP_FIELDS, rows)
        data = json.loads(audit.read_text())
        data['artifact_hashes']['split-membership.csv'] = intake.sha256_file(member)
        audit.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, 'crosses frozen partitions'):
            self.build()

    def test_insufficient_groups_fails_before_output_creation(self):
        with self.assertRaisesRegex(ValueError, 'not enough homogeneous'):
            self.build(reserve=7)
        self.assertFalse((self.root / 'out').exists())

    def test_invalid_limits_and_partial_replay_inputs_are_rejected(self):
        for value in (0, 201, True, -1):
            with self.assertRaises(ValueError):
                self.build('bad-' + str(value), reserve=value)
        output, _ = self.build()
        with self.assertRaisesRegex(ValueError, 'all three'):
            intake.validate_intake(output / 'candidates.csv', output / 'intake-manifest.json', source_csv=self.inputs[0])

    def test_changed_csv_and_manifest_are_rejected(self):
        output, manifest = self.build()
        csv_path, manifest_path = output / 'candidates.csv', output / 'intake-manifest.json'
        csv_path.write_bytes(csv_path.read_bytes().replace(b'dataset', b'verified'))
        with self.assertRaisesRegex(ValueError, 'exact frozen'):
            intake.validate_intake(csv_path, manifest_path)
        csv_path.write_bytes(intake._csv_bytes(manifest))
        manifest['selected'][0]['source_label'] = 0
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'altered manifest'):
            intake.validate_intake(csv_path, manifest_path)

    def test_rehashed_holdout_or_verified_promotion_is_rejected(self):
        output, original = self.build()
        for change in ('holdout', 'confidence', 'labeltime', 'repeatgroup'):
            manifest = deepcopy(original)
            if change == 'holdout': manifest['selected'][0]['split'] = 'test'
            elif change == 'confidence': manifest['label_confidence'] = 'verified'
            elif change == 'labeltime': manifest['label_observed_at'] = manifest['prepared_at']
            else: manifest['selected'][2] = {**manifest['selected'][0], 'order': 3, 'class_order': 2}
            rewrite_manifest(output / 'intake-manifest.json', manifest)
            with self.assertRaises(ValueError):
                intake.validate_intake(output / 'candidates.csv', output / 'intake-manifest.json')

    def test_original_replay_detects_plausibly_rehashed_url_replacement(self):
        output, manifest = self.build()
        row = manifest['selected'][0]
        row.update(url='https://replacement.example/account', domain_group='replacement.example',
                   url_hash=digest('https://replacement.example/account'), domain_group_hash=digest('replacement.example'))
        raw = intake._csv_bytes(manifest)
        manifest.update(csv_sha256=hashlib.sha256(raw).hexdigest(), csv_bytes=len(raw))
        (output / 'candidates.csv').write_bytes(raw)
        rewrite_manifest(output / 'intake-manifest.json', manifest)
        with self.assertRaisesRegex(ValueError, 'deterministic original-input replay'):
            intake.validate_intake(output / 'candidates.csv', output / 'intake-manifest.json', *self.inputs)

    def test_adapter_reconstructs_validated_historical_records(self):
        output, manifest = self.build()
        rows = list(read_dataset_intake(output / 'candidates.csv', output / 'intake-manifest.json'))
        self.assertEqual(rows, list(intake.records_from_manifest(manifest)))
        self.assertTrue(all(set(row) == set(intake.FIELDS) for row in rows))


if __name__ == '__main__':
    unittest.main()
