"""The completion intake must remain training-only, distinct and separately bounded."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from study import phiusiil_intake as base
from study import phiusiil_completion as completion
from study.public_web import collection_config, prepare_public_web, validate_public_manifest
from study.deployment import manifest_hash
try:
    from .test_phiusiil_intake import fixture, group
except ImportError:
    from test_phiusiil_intake import fixture, group


def contract():
    return {'campaign_id': completion.CAMPAIGN, 'target_label': 'phishing', 'target_usable': 59,
        'attempt_limit': 800, 'max_hours': 2, 'prior_usable_counts': {'legitimate': 79, 'phishing': 16},
        'prior_summary_sha256': 'a'*64, 'prior_capture_csv_sha256': 'b'*64, 'prior_audit_sha256': 'c'*64}


class CompletionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent)
        self.root = Path(self.temp.name)
        self.inputs = fixture(self.root, per_class=205)
        self.patches = [patch.object(base, 'domain_group', side_effect=group),
                        patch.object(completion, 'domain_group', side_effect=group)]
        for p in self.patches: p.start()

    def tearDown(self):
        for p in reversed(self.patches): p.stop()
        self.temp.cleanup()

    def build(self):
        out = self.root/'completion'
        m = completion.prepare(*self.inputs, out, contract(), reserve=5)
        return out, m

    def test_completion_replays_originals_and_excludes_all_prior_groups(self):
        out, m = self.build()
        prior = base._build(*self.inputs, 200, base.SEED)
        self.assertEqual(m['previous_selection_sha256'], prior['selection_sha256'])
        self.assertEqual(set(m['excluded_domain_group_hashes']), {r['domain_group_hash'] for r in prior['selected']})
        self.assertEqual({r['label'] for r in m['selected']}, {'phishing'})
        self.assertTrue(all(r['source_label'] == 0 and r['split'] == 'train' for r in m['selected']))
        self.assertFalse(set(m['excluded_domain_group_hashes']) & {r['domain_group_hash'] for r in m['selected']})
        self.assertEqual(base.validate_intake(out/'candidates.csv', out/'intake-manifest.json', *self.inputs), m)

    def test_same_input_selection_is_deterministic_without_reachability(self):
        _, a = self.build()
        b = completion.prepare(*self.inputs, self.root/'second', contract(), reserve=5)
        self.assertEqual(a['selected'], b['selected'])
        self.assertEqual(a['endpoint_visits'], 0)
        self.assertFalse(a['reachability_screened'])

    def test_existing_output_is_preserved(self):
        out, _ = self.build()
        before = (out/'intake-manifest.json').read_bytes()
        with self.assertRaises(ValueError): completion.prepare(*self.inputs, out, contract(), reserve=5)
        self.assertEqual(before, (out/'intake-manifest.json').read_bytes())

    def test_missing_or_changed_originals_stop_replay(self):
        out, _ = self.build()
        self.inputs[0].write_bytes(self.inputs[0].read_bytes()+b'\n')
        with self.assertRaises(ValueError): base.validate_intake(out/'candidates.csv', out/'intake-manifest.json', *self.inputs)

    def test_wrong_label_and_reused_group_rejected_even_after_rehash(self):
        out, m = self.build()
        for change in ('label', 'excluded'):
            altered = deepcopy(m)
            if change == 'label': altered['selected'][0]['source_label'] = 1
            else: altered['excluded_domain_group_hashes'][0] = altered['selected'][0]['domain_group_hash']; altered['excluded_domain_group_hashes'].sort()
            altered['selection_sha256'] = base.digest_json(altered['selected'])
            altered['manifest_sha256'] = base.manifest_hash(altered)
            (out/'intake-manifest.json').write_text(json.dumps(altered))
            with self.assertRaises(ValueError): base.validate_intake(out/'candidates.csv', out/'intake-manifest.json')

    def test_completion_budget_is_explicit_and_old_profile_keeps_400_limit(self):
        self.assertEqual(collection_config('Laoag City, Philippines', 800, 59, contract()).max_attempts, 800)
        for attempts, target, value in ((801,59,contract()),(800,75,contract()),(800,59,None),(400,59,None)):
            with self.assertRaises(ValueError): collection_config('Laoag City, Philippines', attempts, target, value)

    def test_typed_contract_and_prior_receipts_are_required(self):
        for key, value in [('target_usable',True),('attempt_limit',400),('max_hours',3),('prior_summary_sha256','unknown')]:
            altered = contract(); altered[key] = value
            with self.assertRaises(ValueError): completion.validate_completion(altered)

    def test_completion_manifest_cannot_be_promoted_to_old_intake(self):
        m = prepare_public_web(self.root/'bundle', 'Laoag City, Philippines',995,994,
            Path(__file__).resolve().parents[1], intake_manifest_hash='d'*64,upstream_config_hash='e'*64,
            max_attempts=800,usable_per_class=59,completion=contract())
        self.assertTrue(validate_public_manifest(m))
        m['intake_profile'] = 'phiusiil-revisit-v1'; m['configuration_hash'] = manifest_hash(m)
        with self.assertRaises(ValueError): validate_public_manifest(m)
