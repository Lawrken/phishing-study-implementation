"""Dataset availability is an outcome; local containment evidence stays mandatory."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest

from study.deployment import ROOT, file_hash, manifest_hash
from study.public_web import (OBSERVATION_PROFILE, OBSERVATION_ASSURANCE, prepare_public_web,
    validate_public_bundle, validate_public_manifest, validate_public_evidence,
    validate_execution_evidence, validate_public_evidence_files)
from test_public_web import configured, evidence


def observation_proof(manifest, directory):
    proof = evidence(manifest, directory)
    now = datetime.now(timezone.utc)
    proof.update(network_isolation_verified=False, activation_allowed=False, observation_allowed=True,
        public_dns_verified=False, public_tls_verified=False,
        started_at=(now-timedelta(seconds=100)).isoformat(), finished_at=now.isoformat())
    proof['service_stop'] = proof.pop('connected')['service_stop']
    for key in ('connected',):
        proof['evidence_files'].pop(key)
    stop = directory/'service-stop.json'
    stop.write_text(json.dumps(proof['service_stop']))
    proof['evidence_files']['service_stop'] = {'path': str(stop.resolve()), 'sha256': file_hash(stop)}
    return proof


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.bundle = self.directory/'bundle'
        self.manifest = configured(self.bundle, dataset_observation=True)
        self.proof = observation_proof(self.manifest, self.directory)

    def test_dataset_mode_has_separate_identity_and_no_owned_site(self):
        self.assertEqual(self.manifest['verification_profile'], OBSERVATION_PROFILE)
        self.assertEqual(self.manifest['assurance_model'], OBSERVATION_ASSURANCE)
        self.assertEqual(self.manifest['owned_controls'], {})
        self.assertEqual(validate_public_bundle(self.bundle, root=ROOT), self.manifest)
        self.assertTrue(validate_execution_evidence(self.manifest, self.proof))

    def test_dataset_proof_cannot_activate_the_full_public_gate(self):
        with self.assertRaises(ValueError):
            validate_public_evidence(self.manifest, self.proof)

    def test_failed_kernel_receiver_or_firewall_proof_prevents_dataset_visits(self):
        for key, value in (('positive_control_hits', 0), ('workload_hits', 1), ('reject_counter_delta', 0)):
            proof = deepcopy(self.proof)
            proof['kernel']['cases']['private_ipv4_tcp'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_execution_evidence(self.manifest, proof)

    def test_observation_cannot_promote_public_verification_flags(self):
        for key in ('network_isolation_verified', 'activation_allowed', 'public_dns_verified', 'public_tls_verified'):
            proof = deepcopy(self.proof); proof[key] = True
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_execution_evidence(self.manifest, proof)

    def test_expired_or_changed_source_proof_is_rejected(self):
        for change in ('expired', 'source'):
            proof = deepcopy(self.proof)
            if change == 'expired':
                proof['finished_at'] = (datetime.now(timezone.utc)-timedelta(minutes=6)).isoformat()
                proof['started_at'] = (datetime.now(timezone.utc)-timedelta(minutes=7)).isoformat()
            else: proof['source_hash'] = '0'*64
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_execution_evidence(self.manifest, proof)

    def test_ten_clean_lifecycles_and_service_shutdown_are_required(self):
        for change in ('trial', 'stop', 'cleanup'):
            proof = deepcopy(self.proof)
            if change == 'trial': proof['lifecycle_trials'].pop()
            elif change == 'stop': proof['service_stop']['checks']['guard_clean'] = False
            else: proof['cleanup']['accounts_idle'] = False
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_execution_evidence(self.manifest, proof)

    def test_observation_flag_is_typed_and_frozen(self):
        for value in ('true', 1, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                configured(self.directory/('invalid-'+str(value)), dataset_observation=value)
        changed = deepcopy(self.manifest)
        changed['owned_controls'] = {'https_url': 'https://d-tx-t.vercel.app/'}
        changed['configuration_hash'] = manifest_hash(changed)
        with self.assertRaises(ValueError): validate_public_manifest(changed)

    def test_frozen_service_stop_content_cannot_be_replaced(self):
        path = Path(self.proof['evidence_files']['service_stop']['path'])
        path.write_text('{}')
        with self.assertRaises(ValueError): validate_public_evidence_files(self.proof)

    def test_dataset_continuation_is_bound_without_owned_controls(self):
        prior = {'schema_version': 1, 'attempts_used': 10, 'attempt_limit': 400,
                 'candidate_ids': ['a'*64], 'receipts': [{'run_id': 'operator-prior',
                 'source_hash': 'b'*64, 'archive_sha256': 'c'*64, 'attempts': 10}]}
        value = configured(self.directory/'continued', dataset_observation=True,
                           continuation=prior, max_attempts=10)
        self.assertEqual(value['continuation'], prior)
        self.assertEqual(value['owned_controls'], {})
        self.assertEqual(validate_public_bundle(self.directory/'continued', root=ROOT), value)

    def test_dataset_continuation_cannot_exceed_remaining_attempt_budget(self):
        prior = {'schema_version': 1, 'attempts_used': 395, 'attempt_limit': 400,
                 'candidate_ids': ['a'*64], 'receipts': [{'run_id': 'operator-prior',
                 'source_hash': 'b'*64, 'archive_sha256': 'c'*64, 'attempts': 395}]}
        with self.assertRaises(ValueError):
            configured(self.directory/'expanded', dataset_observation=True,
                       continuation=prior, max_attempts=10)
