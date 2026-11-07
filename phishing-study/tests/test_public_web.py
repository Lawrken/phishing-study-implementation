"""Public-web approval is distinct, source-bound, finite and fail closed."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from study.config import load
from study.deployment import ROOT, check_evidence, file_hash, manifest_hash, prepare, source_hash
from study.public_web import (ASSURANCE, ARTIFACTS, CONNECTED_CHECKS, CLEANUP_CHECKS,
    DNS_RESOURCES, KERNEL_CASES, KERNEL_CHECKS, LISTEN, OWNED_URL, PROFILE, SERVICE_STOP_CHECKS,
    RESOURCES, RUNTIME_PINS, CHROMIUM_VERSION, allowed_public_egress, check_public_activation, collection_config,
    prepare_public_web, public_identity, render_firewall, validate_public_bundle,
    validate_public_evidence, validate_public_evidence_files, validate_public_manifest)
from study.deployment_checks import FIXTURE_CHECKS


def configured(output, **changes):
    values = {'region': 'Laoag City, Philippines', 'uid': 999, 'resolver_uid': 997,
              'root': ROOT, 'local_ipv4': ['127.0.0.1', '10.0.2.15'],
              'gateways_ipv4': ['10.0.2.2'], 'intake_manifest_hash': 'a' * 64,
              'upstream_config_hash': 'b' * 64}
    values.update(changes)
    return prepare_public_web(output, **values)


def life(uid):
    return {'cancelled': False, 'abandoned_stages': [], 'pending_abandoned_stage_count': 0,
        'pending_tasks_at_loop_close': 0, 'owned_browser_process_after_cleanup': {'gone': True},
        'captured_browser_identity': {'uid': uid},
        'stages': [{'name': 'context_close', 'ok': True, 'duration_seconds': .1, 'deadline_seconds': 12},
                   {'name': 'guard_close', 'ok': True, 'duration_seconds': .1, 'deadline_seconds': 20},
                   {'name': 'browser_close', 'ok': True, 'duration_seconds': .1, 'deadline_seconds': 12},
                   {'name': 'driver_stop', 'ok': True, 'duration_seconds': .1, 'deadline_seconds': 5}]}


def evidence(manifest, directory):
    start = datetime(2026, 10, 26, 0, 0, tzinfo=timezone.utc)
    result = {**public_identity(manifest), 'status': 'passed', 'network_isolation_verified': True,
        'activation_allowed': True, 'research_collection_count': 0, 'nonce': 'c' * 32,
        'started_at': start.isoformat(), 'finished_at': (start + timedelta(minutes=10)).isoformat(),
        'normal_firewall_state_hash': 'd' * 64, 'runtime_service_hash': 'e' * 64,
        'runtime_resolver_service_hash': 'f' * 64, 'claims': deepcopy(manifest['claims']),
        'cleanup': {name: True for name in CLEANUP_CHECKS}}
    result['suite'] = {'source_hash': manifest['source_hash'], 'successful': True, 'tests_run': 322,
        'python': RUNTIME_PINS['python'], 'versions': {key: value for key, value in RUNTIME_PINS.items() if key != 'python'},
        'passed': 322, 'browser_verified': True, 'skipped': [], 'failures': 0, 'errors': 0,
        'expected_failures': 0, 'unexpected_successes': 0, 'browser_tests': {'passed': 18, 'missing': []}}
    result['selftest'] = {'source_hash': manifest['source_hash'], 'status': 'passed',
        'fixture_verified': True, 'checks': {name: True for name in FIXTURE_CHECKS},
        'export': {'research_eligible': 0}}
    result['kernel'] = {'source_hash': manifest['source_hash'], 'status': 'passed',
        'firewall_hash': manifest['firewall_hash'], 'service_hash': manifest['service_hash'],
        'checks': {name: True for name in KERNEL_CHECKS},
        'cases': {name: {'positive_control_hits': 1, 'workload_hits': 0,
                        'reject_counter_delta': 0 if name == 'redirect' else 1} for name in KERNEL_CASES}}
    result['connected'] = {'source_hash': manifest['source_hash'], 'status': 'passed',
        'firewall_hash': manifest['firewall_hash'], 'checks': {name: True for name in CONNECTED_CHECKS}, 'phases': []}
    result['connected']['service_stop'] = {'status':'passed', 'source_hash':manifest['source_hash'],
        'uid':manifest['study_uid'], 'worker_exit':0, 'stop_sent':True, 'signal_seen':'SIGTERM',
        'namespace_disconnected':True, 'collection_account_idle':True,
        'checks':{name:True for name in SERVICE_STOP_CHECKS}, 'lifecycle':life(manifest['study_uid']),
        'report_sha256':'7'*64, 'runtime_service_hash':'8'*64}
    for index, name in enumerate(('normal', 'blocked', 'restored')):
        blocked = name == 'blocked'
        result['connected']['phases'].append({'phase': name, 'status': 'passed',
            'started_at': (start + timedelta(seconds=1 + index * 5)).isoformat(),
            'finished_at': (start + timedelta(seconds=3 + index * 5)).isoformat(),
            'worker_exit': 0, 'report_sha256': '1' * 64, 'receipt_sha256': '2' * 64,
            'browser_version': CHROMIUM_VERSION,
            'lifecycle': life(manifest['study_uid']), 'target': OWNED_URL, 'effective_dns_verified': True,
            'resolver_query_count': 0 if blocked else 1, 'reject_counter_delta': 1 if blocked else 0,
            'navigation': {'status': None if blocked else 200, 'error_type': 'Error' if blocked else None,
                           'native_dns_error': 'net::ERR_NAME_NOT_RESOLVED' if blocked else None},
            'network': {'response_count': 0 if blocked else 3, 'completed_encoded_bytes': 0 if blocked else 2000},
            'capture_eligible': not blocked, 'dns_metadata': {'measured': not blocked},
            'tls_metadata': {'measured': not blocked, 'validation': 'system_trust_verified'}})
    result['lifecycle_trials'] = [{'status': 'passed', 'source_hash': manifest['source_hash'],
        'report_sha256': '3' * 64, 'phase': 'normal' if index % 2 == 0 else 'redirect',
        'lifecycle': life(manifest['study_uid'])} for index in range(10)]
    result['evidence_files'] = {}
    for name in ('suite', 'selftest', 'kernel', 'connected'):
        path = Path(directory) / (name + '.json')
        path.write_text(json.dumps(result[name], indent=2))
        digest = file_hash(path)
        result[name]['report_sha256'] = digest
        result['evidence_files'][name] = {'path': str(path.resolve()), 'sha256': digest}
    path = Path(directory) / 'lifecycle.json'
    path.write_text(json.dumps({'trials': result['lifecycle_trials']}))
    result['evidence_files']['lifecycle'] = {'path': str(path.resolve()), 'sha256': file_hash(path)}
    return result


class PublicWebBundleTests(unittest.TestCase):
    def test_live_monitor_is_opt_in_and_bound_to_verified_identity(self):
        standard = configured(self.directory / 'standard-view')
        monitored = configured(self.directory / 'monitored-view', live_view=True)
        self.assertIs(standard['live_view_enabled'], False)
        self.assertIs(monitored['live_view_enabled'], True)
        self.assertNotEqual(public_identity(standard), public_identity(monitored))
        self.assertEqual(validate_public_bundle(self.directory / 'monitored-view', root=ROOT), monitored)

    def test_live_monitor_cannot_be_enabled_by_tampering_with_verified_bundle(self):
        value = configured(self.directory / 'view-tamper')
        previous = evidence(value, self.directory)
        value['live_view_enabled'] = True
        value['configuration_hash'] = manifest_hash(value)
        with self.assertRaises(ValueError):
            validate_public_evidence(value, previous)

    def test_live_monitor_rejects_untyped_flags(self):
        for value in (1, 'true', None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                configured(self.directory / ('invalid-view-' + str(value)), live_view=value)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def test_explicit_profile_has_own_schema_resources_and_inactive_template(self):
        bundle = self.directory / 'bundle'
        value = configured(bundle)
        self.assertEqual(value['schema_version'], 3)
        self.assertEqual(value['verification_profile'], PROFILE)
        self.assertEqual(value['assurance_model'], ASSURANCE)
        self.assertEqual(value['resources'], RESOURCES)
        self.assertEqual(value['dns_resources'], DNS_RESOURCES)
        self.assertIs(value['network_isolation_verified'], False)
        self.assertIs(value['activation_allowed'], False)
        self.assertEqual(value['required_inputs'], [])
        self.assertEqual(set(value['artifact_hashes']), ARTIFACTS)
        self.assertEqual(validate_public_bundle(bundle, root=ROOT), value)
        self.assertIn('BindsTo=@@DNS_UNIT@@', (bundle / 'collector.service').read_text())
        self.assertIn('--mode public-web', (bundle / 'resolver.service').read_text())
        self.assertIn('KillMode=mixed', (bundle / 'collector.service').read_text())
        self.assertIn('KillMode=control-group', (bundle / 'resolver.service').read_text())

    def test_remaining_attempt_budget_is_frozen_without_changing_default(self):
        bundle = self.directory / 'remaining-budget'
        value = configured(bundle, max_attempts=343)
        self.assertEqual(value['max_attempts'], 343)
        self.assertEqual(load(bundle / 'pilot.template.toml').max_attempts, 343)
        self.assertEqual(validate_public_bundle(bundle, root=ROOT), value)
        self.assertEqual(collection_config('Laoag City, Philippines').max_attempts, 400)
        altered = deepcopy(value)
        altered['max_attempts'] = 344
        altered['configuration_hash'] = manifest_hash(altered)
        with self.assertRaises(ValueError): validate_public_manifest(altered)

    def test_attempt_budget_cannot_expand_or_use_untyped_values(self):
        for value in (0, -1, 401, True, '343', 343.0):
            with self.subTest(value=value), self.assertRaises(ValueError):
                collection_config('Laoag City, Philippines', max_attempts=value)

    def test_150_capture_target_is_explicit_frozen_and_default_stays_50(self):
        bundle = self.directory / 'target-150'
        value = configured(bundle, usable_per_class=75)
        self.assertEqual(value['usable_per_class'], 75)
        config = load(bundle / 'pilot.template.toml')
        self.assertEqual((config.usable_per_class, config.max_attempts, config.max_hours), (75, 400, 2))
        self.assertEqual(validate_public_bundle(bundle, root=ROOT), value)
        self.assertEqual(collection_config('Laoag City, Philippines').usable_per_class, 50)
        altered = deepcopy(value)
        altered['usable_per_class'] = 50
        altered['configuration_hash'] = manifest_hash(altered)
        with self.assertRaises(ValueError): validate_public_manifest(altered)

    def test_class_target_rejects_unapproved_and_untyped_values(self):
        for value in (0, -1, 74, 76, 150, True, '75', 75.0):
            with self.subTest(value=value), self.assertRaises(ValueError):
                collection_config('Laoag City, Philippines', usable_per_class=value)

    def test_missing_identity_inputs_remain_incomplete(self):
        value = configured(self.directory / 'incomplete', uid=None, intake_manifest_hash=None)
        self.assertEqual(value['status'], 'incomplete')
        self.assertIn('study_uid', value['required_inputs'])
        with self.assertRaises(ValueError):
            validate_public_manifest(value)

    def test_actual_region_and_distinct_nonroot_accounts_are_required(self):
        for changes in ({'region': None}, {'region': 'unspecified'}, {'uid': 0},
                        {'uid': True}, {'resolver_uid': 999}, {'upstream_config_hash': 'placeholder'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                configured(self.directory / 'bad', **changes)

    def test_existing_bundle_and_changed_artifact_are_preserved_and_rejected(self):
        bundle = self.directory / 'bundle'
        configured(bundle)
        with self.assertRaises(ValueError):
            configured(bundle)
        path = bundle / 'resolver/resolv.conf'
        path.write_text('nameserver 8.8.8.8\n')
        with self.assertRaises(ValueError):
            validate_public_bundle(bundle, root=ROOT)

    def test_rehashed_unsafe_resources_claims_and_mode_do_not_validate(self):
        original = configured(self.directory / 'bundle')
        for change in ('resources', 'mode', 'activation', 'claims', 'profile'):
            value = deepcopy(original)
            if change == 'resources': value['resources']['workers'] = 2
            elif change == 'mode': value['resolver']['mode'] = 'owned-only'
            elif change == 'activation': value['network_isolation_verified'] = True
            elif change == 'claims': value['claims']['labels_currently_verified'] = True
            else: value['verification_profile'] = 'local-logged-preview-v1'
            value['configuration_hash'] = manifest_hash(value)
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_public_manifest(value)

    def test_legacy_prepare_default_is_unchanged_and_public_options_are_explicit(self):
        legacy = prepare(self.directory / 'legacy')
        self.assertEqual(legacy['schema_version'], 1)
        self.assertEqual(legacy['resources']['workers'], 2)
        with self.assertRaises(ValueError):
            prepare(self.directory / 'ambiguous', intake_manifest_hash='a' * 64)
        public = prepare(self.directory / 'public', region='Laoag City, Philippines', uid=999, resolver_uid=997,
            verification_profile=PROFILE, intake_manifest_hash='a' * 64, upstream_config_hash='b' * 64)
        self.assertEqual(public['schema_version'], 3)


class PublicWebFirewallTests(unittest.TestCase):
    def test_only_public_web_and_exact_logged_dns_are_permitted(self):
        self.assertTrue(allowed_public_egress('93.184.216.34', 'tcp', 80))
        self.assertTrue(allowed_public_egress('93.184.216.34', 'tcp', 443))
        for transport in ('udp', 'tcp'):
            self.assertTrue(allowed_public_egress(LISTEN, transport, 53))
        for address, transport, port in (('10.0.0.2', 'tcp', 80), ('127.0.0.1', 'tcp', 443),
            ('127.0.0.53', 'udp', 53), ('8.8.8.8', 'udp', 53), ('93.184.216.34', 'tcp', 8443),
            ('93.184.216.34', 'udp', 443), ('::ffff:93.184.216.34', 'tcp', 443)):
            self.assertFalse(allowed_public_egress(address, transport, port))
        self.assertFalse(allowed_public_egress('93.184.216.34', 'tcp', 443, local_ipv4=['93.184.216.34']))
        self.assertFalse(allowed_public_egress('93.184.216.34', 'tcp', 443, gateways_ipv4=['93.184.216.34']))

    def test_uid_scoping_and_dns_exception_precede_private_deny(self):
        rules = render_firewall(999, 997, ['10.0.2.15'], ['10.0.2.2'])
        self.assertIn('table inet study_public_egress', rules)
        self.assertLess(rules.index('jump dns_allow'), rules.index('ip daddr @denied_v4'))
        self.assertIn('meta skuid 999 jump workload', rules)
        self.assertIn('meta skuid 997 jump resolver', rules)
        self.assertIn('ct state established udp sport 53', rules)
        self.assertIn('ct state established tcp sport 53', rules)
        self.assertIn('ip daddr 127.0.0.53 udp dport 53', rules)
        self.assertNotIn('flush ruleset', rules)
        for uid, dnsuid in ((0, 997), (999, 999), (True, 997)):
            with self.assertRaises(ValueError): render_firewall(uid, dnsuid)


class PublicWebEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.bundle = self.directory / 'bundle'
        self.manifest = configured(self.bundle)
        self.proof = evidence(self.manifest, self.directory)

    def test_75_class_activation_requires_its_own_configuration_and_evidence(self):
        from dataclasses import replace
        directory = self.directory / 'target-150'
        directory.mkdir()
        bundle = directory / 'bundle'
        manifest = configured(bundle, usable_per_class=75)
        proof = evidence(manifest, directory)
        config = load(bundle / 'pilot.template.toml')
        args = (manifest, proof, manifest['source_hash'], manifest['firewall_hash'],
                proof['normal_firewall_state_hash'], manifest['resolver_hash'])
        self.assertTrue(check_public_activation(*args, config,
            manifest['upstream_config_hash'], manifest['intake_manifest_hash']))
        with self.assertRaises(ValueError):
            check_public_activation(*args, replace(config, usable_per_class=50),
                manifest['upstream_config_hash'], manifest['intake_manifest_hash'])
        with self.assertRaises(ValueError):
            validate_public_evidence(manifest, self.proof)

    def test_service_stop_evidence_cannot_be_omitted_or_hide_failed_cleanup(self):
        for mutation in ('missing', 'guard', 'signal', 'namespace', 'uid', 'pending_tasks'):
            proof = deepcopy(self.proof)
            stop = proof['connected']['service_stop']
            if mutation == 'missing': del proof['connected']['service_stop']
            elif mutation == 'guard': stop['checks']['guard_clean'] = False
            elif mutation == 'signal': stop['signal_seen'] = None
            elif mutation == 'namespace': stop['namespace_disconnected'] = False
            elif mutation == 'uid': stop['uid'] = 0
            else: stop['lifecycle']['pending_tasks_at_loop_close'] = 1
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_public_evidence(self.manifest, proof)

    def test_prior_attempt_record_is_bound_to_new_approval_and_original_budget(self):
        directory=self.directory/'continuation';directory.mkdir()
        prior={'schema_version':1,'attempts_used':172,'attempt_limit':400,'candidate_ids':['c'*64],
            'receipts':[{'run_id':'prior-1','source_hash':'a'*64,'archive_sha256':'b'*64,'attempts':172}]}
        manifest=configured(directory/'bundle',max_attempts=228,usable_per_class=75,continuation=prior)
        proof=evidence(manifest,directory)
        self.assertTrue(validate_public_evidence(manifest,proof))
        altered=deepcopy(manifest);altered['continuation']['candidate_ids']=['d'*64]
        altered['configuration_hash']=manifest_hash(altered)
        with self.assertRaises(ValueError):validate_public_evidence(altered,proof)
        with self.assertRaises(ValueError):
            configured(directory/'expanded',max_attempts=229,continuation=prior)

    def test_reduced_budget_activation_must_match_its_verified_configuration(self):
        reduced = self.directory / 'reduced'
        reduced.mkdir()
        bundle = reduced / 'bundle'
        manifest = configured(bundle, max_attempts=343)
        proof = evidence(manifest, reduced)
        config = load(bundle / 'pilot.template.toml')
        self.assertTrue(check_public_activation(manifest, proof, manifest['source_hash'],
            manifest['firewall_hash'], proof['normal_firewall_state_hash'], manifest['resolver_hash'],
            config, manifest['upstream_config_hash'], manifest['intake_manifest_hash']))
        from dataclasses import replace
        with self.assertRaises(ValueError):
            check_public_activation(manifest, proof, manifest['source_hash'], manifest['firewall_hash'],
                proof['normal_firewall_state_hash'], manifest['resolver_hash'], replace(config, max_attempts=400),
                manifest['upstream_config_hash'], manifest['intake_manifest_hash'])

    def test_complete_typed_actual_measurements_can_authorize_this_profile(self):
        self.assertTrue(validate_public_evidence(self.manifest, self.proof))
        config = load(self.bundle / 'pilot.template.toml')
        self.assertTrue(check_public_activation(self.manifest, self.proof, self.manifest['source_hash'],
            self.manifest['firewall_hash'], self.proof['normal_firewall_state_hash'], self.manifest['resolver_hash'],
            config, self.manifest['upstream_config_hash'], self.manifest['intake_manifest_hash']))
        self.assertTrue(check_evidence(self.manifest, self.proof, self.manifest['source_hash'],
            self.manifest['firewall_hash'], self.proof['normal_firewall_state_hash'], self.manifest['resolver_hash'],
            config, current_upstream_hash=self.manifest['upstream_config_hash'],
            current_intake_hash=self.manifest['intake_manifest_hash']))

    def test_missing_component_or_freeform_pass_checks_cannot_authorize(self):
        for key in ('suite', 'selftest', 'kernel', 'connected', 'lifecycle_trials', 'evidence_files'):
            value = deepcopy(self.proof)
            value.pop(key)
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_public_evidence(self.manifest, value)
        value = deepcopy(self.proof)
        value['kernel']['checks'] = {'passed': True}
        with self.assertRaises(ValueError): validate_public_evidence(self.manifest, value)

    def test_source_profile_intake_and_upstream_mismatches_fail(self):
        for key in ('source_hash', 'verification_profile', 'intake_manifest_hash', 'upstream_config_hash'):
            value = deepcopy(self.proof)
            value[key] = 'f' * 64 if key != 'verification_profile' else 'local-logged-preview-v1'
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_public_evidence(self.manifest, value)

    def test_dead_receivers_hits_absent_counters_and_bool_counts_fail(self):
        for field, changed in (('positive_control_hits', 0), ('positive_control_hits', True),
                               ('workload_hits', 1), ('workload_hits', False), ('reject_counter_delta', 0)):
            value = deepcopy(self.proof)
            value['kernel']['cases']['alternate_dns_tcp'][field] = changed
            with self.subTest(field=field, changed=changed), self.assertRaises(ValueError):
                validate_public_evidence(self.manifest, value)

    def test_offline_timeout_or_delivered_responses_are_not_dns_blackout(self):
        for problem in ('offline', 'query', 'response', 'bytes', 'counter'):
            value = deepcopy(self.proof)
            blocked = value['connected']['phases'][1]
            if problem == 'offline': blocked['navigation']['native_dns_error'] = 'net::ERR_INTERNET_DISCONNECTED'
            elif problem == 'query': blocked['resolver_query_count'] = 1
            elif problem == 'response': blocked['network']['response_count'] = 1
            elif problem == 'bytes': blocked['network']['completed_encoded_bytes'] = 1
            else: blocked['reject_counter_delta'] = 0
            with self.subTest(problem=problem), self.assertRaises(ValueError):
                validate_public_evidence(self.manifest, value)

    def test_real_tls_dns_extraction_and_capture_are_required(self):
        for field in ('capture_eligible', 'dns_metadata', 'tls_metadata'):
            value = deepcopy(self.proof)
            value['connected']['phases'][0][field] = False if field == 'capture_eligible' else {'measured': False}
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_public_evidence(self.manifest, value)

    def test_wrong_dependency_or_browser_revision_and_boolean_counts_fail(self):
        for problem in ('package', 'browser', 'count'):
            value = deepcopy(self.proof)
            if problem == 'package': value['suite']['versions']['playwright'] = 'changed'
            elif problem == 'browser': value['connected']['phases'][0]['browser_version'] = 'changed'
            else: value['suite']['errors'] = False
            with self.subTest(problem=problem), self.assertRaises(ValueError):
                validate_public_evidence(self.manifest, value)

    def test_lifecycle_timeouts_wrong_deadlines_and_missing_redirect_trial_fail(self):
        for problem in ('timeout', 'deadline', 'pending', 'count', 'redirect'):
            value = deepcopy(self.proof)
            trial = value['lifecycle_trials'][0]
            if problem == 'timeout': trial['lifecycle']['stages'][2]['ok'] = False
            elif problem == 'deadline': trial['lifecycle']['stages'][2]['deadline_seconds'] = 15
            elif problem == 'pending': trial['lifecycle']['pending_tasks_at_loop_close'] = 1
            elif problem == 'count': value['lifecycle_trials'].pop()
            else:
                for trial in value['lifecycle_trials']: trial['phase'] = 'normal'
            with self.subTest(problem=problem), self.assertRaises(ValueError):
                validate_public_evidence(self.manifest, value)

    def test_changed_live_hashes_and_manually_activated_template_fail(self):
        config = load(self.bundle / 'pilot.template.toml')
        arguments = [self.manifest['source_hash'], self.manifest['firewall_hash'],
            self.proof['normal_firewall_state_hash'], self.manifest['resolver_hash'], config,
            self.manifest['upstream_config_hash'], self.manifest['intake_manifest_hash']]
        for index in (0, 1, 2, 3, 5, 6):
            changed = list(arguments)
            changed[index] = '0' * 64
            with self.subTest(index=index), self.assertRaises(ValueError):
                check_public_activation(self.manifest, self.proof, *changed)
        config.network_isolation_verified = True
        with self.assertRaises(ValueError): check_public_activation(self.manifest, self.proof, *arguments)

    def test_protected_actual_report_hash_and_content_are_rechecked(self):
        with patch('study.deployment.secure_root_file', side_effect=lambda p: Path(p)):
            self.assertTrue(validate_public_evidence_files(self.proof))
            path = Path(self.proof['evidence_files']['kernel']['path'])
            path.write_text('{}')
            with self.assertRaises(ValueError): validate_public_evidence_files(self.proof)
            # Rehashing an empty replacement cannot turn copied success fields
            # into measured evidence: the complete frozen report must agree.
            digest = file_hash(path)
            self.proof['evidence_files']['kernel']['sha256'] = digest
            self.proof['kernel']['report_sha256'] = digest
            with self.assertRaises(ValueError): validate_public_evidence_files(self.proof)


if __name__ == '__main__':
    unittest.main()
