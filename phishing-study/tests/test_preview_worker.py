"""Pure and mocked preview worker boundaries; no browsers or external DNS."""
import errno
from pathlib import Path
import socket
import unittest
from unittest.mock import MagicMock, patch

from study import preview_worker as worker

URL = 'https://d-tx-t.vercel.app/'


class PreviewWorkerTests(unittest.TestCase):
    def test_only_exact_owned_origin_passive_subresources(self):
        self.assertTrue(worker.request_allowed(URL + 'script.js?q=1', 'GET', owned_url=URL))
        self.assertTrue(worker.request_allowed(URL + 'style.css', 'HEAD', owned_url=URL))
        for target in ('http://d-tx-t.vercel.app/', 'https://other.example/',
                       'https://d-tx-t.vercel.app.evil.example/', 'https://user@d-tx-t.vercel.app/',
                       'https://d-tx-t.vercel.app:8443/', 'file:///secret', 'https://d-tx-t.vercel.app:bad/'):
            with self.subTest(target=target):
                self.assertFalse(worker.request_allowed(target, 'GET', owned_url=URL))
        for method in ('POST', 'PUT', 'CONNECT', 'DELETE'):
            self.assertFalse(worker.request_allowed(URL, method, owned_url=URL))

    def test_navigation_requires_initial_exact_main_frame_homepage(self):
        self.assertTrue(worker.request_allowed(URL, 'GET', owned_url=URL, navigation=True, main_frame=True))
        for options in ({'main_frame': False}, {'main_frame': True, 'admitted_count': 1}):
            self.assertFalse(worker.request_allowed(URL, 'GET', owned_url=URL, navigation=True, **options))
        self.assertFalse(worker.request_allowed(URL + 'login', 'GET', owned_url=URL, navigation=True, main_frame=True))

    def test_soft_request_and_transfer_caps_stop_new_admissions(self):
        self.assertFalse(worker.request_allowed(URL, 'GET', owned_url=URL, admitted_count=128))
        self.assertFalse(worker.request_allowed(URL, 'GET', owned_url=URL, completed_bytes=20_000_000))

    def test_phase_requires_exact_denial_case(self):
        worker.validate_phase('normal', None)
        worker.validate_phase('denied', 'private')
        for phase, case in (('normal', 'private'), ('blocked', 'ipv6'), ('denied', None), ('denied', 'unknown'), ('other', None)):
            with self.assertRaises(ValueError):
                worker.validate_phase(phase, case)

    def test_native_error_or_correlated_error_is_required_without_timeout(self):
        nav = {'status': None, 'error_type': 'Error', 'native_dns_error': 'net::ERR_NAME_NOT_RESOLVED'}
        network = {'response_count': 0, 'completed_encoded_bytes': 0}
        self.assertTrue(worker.blackout_proved(nav, network, {'ok': False}))
        nav['native_dns_error'] = 'net::ERR_INTERNET_DISCONNECTED'
        self.assertFalse(worker.blackout_proved(nav, network, {'ok': False}))
        self.assertTrue(worker.blackout_proved(nav, network, {'ok': True}))
        nav['error_type'] = 'TimeoutError'
        self.assertFalse(worker.blackout_proved(nav, network, {'ok': True}))

    def test_http_response_or_bytes_prevent_blackout_pass(self):
        nav = {'status': None, 'error_type': 'Error', 'native_dns_error': 'net::ERR_NAME_NOT_RESOLVED'}
        self.assertFalse(worker.blackout_proved(nav, {'response_count': 1, 'completed_encoded_bytes': 0}, {'ok': True}))
        self.assertFalse(worker.blackout_proved(nav, {'response_count': 0, 'completed_encoded_bytes': 1}, {'ok': True}))
        self.assertFalse(worker.blackout_proved({**nav, 'status': 200}, {'response_count': 0, 'completed_encoded_bytes': 0}, {'ok': True}))

    def test_denial_timeout_is_inconclusive(self):
        report = {'checks': {}}
        connection = MagicMock()
        connection.connect.side_effect = TimeoutError()
        with patch.object(worker.socket, 'socket') as create:
            create.return_value.__enter__.return_value = connection
            worker.denial(report, 'private')
        self.assertFalse(report['checks']['categorical_denial']['ok'])
        self.assertEqual(report['denial']['errno'], 'timeout_inconclusive')

    def test_denial_categorical_error_recorded_but_success_cannot_pass(self):
        for error, expected in ((OSError(errno.ECONNREFUSED, 'refused'), True), (OSError(errno.EBADF, 'bad'), False), (None, False)):
            report = {'checks': {}}
            connection = MagicMock()
            connection.connect.side_effect = error
            with patch.object(worker.socket, 'socket') as create:
                create.return_value.__enter__.return_value = connection
                worker.denial(report, 'alternate_tcp')
            self.assertEqual(report['checks']['categorical_denial']['ok'], expected)

    def test_ipv6_address_family_denial_is_distinct_and_not_valid_for_ipv4(self):
        for case, expected in (('ipv6', True), ('private', False)):
            report = {'checks': {}}
            with patch.object(worker.socket, 'socket', side_effect=OSError(errno.EAFNOSUPPORT, 'blocked family')):
                worker.denial(report, case)
            self.assertEqual(report['checks']['categorical_denial']['ok'], expected)
            self.assertIn(report['denial']['errno'], {'EAFNOSUPPORT', 'WSAEAFNOSUPPORT'})

    def test_failed_bundle_stops_before_identity_or_resources(self):
        with patch.object(worker, 'validate_preview_bundle', side_effect=ValueError('mismatch')), \
             patch.object(worker, 'worker_identity_matches') as account, patch.object(worker, 'resource_limits') as resources:
            with self.assertRaises(ValueError):
                worker.preflight({'checks': {}, 'phase': 'normal'}, Path('/unused'))
        account.assert_not_called()
        resources.assert_not_called()

    def test_preflight_requires_account_resources_and_bound_dns(self):
        manifest = {'study_uid': 999, 'owned_controls': {'https_url': URL},
                    'resources': {'memory_max_bytes': 2147483648}}
        for account, memory, bound in ((False, '2147483648', True), (True, '4294967296', True), (True, 'max', True), (True, '2147483648', False)):
            report = {'checks': {}, 'phase': 'normal'}
            with patch.object(worker, 'validate_preview_bundle', return_value=manifest), \
                 patch.object(worker, 'preview_identity', return_value={'verification_profile': worker.PROFILE}), \
                 patch.object(worker, 'worker_identity_matches', return_value=account), \
                 patch.object(worker, 'resource_limits', return_value={'ok': True, 'memory_max': memory}), \
                 patch.object(worker, 'resolver_valid', return_value=bound), patch.object(Path, 'read_text', return_value=''):
                with self.assertRaises(RuntimeError):
                    worker.preflight(report, Path('/unused'))
                self.assertTrue(any(not value['ok'] for value in report['checks'].values()))


if __name__ == '__main__':
    unittest.main()
