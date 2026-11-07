"""Pure rendering/atomic-state regressions; no resolver or receiver is contacted."""
import os
import stat
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from study import preview_controls as controller
from study.local_preview import firewall_template


TABLE = "study_preview_0123456789abcdef"


class PreviewControlRenderingTests(unittest.TestCase):
    def test_service_retains_all_environment_lines_and_argument_boundaries(self):
        template = ('[Service]\nType=exec\nUser=999\nMemoryMax=2G\n'
                    'Environment="PYTHONPATH=/opt/owned-app"\n'
                    'Environment="EXISTING=two words"\n'
                    'ExecStart=@@PYTHON@@ -m study.preview_worker --phase @@PHASE@@\n')
        rendered, properties, execution = controller.render_service(
            template, {'PYTHON': '/opt/venv/bin/python', 'PHASE': 'blocked'},
            '/var/lib/owned/private',
            {'HOME': '/var/lib/owned/private', 'EXTRA': 'spaces and = signs',
             'LITERAL': '$HOME/unchanged;echo untouched'})
        self.assertEqual(execution, ['/opt/venv/bin/python', '-m', 'study.preview_worker', '--phase', 'blocked'])
        self.assertIn('--property=Type=exec', properties)
        self.assertIn('--property=User=999', properties)
        self.assertIn('--property=MemoryMax=2G', properties)
        self.assertIn('--property=ReadWritePaths=/var/lib/owned/private', properties)
        for environment in ('PYTHONPATH=/opt/owned-app', 'EXISTING=two words',
                            'HOME=/var/lib/owned/private', 'EXTRA=spaces and = signs',
                            'LITERAL=$HOME/unchanged;echo untouched'):
            self.assertIn('--setenv=' + environment, properties)
        self.assertFalse(any(value.startswith(('--property=ExecStart=', '--property=Environment=')) for value in properties))
        self.assertNotIn('@@', rendered)

    def test_service_rejects_unfilled_runtime_token(self):
        with self.assertRaisesRegex(ValueError, 'incomplete_service_template'):
            controller.render_service('[Service]\nExecStart=/usr/bin/python @@OUTPUT@@\n', {}, '/owned', {})

    def test_service_rejects_substitution_line_or_nul_injection(self):
        template = '[Service]\nExecStart=/usr/bin/python @@OUTPUT@@\n'
        for value in ('/owned\nUser=root', '/owned\rUser=root', '/owned\x00hidden'):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'invalid_service_substitution'):
                controller.render_service(template, {'OUTPUT': value}, '/owned', {})

    def test_service_environment_quotes_are_preserved_without_shell_interpretation(self):
        _, properties, execution = controller.render_service(
            '[Service]\nExecStart=/usr/bin/python -m owned\n', {}, '/owned',
            {'TEXT': 'a "quoted" value', 'VALUE': 'a=b=c'})
        self.assertIn('--setenv=TEXT=a "quoted" value', properties)
        self.assertIn('--setenv=VALUE=a=b=c', properties)
        self.assertEqual(execution, ['/usr/bin/python', '-m', 'owned'])

    def test_service_rejects_writable_path_property_injection(self):
        for value in ('/owned\nUser=root', '/owned\rReadWritePaths=/', '/owned\x00suffix'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                controller.render_service('[Service]\nExecStart=/usr/bin/python\n', {}, value, {})

    def test_service_rejects_environment_line_injection(self):
        for environment in ({'KEY': 'value\nUser=root'}, {'KEY\rExecStart': 'value'}, {'KEY': 'value\x00suffix'}):
            with self.subTest(environment=environment), self.assertRaises(ValueError):
                controller.render_service('[Service]\nExecStart=/usr/bin/python\n', {}, '/owned', environment)

    def test_service_rejects_whitespace_exec_path_substitutions(self):
        for value in ('/opt/path with space/python', '/opt/path\twith-tab/python'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                controller.render_service('[Service]\nExecStart=@@PYTHON@@ -m owned\n', {'PYTHON': value}, '/owned', {})

    def test_firewall_admits_only_deduplicated_public_owned_ips_and_exact_dns(self):
        # Public-shaped strings are inert parser fixtures, never network probes.
        policy = controller.render_firewall(firewall_template(999), TABLE,
            ['93.184.216.35', '93.184.216.34', '93.184.216.35'], ['10.0.2.15'], ['10.0.2.2'])
        self.assertNotIn('@@', policy)
        self.assertIn('table inet ' + TABLE, policy)
        self.assertIn('meta skuid 999 jump workload', policy)
        self.assertIn('ip daddr { 93.184.216.34, 93.184.216.35 } tcp dport 443 counter accept', policy)
        self.assertIn('ip daddr 127.0.0.153 udp dport 53 counter accept', policy)
        self.assertIn('ip daddr 127.0.0.153 tcp dport 53 counter accept', policy)
        self.assertIn('meta nfproto ipv6 counter reject', policy)
        self.assertLess(policy.index('jump dns_allow'), policy.index('meta nfproto ipv6'))
        self.assertNotIn('tcp dport 80', policy)
        self.assertNotIn('10.0.2.15', policy)

    def test_firewall_rejects_vm_or_gateway_even_when_public_shaped(self):
        for local, gateway in ((['93.184.216.34'], []), ([], ['93.184.216.34'])):
            with self.subTest(local=local, gateway=gateway), self.assertRaisesRegex(ValueError, 'public_owned_control_ipv4_required'):
                controller.render_firewall(firewall_template(999), TABLE, ['93.184.216.34'], local, gateway)

    def test_firewall_rejects_empty_private_loopback_metadata_ipv6_and_bad_addresses(self):
        for addresses in ([], ['10.0.0.1'], ['127.0.0.1'], ['169.254.169.254'],
                          ['192.0.2.1'], ['::1'], ['2606:4700:4700::1111'], ['not-an-ip'],
                          ['93.184.216.34', '10.0.0.1']):
            with self.subTest(addresses=addresses), self.assertRaises(ValueError):
                controller.render_firewall(firewall_template(999), TABLE, addresses, [], [])

    def test_firewall_rejects_untrusted_table_name(self):
        for table in ('study_egress', 'study_preview_ABCDEF0123456789',
                      TABLE + '\nflush ruleset', TABLE + '; flush ruleset',
                      'study_preview_0123', 'study_preview_' + 'a' * 17):
            with self.subTest(table=table), self.assertRaisesRegex(ValueError, 'invalid_preview_table'):
                controller.render_firewall(firewall_template(999), table, ['93.184.216.34'], [], [])


class PreviewAtomicPhaseTests(unittest.TestCase):
    def test_phase_update_keeps_old_bytes_until_atomic_replace(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            phase = Path(directory) / 'phase'
            phase.write_text('preparation\n')
            original_replace = os.replace
            seen = []
            def replace(source, destination):
                seen.append((phase.read_text(), Path(source).read_text(), Path(destination)))
                original_replace(source, destination)
            with mock.patch.object(controller.os, 'replace', side_effect=replace):
                controller.phase_label(phase, 'workload-normal')
            self.assertEqual(seen, [('preparation\n', 'workload-normal\n', phase)])
            self.assertEqual(phase.read_text(), 'workload-normal\n')
            self.assertFalse(phase.with_name('phase.next').exists())
            if os.name == 'posix':
                self.assertEqual(phase.stat().st_mode & 0o777, 0o644)

    def test_failed_phase_fsync_preserves_previous_phase(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            phase = Path(directory) / 'phase'
            phase.write_text('workload-normal\n')
            with mock.patch.object(controller.os, 'fsync', side_effect=OSError('disk unavailable')):
                with self.assertRaises(OSError):
                    controller.phase_label(phase, 'workload-blocked')
            self.assertEqual(phase.read_text(), 'workload-normal\n')
            self.assertTrue(phase.with_name('phase.next').exists())

    def test_existing_phase_next_is_preserved_instead_of_overwritten(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            phase = Path(directory) / 'phase'
            phase.write_text('workload-normal\n')
            pending = phase.with_name('phase.next')
            pending.write_text('preserve failed attempt\n')
            with self.assertRaises(FileExistsError):
                controller.phase_label(phase, 'workload-blocked')
            self.assertEqual(phase.read_text(), 'workload-normal\n')
            self.assertEqual(pending.read_text(), 'preserve failed attempt\n')


class PreviewStorageTests(unittest.TestCase):
    def test_separate_private_leaves_under_root_owned_storage(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            base = Path(directory)
            worker, resolver, phase = base / 'worker', base / 'dns', base / 'phase'
            def info(path):
                owner = 900 if path == worker else 901 if path == resolver else 0
                mode = 0o700 if path in (worker, resolver) else 0o755
                return SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=owner)
            with mock.patch.object(controller, 'PRIVATE_ROOT', base), \
                 mock.patch.object(controller, 'secure_root_file', return_value=phase), \
                 mock.patch.object(Path, 'lstat', autospec=True, side_effect=info):
                controller.validate_runtime_storage(worker, resolver, phase, 900, 901)

    def test_browser_owned_parent_cannot_host_separate_dns_service(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            base = Path(directory)
            worker, resolver, phase = base / 'worker', base / 'dns', base / 'phase'
            def info(path):
                owner = 900 if path in (worker, base) else 901 if path == resolver else 0
                return SimpleNamespace(st_mode=stat.S_IFDIR | (0o700 if path in (worker, resolver, base) else 0o755), st_uid=owner)
            with mock.patch.object(controller, 'PRIVATE_ROOT', base), \
                 mock.patch.object(controller, 'secure_root_file', return_value=phase), \
                 mock.patch.object(Path, 'lstat', autospec=True, side_effect=info):
                with self.assertRaisesRegex(ValueError, 'root_owned_runtime_ancestors_required'):
                    controller.validate_runtime_storage(worker, resolver, phase, 900, 901)

    def test_shared_or_readable_service_leaf_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            base = Path(directory)
            for mode in (0o755, 0o750, 0o770):
                with mock.patch.object(controller, 'PRIVATE_ROOT', base), \
                     mock.patch.object(controller, 'secure_root_file'), \
                     mock.patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=900)):
                    with self.assertRaisesRegex(ValueError, 'private_service_storage_required'):
                        controller.validate_runtime_storage(base / 'worker', base / 'dns', base / 'phase', 900, 901)

    def test_existing_fixture_storage_is_not_repurposed(self):
        with self.assertRaisesRegex(ValueError, 'dedicated_preview_runtime_storage_required'):
            controller.validate_runtime_storage(Path('/var/lib/phishing-study-fixtures/worker'),
                Path('/var/lib/phishing-study-fixtures/dns'), Path('/var/lib/phishing-study-fixtures/phase'), 900, 901)


if __name__ == '__main__':
    unittest.main()
