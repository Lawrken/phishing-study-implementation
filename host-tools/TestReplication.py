"""Replication checks: paths, identity pins and input integrity; no VM or Internet."""
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import PrepareResearchVM as setup
from ResearchPaths import host_configuration, pinned_host_line, ssh_configuration, validate_region


class ReplicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root/'.operator').mkdir()

    def configured(self):
        runtime=self.root/'local qemu';runtime.mkdir()
        for name in ('qemu-system-x86_64.exe','qemu-img.exe'):
            (runtime/name).write_bytes(b'fixture-only')
        for name in ('base.qcow2','key','known_hosts'):
            (self.root/name).write_bytes(b'fixture-only')
        value={'schema_version':1,'region':'Test City, Philippines','qemu_directory':'local qemu',
            'base_disk':'base.qcow2','base_format':'qcow2','base_sha256':'a'*64,
            'identity_file':'key','known_hosts_file':'known_hosts','guest_user':'studyadmin'}
        (self.root/'.operator/host.json').write_text(json.dumps(value))
        return value

    def test_fresh_clone_has_actionable_setup_error(self):
        with patch.dict(os.environ,{'PHISHING_STUDY_HOST_CONFIG':''},clear=False):
            os.environ.pop('PHISHING_STUDY_HOST_CONFIG')
            with self.assertRaisesRegex(ValueError,'SetupResearch'):
                host_configuration(self.root)

    def test_paths_resolve_from_clone_not_owner_downloads(self):
        self.configured()
        with patch.dict(os.environ,{'PHISHING_STUDY_HOST_CONFIG':str(self.root/'.operator/host.json')}):
            value=host_configuration(self.root)
        self.assertEqual(value['base_disk'],str(self.root/'base.qcow2'))
        config=ssh_configuration(value,self.root/'known_hosts')
        self.assertIn('StrictHostKeyChecking yes',config)
        self.assertIn('BatchMode yes',config)
        self.assertIn('Port 22243',config)
        self.assertIn(str(self.root).replace('\\','/'),config)

    def test_missing_credential_and_changed_config_fail_closed(self):
        value=self.configured()
        (self.root/'key').unlink()
        with patch.dict(os.environ,{'PHISHING_STUDY_HOST_CONFIG':str(self.root/'.operator/host.json')}):
            with self.assertRaisesRegex(ValueError,'identity_file'):host_configuration(self.root)
        value['base_sha256']='not-a-hash'
        (self.root/'.operator/host.json').write_text(json.dumps(value))
        with patch.dict(os.environ,{'PHISHING_STUDY_HOST_CONFIG':str(self.root/'.operator/host.json')}):
            with self.assertRaisesRegex(ValueError,'SHA-256'):host_configuration(self.root)

    def test_config_override_cannot_read_another_clone(self):
        with patch.dict(os.environ,{'PHISHING_STUDY_HOST_CONFIG':str(self.root.parent/'outside.json')}):
            with self.assertRaisesRegex(ValueError,'inside this clone'):host_configuration(self.root)

    def test_physical_region_is_required_and_not_inferred(self):
        for bad in ('','unknown',' Laoag','City\nCountry',None):
            with self.subTest(value=bad),self.assertRaises(ValueError):validate_region(bad)
        self.assertEqual(validate_region('Laoag City, Philippines'),'Laoag City, Philippines')

    def test_host_key_must_be_pinned_ed25519(self):
        self.assertEqual(pinned_host_line('ssh-ed25519 YWJj test'), '[127.0.0.1]:22243 ssh-ed25519 YWJj\n')
        for key in ('ssh-rsa YWJj','ssh-ed25519 malformed!',''):
            with self.assertRaises(ValueError):pinned_host_line(key)

    def test_changed_cached_download_is_preserved_without_network(self):
        p=self.root/'download.zip';p.write_bytes(b'changed')
        with patch('urllib.request.urlopen',side_effect=AssertionError('network forbidden')):
            with self.assertRaisesRegex(ValueError,'Cached download changed'):
                setup.download({'filename':p.name,'algorithm':'sha256','digest':'0'*64},self.root)
        self.assertEqual(p.read_bytes(),b'changed')

    def test_input_manifest_rejects_changed_archive_before_extraction(self):
        archive=self.root/'inputs.zip';archive.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'differs from the frozen release'):
            setup.verified_inputs(archive,self.root/'output')
        self.assertFalse((self.root/'output').exists())

    def test_seed_has_nocloud_names_and_per_machine_public_identity(self):
        import pycdlib
        path=self.root/'seed.iso'
        setup.make_seed(path,'ssh-ed25519 YWJj operator','SYNTHETIC PRIVATE HOST KEY','ssh-ed25519 ZGVm host')
        iso=pycdlib.PyCdlib();iso.open(str(path))
        data=io.BytesIO();iso.get_file_from_iso_fp(data,rr_path='/user-data')
        content=json.loads(data.getvalue().decode().split('\n',1)[1])
        iso.close()
        self.assertEqual(content['users'][0]['ssh_authorized_keys'],['ssh-ed25519 YWJj operator'])
        self.assertFalse(content['ssh_pwauth'])
        self.assertTrue(content['disable_root'])
        self.assertNotIn('operator_private_key',content)


if __name__=='__main__':unittest.main()
