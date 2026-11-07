"""Machine-local paths and pinned SSH identity; never committed with credentials."""
import json
import os
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def validate_region(value):
    if (not isinstance(value, str) or value != value.strip() or len(value) > 160
            or value.lower() in {'', 'unknown', 'unspecified', 'todo'}
            or any(ord(c) < 32 for c in value)):
        raise ValueError('Supply the actual collection city and country in setup.')
    return value


def host_configuration(root=ROOT):
    root = Path(root).resolve()
    path = Path(os.environ.get('PHISHING_STUDY_HOST_CONFIG', str(root / '.operator/host.json'))).resolve()
    if not path.is_relative_to(root):
        raise ValueError('Machine configuration must stay inside this clone.')
    if not path.exists():
        raise ValueError('Run host-tools/SetupResearch.ps1 first. No VM has been configured on this computer.')
    value = json.loads(path.read_text(encoding='utf-8-sig'))
    if value.get('schema_version') != 1 or value.get('base_format') not in {'raw', 'qcow2'}:
        raise ValueError('Unsupported machine configuration.')
    validate_region(value.get('region'))
    if re.fullmatch(r'[a-f0-9]{64}', value.get('base_sha256', '')) is None:
        raise ValueError('Pinned base disk SHA-256 required.')
    if re.fullmatch(r'[a-z][a-z0-9_-]{0,31}', value.get('guest_user', '')) is None:
        raise ValueError('Invalid VM administration account.')
    for name in ('qemu_directory', 'base_disk', 'identity_file', 'known_hosts_file'):
        path = Path(value[name]).expanduser()
        value[name] = str((root/path).resolve() if not path.is_absolute() else path.resolve())
    for name in ('base_disk', 'identity_file', 'known_hosts_file'):
        if not Path(value[name]).is_file():
            raise ValueError('Missing local prerequisite: ' + name + '. Run SetupResearch.ps1.')
    for name in ('qemu-system-x86_64.exe', 'qemu-img.exe'):
        if not (Path(value['qemu_directory'])/name).is_file():
            raise ValueError('Missing QEMU executable: ' + name)
    return value


def ssh_configuration(value, known_hosts):
    def quoted(path):
        text = str(Path(path).resolve()).replace('\\', '/')
        if any(c in text for c in ('"', '\n', '\r')):
            raise ValueError('Invalid SSH path.')
        return '"' + text + '"'
    return ('Host study-vm\n  HostName 127.0.0.1\n  Port 22243\n'
        '  User ' + value['guest_user'] + '\n  IdentityFile ' + quoted(value['identity_file'])
        + '\n  UserKnownHostsFile ' + quoted(known_hosts)
        + '\n  StrictHostKeyChecking yes\n  IdentitiesOnly yes\n  BatchMode yes\n')


def pinned_host_line(public_key):
    parts = public_key.strip().split()
    if len(parts) < 2 or parts[0] != 'ssh-ed25519' or re.fullmatch(r'[A-Za-z0-9+/=]+', parts[1]) is None:
        raise ValueError('An ed25519 VM host public key is required.')
    return '[127.0.0.1]:22243 ' + ' '.join(parts[:2]) + '\n'
