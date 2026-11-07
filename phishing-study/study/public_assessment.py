"""Preserved verification, then at most one separately guarded labelled pilot."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import uuid

from .deployment import file_hash, source_hash, network_snapshot
from .preview_controls import snapshot, save
from .public_web import (validate_public_bundle, prepare_public_web, public_identity,
    validate_public_evidence, validate_public_evidence_files)

APP = Path(__file__).resolve().parents[1]
DATA = Path('/var/lib/phishing-study-public')
PYTHON = '/opt/phishing-study-fixtures/venv/bin/python'


def leaf(path, uid):
    path.mkdir(mode=0o700)
    os.chown(path, uid, pwd.getpwuid(uid).pw_gid)
    return path


def step(output, name, arguments, *, private_network=True, timeout=650, memory='2G', extra_properties=()):
    """Keep full console, journal, exit status, source and namespace receipts."""
    unit = 'study-public-' + name + '-' + uuid.uuid4().hex[:12]
    properties = ['--property=MemoryMax=' + memory, '--property=MemorySwapMax=0',
        '--property=CPUQuota=200%', '--property=TasksMax=512', '--property=TimeoutStopSec=60',
        '--property=RuntimeMaxSec=' + str(timeout), '--property=KillMode=control-group']
    if private_network:
        properties.append('--property=PrivateNetwork=yes')
    args = ['systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit=' + unit,
        *properties, *extra_properties, '--setenv=PYTHONPATH=' + str(APP), '--setenv=PYTHONDONTWRITEBYTECODE=1',
        '--setenv=PLAYWRIGHT_BROWSERS_PATH=/opt/phishing-study-fixtures/browsers',
        '--setenv=OMP_NUM_THREADS=2', '--setenv=OPENBLAS_NUM_THREADS=2', *map(str, arguments)]
    with (output / (name + '-console.txt')).open('x') as stream:
        code = subprocess.run(args, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout + 80).returncode
    (output / (name + '-journal.txt')).write_text(subprocess.check_output(
        ['journalctl', '-u', unit, '--no-pager'], text=True, timeout=15))
    save(output / (name + '-execution.json'), {'arguments': args, 'exit_code': code,
        'source_hash': source_hash(APP), 'unit': unit})
    if code != 0:
        raise RuntimeError(name + '_failed')


def assessment(a):
    if os.geteuid() != 0 or subprocess.check_output(['hostname'], text=True).strip() != 'phishing-study-ubuntu':
        raise ValueError('designated_VM_root_required')
    if a.output.exists() or not a.output.resolve().is_relative_to(DATA):
        raise ValueError('fresh_dedicated_assessment_required')
    a.output.mkdir(mode=0o755)
    result = {'status': 'failed', 'started_at': datetime.now(timezone.utc).isoformat(),
        'source_hash': source_hash(APP), 'passed': [], 'failed': [], 'not_tested': [],
        'network_isolation_verified': False, 'collection_activation': False, 'research_collection_count': 0,
        'region': getattr(a, 'region', 'Laoag City, Philippines')}
    before = snapshot(a.output, 'before')
    nonce = uuid.uuid4().hex
    try:
        if shutil.disk_usage(DATA).free < 15_000_000_000:
            raise RuntimeError('initial_15GB_disk_buffer_unavailable')
        uid, dnsuid = pwd.getpwnam('study-public').pw_uid, pwd.getpwnam('study-public-dns').pw_uid
        for value in (uid, dnsuid):
            if subprocess.run(['pgrep', '-u', str(value)], capture_output=True).returncode != 1:
                raise RuntimeError('dedicated_accounts_must_start_idle')
        from .phiusiil_intake import prepare, validate_intake
        intake = a.output / 'intake'
        completion = None
        if getattr(a, 'completion', None) is not None:
            from .deployment import secure_root_file
            from .phiusiil_completion import validate_completion
            completion = validate_completion(json.loads(secure_root_file(a.completion).read_text()))
            if getattr(a, 'completion_intake', None) is None:
                raise ValueError('separately_frozen_completion_intake_required')
            intake.mkdir(mode=0o755)
            for name in ('candidates.csv', 'intake-manifest.json'):
                shutil.copyfile(secure_root_file(a.completion_intake / name), intake / name)
            supplied = validate_intake(intake/'candidates.csv', intake/'intake-manifest.json')
            if supplied.get('completion') != completion or len(supplied['selected']) != 800:
                raise ValueError('completion_contract_or_full_frozen_reserve_changed')
        else:
            prepare(a.source_csv, a.membership, a.audit, intake, reserve_per_class=200, seed=20261010)
        validate_intake(intake / 'candidates.csv', intake / 'intake-manifest.json', a.source_csv, a.membership, a.audit)
        intake.chmod(0o755)
        for path in intake.iterdir():
            path.chmod(0o644)
        result['passed'].append(('800 phishing-only reserve excluding all previous reserve groups' if completion else '400-reserve')
            + ' frozen from original homogeneous training groups; original-input replay passed')
        bundle = a.output / 'bundle'
        continuation = None
        if getattr(a,'continuation',None) is not None:
            from .deployment import secure_root_file
            from .campaign_continuation import validate_continuation
            from .sources import read_dataset_intake
            from .urls import digest,canonical_url
            continuation=json.loads(secure_root_file(a.continuation).read_text())
            validate_continuation(continuation,a.max_attempts,
                {digest(canonical_url(row['url'])) for row in read_dataset_intake(intake/'candidates.csv',intake/'intake-manifest.json')},
                attempt_limit=800 if completion else 400)
            save(a.output/'continuation.json',continuation)
        topology = network_snapshot()
        prepare_public_web(bundle, region=result['region'], uid=uid, resolver_uid=dnsuid, root=APP,
            **topology, intake_manifest_hash=file_hash(intake / 'intake-manifest.json'),
            upstream_config_hash=file_hash('/run/systemd/resolve/resolv.conf'),
            max_attempts=getattr(a, 'max_attempts', 400),
            usable_per_class=getattr(a, 'usable_per_class', 50),continuation=continuation,completion=completion,
            live_view=getattr(a, 'live_view', False),
            dataset_observation=getattr(a, 'dataset_observation', False))
        for path in bundle.rglob('*'):
            path.chmod(0o755 if path.is_dir() else 0o644)
        manifest = validate_public_bundle(bundle, root=APP)
        result['identity'] = public_identity(manifest)
        # No Internet interface is present in these test units.
        step(a.output, 'suite', [PYTHON, APP / 'scripts/verify.py', '--require-browser', '--output', a.output / 'suite'])
        suite = json.loads((a.output / 'suite/test-report.json').read_text())
        suite['source_hash'] = manifest['source_hash']
        save(a.output / 'suite-report.json', suite)
        result['passed'].append('complete Linux/Chromium suite')
        step(a.output, 'selftest', [PYTHON, '-m', 'study', 'selftest', '--output', a.output / 'selftest'])
        fixture = json.loads((a.output / 'selftest/fixture-report.json').read_text())
        fixture['source_hash'] = manifest['source_hash']
        save(a.output / 'selftest-report.json', fixture)
        result['passed'].append('separate fixture selftest')
        private_parent = DATA / 'verification-private'
        private_parent.mkdir(mode=0o755, exist_ok=True)
        kernel_private = leaf(private_parent / ('kernel-' + nonce), uid)
        outer_inode = os.stat('/proc/self/ns/net').st_ino
        step(a.output, 'kernel', [PYTHON, '-m', 'study.public_kernel', '--bundle', bundle,
            '--output', a.output / 'kernel', '--private', kernel_private,
            '--outer-inode', outer_inode, '--nonce', nonce], timeout=600,
            extra_properties=['--property=BindReadOnlyPaths=' + str(bundle / 'resolver/resolv.conf')
                + ':/etc/resolv.conf ' + str(bundle / 'resolver/nsswitch.conf') + ':/etc/nsswitch.conf'])
        kernel = json.loads((a.output / 'kernel/kernel-report.json').read_text())
        trials = json.loads((a.output / 'kernel/lifecycle-trials.json').read_text())
        result['passed'].append('exact installed kernel policy and ten clean lifecycle trials')
        if getattr(a, 'dataset_observation', False):
            from .observation import freeze_evidence
            proof = freeze_evidence(a.output, bundle, manifest, suite, fixture, kernel, trials,
                nonce, result['started_at'], leaf(private_parent / ('stop-' + nonce), uid))
            result.update(status='passed', observation_allowed=True,
                verification_profile=manifest['verification_profile'],
                public_dns_verified=False, public_tls_verified=False)
            result['passed'].append('generated-service cancellation; dataset outcomes enabled without owned-site visits')
            result['not_tested'].append('owned-site Internet verification: excluded from dataset-observation purpose')
            return result
        from .public_connection import run_connected
        connected = run_connected(bundle, a.output / 'connected', leaf(private_parent / ('connected-' + nonce), uid),
            leaf(private_parent / ('connected-dns-' + nonce), dnsuid), a.output / 'connected-phase.txt', nonce)
        if connected['status'] != 'passed':
            raise RuntimeError('connected_owned_site_failed')
        result['passed'].append('installed owned-site normal/blocked/restored checks')
        paths = {'suite': a.output / 'suite-report.json', 'selftest': a.output / 'selftest-report.json',
            'kernel': a.output / 'kernel/kernel-report.json', 'connected': a.output / 'connected/connected-report.json',
            'lifecycle': a.output / 'kernel/lifecycle-trials.json',
            'connected_collector_service': a.output / 'connected/normal-runtime.service',
            'connected_resolver_service': a.output / 'connected/resolver-runtime.service'}
        frozen = a.output / 'frozen-evidence'
        frozen.mkdir(mode=0o755)
        for name, path in list(paths.items()):
            target = frozen / (name + path.suffix)
            shutil.copyfile(path, target)
            target.chmod(0o644)
            paths[name] = target
        evidence = {**public_identity(manifest), 'status': 'passed', 'network_isolation_verified': True,
            'activation_allowed': True, 'research_collection_count': 0, 'nonce': nonce,
            'started_at': result['started_at'], 'finished_at': datetime.now(timezone.utc).isoformat(),
            'claims': manifest['claims'], 'lifecycle_trials': trials['trials'],
            'evidence_files': {name: {'path': str(path), 'sha256': file_hash(path)} for name, path in paths.items()},
            'cleanup': {'accounts_idle': connected['checks']['accounts_idle'],
                'listeners_stopped': connected['checks']['receivers_stopped'],
                **{name: connected['checks'][name] for name in ('outer_firewall_restored', 'outer_dns_nss_hosts_unchanged', 'source_unchanged')}}}
        for name, value in (('suite', suite), ('selftest', fixture), ('kernel', kernel), ('connected', connected)):
            evidence[name] = {**value, 'report_sha256': file_hash(paths[name])}
        for name in ('normal_firewall_state_hash', 'runtime_service_hash', 'runtime_resolver_service_hash'):
            evidence[name] = connected[name]
        validate_public_evidence(manifest, evidence)
        # Root-freeze report copies. Service-owned raw artifacts remain separate.
        for path in paths.values():
            path.chmod(0o644)
        evidence_path = a.output / 'deployment-evidence.json'
        save(evidence_path, evidence)
        evidence_path.chmod(0o644)
        validate_public_evidence_files(evidence)
        result['network_isolation_verified'] = True
        if a.run_pilot:
            from .public_pilot import run_pilot
            pilot = run_pilot(bundle, evidence_path, intake, a.output / 'pilot',
                leaf(a.output / 'pilot-private', uid), leaf(a.output / 'pilot-dns', dnsuid),
                a.output / 'pilot-phase.txt', nonce)
            result['pilot'] = pilot
            result['collection_activation'] = pilot.get('collection_activation') is True
            result['dataset_visit_attempts'] = pilot.get('attempts', 0)
            result['distinct_dataset_urls_attempted'] = pilot.get('distinct_urls_attempted', 0)
            result['dataset_label_usable_per_class'] = pilot.get('usable_per_class', {'legitimate': 0, 'phishing': 0})
            result['research_collection_count'] = sum(result['dataset_label_usable_per_class'].values())
            result['collection_count_policy'] = 'Technically usable dataset-label captures; current labels are not independently verified.'
            if pilot.get('status') != 'passed':
                raise RuntimeError('bounded_pilot_failed')
        else:
            result['not_tested'].append('dataset pilot not requested by command')
        result['status'] = 'passed'
    except BaseException as error:
        result['failed'].append({'stage': str(error)[:500], 'error_type': type(error).__name__})
        if not result['collection_activation']:
            result['not_tested'].append('dataset-site pilot: deployment checks incomplete; no activation')
    finally:
        after = snapshot(a.output, 'after')
        from .deployment import firewall_state_hash
        result['final_cleanup'] = {'outer_firewall_restored': firewall_state_hash(before['firewall']) == firewall_state_hash(after['firewall']),
            'outer_dns_nss_hosts_unchanged': before['dns'] == after['dns'],
            'source_unchanged': source_hash(APP) == result['source_hash']}
        if not all(result['final_cleanup'].values()):
            result['status'] = 'failed'
        result['finished_at'] = datetime.now(timezone.utc).isoformat()
        save(a.output / 'assessment-result.json', result)
        lines = ['# Public-web deployment and bounded pilot assessment', '', 'Status: ' + result['status'],
            '', 'Region: ' + result['region'] + ' (operator supplied).', '', '## Passed', '']
        lines += ['- ' + row for row in result['passed']]
        lines += ['', '## Failed', ''] + ['- ' + json.dumps(row) for row in result['failed']]
        lines += ['', '## Not tested', ''] + ['- ' + row for row in result['not_tested']]
        lines += ['', 'The historical labels were preserved. No model was retrained. Local DNS logging is not authoritative DNS evidence.']
        (a.output / 'REPORT.md').write_text('\n'.join(lines) + '\n')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'source-csv', 'membership', 'audit'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--run-pilot', action='store_true')
    parser.add_argument('--region', default='Laoag City, Philippines',
                        help='Actual operator-confirmed collection city and country')
    parser.add_argument('--dataset-observation', action='store_true',
                        help='Verify local containment for dataset outcomes; do not visit an owned site')
    parser.add_argument('--live-view', action='store_true', help='Bind browser screenshot monitoring into this run identity')
    parser.add_argument('--max-attempts', type=int, default=400,
                        help='Lower remaining operational budget; never more than 400')
    parser.add_argument('--usable-per-class', type=int, default=50,
                        help='Explicit published-label target; does not expand time or attempt limits')
    parser.add_argument('--continuation',type=Path,
                        help='Root-owned receipt of every prior attempted identity in the same frozen reserve')
    parser.add_argument('--completion',type=Path,
                        help='Root-owned explicit separate phishing completion contract; old defaults remain unchanged')
    parser.add_argument('--completion-intake',type=Path,
                        help='Root-owned already-frozen 800-row phishing-only reserve')
    result = assessment(parser.parse_args(argv))
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
