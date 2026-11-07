"""Dataset outcomes after measured local controls, without an owned-site visit.

This purpose has its own identity and cannot satisfy the public-web approval
gate. An unavailable website is an observation, not a verification failure.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil


def validate_tail(manifest, evidence, start, end):
    from .public_web import (_checks, _hash, _lifecycle, CLEANUP_CHECKS,
                             SERVICE_STOP_CHECKS)
    now = datetime.now(timezone.utc).timestamp()
    if not 0 <= now - end.timestamp() <= 300 or (end - start).total_seconds() > 1200:
        raise ValueError('fresh_observation_verification_required')
    if (evidence.get('public_dns_verified') is not False
            or evidence.get('public_tls_verified') is not False or 'connected' in evidence):
        raise ValueError('observation_cannot_claim_owned_internet_verification')
    trials = evidence.get('lifecycle_trials')
    if not isinstance(trials, list) or len(trials) != 10:
        raise ValueError('ten_clean_lifecycle_trials_required')
    if not {'normal', 'redirect'}.issubset({t.get('phase') for t in trials if isinstance(t, dict)}):
        raise ValueError('normal_and_redirect_trials_required')
    for trial in trials:
        if trial.get('status') != 'passed' or trial.get('source_hash') != manifest['source_hash']:
            raise ValueError('source_bound_lifecycle_trial_required')
        _hash(trial.get('report_sha256'), 'lifecycle report')
        _lifecycle(trial, manifest['study_uid'])
    stop = evidence.get('service_stop', {})
    if (stop.get('status') != 'passed' or stop.get('worker_exit') != 0
            or stop.get('source_hash') != manifest['source_hash'] or stop.get('uid') != manifest['study_uid']
            or stop.get('signal_seen') != 'SIGTERM'
            or any(stop.get(k) is not True for k in ('stop_sent', 'namespace_disconnected', 'collection_account_idle'))):
        raise ValueError('generated_service_cancellation_required')
    _checks(stop.get('checks'), SERVICE_STOP_CHECKS, 'service stop')
    _hash(stop.get('report_sha256'), 'service stop report')
    _hash(stop.get('runtime_service_hash'), 'service stop unit')
    _lifecycle(stop, manifest['study_uid'])
    _checks(evidence.get('cleanup'), CLEANUP_CHECKS, 'cleanup')
    files = evidence.get('evidence_files', {})
    if set(files) != {'suite', 'selftest', 'kernel', 'lifecycle', 'service_stop'}:
        raise ValueError('exact_frozen_observation_reports_required')
    for key, item in files.items():
        if not Path(item.get('path', '')).is_absolute():
            raise ValueError('absolute_frozen_report_path_required')
        _hash(item.get('sha256'), key)
        if key in {'suite', 'selftest', 'kernel'} and item['sha256'] != evidence[key].get('report_sha256'):
            raise ValueError('frozen_report_identity_changed')
    return True


def freeze_evidence(output, bundle, manifest, suite, fixture, kernel, trials, nonce, started, private):
    from .deployment import file_hash, firewall_state_hash, source_hash
    from .preview_controls import command, reject_counter, save, snapshot
    from .public_web import NFT_TABLE, public_identity, validate_execution_evidence, validate_public_evidence_files
    from .service_stop_control import run_service_stop
    before = snapshot(output, 'observation-before')
    # Only disconnected loopback fixtures are used for the generated-service stop.
    stopdir = output / 'stop-control'
    stopdir.mkdir(mode=0o755)
    stop = run_service_stop(bundle, stopdir, private,
        {'PYTHON': __import__('sys').executable, 'BUNDLE': bundle, 'OUTPUT': private,
         'DNS_UNIT': 'network.target'},
        {'PYTHONDONTWRITEBYTECODE': '1', 'PLAYWRIGHT_BROWSERS_PATH': '/opt/phishing-study-fixtures/browsers',
         'HOME': str(private), 'OMP_NUM_THREADS': '2', 'OPENBLAS_NUM_THREADS': '2'}, nonce)
    # Bind the actual installed policy state without making any Internet request.
    installed = False
    try:
        command('nft', '-c', '-f', str(bundle / 'collector.nft'))
        command('nft', '-f', str(bundle / 'collector.nft'))
        installed = True
        policy_hash = reject_counter(NFT_TABLE)['policy_hash']
    finally:
        if installed:
            command('nft', 'delete', 'table', 'inet', NFT_TABLE)
    paths = {'suite': output / 'suite-report.json', 'selftest': output / 'selftest-report.json',
             'kernel': output / 'kernel/kernel-report.json', 'lifecycle': output / 'kernel/lifecycle-trials.json',
             'service_stop': stopdir / 'service-stop-report.json'}
    frozen = output / 'frozen-evidence'
    frozen.mkdir(mode=0o755)
    for key, path in list(paths.items()):
        target = frozen / (key + '.json')
        shutil.copyfile(path, target)
        target.chmod(0o644)
        paths[key] = target
    after = snapshot(output, 'observation-after')
    import subprocess
    idle = all(subprocess.run(['pgrep', '-u', str(uid)], capture_output=True).returncode == 1
               for uid in (manifest['study_uid'], manifest['resolver']['uid']))
    proof = {**public_identity(manifest), 'status': 'passed', 'network_isolation_verified': False,
        'activation_allowed': False, 'observation_allowed': True,
        'public_dns_verified': False, 'public_tls_verified': False,
        'research_collection_count': 0, 'nonce': nonce,
        'started_at': started, 'finished_at': datetime.now(timezone.utc).isoformat(),
        'claims': manifest['claims'], 'lifecycle_trials': trials['trials'], 'service_stop': stop,
        'normal_firewall_state_hash': policy_hash,
        'evidence_files': {key: {'path': str(p), 'sha256': file_hash(p)} for key, p in paths.items()},
        'cleanup': {'accounts_idle': idle,
                    'listeners_stopped': idle and kernel['status'] == 'passed' and stop['collection_account_idle'],
                    'outer_firewall_restored': firewall_state_hash(before['firewall']) == firewall_state_hash(after['firewall']),
                    'outer_dns_nss_hosts_unchanged': before['dns'] == after['dns'],
                    'source_unchanged': source_hash(manifest['source_root']) == manifest['source_hash']}}
    for key, value in (('suite', suite), ('selftest', fixture), ('kernel', kernel)):
        proof[key] = {**value, 'report_sha256': file_hash(paths[key])}
    validate_execution_evidence(manifest, proof)
    validate_public_evidence_files(proof)
    path = output / 'deployment-evidence.json'
    save(path, proof)
    path.chmod(0o644)
    return proof
