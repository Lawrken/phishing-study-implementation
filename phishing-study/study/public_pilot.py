"""Root supervision for the finite, source-labelled public-web pilot.

Only a previously verified schema-three bundle can reach the service launch.
The controller does not visit candidate websites. It measures the installed
services, writes short-lived health receipts and preserves unsuccessful runs.
"""
import configparser
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time

from .deployment import (file_hash, firewall_state_hash, network_snapshot,
                         secure_root_file, source_hash)
from .public_web import (ARTIFACTS, DNS_RESOURCES, NFT_TABLE, RESOURCES,
    public_gate, public_identity, validate_public_bundle, validate_public_evidence,
    validate_public_evidence_files)
from .public_web import OBSERVATION_PROFILE, validate_execution_evidence, execution_gate

APP = Path(__file__).resolve().parents[1]
INITIAL_FREE = 15_000_000_000
FREE_FLOOR = 5_000_000_000
STORAGE_BUDGET = 10_000_000_000
WINDOW_SECONDS = 7200
SHUTDOWN_SECONDS = 60


def atomic_root_json(path, value):
    """Replace a controller-owned receipt, never a service-writable target."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError('receipt_symlink_forbidden')
    temporary = path.with_name(path.name + '.tmp')
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, indent=2, allow_nan=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o644)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def measured_storage(*roots):
    """Count every regular runtime file, including the separate DNS log."""
    # Observation/status saves atomically rename known temporary files. Retry
    # the complete measurement so the renamed final file is counted. Missing
    # logs, unexpected paths and symlinks remain failures, never exclusions.
    for attempt in range(3):
        total = 0
        retry = False
        for root in roots:
            root = Path(root)
            if not root.exists():
                continue
            for path in root.rglob('*'):
                try:
                    info = path.lstat()
                except FileNotFoundError:
                    expected = ((path.parent.name == 'observations' and re.fullmatch(
                        r'[a-f0-9]{32}(?:\.events\.jsonl)?\.tmp', path.name))
                        or path.name in {'status.tmp', 'study.sqlite-wal', 'study.sqlite-shm'})
                    if not expected:
                        raise
                    retry = True
                    break
                if stat.S_ISLNK(info.st_mode):
                    raise ValueError('runtime_storage_symlink_forbidden')
                if stat.S_ISREG(info.st_mode):
                    total += info.st_size
            if retry:
                break
        if not retry:
            return total
    raise ValueError('runtime_storage_snapshot_unstable')


def _parser(text):
    result = configparser.ConfigParser(interpolation=None, strict=False)
    result.optionxform = str
    result.read_string(text)
    return result


def frozen_service_references(bundle, evidence):
    """Match measured concrete verification units to the unchanged templates.

    Unique unit names, output directories and the owned-control entry point
    necessarily differ in the pilot. Security properties must agree exactly.
    """
    measured = {}
    for role, filename, hash_key, entry_key in (
        ('collector', 'collector.service', 'runtime_service_hash', 'connected_collector_service'),
        ('resolver', 'resolver.service', 'runtime_resolver_service_hash', 'connected_resolver_service')):
        entry = evidence.get('evidence_files', {}).get(entry_key)
        if not isinstance(entry, dict):
            raise ValueError('frozen_connected_unit_required_' + role)
        path = secure_root_file(entry['path'])
        digest = file_hash(path)
        if digest != entry.get('sha256') or digest != evidence.get(hash_key):
            raise ValueError('frozen_connected_unit_changed_' + role)
        template = _parser((Path(bundle) / filename).read_text())
        actual = _parser(path.read_text())
        if 'Service' not in actual:
            raise ValueError('connected_unit_service_section_missing')
        for key, value in template['Service'].items():
            if key not in {'Environment', 'ExecStart'} and actual['Service'].get(key) != value:
                raise ValueError('connected_unit_security_property_changed_' + key)
        measured[role] = {'path': str(path), 'sha256': digest}
    return measured


def _readable_by_collector(paths, uid):
    import pwd
    gid = pwd.getpwuid(uid).pw_gid
    script = 'import sys; [(open(p,"rb").read(1)) for p in sys.argv[1:]]'
    subprocess.run(['setpriv', '--reuid=' + str(uid), '--regid=' + str(gid), '--clear-groups',
        os.sys.executable, '-c', script, *[str(path) for path in paths]], check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=10)


def _unit_snapshot(unit, role, manifest, execution):
    """Measure effective properties and the current Python process identity."""
    import pwd
    names = ('User', 'MainPID', 'MemoryMax', 'MemorySwapMax', 'TasksMax',
        'CPUQuotaPerSecUSec', 'NoNewPrivileges', 'PrivateTmp', 'ProtectHome',
        'ProtectSystem', 'KillMode', 'RestrictAddressFamilies', 'AmbientCapabilities')
    result = subprocess.run(['systemctl', 'show', unit, *['--property=' + key for key in names]],
        check=True, capture_output=True, text=True, timeout=4)
    values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    uid = manifest['study_uid'] if role == 'collector' else manifest['resolver']['uid']
    resources = RESOURCES if role == 'collector' else DNS_RESOURCES
    if values.get('User') not in {str(uid), pwd.getpwuid(uid).pw_name}:
        raise ValueError('effective_unit_account_changed_' + role)
    for key, expected in (('MemoryMax', resources['memory_max_bytes']), ('MemorySwapMax', 0),
                          ('TasksMax', resources['tasks_max'])):
        if values.get(key) != str(expected):
            raise ValueError('effective_unit_limit_changed_' + role + '_' + key)
    # systemctl formats this microsecond property with a human-readable suffix.
    cpu = values.get('CPUQuotaPerSecUSec', '')
    expected_cpu = {'2s', '2000000us'} if role == 'collector' else {'200ms', '200000us'}
    if cpu not in expected_cpu:
        raise ValueError('effective_unit_cpu_quota_changed_' + role)
    for key, expected in (('NoNewPrivileges', 'yes'), ('PrivateTmp', 'yes'),
        ('ProtectHome', 'yes'), ('ProtectSystem', 'strict'), ('KillMode', 'mixed' if role == 'collector' else 'control-group')):
        if values.get(key) != expected:
            raise ValueError('effective_unit_protection_changed_' + role + '_' + key)
    families = {'AF_UNIX', 'AF_INET', 'AF_NETLINK'} if role == 'collector' else {'AF_UNIX', 'AF_INET'}
    if set(values.get('RestrictAddressFamilies', '').split()) != families:
        raise ValueError('effective_unit_address_families_changed_' + role)
    capabilities = set(values.get('AmbientCapabilities', '').split())
    if capabilities != ({'cap_net_bind_service'} if role == 'resolver' else set()):
        raise ValueError('effective_ambient_capability_changed_' + role)
    pid = int(values.get('MainPID', '0'))
    if pid <= 0:
        raise ValueError('effective_unit_process_missing_' + role)
    process = Path('/proc') / str(pid)
    started = (process / 'stat').read_text().rsplit(')', 1)[1].split()[19]
    status = dict(line.split(':', 1) for line in (process / 'status').read_text().splitlines() if ':' in line)
    if ([int(value) for value in status['Uid'].split()] != [uid] * 4
            or 0 in [int(value) for value in status.get('Groups', '').split()]
            or int(status['CapEff'].strip(), 16) != (1024 if role == 'resolver' else 0)):
        raise ValueError('effective_process_privileges_changed_' + role)
    raw_command = (process / 'cmdline').read_bytes()
    if raw_command != b'\0'.join(str(value).encode() for value in execution) + b'\0':
        raise ValueError('effective_process_entrypoint_changed_' + role)
    if (process / 'exe').resolve(strict=True) != Path(execution[0]).resolve(strict=True):
        raise ValueError('effective_python_executable_changed_' + role)
    secure_root_file((process / 'exe').resolve(strict=True))
    if (process / 'stat').read_text().rsplit(')', 1)[1].split()[19] != started:
        raise ValueError('effective_process_changed_during_measurement')
    return {'unit': unit, 'properties': values, 'pid': pid, 'start_time': started,
            'uid': uid, 'command_sha256': hashlib.sha256(raw_command).hexdigest(),
            'cap_eff': status['CapEff'].strip()}


def logged_health_probe(logpath):
    """A refused reserved name exercises durable logging without Internet DNS."""
    import dns.message
    import dns.query
    import dns.rcode
    from .public_web import LISTEN
    logpath = Path(logpath)
    offset = logpath.stat().st_size
    query = dns.message.make_query('health.controls.test', 'A')
    response = dns.query.udp(query, LISTEN, timeout=2)
    if response.rcode() != dns.rcode.REFUSED:
        raise ValueError('local_health_query_not_refused')
    with logpath.open('rb') as stream:
        stream.seek(offset)
        added = stream.read(DNS_RESOURCES['max_log_bytes'] + 1)
    rows = [json.loads(line) for line in added.splitlines() if line]
    if not any(row.get('event') == 'query' and row.get('status') == 'refused'
               and row.get('hostname') == '<refused>' and row.get('rcode') == 'REFUSED'
               and row.get('query_id') == query.id for row in rows):
        raise ValueError('durable_health_query_log_missing')
    return {'log_offset_before': offset, 'log_offset_after': logpath.stat().st_size,
            'new_log_rows': len(rows), 'rcode': 'REFUSED', 'internet_query': False}


def _freeze_dataset(source, destination):
    """Freeze only this new run after account-idle proof; avoid a second copy."""
    if not source.exists():
        return None
    if source.is_symlink() or destination.exists():
        raise ValueError('fresh_dataset_freeze_target_required')
    os.rename(source, destination)
    paths = sorted(destination.rglob('*'), key=lambda path: len(path.parts), reverse=True)
    for path in paths:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise ValueError('dataset_freeze_requires_regular_files')
        os.chown(path, 0, 0)
        path.chmod(0o500 if path.is_dir() else 0o400)
    os.chown(destination, 0, 0)
    destination.chmod(0o500)
    return str(destination)


def summarize_dataset(path):
    """Report real attempts separately from distinct endpoints and usable rows."""
    import sqlite3
    path = Path(path) / 'study.sqlite'
    empty = {'attempts': 0, 'distinct_urls_attempted': 0, 'failed_attempts': 0,
        'unfinished_attempts': 0, 'usable_per_class': {'legitimate': 0, 'phishing': 0},
        'collector_stop_reason': None}
    if not path.exists():
        return empty
    with sqlite3.connect('file:' + str(path) + '?mode=ro', uri=True) as db:
        empty.update(attempts=db.execute('SELECT COUNT(*) FROM attempts').fetchone()[0],
            distinct_urls_attempted=db.execute('SELECT COUNT(DISTINCT candidate_id) FROM attempts').fetchone()[0],
            failed_attempts=db.execute('SELECT COUNT(*) FROM attempts WHERE finished IS NOT NULL AND eligible=0').fetchone()[0],
            unfinished_attempts=db.execute('SELECT COUNT(*) FROM attempts WHERE finished IS NULL').fetchone()[0])
        for label in empty['usable_per_class']:
            empty['usable_per_class'][label] = db.execute(
                "SELECT COUNT(*) FROM candidates WHERE label=? AND confidence='dataset' AND state='done' AND eligible=1", (label,)).fetchone()[0]
        run = db.execute('SELECT stop_reason FROM runs ORDER BY started DESC LIMIT 1').fetchone()
        empty['collector_stop_reason'] = run[0] if run else None
    return empty


def run_pilot(bundle, evidence_path, intake_dir, output, private, dnsdir, phasefile, nonce):
    """Return a preserved report; any failed control prevents or stops visits."""
    from .preview_controls import command, readlogs, phase_label, service_alive, snapshot, reject_counter
    from .public_connection import service_arguments
    from .phiusiil_intake import validate_intake
    bundle, evidence_path, intake_dir, output, private, dnsdir, phasefile = map(Path,
        (bundle, evidence_path, intake_dir, output, private, dnsdir, phasefile))
    if os.geteuid() != 0 or re.fullmatch('[a-f0-9]{32}', nonce) is None:
        raise ValueError('root_controller_and_fresh_nonce_required')
    output.mkdir(mode=0o700, exist_ok=False)
    report = {'status': 'failed', 'started_at': datetime.now(timezone.utc).isoformat(),
        'nonce': nonce, 'checks': {}, 'health_samples': [], 'pilot_activated': False,
        'models_retrained': False, 'assurance_model': 'local-kernel-plus-owned-internet-v1'}
    before = None
    installed = False
    manifest = None
    worker = resolver = None
    units = {}
    console_streams = []
    health_path = phasefile.with_name('pilot-health-' + nonce + '.json')
    activation_path = phasefile.with_name('pilot-activation-' + nonce + '.json')
    logpath, ready = dnsdir / 'queries.jsonl', dnsdir / 'ready.json'
    collection_output = private / 'dataset'
    beginning = time.monotonic()
    window_end, controller_end = beginning + WINDOW_SECONDS, beginning + WINDOW_SECONDS + SHUTDOWN_SECONDS
    def check(name, value):
        report['checks'][name] = bool(value)
        if not value:
            raise ValueError(name)
    def launch(unit, template, substitutions, writable, environment, label):
        rendered, properties, execution = service_arguments(template.read_text(), substitutions, writable, environment)
        path = output / (label + '-runtime.service')
        path.write_text(rendered)
        path.chmod(0o400)
        stream = (output / (label + '-console.txt')).open('x')
        console_streams.append(stream)
        process = subprocess.Popen(['systemd-run', '--quiet', '--wait', '--pipe', '--collect',
            '--unit=' + unit, *properties, *execution], stdout=stream, stderr=subprocess.STDOUT)
        units[label] = {'name': unit, 'execution': execution, 'rendered_sha256': file_hash(path)}
        return process
    try:
        manifest = validate_public_bundle(bundle, root=APP)
        identity = public_identity(manifest)
        report.update(identity)
        evidence = json.loads(secure_root_file(evidence_path).read_text())
        observation = manifest['verification_profile'] == OBSERVATION_PROFILE
        validate_execution_evidence(manifest, evidence)
        validate_public_evidence_files(evidence)
        if not observation:
            report['frozen_connected_services'] = frozen_service_references(bundle, evidence)
        report.update(network_isolation_verified=not observation,
                      public_dns_verified=not observation, public_tls_verified=not observation)
        intake_path = secure_root_file(intake_dir / 'intake-manifest.json')
        candidates = secure_root_file(intake_dir / 'candidates.csv')
        intake_manifest = validate_intake(candidates, intake_path)
        check('intake_profile_and_campaign_identity', intake_manifest['intake_profile'] == manifest['intake_profile']
              and intake_manifest.get('completion') == manifest.get('completion'))
        candidates_hash = file_hash(candidates)
        check('frozen_intake_identity', file_hash(intake_path) == manifest['intake_manifest_hash'])
        for path in (private, dnsdir):
            info = path.lstat()
            expected_uid = manifest['study_uid'] if path == private else manifest['resolver']['uid']
            check('private_directory_' + str(expected_uid), stat.S_ISDIR(info.st_mode)
                  and not path.is_symlink() and info.st_uid == expected_uid and info.st_mode & 0o777 == 0o700)
        check('dedicated_accounts_idle_before', all(subprocess.run(['pgrep', '-u', str(uid)],
            capture_output=True).returncode == 1 for uid in (manifest['study_uid'], manifest['resolver']['uid'])))
        check('initial_disk_buffer', shutil.disk_usage(private).free >= INITIAL_FREE)
        check('fresh_runtime_paths', not any(path.exists() for path in (logpath, ready, health_path, activation_path, collection_output)))
        before = snapshot(output, 'before')
        check('fresh_profile_firewall', subprocess.run(['nft', 'list', 'table', 'inet', NFT_TABLE],
            capture_output=True).returncode != 0)
        command('nft', '-c', '-f', str(bundle / 'collector.nft'))
        command('nft', '-f', str(bundle / 'collector.nft'))
        installed = True
        execution_gate(bundle, evidence_path, intake_path, root=APP, kernel_only=observation)
        check('source_bound_root_gate', True)
        dnsunit = 'study-public-pilot-dns-' + nonce[:16]
        collectorunit = 'study-public-pilot-' + nonce[:16]
        environment = {'PYTHONDONTWRITEBYTECODE': '1', 'PLAYWRIGHT_BROWSERS_PATH': '/opt/phishing-study-fixtures/browsers',
            'HOME': str(private), 'OMP_NUM_THREADS': '2', 'OPENBLAS_NUM_THREADS': '2'}
        if manifest.get('completion') is not None or manifest.get('live_view_enabled') is True:
            import pwd
            view = private / 'live-view'
            view.mkdir(mode=0o700)
            os.chown(view, manifest['study_uid'], pwd.getpwuid(manifest['study_uid']).pw_gid)
            environment['STUDY_LIVE_VIEW'] = str(view)
            report['live_view'] = {'replace_only': True, 'research_feature': False,
                                   'screenshot_limit_bytes': 524288, 'interval_seconds': 2}
        substitutions = {'PYTHON': os.sys.executable, 'BUNDLE': bundle,
            'RUNNER': APP / ('scripts/dataset-observe.py' if observation else 'scripts/public-collect.py'), 'OUTPUT': collection_output,
            'DNS_UNIT': dnsunit + '.service', 'DNS_LOG': logpath, 'DNS_READY': ready, 'PHASE_FILE': phasefile}
        phase_label(phasefile, 'pilot')
        resolver = launch(dnsunit, bundle / 'resolver.service', substitutions, dnsdir, environment, 'resolver')
        deadline = min(window_end, time.monotonic() + 8)
        while not ready.exists() and resolver.poll() is None and time.monotonic() < deadline:
            time.sleep(.05)
        check('logging_resolver_started', ready.exists() and service_alive(dnsunit))
        readiness = json.loads(ready.read_text())
        check('logging_resolver_identity', readiness.get('uid') == manifest['resolver']['uid']
              and readiness.get('mode') == 'public-web' and readiness.get('max_log_bytes') == DNS_RESOURCES['max_log_bytes'])
        report['resolver_initial'] = _unit_snapshot(dnsunit, 'resolver', manifest, units['resolver']['execution'])
        report['initial_logging_probe'] = logged_health_probe(logpath)
        required = {'resolver_service': True, 'durable_dns_logging': True, 'source_identity': True,
            'firewall_identity': True, 'topology_identity': True, 'upstream_identity': True,
            'intake_identity': True, 'storage_budget': True, 'free_disk_floor': True,
            'collector_service': False}
        atomic_root_json(health_path, {'identity': identity, 'healthy': False,
            'timestamp': time.time(), 'checks': required})
        atomic_root_json(activation_path, {'identity': identity, 'activation_allowed': True,
            'created': time.time(), 'evidence': str(evidence_path), 'evidence_sha256': file_hash(evidence_path),
            'intake': str(intake_path), 'candidates': str(candidates), 'health': str(health_path),
            'root_gate': 'public_gate', 'runtime_template_hash': manifest['service_hash']})
        readables = [activation_path, health_path, evidence_path, intake_path, candidates,
            *[bundle / name for name in ARTIFACTS], *[Path(value['path']) for value in evidence['evidence_files'].values()]]
        _readable_by_collector(readables, manifest['study_uid'])
        worker = launch(collectorunit, bundle / 'collector.service', substitutions, private,
            {**environment, 'STUDY_PUBLIC_ACTIVATION': str(activation_path)}, 'collector')
        report['pilot_activated'] = True
        report['units'] = units
        deadline = min(window_end, time.monotonic() + 6)
        while not service_alive(collectorunit) and worker.poll() is None and time.monotonic() < deadline:
            time.sleep(.05)
        check('collector_service_started', service_alive(collectorunit))
        while worker.poll() is None:
            if time.monotonic() >= window_end:
                report['stop_reason'] = 'two_hour_collection_window'
                atomic_root_json(health_path, {'identity': identity, 'healthy': False,
                    'timestamp': time.time(), 'checks': {'collection_window_open': False}})
                break
            start = time.monotonic()
            if resolver.poll() is not None or not service_alive(dnsunit):
                raise ValueError('resolver_or_logging_service_stopped')
            checks = {'resolver_service': True,
                'source_identity': source_hash(APP) == manifest['source_hash'],
                'firewall_identity': reject_counter(NFT_TABLE)['policy_hash'] == evidence['normal_firewall_state_hash'],
                'topology_identity': network_snapshot() == {key: manifest[key] for key in ('local_ipv4', 'gateways_ipv4')},
                'upstream_identity': file_hash('/run/systemd/resolve/resolv.conf') == manifest['upstream_config_hash'],
                'intake_identity': file_hash(intake_path) == manifest['intake_manifest_hash'] and file_hash(candidates) == candidates_hash,
                'storage_budget': measured_storage(private, dnsdir) <= STORAGE_BUDGET,
                'dns_log_budget': logpath.stat().st_size < DNS_RESOURCES['max_log_bytes'],
                'free_disk_floor': shutil.disk_usage(private).free >= FREE_FLOOR}
            probe = logged_health_probe(logpath)
            checks['durable_dns_logging'] = True
            resolver_state = _unit_snapshot(dnsunit, 'resolver', manifest, units['resolver']['execution'])
            try:
                collector_state = _unit_snapshot(collectorunit, 'collector', manifest, units['collector']['execution'])
            except (ValueError, FileNotFoundError, subprocess.SubprocessError):
                if not service_alive(collectorunit):
                    worker.wait(timeout=1)
                    break
                raise
            checks['collector_service'] = True
            healthy = all(checks.values())
            sample = {'at': datetime.now(timezone.utc).isoformat(), 'checks': checks,
                'logging': probe, 'collector_pid': collector_state['pid'], 'resolver_pid': resolver_state['pid'],
                'storage_bytes': measured_storage(private, dnsdir)}
            report['health_samples'].append(sample)
            if 'collector_initial' not in report:
                report['collector_initial'] = collector_state
            atomic_root_json(health_path, {'identity': identity, 'healthy': healthy,
                'timestamp': time.time(), 'checks': checks})
            if not healthy:
                raise ValueError('pilot_runtime_health_failure')
            time.sleep(max(0, 1 - (time.monotonic() - start)))
        if worker.poll() is not None:
            report['worker_exit'] = worker.returncode
            check('collection_worker_exit_zero', worker.returncode == 0)
            report['stop_reason'] = 'finite_collector_finished'
        report['status'] = 'passed'
    except BaseException as error:
        report['error_type'] = type(error).__name__
        report['error_message'] = str(error)[:500]
        report.setdefault('stop_reason', 'verification_or_runtime_failure')
    finally:
        cleanup_errors = []
        def clean(name, action):
            try:
                return action()
            except BaseException as error:
                cleanup_errors.append({'step': name, 'error_type': type(error).__name__})
                return None
        if health_path.exists() and manifest is not None:
            clean('invalidate_health', lambda: atomic_root_json(health_path, {'identity': public_identity(manifest),
                'healthy': False, 'timestamp': time.time(), 'checks': {'controller_stopped': False}}))
        # Stop workloads first; keep the DNS/policy containment until they exit.
        for role, process in (('collector', worker), ('resolver', resolver)):
            if process is None:
                continue
            unit = units[role]['name']
            if process.poll() is None:
                clean('request_stop_' + role, lambda unit=unit: subprocess.run(
                    ['systemctl', 'stop', '--no-block', unit], check=True, capture_output=True, timeout=3))
                code = clean('wait_' + role, lambda process=process: process.wait(
                    timeout=max(.1, min(45 if role == 'collector' else 12, controller_end - time.monotonic()))))
                if code is None:
                    cleanup_errors.append({'step': role + '_shutdown_deadline'})
                elif role == 'collector':
                    report['worker_exit'] = code
            if role == 'collector':
                report['checks']['collection_worker_exit_zero'] = process.poll() == 0
            else:
                report['checks']['resolver_worker_exit_zero'] = process.poll() == 0
            clean('journal_' + role, lambda role=role, unit=unit: (output / (role + '-journal.txt')).write_text(
                command('journalctl', '-u', unit, '--no-pager')))
        for stream in console_streams:
            clean('console_close', stream.close)
        idle = manifest is not None and all(subprocess.run(['pgrep', '-u', str(uid)],
            capture_output=True).returncode == 1 for uid in (manifest['study_uid'], manifest['resolver']['uid']))
        report['checks']['dedicated_accounts_idle_after'] = idle
        if logpath.exists():
            logs = clean('read_dns_log', lambda: readlogs(logpath)) or []
            report['checks']['resolver_logged_clean_shutdown'] = bool(logs) and logs[-1].get('event') == 'stopped'
            clean('freeze_dns_log', lambda: shutil.copyfile(logpath, output / 'queries.jsonl'))
        if ready.exists():
            clean('freeze_dns_ready', lambda: shutil.copyfile(ready, output / 'resolver-ready.json'))
        if idle:
            report['frozen_dataset_path'] = clean('freeze_dataset', lambda: _freeze_dataset(collection_output, output / 'dataset'))
            summary = clean('dataset_summary', lambda: summarize_dataset(output / 'dataset'))
            if summary is not None:
                report.update(summary)
                if report['attempts']:
                    report['checks']['no_unfinished_attempts'] = summary['unfinished_attempts'] == 0
                    report['checks']['finite_collector_stop'] = summary['collector_stop_reason'] in {
                        'class_caps', 'attempt_budget', 'time_budget', 'queue_exhausted', 'available_class_caps', 'signal'}
        report['collection_activation'] = report['pilot_activated']
        if installed:
            clean('final_firewall_snapshot', lambda: atomic_root_json(output / 'final-firewall.json', reject_counter(NFT_TABLE)))
            if idle:
                clean('remove_owned_firewall', lambda: command('nft', 'delete', 'table', 'inet', NFT_TABLE))
            else:
                cleanup_errors.append({'step': 'containment_retained_for_pending_processes'})
        after = clean('snapshot_after', lambda: snapshot(output, 'after')) if before is not None else None
        report['checks']['outer_firewall_restored'] = before is not None and after is not None and firewall_state_hash(before['firewall']) == firewall_state_hash(after['firewall'])
        report['checks']['outer_dns_nss_hosts_unchanged'] = before is not None and after is not None and before['dns'] == after['dns']
        report['checks']['source_unchanged'] = manifest is not None and source_hash(APP) == manifest['source_hash']
        report['controller_duration_seconds'] = time.monotonic() - beginning
        report['checks']['controller_bounded'] = report['controller_duration_seconds'] <= WINDOW_SECONDS + SHUTDOWN_SECONDS
        report['cleanup_errors'] = cleanup_errors
        if cleanup_errors or not report['checks'] or not all(report['checks'].values()):
            report['status'] = 'failed'
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        report['file_hashes'] = {path.relative_to(output).as_posix(): file_hash(path)
            for path in output.rglob('*') if path.is_file() and not path.is_symlink()}
        atomic_root_json(output / 'pilot-report.json', report)
    return report
