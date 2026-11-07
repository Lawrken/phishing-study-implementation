"""Owned Internet measurements with the full generated public-web policy."""
import configparser
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time

from .deployment import file_hash, firewall_state_hash, source_hash
from .preview_controls import (command, save, readlogs, phase_label, render_service,
    service_alive, snapshot, reject_counter, TCP, TCP6, UDP, receiver)
from .public_web import (NFT_TABLE, LISTEN, OWNED_URL, validate_public_bundle,
                         public_identity)

APP = Path(__file__).resolve().parents[1]


def service_arguments(template, substitutions, writable, environment):
    rendered, properties, execution = render_service(template, substitutions, writable, environment)
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    parser.read_string(rendered)
    if 'Unit' in parser:
        for key in ('Requires', 'BindsTo', 'After'):
            if key in parser['Unit']:
                properties.append('--property=' + key + '=' + parser['Unit'][key])
    return rendered, properties, execution


def run_connected(bundle, output, private, dnsdir, phasefile, nonce):
    if os.geteuid() != 0:
        raise ValueError('root_owned_controller_required')
    manifest = validate_public_bundle(bundle, root=APP)
    uid, dnsuid = manifest['study_uid'], manifest['resolver']['uid']
    output.mkdir(mode=0o700, exist_ok=False)
    report = {'status': 'failed', 'source_hash': manifest['source_hash'],
        'firewall_hash': manifest['firewall_hash'], 'checks': {}, 'phases': [],
        'negative_cases': {}, 'started_at': datetime.now(timezone.utc).isoformat(),
        'research_collection_count': 0, 'network_isolation_verified': False}
    def check(name, value):
        report['checks'][name] = bool(value)
    before = snapshot(output, 'before')
    if subprocess.run(['nft', 'list', 'table', 'inet', NFT_TABLE], capture_output=True).returncode == 0:
        raise ValueError('existing_profile_firewall_must_be_preserved')
    dnsunit = 'study-public-dns-' + nonce[:16]
    installed, launcher = False, None
    servers, threads, receiver_log, workerunits = [], [], [], []
    logpath, ready = dnsdir / 'queries.jsonl', dnsdir / 'ready.json'
    environment = {'PYTHONDONTWRITEBYTECODE': '1', 'PLAYWRIGHT_BROWSERS_PATH': '/opt/phishing-study-fixtures/browsers',
                   'HOME': str(private), 'OMP_NUM_THREADS': '2', 'OPENBLAS_NUM_THREADS': '2'}
    substitutions = {'PYTHON': os.sys.executable, 'BUNDLE': bundle,
        'RUNNER': APP / 'scripts/public-owned-control.py', 'OUTPUT': private,
        'DNS_UNIT': dnsunit + '.service', 'DNS_LOG': logpath, 'DNS_READY': ready, 'PHASE_FILE': phasefile}
    try:
        phase_label(phasefile, 'preparation')
        command('nft', '-c', '-f', str(bundle / 'collector.nft'))
        command('nft', '-f', str(bundle / 'collector.nft'))
        installed = True
        normal_hash = reject_counter(NFT_TABLE)['policy_hash']
        report['normal_firewall_state_hash'] = normal_hash
        text, properties, execution = service_arguments((bundle / 'resolver.service').read_text(), substitutions, dnsdir, environment)
        (output / 'resolver-runtime.service').write_text(text)
        report['runtime_resolver_service_hash'] = file_hash(output / 'resolver-runtime.service')
        with (output / 'resolver-console.txt').open('x') as stream:
            launcher = subprocess.Popen(['systemd-run', '--quiet', '--wait', '--pipe', '--collect',
                '--unit=' + dnsunit, *properties, *execution], stdout=stream, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 8
        while not ready.exists() and launcher.poll() is None and time.monotonic() < deadline:
            time.sleep(.05)
        if not ready.exists() or not service_alive(dnsunit):
            raise RuntimeError('unprivileged_public_dns_start_failed')
        report['resolver_ready'] = json.loads(ready.read_text())
        if report['resolver_ready'].get('uid') != dnsuid:
            raise RuntimeError('resolver_identity_mismatch')
        pid = report['resolver_ready']['pid']
        status = dict(line.split(':', 1) for line in Path('/proc/' + str(pid) + '/status').read_text().splitlines() if ':' in line)
        report['resolver_process'] = {'uid': int(status['Uid'].split()[0]),
            'gid': int(status['Gid'].split()[0]), 'effective_capabilities': status['CapEff'].strip(),
            'no_new_privileges': int(status['NoNewPrivs'].strip())}
        if (report['resolver_process']['uid'] != dnsuid
                or int(report['resolver_process']['effective_capabilities'], 16) != 1024
                or report['resolver_process']['no_new_privileges'] != 1):
            raise RuntimeError('resolver_must_have_only_bind_capability_and_no_new_privileges')
        report['resolver_service_properties'] = command('systemctl', 'show', dnsunit,
            '--property=User,MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec,TasksMax,CapabilityBoundingSet,AmbientCapabilities,RestrictAddressFamilies')
        fixtures = {'alternate_tcp': ('127.0.0.55', 53, TCP, socket.SOCK_STREAM),
            'alternate_udp': ('127.0.0.55', 53, UDP, socket.SOCK_DGRAM),
            'private': ('127.0.0.56', 8443, TCP, socket.SOCK_STREAM),
            'ipv6': ('::1', 8443, TCP6, socket.SOCK_STREAM)}
        for key, (address, port, kind, _) in fixtures.items():
            server = kind((address, port), receiver(receiver_log, key))
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
            thread.start()
            servers.append(server)
            threads.append(thread)
        for phase, case in [('normal', None), *[('denied', key) for key in fixtures], ('blocked', None), ('restored', None)]:
            key = phase + ('-' + case if case else '')
            if subprocess.run(['pgrep', '-u', str(uid)], capture_output=True).returncode != 1:
                raise RuntimeError('collection_account_not_idle_between_controls')
            if not service_alive(dnsunit):
                raise RuntimeError('resolver_or_logging_failed')
            phase_label(phasefile, 'controller-' + key)
            positive_hits = 0
            if case:
                address, port, _, kind = fixtures[case]
                first = len(receiver_log)
                with socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET, kind) as connection:
                    connection.settimeout(2)
                    connection.connect((address, port))
                    connection.sendall(b'OWNED POSITIVE')
                    if not connection.recv(128):
                        raise RuntimeError('owned_receiver_not_working')
                positive_hits = len(receiver_log) - first
            if phase == 'blocked':
                command('nft', 'flush', 'chain', 'inet', NFT_TABLE, 'dns_allow')
            elif phase == 'restored':
                for transport in ('udp', 'tcp'):
                    command('nft', 'add', 'rule', 'inet', NFT_TABLE, 'dns_allow', 'ip', 'daddr', LISTEN,
                            transport, 'dport', '53', 'counter', 'accept')
            first_counter = reject_counter(NFT_TABLE)
            query_index, receiver_index = len(readlogs(logpath)), len(receiver_log)
            phase_label(phasefile, 'workload-' + key)
            target = private / key
            env = {**environment, 'STUDY_CONTROL_PHASE': phase}
            if case:
                env['STUDY_CONTROL_CASE'] = case
            text, properties, execution = service_arguments((bundle / 'collector.service').read_text(),
                {**substitutions, 'OUTPUT': target}, private, env)
            (output / (key + '-runtime.service')).write_text(text)
            unit = 'study-public-control-' + key.replace('_', '-') + '-' + nonce[:16]
            workerunits.append(unit)
            with (output / (key + '-console.txt')).open('x') as stream:
                code = subprocess.run(['systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit=' + unit,
                    *properties, *execution], stdout=stream, stderr=subprocess.STDOUT, timeout=190).returncode
            (output / (key + '-journal.txt')).write_text(command('journalctl', '-u', unit, '--no-pager'))
            time.sleep(.15)
            final_counter = reject_counter(NFT_TABLE)
            worker = json.loads((target / 'report.json').read_text())
            queries = [row for row in readlogs(logpath)[query_index:] if row.get('event') == 'query']
            hits = receiver_log[receiver_index:]
            delta = final_counter['reject_packets'] - first_counter['reject_packets']
            receipt = {'phase': key, 'nonce': nonce, 'worker_exit': code,
                'before': first_counter, 'after': final_counter, 'reject_counter_delta': delta,
                'resolver_queries': queries, 'workload_receiver_hits': hits,
                'positive_control_hits': positive_hits, 'runtime_service_hash': file_hash(output / (key + '-runtime.service'))}
            save(output / (key + '-receipt.json'), receipt)
            if (code != 0 or worker.get('status') != 'passed'
                    or worker.get('source_hash') != manifest['source_hash'] or hits
                    or not service_alive(dnsunit)):
                raise RuntimeError('owned_control_failed_' + key)
            if case:
                os_ipv6 = case == 'ipv6' and worker.get('denial', {}).get('errno') == 'EAFNOSUPPORT'
                if positive_hits <= 0 or not (delta > 0 or os_ipv6):
                    raise RuntimeError('owned_receiver_denial_not_proved_' + case)
                report['negative_cases'][case] = receipt
            else:
                phase_report = {**worker, 'worker_exit': code, 'resolver_query_count': len(queries),
                    'reject_counter_delta': delta, 'report_sha256': file_hash(target / 'report.json'),
                    'receipt_sha256': file_hash(output / (key + '-receipt.json'))}
                report['phases'].append(phase_report)
                if phase in ('normal', 'restored'):
                    check(phase + '_logged_owned_query', any(row.get('hostname') == 'd-tx-t.vercel.app' for row in queries))
                if phase == 'blocked':
                    check('blackout_zero_resolver_queries', not queries and delta > 0)
                if phase == 'restored':
                    check('dns_policy_restored', final_counter['policy_hash'] == normal_hash)
                if phase == 'normal':
                    report['runtime_service_hash'] = receipt['runtime_service_hash']
        from .service_stop_control import run_service_stop
        report['service_stop'] = run_service_stop(bundle, output, private, substitutions, environment, nonce)
        check('generated_service_stop_clean', True)
        report['status'] = 'passed'
    except Exception as error:
        report.update(error_type=type(error).__name__, error_message=str(error)[:700])
    finally:
        errors = []
        def clean(name, action):
            try:
                return action()
            except Exception as error:
                errors.append({'step': name, 'error_type': type(error).__name__, 'message': str(error)[:400]})
                return None
        for unit in workerunits:
            if service_alive(unit):
                clean('stop_worker', lambda unit=unit: command('systemctl', 'stop', unit))
                errors.append({'step': 'worker_required_late_stop'})
        for server in servers:
            clean('receiver_shutdown', server.shutdown)
            clean('receiver_close', server.server_close)
        for thread in threads:
            thread.join(3)
        check('receivers_stopped', all(not thread.is_alive() for thread in threads))
        clean('receiver_log', lambda: save(output / 'receiver-logs.json', receiver_log))
        if launcher is not None:
            clean('resolver_stop', lambda: command('systemctl', 'stop', dnsunit))
            code = clean('resolver_wait', lambda: launcher.wait(timeout=15))
            report['resolver_service_exit'] = code
            check('resolver_service_exit_zero', code == 0)
            log = clean('resolver_log', lambda: readlogs(logpath)) or []
            check('resolver_logged_clean_shutdown', bool(log) and log[-1].get('event') == 'stopped')
            journal = clean('resolver_journal', lambda: command('journalctl', '-u', dnsunit, '--no-pager')) or ''
            (output / 'resolver-journal.txt').write_text(journal)
        else:
            check('resolver_service_exit_zero', False)
            check('resolver_logged_clean_shutdown', False)
        idle = all(subprocess.run(['pgrep', '-u', str(value)], capture_output=True).returncode == 1 for value in (uid, dnsuid))
        check('accounts_idle', idle)
        if installed:
            clean('final_firewall', lambda: save(output / 'firewall-final.json', reject_counter(NFT_TABLE)))
            if idle:
                clean('remove_firewall', lambda: command('nft', 'delete', 'table', 'inet', NFT_TABLE))
            else:
                errors.append({'step': 'containment_retained_for_pending_processes'})
        after = clean('snapshot_after', lambda: snapshot(output, 'after'))
        check('outer_firewall_restored', after is not None and firewall_state_hash(before['firewall']) == firewall_state_hash(after['firewall']))
        check('outer_dns_nss_hosts_unchanged', after is not None and before['dns'] == after['dns'])
        check('source_unchanged', source_hash(APP) == manifest['source_hash'])
        report['cleanup_errors'] = errors
        if errors or not all(report['checks'].values()):
            report['status'] = 'failed'
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        save(output / 'connected-report.json', report)
    return report
