"""Root controller for the non-activating, owned-site local DNS preview.

The root controller measures receivers and freezes receipts. Only dedicated
unprivileged systemd services perform DNS forwarding and owned-site visits.
"""
import argparse
import configparser
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
import socketserver
import stat
import subprocess
import threading
import time

import dns.message
import dns.query
import dns.rdatatype

from .deployment import (file_hash, firewall_state_hash, parse_network_snapshot,
                         secure_root_file, source_files, source_hash)
from .local_preview import (LISTEN, UPSTREAM, preview_identity,
                            validate_preview_bundle, validate_preview_evidence)

APP = Path(__file__).resolve().parents[1]
PRIVATE_ROOT = Path('/var/lib/phishing-study-local-preview')


def validate_runtime_storage(private, resolver_output, phasefile, uid, dns_uid):
    """Separate service-owned leaves must have protected root-owned ancestors."""
    for path in (private, resolver_output, phasefile):
        if not path.absolute().is_relative_to(PRIVATE_ROOT) or path.is_symlink():
            raise ValueError('dedicated_preview_runtime_storage_required')
    secure_root_file(phasefile)
    for path, owner in ((private, uid), (resolver_output, dns_uid)):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o077:
            raise ValueError('private_service_storage_required')
        for parent in path.parents:
            info = parent.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('root_owned_runtime_ancestors_required')


def command(*args, timeout=15):
    return subprocess.check_output(args, text=True, timeout=timeout)


def save(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def readlogs(path):
    return [json.loads(row) for row in Path(path).read_text().splitlines() if row.strip()]


def phase_label(path, label):
    """Root atomic replacement avoids a transient empty phase at query receipt."""
    temporary = path.with_name(path.name + '.next')
    with temporary.open('x') as stream:
        stream.write(label + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(0o644)
    os.replace(temporary, path)


def render_service(template, substitutions, writable, extra_environment):
    if any(character.isspace() or character == '\x00' for character in str(writable)):
        raise ValueError('invalid_service_write_path')
    rendered = template
    for key, value in substitutions.items():
        if any(character.isspace() or character == '\x00' for character in str(value)):
            raise ValueError('invalid_service_substitution')
        rendered = rendered.replace('@@' + key + '@@', str(value))
    if re.search(r'@@[A-Z_]+@@', rendered):
        raise ValueError('incomplete_service_template')
    rendered += 'ReadWritePaths=' + str(writable) + '\n'
    for key, value in extra_environment.items():
        if not re.fullmatch('[A-Z_][A-Z0-9_]*', key) or any(character in value for character in ('\n', '\r', '\x00')):
            raise ValueError('invalid_service_environment')
        rendered += 'Environment=' + json.dumps(key + '=' + value) + '\n'
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    # Preserve repeated Environment lines ourselves; ConfigParser keeps last.
    parser.read_string(rendered)
    arguments = []
    for key, value in parser['Service'].items():
        if key not in ('ExecStart', 'Environment'):
            arguments.append('--property=' + key + '=' + value)
    for line in rendered.splitlines():
        if line.startswith('Environment='):
            for value in shlex.split(line.split('=', 1)[1]):
                arguments.append('--setenv=' + value)
    return rendered, arguments, shlex.split(parser['Service']['ExecStart'])


def service_alive(unit):
    return subprocess.run(['systemctl', 'is-active', '--quiet', unit], capture_output=True).returncode == 0


def snapshot(output, suffix):
    result = {}
    for key, args in {
        'firewall': ('nft', '-j', 'list', 'ruleset'),
        'addresses': ('ip', '-j', 'address', 'show'),
        'routes': ('ip', '-j', '-4', 'route', 'show'),
        'ipv6-routes': ('ip', '-j', '-6', 'route', 'show'),
    }.items():
        raw = command(*args)
        (output / ('outer-' + key + '-' + suffix + '.json')).write_text(raw)
        result[key] = json.loads(raw)
    result['dns'] = command('sha256sum', '/etc/resolv.conf', '/etc/nsswitch.conf', '/etc/hosts')
    (output / ('outer-dns-' + suffix + '.sha256')).write_text(result['dns'])
    return result


def reject_counter(table):
    rules = json.loads(command('nft', '-j', 'list', 'table', 'inet', table))
    rejected = sum(expr.get('counter', {}).get('packets', 0)
        for item in rules['nftables'] for rule in [item.get('rule', {})]
        if any('reject' in item for item in rule.get('expr', []))
        for expr in rule.get('expr', []))
    return {'reject_packets': rejected, 'rules': rules,
            'policy_hash': firewall_state_hash(rules)}


def render_firewall(template, table, addresses, local_ipv4, gateways):
    if not re.fullmatch(r'study_preview_[a-f0-9]{16}', table):
        raise ValueError('invalid_preview_table')
    if not addresses or any(not ipaddress.IPv4Address(value).is_global
                             or value in {*local_ipv4, *gateways} for value in addresses):
        raise ValueError('public_owned_control_ipv4_required')
    return template.replace('@@TABLE@@', table).replace('@@SITE_IPV4@@', ', '.join(sorted(set(addresses))))


class TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True


class TCP6(TCP):
    address_family = socket.AF_INET6


class UDP(socketserver.ThreadingUDPServer):
    allow_reuse_address = False
    daemon_threads = True


def receiver(log, endpoint):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            if isinstance(self.request, tuple):
                _, connection = self.request
                log.append({'endpoint': endpoint, 'utc': datetime.now(timezone.utc).isoformat()})
                connection.sendto(b'OWNED ACK', self.client_address)
            else:
                self.request.settimeout(2)
                self.request.recv(256)
                log.append({'endpoint': endpoint, 'utc': datetime.now(timezone.utc).isoformat()})
                self.request.sendall(b'OWNED ACK')
    return Handler


def run(bundle, output, private, resolver_output, phasefile, nonce):
    manifest = validate_preview_bundle(bundle, root=APP)
    if os.geteuid() != 0 or not re.fullmatch('[a-f0-9]{32}', nonce):
        raise ValueError('root_controller_and_fresh_nonce_required')
    for path in (bundle / 'deployment.json', *source_files(APP)):
        secure_root_file(path)
    if any(Path(path).exists() for path in ('/opt/phishing-study', '/etc/phishing-study', '/var/lib/phishing-study')):
        raise ValueError('production_installation_must_remain_absent')
    uid, dns_uid = manifest['study_uid'], manifest['resolver']['uid']
    if uid == dns_uid or any(subprocess.run(['pgrep', '-u', str(value)], capture_output=True).returncode != 1 for value in (uid, dns_uid)):
        raise ValueError('dedicated_preview_accounts_must_be_idle')
    validate_runtime_storage(private, resolver_output, phasefile, uid, dns_uid)
    output.mkdir(mode=0o700, exist_ok=False)
    report = {**preview_identity(manifest), 'started_at': datetime.now(timezone.utc).isoformat(),
        'nonce': nonce, 'status': 'failed', 'checks': {}, 'phases': [], 'phase_receipt_hashes': {},
        'activation_allowed': False, 'research_eligible': False,
        'network_isolation_verified': False, 'public_dns_verified': False,
        'public_tls_verified': False, 'full_production_verification': False,
        'research_collection_count': 0, 'region_confirmed': manifest['region_confirmed'],
        'scope': 'owned HTTPS/local receiver deployment preview; no candidate intake'}
    def check(name, value):
        report['checks'][name] = bool(value)
    before = snapshot(output, 'before')
    topology = parse_network_snapshot(before['addresses'], before['routes'])
    check('recorded_vm_topology_matches', topology == {key: manifest[key] for key in ('local_ipv4', 'gateways_ipv4')})
    resolver_unit = 'study-preview-dns-' + nonce[:16]
    table = 'study_preview_' + nonce[:16]
    installed = False
    servers, threads, receiver_log = [], [], []
    logfile, ready = resolver_output / 'queries.jsonl', resolver_output / 'ready.json'
    runtime_units = []
    resolver_launcher = None
    environment = {'PYTHONDONTWRITEBYTECODE': '1', 'PLAYWRIGHT_BROWSERS_PATH': '/opt/phishing-study-fixtures/browsers',
                   'OMP_NUM_THREADS': '2', 'OPENBLAS_NUM_THREADS': '2', 'HOME': str(private)}
    host = manifest['resolver']['allow_hosts'][0]
    substitutions = {'PYTHON': os.sys.executable, 'BUNDLE': bundle, 'OWNED_HOST': host,
                     'DNS_LOG': logfile, 'DNS_READY': ready, 'PHASE_FILE': phasefile}
    try:
        if not all(report['checks'].values()):
            raise RuntimeError('topology_preflight_failed')
        phase_label(phasefile, 'preparation')
        rendered, properties, execution = render_service((bundle / 'preview-resolver.service').read_text(),
            substitutions, resolver_output, environment)
        (output / 'resolver-runtime.service').write_text(rendered)
        report['resolver_runtime_service_hash'] = file_hash(output / 'resolver-runtime.service')
        resolver_console = (output / 'resolver-console.txt').open('x')
        resolver_launcher = subprocess.Popen(['systemd-run', '--quiet', '--wait', '--pipe', '--collect',
            '--unit=' + resolver_unit, *properties, *execution], stdout=resolver_console, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 8
        while not ready.exists() and resolver_launcher.poll() is None and time.monotonic() < deadline:
            time.sleep(.05)
        check('non_root_logging_resolver_ready', ready.exists() and service_alive(resolver_unit))
        if not report['checks']['non_root_logging_resolver_ready']:
            raise RuntimeError('resolver_start_failed')
        readiness = json.loads(ready.read_text())
        check('resolver_identity', readiness.get('uid') == dns_uid and readiness.get('listen') == LISTEN
              and readiness.get('upstream') == UPSTREAM)
        report['resolver_ready'] = readiness
        status = Path('/proc/' + str(readiness['pid']) + '/status').read_text()
        effective = next(int(line.split()[1], 16) for line in status.splitlines() if line.startswith('CapEff:'))
        check('resolver_only_bind_capability', effective == 1 << 10)
        report['resolver_effective_capabilities'] = effective
        response = dns.query.udp(dns.message.make_query(host, 'A'), LISTEN, timeout=4)
        addresses = sorted({item.address for rrset in response.answer if rrset.rdtype == dns.rdatatype.A for item in rrset})
        rules = render_firewall((bundle / 'preview.nft.in').read_text(), table, addresses,
                                manifest['local_ipv4'], manifest['gateways_ipv4'])
        report['frozen_site_ipv4'] = addresses
        tcp = dns.query.tcp(dns.message.make_query(host, 'A'), LISTEN, timeout=4)
        check('resolver_udp_tcp_positive', bool(addresses) and bool(tcp.answer))
        if not all(report['checks'].values()):
            raise RuntimeError('resolver_preflight_failed')
        fixtures = {'alternate_tcp': ('127.0.0.55', 53, TCP, socket.SOCK_STREAM),
                    'alternate_udp': ('127.0.0.55', 53, UDP, socket.SOCK_DGRAM),
                    'private': ('127.0.0.56', 8443, TCP, socket.SOCK_STREAM),
                    'ipv6': ('::1', 8443, TCP6, socket.SOCK_STREAM)}
        for name, (address, port, cls, _) in fixtures.items():
            server = cls((address, port), receiver(receiver_log, name))
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
            thread.start()
            servers.append(server)
            threads.append(thread)
        rulefile = output / 'runtime-rules.nft'
        rulefile.write_text(rules)
        report['firewall_file_hash'] = file_hash(rulefile)
        command('nft', '-c', '-f', str(rulefile))
        command('nft', '-f', str(rulefile))
        installed = True
        normal_policy = reject_counter(table)['policy_hash']
        report['normal_firewall_state_hash'] = normal_policy
        for phase, case in [('normal', None), *[('denied', name) for name in fixtures], ('blocked', None), ('restored', None)]:
            key = phase + ('-' + case if case else '')
            if subprocess.run(['pgrep', '-u', str(uid)], capture_output=True).returncode != 1:
                raise RuntimeError('worker_account_busy')
            if not service_alive(resolver_unit):
                raise RuntimeError('resolver_or_logging_failed')
            phase_label(phasefile, 'controller-before-' + key)
            if case:
                address, port, _, kind = fixtures[case]
                family = socket.AF_INET6 if ':' in address else socket.AF_INET
                positive_start = len(receiver_log)
                with socket.socket(family, kind) as connection:
                    connection.settimeout(2)
                    connection.connect((address, port))
                    connection.sendall(b'OWNED CONTROL POSITIVE')
                    positive = bool(connection.recv(128))
                check(key + '_working_receiver', positive and len(receiver_log) > positive_start)
            if phase == 'blocked':
                command('nft', 'flush', 'chain', 'inet', table, 'dns_allow')
            elif phase == 'restored':
                for transport in ('udp', 'tcp'):
                    command('nft', 'add', 'rule', 'inet', table, 'dns_allow', 'ip', 'daddr', LISTEN,
                            transport, 'dport', '53', 'counter', 'accept')
            first = reject_counter(table)
            dns_index, receiver_index = len(readlogs(logfile)), len(receiver_log)
            phase_label(phasefile, 'workload-' + key)
            destination = private / key
            replacements = {**substitutions, 'PHASE': phase, 'OUTPUT': destination}
            rendered, properties, execution = render_service((bundle / 'preview-worker.service').read_text(),
                replacements, private, environment)
            if case:
                execution += ['--case', case]
                rendered = rendered.replace('--phase denied', '--phase denied --case ' + case)
            unit = 'study-preview-' + key.replace('_', '-') + '-' + nonce[:16]
            runtime_units.append(unit)
            (output / (key + '-runtime.service')).write_text(rendered)
            with (output / (key + '-console.txt')).open('x') as stream:
                code = subprocess.run(['systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--unit=' + unit,
                    *properties, *execution], stdout=stream, stderr=subprocess.STDOUT, timeout=190).returncode
            (output / (key + '-journal.txt')).write_text(command('journalctl', '-u', unit, '--no-pager'))
            time.sleep(.15)
            last = reject_counter(table)
            queries = [row for row in readlogs(logfile)[dns_index:] if row.get('event') == 'query']
            hits = receiver_log[receiver_index:]
            worker = json.loads((destination / 'report.json').read_text())
            identity_ok = (all(worker.get(name) == value for name, value in preview_identity(manifest).items())
                           and worker.get('phase') == phase and worker.get('case') == case)
            check(key + '_worker_passed', code == 0 and worker['status'] == 'passed' and identity_ok)
            check(key + '_zero_receiver_hits', not hits)
            check(key + '_resolver_healthy', service_alive(resolver_unit))
            delta = last['reject_packets'] - first['reject_packets']
            if phase == 'blocked' or case in {'alternate_tcp', 'alternate_udp', 'private'}:
                check(key + '_kernel_reject', delta > 0)
            if case == 'ipv6':
                check(key + '_os_address_family_denial', worker.get('denial', {}).get('denied') is True)
            if phase == 'blocked':
                check('blackout_zero_resolver_queries', not queries)
            if phase in {'normal', 'restored'}:
                check(key + '_logged_owned_query', any(row.get('hostname') == host for row in queries))
            if phase == 'restored':
                check('dns_policy_restored', last['policy_hash'] == normal_policy)
            receipt = {'phase': key, 'nonce': nonce, 'started_at': worker.get('started_at'),
                       'finished_at': worker.get('finished_at'), 'worker_exit': code,
                       'worker_identity_matches': identity_ok, 'service_hash': file_hash(output / (key + '-runtime.service')),
                       'before': first, 'after': last, 'reject_counter_delta': delta,
                       'dns_queries': queries, 'denied_receiver_hits': hits}
            save(output / (key + '-receipt.json'), receipt)
            report['phase_receipt_hashes'][key] = file_hash(output / (key + '-receipt.json'))
            report['phases'].append({k: receipt[k] for k in ('phase', 'worker_exit', 'reject_counter_delta', 'service_hash', 'started_at', 'finished_at')})
            if not all(report['checks'].values()):
                raise RuntimeError('preview_phase_failed_' + key)
        report['status'] = 'preview-passed'
    except Exception as error:
        report.update(error_type=type(error).__name__, error_message=str(error)[:800])
    finally:
        cleanup_errors = []
        def cleanup(name, action):
            try:
                return action()
            except Exception as error:
                cleanup_errors.append({'step': name, 'error_type': type(error).__name__, 'message': str(error)[:500]})
                check(name, False)
                return None
        for unit in runtime_units:
            if service_alive(unit):
                cleanup('stop_' + unit, lambda unit=unit: subprocess.run(['systemctl', 'stop', unit],
                    capture_output=True, timeout=20, check=True))
                check('no_forced_worker_stop', False)
        for server in servers:
            cleanup('receiver_shutdown', server.shutdown)
            cleanup('receiver_close', server.server_close)
        for thread in threads:
            thread.join(3)
        check('receivers_stopped', all(not thread.is_alive() for thread in threads))
        cleanup('save_receiver_logs', lambda: save(output / 'receiver-logs.json', receiver_log))
        if resolver_launcher is not None:
            stopped = cleanup('resolver_stop_command', lambda: subprocess.run(['systemctl', 'stop', resolver_unit],
                capture_output=True, text=True, timeout=20))
            check('resolver_stop_command', stopped is not None and stopped.returncode == 0)
        if resolver_launcher is not None:
            try:
                resolver_exit = resolver_launcher.wait(timeout=15)
                check('resolver_service_exit_zero', resolver_exit == 0)
                report['resolver_service_exit'] = resolver_exit
            except subprocess.TimeoutExpired:
                # Only this exact unit is stopped. A later kill is a failed run.
                cleanup('kill_exact_resolver_unit', lambda: subprocess.run(['systemctl', 'kill', '--signal=KILL', resolver_unit], capture_output=True, timeout=10))
                cleanup('reap_resolver_launcher', lambda: resolver_launcher.wait(timeout=5))
                check('resolver_service_exit_zero', False)
        journal = cleanup('resolver_journal', lambda: command('journalctl', '-u', resolver_unit, '--no-pager')) or ''
        cleanup('save_resolver_journal', lambda: (output / 'resolver-journal.txt').write_text(journal))
        events = cleanup('resolver_final_log', lambda: readlogs(logfile)) if logfile.exists() else []
        check('resolver_logged_clean_shutdown', bool(events) and events[-1].get('event') == 'stopped'
              and not any('timed out' in row.lower() or 'status=9/KILL' in row for row in journal.splitlines()))
        check('preview_accounts_idle', all(subprocess.run(['pgrep', '-u', str(value)], capture_output=True).returncode == 1 for value in (uid, dns_uid)))
        if installed:
            cleanup('save_final_firewall', lambda: save(output / 'firewall-final.json', reject_counter(table)))
            # Never remove containment while an owned workload may still run.
            if subprocess.run(['pgrep', '-u', str(uid)], capture_output=True).returncode == 1:
                cleanup('remove_preview_firewall', lambda: command('nft', 'delete', 'table', 'inet', table))
            else:
                check('remove_preview_firewall', False)
                report['firewall_retained_for_pending_workload'] = True
        after = cleanup('snapshot_after', lambda: snapshot(output, 'after'))
        if after is not None:
            check('outer_firewall_unchanged', firewall_state_hash(before['firewall']) == firewall_state_hash(after['firewall']))
            check('outer_dns_nss_hosts_unchanged', before['dns'] == after['dns'])
            check('outer_ipv4_topology_unchanged', parse_network_snapshot(before['addresses'], before['routes'])
                  == parse_network_snapshot(after['addresses'], after['routes']))
        check('source_unchanged', source_hash(APP) == manifest['source_hash'])
        report['cleanup_errors'] = cleanup_errors
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        if not all(report['checks'].values()):
            report['status'] = 'failed'
        if report['status'] == 'preview-passed':
            validate_preview_evidence(manifest, report)
        save(output / 'report.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('bundle', 'output', 'private', 'resolver-output', 'phase-file'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--nonce', required=True)
    args = parser.parse_args()
    for path in (args.private, args.resolver_output, args.phase_file):
        if not path.resolve().is_relative_to(PRIVATE_ROOT):
            parser.error('fresh runtime state must remain under fixture storage')
    report = run(args.bundle, args.output, args.private, args.resolver_output, args.phase_file, args.nonce)
    print(json.dumps({'status': report['status'], 'checks': report['checks'], 'output': str(args.output)}))
    return 0 if report['status'] == 'preview-passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
