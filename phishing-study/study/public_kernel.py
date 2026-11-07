"""Exercise an exact public-web bundle inside an already disconnected namespace.

All addresses here are synthetic laboratory aliases on loopback. This module
never creates an Internet interface, moves interfaces, edits a global resolver,
visits candidates, or changes a collection gate. Invoke it through a bounded
root-owned PrivateNetwork service with the bundle's resolver files bind-mounted.
IPv6 socket creation is deliberately available here to measure nft rejection;
the installed collection service also denies AF_INET6 at its OS boundary.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import socketserver
import stat
import subprocess
import sys
import threading
import time

from .browser_lifecycle import read_process_identity, process_identity_state
from .deployment import file_hash, firewall_state_hash, secure_root_file, source_files, source_hash
from .deployment_checks import resource_limits
from .public_web import (KERNEL_CASES, KERNEL_CHECKS, NFT_TABLE,
                         validate_public_bundle, _lifecycle)

APP = Path(__file__).resolve().parents[1]
PRIVATE_ROOT = Path('/var/lib/phishing-study-public/verification-private')
PUBLIC, ALTERNATE, PRIVATE = '93.184.216.34', '93.184.216.36', '10.0.0.2'
RESOLVER, STUB, V6 = '127.0.0.153', '127.0.0.53', '2001:4860::1234'
FIXTURES = (('http', PUBLIC, 80, 'http'),
    ('approved_dns_udp', RESOLVER, 53, 'dns-udp'),
    ('approved_dns_tcp', RESOLVER, 53, 'dns-tcp'),
    ('stub_dns_udp', STUB, 53, 'dns-udp'), ('stub_dns_tcp', STUB, 53, 'dns-tcp'),
    ('alternate_dns_udp', ALTERNATE, 53, 'dns-udp'),
    ('alternate_dns_tcp', ALTERNATE, 53, 'dns-tcp'),
    ('private_ipv4_tcp', PRIVATE, 8443, 'tcp'),
    ('public_shaped_nonweb_tcp', PUBLIC, 8443, 'tcp'),
    ('ipv6_tcp', V6, 443, 'tcp'), ('nonweb_udp_443', PUBLIC, 443, 'udp'))
ALLOWED_WORKLOAD_RECEIVERS = frozenset(('http', 'approved_dns_udp', 'approved_dns_tcp'))
ALIAS_SPECS = ((PUBLIC, 32), (RESOLVER, 32), (STUB, 32),
               (ALTERNATE, 32), (PRIVATE, 32), (V6, 128))


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def write(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def command(*arguments):
    return subprocess.check_output(arguments, text=True, timeout=10)


def network():
    return {'inode': os.stat('/proc/self/ns/net').st_ino,
        'interfaces': sorted(x['ifname'] for x in json.loads(command('ip', '-j', 'link'))),
        'addresses': json.loads(command('ip', '-j', 'address')),
        'ipv4_routes': json.loads(command('ip', '-j', '-4', 'route', 'show', 'table', 'all')),
        'ipv6_routes': json.loads(command('ip', '-j', '-6', 'route', 'show', 'table', 'all')),
        'ipv4_defaults': json.loads(command('ip', '-j', '-4', 'route', 'show', 'default')),
        'ipv6_defaults': json.loads(command('ip', '-j', '-6', 'route', 'show', 'default'))}


def disconnected(snapshot, outer_inode):
    return (type(outer_inode) is int and outer_inode > 0
        and type(snapshot.get('inode')) is int and snapshot['inode'] > 0
        and snapshot['inode'] != outer_inode and snapshot.get('interfaces') == ['lo']
        and all(isinstance(snapshot.get(key), list) for key in
                ('ipv4_routes', 'ipv6_routes', 'ipv4_defaults', 'ipv6_defaults'))
        and not snapshot.get('ipv4_defaults') and not snapshot.get('ipv6_defaults')
        and all(row.get('dev', 'lo') == 'lo'
                for key in ('ipv4_routes', 'ipv6_routes') for row in snapshot.get(key, [])))


def normalized_network(snapshot):
    """Ignore volatile address lifetimes, keeping addresses, flags and routes."""
    def clean(value):
        if isinstance(value, dict):
            return {k: clean(v) for k, v in value.items()
                    if k not in {'valid_life_time', 'preferred_life_time', 'cache', 'expires', 'used', 'age'}}
        if isinstance(value, list):
            return sorted((clean(v) for v in value), key=lambda x: json.dumps(x, sort_keys=True))
        return value
    return clean(snapshot)


def counter_receipt(rules):
    result = {'reject_packets': 0, 'resolver_reply_udp': 0, 'resolver_reply_tcp': 0,
              'resolver_stub_udp': 0, 'resolver_stub_tcp': 0}
    for item in rules.get('nftables', []):
        rule = item.get('rule', {})
        expressions = rule.get('expr', [])
        packets = sum(e.get('counter', {}).get('packets', 0) for e in expressions)
        if any('reject' in expr for expr in expressions):
            result['reject_packets'] += packets
        if rule.get('chain') == 'resolver':
            signature = json.dumps([e for e in expressions if 'counter' not in e], sort_keys=True)
            for transport in ('udp', 'tcp'):
                if ('"protocol": "' + transport + '"') not in signature:
                    continue
                if '"sport"' in signature and 'established' in signature:
                    result['resolver_reply_' + transport] += packets
                if '"dport"' in signature and STUB in signature:
                    result['resolver_stub_' + transport] += packets
    return result


def nft_snapshot():
    rules = json.loads(command('nft', '-j', 'list', 'table', 'inet', NFT_TABLE))
    return {**counter_receipt(rules), 'rules': rules}


def exact_read(connection, length):
    data = b''
    while len(data) < length:
        part = connection.recv(length - len(data))
        if not part:
            raise EOFError('fixture_peer_closed')
        data += part
    return data


def fixture_dns(data, nonce):
    """Only answer this run's controls.test names; no forwarding exists."""
    import dns.message
    import dns.rcode
    import dns.rdatatype
    import dns.rrset
    query = dns.message.from_wire(data)
    if len(query.question) != 1:
        raise ValueError('single_fixture_question_required')
    question = query.question[0]
    name = str(question.name).lower()
    valid = re.fullmatch('[a-z0-9]{1,24}' + re.escape(nonce) + r'\.controls\.test\.', name) is not None
    response = dns.message.make_response(query)
    if valid and question.rdtype == dns.rdatatype.A:
        response.answer.append(dns.rrset.from_text(name, 0, 'IN', 'A', PUBLIC))
    elif not valid:
        response.set_rcode(dns.rcode.NXDOMAIN)
    return response.to_wire(), {'query_name': name,
        'query_type': dns.rdatatype.to_text(question.rdtype), 'fixture_name_allowed': valid}


class ReceiverLog:
    def __init__(self, dns_log, phase_fd):
        self.lock, self.rows = threading.Lock(), []
        self.dns_log, self.phase_fd, self.phase = Path(dns_log), phase_fd, 'preparation'

    def set_phase(self, phase):
        self.phase = phase
        value = phase.encode('ascii')
        os.pwrite(self.phase_fd, value, 0)
        os.ftruncate(self.phase_fd, len(value))

    def add(self, endpoint, **details):
        with self.lock:
            self.rows.append({'utc': timestamp(), 'monotonic_ns': time.monotonic_ns(),
                'phase': self.phase, 'endpoint': endpoint, 'server_uid': os.geteuid(), **details})

    def snapshot(self):
        with self.lock:
            root_rows = list(self.rows)
        dns_rows = []
        if self.dns_log.exists():
            # A concurrent append may have an incomplete final line. It becomes
            # visible in the next receipt, never fabricated as a complete query.
            raw = self.dns_log.read_bytes()
            for line in raw.splitlines(keepends=True):
                if line.endswith(b'\n'):
                    dns_rows.append(json.loads(line))
        return sorted(root_rows + dns_rows, key=lambda item: item['monotonic_ns'])


class TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = False


class TCP6(TCP):
    address_family = socket.AF_INET6


class UDP(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = False


def handler(log, endpoint, kind, nonce):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                if kind.endswith('udp'):
                    data, connection = self.request
                    if kind == 'dns-udp':
                        reply, details = fixture_dns(data, nonce)
                    else:
                        reply, details = b'CONTROL-ACK', {'bytes_received': len(data)}
                    log.add(endpoint, transport='udp', **details)
                    connection.sendto(reply, self.client_address)
                    return
                self.request.settimeout(2)
                if kind == 'dns-tcp':
                    length = int.from_bytes(exact_read(self.request, 2), 'big')
                    if not 0 < length <= 4096:
                        raise ValueError('fixture_dns_length')
                    reply, details = fixture_dns(exact_read(self.request, length), nonce)
                    log.add(endpoint, transport='tcp', **details)
                    self.request.sendall(len(reply).to_bytes(2, 'big') + reply)
                elif kind == 'http':
                    data = self.request.recv(4096)
                    redirect = data.startswith(b'GET /redirect ')
                    log.add(endpoint, transport='tcp', redirected=redirect)
                    if redirect:
                        reply = (b'HTTP/1.1 302 Found\r\nLocation: http://10.0.0.2:8443/'
                            b'\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                    else:
                        body = b'<!doctype html><title>Local fixture</title><p>LOCAL CONTROL</p>'
                        reply = (b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: '
                            + str(len(body)).encode() + b'\r\nConnection: close\r\n\r\n' + body)
                    self.request.sendall(reply)
                else:
                    self.request.recv(4096)
                    log.add(endpoint, transport='tcp')
                    self.request.sendall(b'CONTROL-ACK')
            except Exception as exc:
                log.add(endpoint, fixture_error=type(exc).__name__)
    return Handler


def listener_uid_rows(address, port=53):
    """Linux socket ownership is the identity nft meta skuid actually sees."""
    key = socket.inet_aton(address)[::-1].hex().upper() + ':' + format(port, '04X')
    result = {}
    for transport in ('udp', 'tcp'):
        rows = [line.split() for line in Path('/proc/net/' + transport).read_text().splitlines()[1:]]
        found = [int(row[7]) for row in rows if len(row) > 7 and row[1] == key]
        result[transport] = found
    return result


def bind_dns_as_account(uid, gid):
    """Create sockets after dropping UID; inode chown cannot change sk_uid."""
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    class Header(ctypes.Structure):
        _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]
    class Data(ctypes.Structure):
        _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32), ('inheritable', ctypes.c_uint32)]
    def checked(value):
        if value != 0:
            number = ctypes.get_errno()
            raise OSError(number, os.strerror(number))
    def caps(bits):
        header, values = Header(0x20080522, 0), (Data * 2)()
        values[0].effective = values[0].permitted = bits
        checked(libc.capset(ctypes.byref(header), ctypes.byref(values)))
    checked(libc.prctl(8, 1, 0, 0, 0))  # PR_SET_KEEPCAPS, scoped to this child.
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    sockets = []
    try:
        caps(1 << 10)  # Only CAP_NET_BIND_SERVICE while binding port 53.
        for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
            listener = socket.socket(socket.AF_INET, kind)
            sockets.append(listener)
            listener.bind((RESOLVER, 53))
            if kind == socket.SOCK_STREAM:
                listener.listen(16)
        caps(0)
        checked(libc.prctl(8, 0, 0, 0, 0))
        checked(libc.prctl(38, 1, 0, 0, 0))  # NoNewPrivileges after all caps drop.
        return sockets
    except BaseException:
        for listener in sockets:
            listener.close()
        raise


def dns_child(sockets, uid, gid, log_fd, phase_fd, ready_fd, nonce):
    """One bounded fixture process with its own sockets and no capabilities."""
    running = True
    def stop(_signal, _frame):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, stop)
    if os.geteuid() != uid or os.getegid() != gid or os.getgroups():
        raise ValueError('dns_fixture_identity_not_dropped')
    status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    os.write(ready_fd, json.dumps({'uid': os.geteuid(), 'gid': os.getegid(),
        'groups': os.getgroups(), 'socket_creation_uid': uid, 'cap_eff': status['CapEff'].strip(),
        'socket_uids': [os.fstat(s.fileno()).st_uid for s in sockets]}).encode() + b'\n')
    os.close(ready_fd)
    try:
        while running:
            readable, _, _ = select.select(sockets, [], [], .1)
            for listener in readable:
                transport = 'udp' if listener.type == socket.SOCK_DGRAM else 'tcp'
                connection = None
                try:
                    if transport == 'udp':
                        data, peer = listener.recvfrom(4096)
                    else:
                        connection, peer = listener.accept()
                        connection.settimeout(2)
                        length = int.from_bytes(exact_read(connection, 2), 'big')
                        if not 0 < length <= 4096:
                            raise ValueError('fixture_dns_length')
                        data = exact_read(connection, length)
                    reply, details = fixture_dns(data, nonce)
                    row = {'utc': timestamp(), 'monotonic_ns': time.monotonic_ns(),
                        'phase': os.pread(phase_fd, 128, 0).decode('ascii'),
                        'endpoint': 'approved_dns_' + transport, 'transport': transport,
                        'server_uid': os.geteuid(), 'socket_uid': os.fstat(listener.fileno()).st_uid,
                        **details}
                    os.write(log_fd, json.dumps(row, sort_keys=True).encode() + b'\n')
                    if transport == 'udp':
                        listener.sendto(reply, peer)
                    else:
                        connection.sendall(len(reply).to_bytes(2, 'big') + reply)
                except Exception as exc:
                    row = {'utc': timestamp(), 'monotonic_ns': time.monotonic_ns(),
                        'phase': os.pread(phase_fd, 128, 0).decode('ascii'),
                        'endpoint': 'approved_dns_' + transport, 'fixture_error': type(exc).__name__,
                        'server_uid': os.geteuid()}
                    os.write(log_fd, json.dumps(row).encode() + b'\n')
                finally:
                    if connection is not None:
                        connection.close()
    finally:
        for listener in sockets:
            listener.close()


def start_dns(uid, gid, output, phase_fd, nonce):
    """Fork, drop privilege, bind under the actual DNS UID, then prove replies."""
    sockets, log_fd, read_fd, write_fd, pid = [], None, None, None, None
    try:
        log_fd = os.open(output / 'dns-account-queries.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND, 0o600)
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            try:
                sockets = bind_dns_as_account(uid, gid)
                dns_child(sockets, uid, gid, log_fd, phase_fd, write_fd, nonce)
                os._exit(0)
            except BaseException:
                os._exit(1)
        os.close(write_fd)
        write_fd = None
        ready, _, _ = select.select([read_fd], [], [], 4)
        if not ready:
            raise RuntimeError('dns_fixture_ready_deadline')
        evidence = json.loads(os.read(read_fd, 4096))
        evidence['identity'] = read_process_identity(pid)
        evidence['listener_uid_rows'] = listener_uid_rows(RESOLVER)
        if (evidence['uid'] != uid or evidence['gid'] != gid or evidence['groups'] != []
                or evidence.get('socket_creation_uid') != uid or int(evidence.get('cap_eff', '-1'), 16) != 0
                or evidence['socket_uids'] != [uid, uid]
                or any(rows != [uid] for rows in evidence['listener_uid_rows'].values())):
            raise RuntimeError('dns_fixture_socket_identity_mismatch')
        return evidence
    except BaseException:
        if pid:
            # This direct child cannot be replaced before waitpid reaps it.
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        raise
    finally:
        for listener in sockets:
            listener.close()
        for fd in (log_fd, read_fd, write_fd):
            if fd is not None:
                os.close(fd)


def same_process(identity):
    try:
        return read_process_identity(identity['pid']) == identity
    except (OSError, ValueError, KeyError):
        return False


def bounded_stop(identity, direct_child=False):
    receipt = {'identity': identity, 'signals': [], 'gone': False}
    for sig, seconds in ((signal.SIGTERM, 3), (signal.SIGKILL, 2)):
        if direct_child:
            found, status = os.waitpid(identity['pid'], os.WNOHANG)
            if found:
                receipt.update(gone=True, wait_status=status)
                return receipt
        elif process_identity_state(identity)['gone']:
            receipt['gone'] = True
            return receipt
        if not same_process(identity):
            receipt['reason'] = 'identity_changed_signal_refused'
            return receipt
        os.kill(identity['pid'], sig)
        receipt['signals'].append(sig.name)
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if direct_child:
                found, status = os.waitpid(identity['pid'], os.WNOHANG)
                if found:
                    receipt.update(gone=True, wait_status=status)
                    return receipt
            elif process_identity_state(identity)['gone']:
                receipt['gone'] = True
                return receipt
            time.sleep(.03)
    return receipt


def positive_controls(nonce):
    import dns.message
    import dns.rcode
    results = []
    for endpoint, address, port, kind in FIXTURES:
        family = socket.AF_INET6 if ':' in address else socket.AF_INET
        transport = socket.SOCK_DGRAM if kind.endswith('udp') else socket.SOCK_STREAM
        query = dns.message.make_query('positive' + nonce + '.controls.test', 'A').to_wire()
        with socket.socket(family, transport) as connection:
            connection.settimeout(2)
            connection.connect((address, port))
            if kind.startswith('dns'):
                connection.sendall((len(query).to_bytes(2, 'big') if transport == socket.SOCK_STREAM else b'') + query)
                reply = (exact_read(connection, int.from_bytes(exact_read(connection, 2), 'big'))
                         if transport == socket.SOCK_STREAM else connection.recv(4096))
                ok = dns.message.from_wire(reply).rcode() == dns.rcode.NOERROR
            elif kind == 'http':
                connection.sendall(b'GET /positive HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n')
                ok = connection.recv(4096).startswith(b'HTTP/1.1 200')
            else:
                connection.sendall(b'CONTROL-POSITIVE-' + nonce.encode())
                ok = bool(connection.recv(4096))
        results.append({'endpoint': endpoint, 'ok': ok, 'at': timestamp()})
    return results


def tracked_descendants(pid, uid, captured):
    """Capture only descendants of our exact still-live worker, never a UID scan."""
    pending = [pid]
    while pending:
        parent = pending.pop()
        try:
            children = Path('/proc/' + str(parent) + '/task/' + str(parent) + '/children').read_text().split()
        except OSError:
            continue
        for value in children:
            try:
                identity = read_process_identity(int(value))
                if identity['uid'] == uid and identity['netns'] == os.readlink('/proc/self/ns/net'):
                    captured[(identity['pid'], identity['start_time'])] = identity
                    pending.append(identity['pid'])
            except (OSError, ValueError, KeyError):
                continue


def run_worker(a, manifest, key, phase, case=None, role='workload'):
    import pwd
    uid = manifest['resolver']['uid'] if role == 'resolver' else manifest['study_uid']
    private = a.resolver_private if role == 'resolver' else a.private
    output = private / key
    arguments = [sys.executable, '-m', 'study.public_kernel_worker', '--phase', phase,
        '--nonce', a.nonce, '--bundle', str(a.bundle), '--output', str(output),
        '--role', role, '--label', re.sub('[^a-z0-9]', '', key)[:24]]
    if case:
        arguments += ['--socket-case', case]
    captured, deadline = {}, time.monotonic() + 170
    forced, exitcode, worker_identity = [], None, None
    cleanup = {'forced_stops': forced, 'captured_identities': [],
               'all_owned_processes_gone': False}
    # Register failure-closed before launch: even an identity/cleanup exception
    # cannot cause the controller to remove containment for an unproved worker.
    a.process_receipts.append(cleanup)
    with (a.output / (key + '-console.txt')).open('x', encoding='utf-8') as console:
        process = subprocess.Popen(arguments, user=uid, group=pwd.getpwuid(uid).pw_gid,
            extra_groups=[], stdout=console, stderr=subprocess.STDOUT, cwd=APP,
            env={**os.environ, 'HOME': str(private), 'PYTHONPATH': str(APP)}, start_new_session=True)
        try:
            worker_identity = read_process_identity(process.pid)
            if worker_identity['uid'] != uid:
                raise RuntimeError('worker_did_not_drop_identity')
            captured[(process.pid, worker_identity['start_time'])] = worker_identity
            while process.poll() is None and time.monotonic() < deadline:
                if same_process(worker_identity):
                    tracked_descendants(process.pid, uid, captured)
                time.sleep(.05)
            exitcode = process.poll()
        finally:
            if process.poll() is None and worker_identity is not None:
                try:
                    forced.append(bounded_stop(worker_identity))
                except Exception as exc:
                    forced.append({'gone': False, 'error_type': type(exc).__name__})
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
            # Native lifecycle cleanup must have removed every captured child.
            for identity in reversed(list(captured.values())):
                if identity['pid'] != process.pid and not process_identity_state(identity)['gone']:
                    try:
                        forced.append(bounded_stop(identity))
                    except Exception as exc:
                        forced.append({'gone': False, 'error_type': type(exc).__name__})
            cleanup.update(worker_pid=process.pid, worker_returncode=process.poll(),
                captured_identities=list(captured.values()),
                all_owned_processes_gone=(process.poll() is not None
                    and all(process_identity_state(i)['gone'] for i in captured.values())))
    write(a.output / (key + '-process-receipt.json'), cleanup)
    path = output / 'report.json'
    worker = json.loads(path.read_text(encoding='utf-8')) if path.is_file() else {'status': 'failed', 'error_type': 'WorkerReportMissing'}
    worker['report_sha256'] = file_hash(path) if path.is_file() else None
    worker['worker_exit'] = exitcode
    worker['worker_report_path'] = str(path)
    write(a.output / (key + '-worker-report.json'), worker)
    if (exitcode != 0 or worker.get('status') != 'passed'
            or worker.get('source_hash') != manifest['source_hash'] or forced
            or not cleanup['all_owned_processes_gone']):
        raise RuntimeError('worker_failed_' + key)
    if phase in {'normal', 'blocked', 'restored', 'redirect'}:
        _lifecycle(worker, uid)
    return worker


def protected_directory(path, owner):
    """No symlinks; only this private leaf may belong to the workload UID."""
    path = Path(path).absolute()
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != owner or info.st_mode & 0o077):
        raise ValueError('private_directory_identity_or_mode')
    for parent in path.parents:
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('private_parent_not_protected')
    if not path.is_relative_to(PRIVATE_ROOT):
        raise ValueError('private_directory_outside_verification_root')
    return path


def preflight(a, report):
    import pwd
    if os.geteuid() != 0 or re.fullmatch('[a-f0-9]{32}', a.nonce) is None:
        raise ValueError('root_and_fresh_32hex_nonce_required')
    state = network()
    report['network_before'] = state
    if not disconnected(state, a.outer_inode):
        raise ValueError('already_disconnected_separate_namespace_required')
    for directory in (a.output, *a.output.parents):
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != 0 or info.st_mode & 0o022):
            raise ValueError('root_protected_evidence_directory_required')
    for name in ('deployment.json', 'source-hashes.json'):
        secure_root_file(a.bundle / name)
    manifest = validate_public_bundle(a.bundle, root=APP)
    if Path(manifest['source_root']).resolve() != APP:
        raise ValueError('installed_source_root_mismatch')
    for path in [*source_files(APP), *(a.bundle / name for name in manifest['artifact_hashes'])]:
        secure_root_file(path)
    if {PUBLIC, ALTERNATE, PRIVATE, RESOLVER, STUB}.intersection(manifest['local_ipv4'] + manifest['gateways_ipv4']):
        raise ValueError('synthetic_alias_conflicts_with_real_vm_topology')
    for uid in (manifest['study_uid'], manifest['resolver']['uid']):
        pwd.getpwuid(uid)
    a.private = protected_directory(a.private, manifest['study_uid'])
    a.resolver_private = a.private.parent / (a.private.name + '-resolver')
    if a.resolver_private.exists() or a.resolver_private.is_symlink():
        raise ValueError('fresh_resolver_probe_directory_required')
    a.resolver_private.mkdir(mode=0o700)
    os.chown(a.resolver_private, manifest['resolver']['uid'], pwd.getpwuid(manifest['resolver']['uid']).pw_gid)
    report['resources'] = resource_limits()
    if not report['resources'].get('ok') or int(report['resources']['memory_max']) > 2147483648:
        raise ValueError('two_gib_two_cpu_bounded_service_required')
    report.update({key: manifest[key] for key in ('source_hash', 'firewall_hash', 'service_hash')})
    report['checks']['namespace_disconnected'] = True
    return manifest


def run(a, report):
    manifest = preflight(a, report)
    import pwd
    uid, dnsuid = manifest['study_uid'], manifest['resolver']['uid']
    before_firewall = json.loads(command('nft', '-j', 'list', 'ruleset'))
    before_dns = {name: file_hash('/etc/' + name) for name in ('resolv.conf', 'nsswitch.conf', 'hosts')}
    report['firewall_before'] = before_firewall
    if any(item.get('table', {}).get('name') == NFT_TABLE for item in before_firewall.get('nftables', [])):
        raise ValueError('collection_table_already_exists_in_namespace')
    sentinel = 'public_kernel_sentinel_' + a.nonce[:12]
    if any(item.get('table', {}).get('name') == sentinel for item in before_firewall.get('nftables', [])):
        raise ValueError('fresh_unrelated_sentinel_identity_required')
    servers, aliases, dns_process, phase_fd = [], [], None, None
    own_table, sentinel_created = False, False
    log, normal_hash = None, None
    a.process_receipts = []
    report['phases'], report['cases'], report['cleanup'] = [], {}, {}
    trials = []
    try:
        command('nft', 'add', 'table', 'inet', sentinel)
        sentinel_created = True
        for address, prefix in ALIAS_SPECS:
            arguments = ['ip', '-6'] if ':' in address else ['ip']
            arguments += ['address', 'add', address + '/' + str(prefix), 'dev', 'lo']
            if ':' in address:
                arguments += ['nodad']
            command(*arguments)
            aliases.append((address, prefix))
        phase_fd = os.open(a.output / 'phase.txt', os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        log = ReceiverLog(a.output / 'dns-account-queries.jsonl', phase_fd)
        log.set_phase('preparation')
        dns_process = start_dns(dnsuid, pwd.getpwuid(dnsuid).pw_gid, a.output, phase_fd, a.nonce)
        report['dns_account_fixture'] = dns_process
        for endpoint, address, port, kind in FIXTURES:
            if endpoint.startswith('approved_dns'):
                continue
            cls = UDP if kind.endswith('udp') else TCP6 if ':' in address else TCP
            server = cls((address, port), handler(log, endpoint, kind, a.nonce))
            thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
            servers.append((server, thread))
            thread.start()
        # The exact installed artifact is applied, without address or UID edits.
        command('nft', '-c', '-f', str(a.bundle / 'collector.nft'))
        command('nft', '-f', str(a.bundle / 'collector.nft'))
        own_table = True
        write(a.output / 'applied-policy.json', {'artifact': str(a.bundle / 'collector.nft'),
            'sha256': file_hash(a.bundle / 'collector.nft'), 'initial': nft_snapshot()})

        sequence = [('normal', 'normal', None, 'workload')]
        sequence += [(case, 'sockets', case, 'workload') for case in sorted(KERNEL_CASES - {'redirect', 'resolver_web_tcp'})]
        sequence += [('redirect', 'redirect', None, 'workload'),
            ('resolver-web', 'sockets', 'resolver_web_tcp', 'resolver'),
            ('resolver-stub', 'resolver', None, 'resolver'),
            ('blocked', 'blocked', None, 'workload'), ('restored', 'restored', None, 'workload')]
        sequence += [('trial' + str(i + 1).zfill(2), 'normal' if i < 6 else 'redirect', None, 'workload')
                     for i in range(10)]
        for key, phase, case, role in sequence:
            log.set_phase('positive-' + key)
            positive_start = timestamp()
            positives = positive_controls(a.nonce)
            time.sleep(.05)
            positive_rows = [row for row in log.snapshot() if row['phase'] == 'positive-' + key]
            positive_receipt = {'started_at': positive_start, 'finished_at': timestamp(),
                'results': positives, 'logs': positive_rows}
            write(a.output / (key + '-positive-controls.json'), positive_receipt)
            positive_endpoints = {row['endpoint'] for row in positive_rows if not row.get('fixture_error')}
            if not all(row['ok'] for row in positives) or positive_endpoints != {f[0] for f in FIXTURES}:
                raise RuntimeError('positive_control_failed_' + key)
            if phase == 'blocked':
                command('nft', 'flush', 'chain', 'inet', NFT_TABLE, 'dns_allow')
            elif phase == 'restored':
                for transport in ('udp', 'tcp'):
                    command('nft', 'add', 'rule', 'inet', NFT_TABLE, 'dns_allow',
                        'ip', 'daddr', RESOLVER, transport, 'dport', '53', 'counter', 'accept')
            before = nft_snapshot()
            write(a.output / (key + '-before-counters.json'), before)
            log.set_phase('workload-' + key)
            started = timestamp()
            worker_error = None
            try:
                worker = run_worker(a, manifest, key, phase, case, role)
            except BaseException as exc:
                worker_error = exc
                retained = a.output / (key + '-worker-report.json')
                worker = json.loads(retained.read_text()) if retained.is_file() else {}
            time.sleep(.05)
            finished = timestamp()
            after = nft_snapshot()
            write(a.output / (key + '-after-counters.json'), after)
            rows = [row for row in log.snapshot() if row['phase'] == 'workload-' + key]
            delta = after['reject_packets'] - before['reject_packets']
            if any(row.get('fixture_error') for row in rows):
                raise RuntimeError('workload_fixture_error_' + key)
            allowed = {'stub_dns_udp', 'stub_dns_tcp'} if phase == 'resolver' else ALLOWED_WORKLOAD_RECEIVERS
            if any(row['endpoint'] not in allowed for row in rows):
                raise RuntimeError('denied_workload_receiver_hit_' + key)
            receipt = {'key': key, 'phase': phase, 'started_at': started, 'finished_at': finished,
                'worker_exit': worker.get('worker_exit'), 'worker_report_sha256': worker.get('report_sha256'),
                'positive_control_window': positive_receipt, 'before': before, 'after': after,
                'reject_counter_delta': delta, 'receiver_logs': rows}
            write(a.output / (key + '-receipt.json'), receipt)
            report['phases'].append({k: receipt[k] for k in ('key', 'phase', 'started_at', 'finished_at', 'worker_exit', 'reject_counter_delta')})
            if worker_error is not None:
                raise worker_error
            if case or phase == 'redirect' and not key.startswith('trial'):
                name = case or 'redirect'
                endpoint = 'http' if name == 'resolver_web_tcp' else 'private_ipv4_tcp' if name == 'redirect' else name
                counts = {'positive_control_hits': sum(row['endpoint'] == endpoint for row in positive_rows),
                    'workload_hits': sum(row['endpoint'] == endpoint for row in rows),
                    'reject_counter_delta': delta}
                report['cases'][name] = counts
                if counts['positive_control_hits'] <= 0 or counts['workload_hits'] != 0 or name != 'redirect' and delta <= 0:
                    raise RuntimeError('negative_case_inconclusive_' + name)
            if key in {'normal', 'restored'}:
                report['checks'][key + '_http_200'] = worker['navigation']['status'] == 200
                target = worker['dns_hostname'] + '.'
                if not any(row.get('query_name') == target for row in rows):
                    raise RuntimeError('fresh_browser_query_not_logged_' + key)
                for transport in ('udp', 'tcp'):
                    report['checks'][key + '_dns_' + transport] = any(
                        row['endpoint'] == 'approved_dns_' + transport
                        and row['server_uid'] == dnsuid and row.get('socket_uid') == dnsuid for row in rows)
                if key == 'normal':
                    normal_hash = firewall_state_hash(after['rules'])
                    report['normal_firewall_state_hash'] = normal_hash
                    report['checks']['resolver_replies_allowed'] = all(
                        after['resolver_reply_' + t] > before['resolver_reply_' + t] for t in ('udp', 'tcp'))
                else:
                    report['restored_firewall_state_hash'] = firewall_state_hash(after['rules'])
                    report['checks']['firewall_restored'] = report['restored_firewall_state_hash'] == normal_hash
            elif key == 'blocked':
                report['checks']['native_dns_blackout'] = worker['checks']['native_dns_failure']['ok'] and delta > 0
                report['checks']['blackout_zero_dns_queries'] = not any('dns' in row['endpoint'] for row in rows) and not rows
            elif key == 'resolver-stub':
                report['checks']['resolver_stub_allowed'] = all(
                    after['resolver_stub_' + t] > before['resolver_stub_' + t]
                    and any(row['endpoint'] == 'stub_dns_' + t for row in rows) for t in ('udp', 'tcp'))
            if key.startswith('trial'):
                trials.append(worker)
                write(a.output / (key + '-lifecycle.json'), worker)
        report['sentinel_before_cleanup'] = json.loads(command('nft', '-j', 'list', 'table', 'inet', sentinel))
        report['sentinel_preserved'] = True
    finally:
        cleanup_errors = []
        for server, thread in servers:
            try:
                if thread.is_alive():
                    server.shutdown()
                server.server_close()
                thread.join(3)
            except Exception as exc:
                cleanup_errors.append({'step': 'receiver_stop', 'error_type': type(exc).__name__})
        if dns_process is not None:
            try:
                report['dns_fixture_cleanup'] = bounded_stop(dns_process['identity'], direct_child=True)
            except Exception as exc:
                cleanup_errors.append({'step': 'dns_stop', 'error_type': type(exc).__name__})
        if log is not None:
            try:
                write(a.output / 'fixture-receiver-logs.json', log.snapshot())
            except Exception as exc:
                cleanup_errors.append({'step': 'receiver_log_freeze', 'error_type': type(exc).__name__})
        accounts_idle = all(r['all_owned_processes_gone'] for r in a.process_receipts)
        dns_gone = report.get('dns_fixture_cleanup', {}).get('gone', dns_process is None)
        report['cleanup']['accounts_idle'] = accounts_idle and dns_gone
        report['cleanup']['listeners_stopped'] = dns_gone and all(not t.is_alive() for s, t in servers)
        report['cleanup']['dns_fixture_graceful'] = (dns_process is None or dns_gone
            and report['dns_fixture_cleanup'].get('wait_status') == 0
            and 'SIGKILL' not in report['dns_fixture_cleanup'].get('signals', []))
        # Never remove the containment rule while a captured owned process lives.
        if own_table and accounts_idle and dns_gone:
            try:
                command('nft', 'delete', 'table', 'inet', NFT_TABLE)
                own_table = False
            except Exception as exc:
                cleanup_errors.append({'step': 'firewall_remove', 'error_type': type(exc).__name__})
        if sentinel_created:
            try:
                command('nft', 'list', 'table', 'inet', sentinel)
                report['sentinel_preserved'] = True
                command('nft', 'delete', 'table', 'inet', sentinel)
            except Exception as exc:
                cleanup_errors.append({'step': 'sentinel_remove', 'error_type': type(exc).__name__})
        for address, prefix in reversed(aliases):
            try:
                command(*(['ip', '-6'] if ':' in address else ['ip']), 'address', 'del',
                        address + '/' + str(prefix), 'dev', 'lo')
            except Exception as exc:
                cleanup_errors.append({'step': 'alias_remove', 'address': address, 'error_type': type(exc).__name__})
        if phase_fd is not None:
            try:
                os.close(phase_fd)
            except Exception as exc:
                cleanup_errors.append({'step': 'phase_fd_close', 'error_type': type(exc).__name__})
        report['cleanup_errors'] = cleanup_errors
        report['firewall_after'] = json.loads(command('nft', '-j', 'list', 'ruleset'))
        report['network_after'] = network()
        report['cleanup'].update({
            'own_firewall_removed': not own_table,
            'unrelated_tables_preserved': firewall_state_hash(before_firewall) == firewall_state_hash(report['firewall_after']),
            'normalized_network_restored': normalized_network(report['network_before']) == normalized_network(report['network_after']),
            'namespace_still_disconnected': disconnected(report['network_after'], a.outer_inode),
            'outer_dns_nss_hosts_unchanged': before_dns == {name: file_hash('/etc/' + name) for name in before_dns},
            'source_unchanged': source_hash(APP) == manifest['source_hash'],
            'cleanup_errors_absent': not cleanup_errors})
        write(a.output / 'lifecycle-trials.json', {'trials': trials})
    if set(report['cases']) != KERNEL_CASES or len(trials) != 10:
        raise RuntimeError('complete_negative_matrix_and_ten_trials_required')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--private', type=Path, required=True)
    parser.add_argument('--outer-inode', type=int, required=True)
    parser.add_argument('--nonce', required=True)
    a = parser.parse_args(argv)
    a.bundle, a.output, a.private = (p.absolute() for p in (a.bundle, a.output, a.private))
    if a.output.exists() or a.output.is_symlink():
        parser.error('fresh output required; preserve previous failures')
    a.output.mkdir(mode=0o700, parents=False)
    os.umask(0o077)
    report = {'schema_version': 1, 'started_at': timestamp(), 'status': 'failed',
        'nonce': a.nonce, 'scope': 'disconnected synthetic aliases exercising exact installed collector.nft',
        'research_eligible': False, 'network_isolation_verified': False,
        'public_dns_verified': False, 'public_tls_verified': False, 'research_collection_count': 0,
        'checks': {name: False for name in sorted(KERNEL_CHECKS)},
        'assurance_limitations': ['Synthetic aliases are not public receiver infrastructure.',
            'DNS fixture logs do not prove authoritative DNS access.',
            'AF_INET6 is allowed in this diagnostic so the real kernel rejection can be observed.']}
    try:
        run(a, report)
        report['status'] = 'passed' if (all(report['checks'].values()) and report.get('cleanup')
            and all(report['cleanup'].values()) and report.get('sentinel_preserved')) else 'failed'
    except BaseException as exc:
        report['error_type'] = type(exc).__name__
        report['error_message'] = str(exc)[:600]
    report['finished_at'] = timestamp()
    write(a.output / 'kernel-report.json', report)
    print(json.dumps({'status': report['status'], 'output': str(a.output)}))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
