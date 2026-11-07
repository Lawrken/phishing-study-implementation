"""User-operated, finite collection using the existing guarded QEMU pipeline."""
import argparse
import ast
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import subprocess
import sys
import threading
import time

import RunQemuResearch as supervisor

ROOT = Path(__file__).resolve().parents[1]
CONTROL = ROOT / '.operator'


def write_json(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2), encoding='utf-8')
    os.replace(temporary, path)


def current(run_id=None):
    if run_id is None:
        path = CONTROL / 'current.json'
        if not path.exists():
            raise ValueError('No operator run has been prepared yet.')
        value = json.loads(path.read_text(encoding='utf-8'))
    else:
        if re.fullmatch(r'operator-[0-9]{8}-[0-9]{6}(?:-[0-9]{6})?', run_id) is None:
            raise ValueError('Use an operator run ID printed by the Run command.')
        value = {'run_id': run_id, 'folder': 'phishing-study/validation/' + run_id}
    folder = (ROOT / value['folder']).resolve()
    if (not folder.is_relative_to(ROOT / 'phishing-study/validation')
            or folder.name != value['run_id'] or not folder.name.startswith('operator-')
            or not folder.is_dir() or folder.is_symlink()):
        raise ValueError('Invalid operator run pointer.')
    return value, folder


def bounded_attempts(value):
    if type(value) is not int or not 1 <= value <= 400:
        raise ValueError('Choose between 1 and 400 total attempts, including retries.')
    return value


def continuation_record(prior, run_id, source_hash, archive_hash, attempts, candidate_ids, next_attempts):
    """Exclude every attempted endpoint, without copying or fabricating captures."""
    sys.path.insert(0, str(ROOT / 'phishing-study'))
    from study.campaign_continuation import validate_continuation
    previous = set(prior['candidate_ids']) if prior else set()
    ids = set(candidate_ids)
    if not ids or previous & ids:
        raise ValueError('Previous continuation overlaps or has no attempted endpoints.')
    value = {'schema_version': 1, 'attempt_limit': 400,
        'attempts_used': (prior['attempts_used'] if prior else 0) + attempts,
        'candidate_ids': sorted(previous | ids),
        'receipts': (list(prior['receipts']) if prior else []) + [
            {'run_id': run_id, 'source_hash': source_hash, 'archive_sha256': archive_hash, 'attempts': attempts}]}
    validate_continuation(value, next_attempts)
    return value


def freeze_continuation(folder, output, next_attempts):
    """Remeasure the prior frozen archive and database before advancing its queue."""
    folder = folder.resolve()
    if not folder.is_relative_to(ROOT / 'phishing-study/validation'):
        raise ValueError('Continuation must use a saved project run.')
    report = json.loads((folder / 'analysis/summary.json').read_text())
    receipt = json.loads((folder / 'guest-export.json').read_text())
    if (report['profile'] != 'local-dataset-observation-v1'
            or report['host_result_status'] != 'passed' or report['pilot_status'] != 'passed'
            or not report['archive_verification']['passed']
            or supervisor.sha(folder / 'guest-evidence.tar.gz') != receipt['sha256']):
        raise ValueError('A completed, hash-verified dataset run is required for continuation.')
    run_id = folder.name
    root = folder / 'guest-export/guest'
    database = root / ('pilot-' + run_id) / 'dataset/study.sqlite'
    inventory = json.loads((root / 'inventory.json').read_text())
    if supervisor.sha(database) != inventory[database.relative_to(root).as_posix()]['sha256']:
        raise ValueError('The prior frozen attempt database changed.')
    with sqlite3.connect(database.as_uri() + '?mode=ro&immutable=1', uri=True) as connection:
        ids = [row[0] for row in connection.execute('SELECT DISTINCT candidate_id FROM attempts')]
        count = connection.execute('SELECT COUNT(*) FROM attempts').fetchone()[0]
    if count != report['counts']['attempts'] or len(ids) != report['counts']['distinct_urls_attempted']:
        raise ValueError('Prior attempt counts disagree with the frozen export.')
    bundle = root / ('assessment-' + run_id) / 'bundle/deployment.json'
    if supervisor.sha(bundle) != inventory[bundle.relative_to(root).as_posix()]['sha256']:
        raise ValueError('The prior continuation manifest changed.')
    previous = json.loads(bundle.read_text()).get('continuation')
    value = continuation_record(previous, run_id, report['source_hash'], receipt['sha256'], count, ids, next_attempts)
    write_json(output, value)
    return value


class OperatorRun(supervisor.Run):
    def start(self):
        print('1/6 Checking RAM, disk and original VM; booting a fresh Ubuntu overlay.', flush=True)
        return super().start()

    def launch_verification(self):
        print('2/6 Checking installed code, Chromium, local firewall/DNS controls and shutdown. No Vercel visit.', flush=True)
        return super().launch_verification()

    def launch_pilot(self, guest):
        print('3/6 Verification passed. Starting the real sequential collector.', flush=True)
        return super().launch_pilot(guest)

    def probe(self, enforce=True):
        if enforce and (self.output / 'operator-stop.request').exists():
            raise RuntimeError('operator_requested_stop')
        guest = super().probe(enforce=enforce)
        seen = getattr(self, '_seen_attempts', set())
        for attempt in guest.get('dataset_attempts', []):
            key = (attempt['id'], bool(attempt['finished']))
            if key not in seen:
                seen.add(key)
                print(('Saved' if attempt['finished'] else 'Visiting') + ' dataset endpoint: '
                      + attempt['origin'] + ' | ' + attempt['label'] + ' | '
                      + str(attempt['outcome'] or 'checking DNS/loading')
                      + (' | ' + str(attempt['reason']) if attempt.get('reason') else ''), flush=True)
        self._seen_attempts = seen
        counts = guest.get('pilot_counts', {})
        signature = (counts.get('attempts'), counts.get('collector_stop_reason'))
        if signature != getattr(self, '_last_counts', None):
            self._last_counts = signature
            print('Attempts: %s / %s | usable captures: %s | failed attempts: %s' % (
                counts.get('attempts', 0), self.args.max_attempts,
                counts.get('usable_per_class', {}), counts.get('failed_attempts', 0)), flush=True)
        return guest


def run(args):
    bounded_attempts(args.max_attempts)
    with socket.socket() as probe:
        try: probe.bind(('127.0.0.1', 8766))
        except OSError: raise ValueError('Port 8766 is occupied. Close the saved viewer with Ctrl+C before starting a new run.') from None
    # Keep this lock for the entire supervisor lifetime, including cleanup.
    import msvcrt
    CONTROL.mkdir(exist_ok=True)
    with (CONTROL / 'operator.lock').open('a+b') as lock:
        lock.seek(0)
        if lock.read(1) == b'':
            lock.write(b'0'); lock.flush()
        lock.seek(0)
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            raise ValueError('Another operator command is active. Use Status or Stop.') from None
        try:
            stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-%f')
            run_id = 'operator-' + stamp
            parent = ROOT / 'phishing-study/validation'
            preparation = parent / (run_id + '-preparation')
            preparation.mkdir(exist_ok=False)
            continuation_path = None
            if args.continue_previous:
                _, previous_folder = current()
                continuation_path = preparation / 'continuation.json'
                continuation = freeze_continuation(previous_folder, continuation_path, args.max_attempts)
                print('Continuing after %s prior attempts; skipping %s previously attempted endpoints.' % (
                    continuation['attempts_used'], len(continuation['candidate_ids'])), flush=True)
            source = preparation / 'source'
            subprocess.run([sys.executable, str(ROOT / 'host-tools/FreezePilotSource.py'),
                            '--output', str(source)], check=True, timeout=60)
            manifest = json.loads((source / 'manifest.json').read_text(encoding='utf-8'))
            # The guest independently discovers and checks this count before running.
            count = sum(1 for f in (ROOT / 'phishing-study/tests').glob('test_*.py')
                        for node in ast.walk(ast.parse(f.read_text(encoding='utf-8')))
                        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith('test_'))
            folder = parent / run_id
            view = ROOT / 'tmp' / run_id
            view.mkdir(parents=True, exist_ok=False)
            identity = {'run_id': run_id, 'folder': str(folder.relative_to(ROOT)),
                        'max_attempts': args.max_attempts, 'verify_only': args.verify_only,
                        'monitor_url': 'http://127.0.0.1:8766/', 'source_hash': manifest['source_hash']}
            identity['verification_profile'] = 'local-dataset-observation-v1'
            settings = argparse.Namespace(output=folder, run_id=run_id, minutes=60,
                pilot=not args.verify_only, app_root='/opt/' + run_id + '/app',
                expected_source_hash=manifest['source_hash'], expected_tests=count,
                source_archive=source / 'source.tar.gz', source_manifest=source / 'manifest.json',
                max_attempts=args.max_attempts, usable_per_class=75, campaign_budget=None,
                continuation=continuation_path, completion=None, completion_intake=None, live_view_dir=view,
                dataset_observation=True)
            controller = OperatorRun(settings)
            write_json(CONTROL / 'current.json', identity)
            write_json(view / 'operator.json', identity)
            write_json(view / 'status.json', {'run_id': run_id, 'vm_running': False,
                                            'finished': False, 'stage': 'Preparing Ubuntu VM'})
            (folder / 'operator-command.json').write_text(json.dumps(identity, indent=2), encoding='utf-8')
            flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
            server = subprocess.Popen([sys.executable, str(ROOT / 'host-tools/WatchResearch.py'),
                '--directory', str(view), '--port', '8766', '--operator'], creationflags=flags,
                stdout=(folder / 'monitor-console.txt').open('x'), stderr=subprocess.STDOUT)
            ended = threading.Event()
            def observer():
                # Boot/status remain visible even before SSH is ready.
                bridge = None
                try:
                    while not ended.is_set():
                        serial = folder / 'serial.log'
                        if serial.exists():
                            with serial.open('rb') as stream:
                                stream.seek(max(0, serial.stat().st_size - 12000))
                                tail = stream.read().decode('utf-8', errors='replace')
                            write_json(view / 'boot.json', {'text': tail})
                        if bridge is None and (folder / 'ssh_config').exists():
                            bridge = subprocess.Popen([sys.executable, str(ROOT / 'host-tools/WatchCommittedSignals.py'),
                                '--phase', str(folder), '--directory', str(view), '--run-id', run_id],
                                creationflags=flags, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        ended.wait(2)
                finally:
                    if bridge is not None:
                        try: bridge.wait(timeout=8)
                        except subprocess.TimeoutExpired: bridge.terminate(); bridge.wait(timeout=5)
            thread = threading.Thread(target=observer, daemon=True)
            thread.start()
            print('Open the view-only monitor: http://127.0.0.1:8766/', flush=True)
            try:
                time.sleep(.3)
                if server.poll() is not None:
                    raise RuntimeError('Monitor failed to start. Check whether port 8766 is occupied.')
                result = controller.execute()
                runtime = json.loads((folder / 'result.json').read_text(encoding='utf-8'))
                exported = False
                if (folder / 'guest-evidence.tar.gz').exists() and runtime.get('pilot'):
                    print('5/6 Verifying and exporting the frozen evidence.', flush=True)
                    report = subprocess.run([sys.executable, str(ROOT / 'host-tools/ReportQemuPilot.py'),
                                             str(folder)], timeout=300)
                    exported = report.returncode == 0
                    if not exported: result = 1
                cancelled = runtime.get('stop_reason') == 'operator_requested_stop'
                cleanup_ok = runtime.get('graceful_vm_exit') is True and not any(
                    key in runtime for key in ('stop_error','freeze_error','shutdown_error'))
                operator_status = 'passed' if result == 0 else 'failed'
                if cancelled and cleanup_ok:
                    operator_status = 'stopped_by_operator'
                    result = 0
                write_json(folder / 'operator-outcome.json', {'status': operator_status,
                    'host_status': runtime['status'], 'export_verified': exported,
                    'graceful_vm_exit': runtime.get('graceful_vm_exit', False)})
                print('6/6 Run stopped. Saved results: ' + str(folder), flush=True)
                return result
            finally:
                ended.set(); thread.join(timeout=15)
                server.terminate(); server.wait(timeout=5)
        finally:
            lock.seek(0); msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('run', 'status', 'stop', 'report', 'view'))
    parser.add_argument('--max-attempts', type=int, default=10)
    parser.add_argument('--verify-only', action='store_true')
    parser.add_argument('--continue-previous', action='store_true',
                        help='Advance beyond every attempted URL in the previous verified dataset batch')
    parser.add_argument('--run-id', help='Read a specific saved run in Status, Report or View')
    args = parser.parse_args()
    if args.run_id and args.mode in ('run', 'stop'):
        parser.error('--run-id is only available for Status, Report and View')
    if args.mode == 'run': return run(args)
    value, folder = current(args.run_id)
    if args.mode == 'view':
        view = ROOT / 'tmp' / value['run_id']
        if not view.is_dir() or view.is_symlink():
            raise ValueError('The saved monitor directory is unavailable.')
        print('View-only monitor: http://127.0.0.1:8766/ (Ctrl+C closes this viewer only)', flush=True)
        return subprocess.call([sys.executable, str(ROOT / 'host-tools/WatchResearch.py'),
                                '--directory', str(view), '--port', '8766', '--operator'])
    if args.mode == 'report':
        report = folder / 'analysis/summary.json'
        if not report.exists():
            raise ValueError('The verified export is not ready. Check Status or wait for the run to finish.')
        record = json.loads(report.read_text(encoding='utf-8'))
        print(json.dumps({'report_folder': str(report.parent), 'counts': record['counts'],
                          'verification_status': record['verification_status']}, indent=2))
        return 0
    if args.mode == 'status':
        result = folder / 'result.json'
        progress = folder / 'progress.json'
        if result.exists():
            record = json.loads(result.read_text(encoding='utf-8'))
            outcome_path = folder / 'operator-outcome.json'
            outcome = json.loads(outcome_path.read_text(encoding='utf-8')) if outcome_path.exists() else {}
            pilot = record.get('pilot', {})
            value.update(finished=True, status=outcome.get('status', record['status']),
                         host_status=record['status'], export_verified=outcome.get('export_verified',
                             (folder / 'analysis/summary.json').exists()), stop_reason=record.get('stop_reason'),
                         counts={k:pilot[k] for k in ('attempts','distinct_urls_attempted','failed_attempts',
                             'unfinished_attempts','usable_per_class','collector_stop_reason') if k in pilot})
        elif progress.exists():
            record = json.loads(progress.read_text(encoding='utf-8'))
            value.update(finished=False, counts=record.get('guest', {}).get('pilot_counts'))
        print(json.dumps(value, indent=2)); return 0
    if (folder / 'result.json').exists():
        print('This run has already stopped.'); return 0
    with (folder / 'operator-stop.request').open('a', encoding='utf-8') as stream:
        stream.write(datetime.now(timezone.utc).isoformat() + '\n')
    print('Stop requested. Leave the operator terminal open for bounded cleanup and export.')
    return 0


if __name__ == '__main__':
    try: raise SystemExit(main())
    except (ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr); raise SystemExit(1)
