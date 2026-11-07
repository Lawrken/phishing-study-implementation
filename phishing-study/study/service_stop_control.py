"""Disconnected Chromium cancellation through the generated collection service.

The worker serves loopback fixtures in its own PrivateNetwork namespace. This
control measures service shutdown, not public DNS, TLS, labels or capture yield.
"""
import argparse
import asyncio
from dataclasses import replace
import json
import os
from pathlib import Path
import signal
import subprocess
import time
from types import SimpleNamespace
from unittest.mock import patch
import uuid

from .deployment import file_hash, source_hash
from .public_web import validate_public_bundle

APP = Path(__file__).resolve().parents[1]

async def worker(args, report):
    from .browser_lifecycle import process_identity_state
    from .collector import Collector
    from .config import Config
    from .fixtures import FixtureServer
    from .policy import Policy
    from .runtime_lifecycle import browser_session
    from .urls import digest
    manifest = validate_public_bundle(args.bundle, root=APP)
    assert os.geteuid() == manifest['study_uid'] != 0
    stopped, entered = asyncio.Event(), asyncio.Event()
    loop = asyncio.get_running_loop()
    def stop():
        report['signal_seen'] = 'SIGTERM'
        stopped.set()
    loop.add_signal_handler(signal.SIGTERM, stop)
    original, waiting = Policy.check, 0
    async def pending_check(policy, url):
        nonlocal waiting
        if '/api/status?' in url:
            waiting += 1
            if waiting >= 16:
                entered.set()
            await asyncio.Event().wait()
        return await original(policy, url)
    report['network_namespace_inode'] = os.stat('/proc/self/ns/net').st_ino
    from .public_kernel import network
    report['network_snapshot'] = network()
    report['uid'] = os.geteuid()
    report['source_hash'] = source_hash(APP)
    report['checks'] = {}
    try:
        with FixtureServer() as fixture:
            config = Config(profile='fixture', fixture_origins=[fixture.url], observation_seconds=30,
                            navigation_seconds=5, attempt_seconds=45, lease_seconds=90)
            async with browser_session(SimpleNamespace(root=args.output), Config(profile='live')) as (browser, life):
                from .redirects import RedirectGuard
                guard = await RedirectGuard.start(browser)
                life.guard = guard
                url = fixture.url + '/fanout'
                with patch.object(Policy, 'check', pending_check):
                    task = asyncio.create_task(Collector(browser, config, redirect_guard=guard).observe(
                        {'id': digest(url), 'attempt_id': uuid.uuid4().hex, 'url': url}))
                    try:
                        await asyncio.wait_for(entered.wait(), timeout=8)
                        (args.output/'ready.json').write_text(json.dumps({'pid': os.getpid(), 'waiting': waiting}))
                        await asyncio.wait_for(stopped.wait(), timeout=20)
                        task.cancel()
                        try:
                            await asyncio.wait_for(task, timeout=12)
                        except asyncio.CancelledError:
                            report['checks']['operation_cancelled'] = True
                    finally:
                        if not task.done():
                            task.cancel()
                            await asyncio.gather(task, return_exceptions=True)
                report['checks']['contexts_closed'] = not browser.contexts
                report['checks']['guard_clean'] = not guard.failed and not guard._owners and not guard._contexts
                report['checks']['no_fixture_resource_hits'] = fixture.hit_snapshot().get(('GET','/api/status'),0) == 0
            report['checks']['browser_lifecycle_clean'] = all(v['ok'] for v in life.report['checks'].values())
            report['checks']['owned_browser_gone'] = process_identity_state(life.report['lifecycle']['captured_browser_identity'])['gone']
            report['checks']['renderer_sandbox'] = life.report['checks']['renderer_sandbox']['ok']
            report['checks']['signal_received'] = report.get('signal_seen') == 'SIGTERM'
            report['lifecycle'] = life.report['lifecycle']
    finally:
        loop.remove_signal_handler(signal.SIGTERM)

def main(argv=None):
    from .browser_lifecycle import run_bounded
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    assert not args.output.exists()
    args.output.mkdir(mode=0o700)
    report = {'status':'failed', 'scope':'disconnected local service-stop control', 'checks':{}}
    try:
        run_bounded(worker(args, report), timeout=60, cleanup_seconds=60, report=report)
        if report['checks'] and all(report['checks'].values()):
            report['status'] = 'passed'
    except BaseException as error:
        report['error_type'] = type(error).__name__
    (args.output/'report.json').write_text(json.dumps(report, indent=2))
    return 0 if report['status']=='passed' else 1

def run_service_stop(bundle, output, private, substitutions, environment, nonce):
    from .public_connection import service_arguments
    from .preview_controls import command
    manifest = validate_public_bundle(bundle, root=APP)
    target = private/'service-stop'
    text, properties, execution = service_arguments((bundle/'collector.service').read_text(),
        {**substitutions, 'RUNNER':APP/'scripts/public-stop-control.py', 'OUTPUT':target}, private, environment)
    runtime = output/'stop-runtime.service'
    runtime.write_text(text)
    unit = 'study-public-stop-'+nonce[:16]
    started = time.monotonic()
    with (output/'stop-console.txt').open('x') as stream:
        process = subprocess.Popen(['systemd-run','--quiet','--wait','--pipe','--collect','--unit='+unit,
            '--property=PrivateNetwork=true',*properties,*execution],stdout=stream,stderr=subprocess.STDOUT)
        stop_sent = False
        try:
            deadline = started+25
            while process.poll() is None and not (target/'ready.json').exists() and time.monotonic()<deadline:
                time.sleep(.05)
            if not (target/'ready.json').exists():
                raise RuntimeError('service_stop_control_not_ready')
            command('systemctl','stop','--no-block',unit)
            stop_sent = True
            code = process.wait(timeout=45)
        finally:
            if process.poll() is None:
                command('systemctl','stop','--no-block',unit)
                process.wait(timeout=45)
            (output/'stop-journal.txt').write_text(command('journalctl','-u',unit,'--no-pager'))
    path = target/'report.json'
    worker_report = json.loads(path.read_text()) if path.is_file() else {'status':'failed','checks':{}}
    from .public_kernel import disconnected
    result = {**worker_report, 'worker_exit':code, 'stop_sent':stop_sent,
        'elapsed_seconds':time.monotonic()-started, 'runtime_service_hash':file_hash(runtime),
        'report_sha256':file_hash(path) if path.is_file() else None,
        'namespace_disconnected':disconnected(worker_report.get('network_snapshot', {}), os.stat('/proc/self/ns/net').st_ino),
        'collection_account_idle':subprocess.run(['pgrep','-u',str(manifest['study_uid'])],capture_output=True).returncode==1}
    (output/'service-stop-report.json').write_text(json.dumps(result,indent=2))
    if (code != 0 or result['status'] != 'passed' or not result['namespace_disconnected']
            or not result['collection_account_idle'] or not result['checks'] or not all(result['checks'].values())):
        raise RuntimeError('generated_collection_service_stop_failed')
    return result

if __name__ == '__main__':
    raise SystemExit(main())
