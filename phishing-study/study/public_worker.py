"""Actual collector measurements against the owned control, never dataset intake."""
import argparse
import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pwd
import time
import uuid
from urllib.parse import urlsplit

from .browser_lifecycle import Lifecycle, run_bounded
from .collector import Collector
from .config import load
from .deployment import secure_root_file, source_files
from .deployment_checks import (_browser_process_evidence, _sandbox_evidence,
    dns_failure_code, netlog_dns, resolver_valid, resource_limits)
from .dns_evidence import native_dns_evidence
from .public_web import OWNED_URL, LISTEN, public_identity, validate_public_bundle
from .redirects import RedirectGuard

APP = Path(__file__).resolve().parents[1]
DATA = Path('/var/lib/phishing-study-public')


def check(report, key, value):
    report['checks'][key] = {'ok': bool(value)}


async def probe(report, args, manifest, config):
    from playwright.async_api import async_playwright
    life = Lifecycle(report, stage_timeouts={'preflight_context_close': 12},
                     event_path=args.output / 'lifecycle-events.jsonl')
    logpath = args.output / 'netlog.json'
    try:
        ok, driver = await life.stage('driver_start', async_playwright().start)
        if not ok:
            raise RuntimeError('driver_start_failed')
        life.driver = driver
        ok, browser = await life.stage('browser_launch', lambda: driver.chromium.launch(
            headless=True, chromium_sandbox=True, timeout=30000,
            args=['--disable-quic', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
                  '--log-net-log=' + str(logpath)]))
        if not ok:
            raise RuntimeError('browser_launch_failed')
        life.browser = browser
        report['browser_version'] = browser.version
        await life.capture_browser_identity()
        process = await _browser_process_evidence(browser)
        check(report, 'owned_sandbox_requested', process['ok'])
        report['browser_process'] = process
        life.guard = guard = await RedirectGuard.start(browser)
        context = await browser.new_context(service_workers='block')
        life.context = context
        page = await context.new_page()
        await page.goto('about:blank')
        check(report, 'renderer_sandbox', await _sandbox_evidence(browser))
        ok, _ = await life.stage('preflight_context_close', context.close)
        if ok:
            life.context = None
        if not ok or not all(value['ok'] for value in report['checks'].values()):
            raise RuntimeError('browser_preflight_failed')
        if args.phase in ('normal', 'restored'):
            identity = uuid.uuid4().hex
            collector = Collector(browser, config, redirect_guard=guard, control_origin=OWNED_URL)
            record, events = await collector.observe({'id': 'owned-' + identity,
                'attempt_id': identity, 'url': OWNED_URL, 'label': 'legitimate',
                'confidence': 'candidate', 'attempt_number': 1})
            groups = record['groups']
            network = groups['network']
            report['navigation'] = {'status': groups['http'].get('status'),
                                    'error_type': None if record['eligible'] else record['outcome'],
                                    'native_dns_error': None}
            report['capture_eligible'] = record['eligible']
            report['dns_metadata'], report['tls_metadata'] = groups['dns'], groups['tls']
            report['network'] = {'response_count': network.get('response_count', 0),
                'admitted_requests': network.get('request_count', 0),
                'completed_encoded_bytes': network.get('response_transfer_bytes', 0),
                'methods': network.get('methods', {}), 'body_policy': 'never_persisted'}
            check(report, 'actual_collector_capture', record['eligible'] and groups['http'].get('status') == 200)
            check(report, 'actual_dns_extraction', groups['dns'].get('measured') is True)
            check(report, 'actual_trusted_tls_extraction', groups['tls'].get('measured') is True
                  and groups['tls'].get('validation') == 'system_trust_verified')
            with (args.output / 'owned-record.json').open('x') as stream:
                json.dump(record, stream, indent=2)
            with (args.output / 'events.jsonl').open('x') as stream:
                for event in events:
                    stream.write(json.dumps(event) + '\n')
        else:
            # A Policy DNS rejection is insufficient: exercise the native browser.
            context = await browser.new_context(service_workers='block', ignore_https_errors=False)
            life.context = context
            page = await context.new_page()
            responses, encoded, native = [], [], None
            status = error_type = None
            owner_host = urlsplit(OWNED_URL).hostname
            async def route(route):
                target = urlsplit(route.request.url)
                if target.scheme == 'https' and target.hostname == owner_host and route.request.method in {'GET', 'HEAD'}:
                    await route.continue_()
                else:
                    await route.abort()
            async def redirect(target, event):
                return False
            async def failed(reason):
                check(report, 'redirect_guard', False)
                await context.close()
            await context.route('**/*', route)
            await context.route_web_socket('**/*', lambda socket: socket.close())
            life.owner = await guard.register(page, redirect, failed)
            session = await context.new_cdp_session(page)
            await session.send('Network.enable')
            session.on('Network.responseReceived', lambda event: responses.append(event['response']['status']))
            session.on('Network.loadingFinished', lambda event: encoded.append(event.get('encodedDataLength', 0)))
            try:
                response = await page.goto(OWNED_URL, wait_until='domcontentloaded', timeout=15000)
                status = response.status if response else None
            except Exception as error:
                error_type = type(error).__name__
                native = dns_failure_code(str(error))
            report['navigation'] = {'status': status, 'error_type': error_type, 'native_dns_error': native}
            report['network'] = {'response_count': len(responses), 'completed_encoded_bytes': sum(encoded)}
            report['capture_eligible'] = False
            check(report, 'no_http_during_blackout', status is None and not responses and not sum(encoded)
                  and error_type != 'TimeoutError')
        check(report, 'redirect_guard', not guard.failed)
    finally:
        await life.cleanup()
    if logpath.exists():
        netlog = json.loads(logpath.read_text())
        dns = netlog_dns(netlog, LISTEN, urlsplit(OWNED_URL).hostname)
        report['netlog_dns'] = dns
        report['effective_dns_verified'] = dns['ok']
        check(report, 'native_dns_configuration', dns['ok'])
        if args.phase == 'blocked':
            correlated = native_dns_evidence(netlog, urlsplit(OWNED_URL).hostname)
            report['correlated_dns_failure'] = correlated
            if report['navigation']['native_dns_error'] is None and correlated['ok']:
                report['navigation']['native_dns_error'] = correlated['dns_error_codes'][0]
            check(report, 'native_dns_failure', bool(dns_failure_code(report['navigation']['native_dns_error'])))
    else:
        check(report, 'native_dns_configuration', False)


async def execute(report, args):
    manifest = validate_public_bundle(args.bundle, root=APP)
    report.update(public_identity(manifest))
    for path in (args.bundle / 'deployment.json', *source_files(APP)):
        secure_root_file(path)
    uid = manifest['study_uid']
    check(report, 'actual_collection_identity', os.geteuid() == uid != 0
          and os.getegid() == pwd.getpwuid(uid).pw_gid and 0 not in os.getgroups())
    report['resources'] = resource_limits()
    check(report, 'resource_bounds', report['resources']['ok']
          and int(report['resources'].get('memory_max', '0')) <= 2147483648)
    check(report, 'bound_resolver', resolver_valid(Path('/etc/resolv.conf').read_text(),
          Path('/etc/nsswitch.conf').read_text(), LISTEN))
    if not all(value['ok'] for value in report['checks'].values()):
        raise RuntimeError('public_control_preflight_failed')
    config = load(args.bundle / 'pilot.template.toml')
    if args.phase == 'denied':
        from .preview_worker import denial
        if args.case not in ('alternate_tcp', 'alternate_udp', 'private', 'ipv6'):
            raise ValueError('exact owned denial case required')
        denial(report, args.case)
    else:
        await probe(report, args, manifest, config)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--phase', choices=('normal', 'blocked', 'restored', 'denied'),
                        default=os.environ.get('STUDY_CONTROL_PHASE', 'normal'))
    parser.add_argument('--case', default=os.environ.get('STUDY_CONTROL_CASE'))
    args = parser.parse_args(argv)
    if args.output.exists() or args.output.is_symlink() or not args.output.resolve().is_relative_to(DATA):
        parser.error('fresh protected public-control output required')
    args.output.mkdir(mode=0o700)
    report = {'status': 'failed', 'phase': args.phase, 'target': OWNED_URL,
        'started_at': datetime.now(timezone.utc).isoformat(), 'checks': {},
        'network_isolation_verified': False, 'research_collection_count': 0}
    try:
        run_bounded(execute(report, args), timeout=120, cleanup_seconds=60, report=report)
        if report['checks'] and all(value['ok'] for value in report['checks'].values()):
            report['status'] = 'passed'
    except BaseException as error:
        report['error_type'] = type(error).__name__
    report['finished_at'] = datetime.now(timezone.utc).isoformat()
    with (args.output / 'report.json').open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'phase': args.phase, 'status': report['status']}))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
