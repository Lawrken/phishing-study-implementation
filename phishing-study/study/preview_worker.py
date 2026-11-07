"""Bounded owned-homepage controls for the non-activating local DNS preview.

The root controller owns the DNS service, firewall, positive controls and phase
windows. This worker never reads a candidate queue or changes deployment gates.
"""
import argparse
import asyncio
from collections import Counter
from datetime import datetime, timezone
import errno
import json
import os
from pathlib import Path
import socket
import time
from urllib.parse import urlsplit

from .browser_lifecycle import Lifecycle, run_bounded
from .collector import DOM_SCRIPT, header_features
from .deployment import digest_json
from .deployment_checks import (_browser_process_evidence, _sandbox_evidence,
                                dns_failure_code, netlog_dns, resource_limits,
                                resolver_valid)
from .dns_evidence import native_dns_evidence
from .local_preview import (LISTEN, PROFILE, owned_homepage, preview_identity,
                            validate_preview_bundle)
from .redirects import RedirectGuard
from .urls import safe_url

APP = Path(__file__).resolve().parents[1]
OUTPUT_ROOT = Path('/var/lib/phishing-study-local-preview')
PHASES = ('normal', 'blocked', 'restored', 'denied')
DENIALS = {
    'alternate_tcp': ('127.0.0.55', 53, socket.AF_INET, socket.SOCK_STREAM),
    'alternate_udp': ('127.0.0.55', 53, socket.AF_INET, socket.SOCK_DGRAM),
    'private': ('127.0.0.56', 8443, socket.AF_INET, socket.SOCK_STREAM),
    'ipv6': ('::1', 8443, socket.AF_INET6, socket.SOCK_STREAM),
}


def check(report, name, passed, **values):
    report['checks'][name] = {'ok': bool(passed), **values}


def validate_phase(phase, case):
    if phase not in PHASES or (phase == 'denied' and case not in DENIALS) or (phase != 'denied' and case is not None):
        raise ValueError('denied_phase_requires_exact_case_other_phases_forbid_case')


def worker_identity_matches(manifest):
    """Require the configured UID, its normal group, and no root groups."""
    import pwd
    uid = manifest['study_uid']
    return (os.geteuid() == uid and uid != 0 and os.getegid() != 0
            and os.getegid() == pwd.getpwuid(uid).pw_gid and 0 not in os.getgroups())


def request_allowed(url, method, *, owned_url, navigation=False, main_frame=False,
                    admitted_count=0, completed_bytes=0):
    """Admit only passive requests to the configured exact HTTPS origin."""
    try:
        target, owned = urlsplit(url), urlsplit(owned_url)
        allowed = (target.scheme == 'https' and target.hostname == owned.hostname
                   and (target.port or 443) == 443
                   and target.username is None and target.password is None
                   and method in {'GET', 'HEAD'}
                   and admitted_count < 128 and completed_bytes < 20_000_000)
        if navigation:
            allowed = allowed and main_frame and url == owned_url and admitted_count == 0
        return bool(allowed)
    except (TypeError, ValueError):
        return False


def blackout_proved(navigation, network, correlated):
    """A timeout/offline wrapper alone never proves a DNS blackout."""
    native = dns_failure_code(navigation.get('native_dns_error'))
    return (navigation.get('status') is None
            and navigation.get('error_type') != 'TimeoutError'
            and network.get('response_count') == 0
            and network.get('completed_encoded_bytes') == 0
            and (bool(native) or correlated.get('ok') is True))


def preflight(report, bundle):
    manifest = validate_preview_bundle(bundle, root=APP)
    report.update(preview_identity(manifest))
    url, host = owned_homepage(manifest['owned_controls']['https_url'])
    report['target'] = url
    report['phase_identity'] = digest_json({**preview_identity(manifest),
        'phase': report['phase'], 'case': report.get('case'), 'target': url})
    check(report, 'bundle_source_and_artifacts_verified', True)
    check(report, 'configured_non_root_account', worker_identity_matches(manifest))
    report['resources'] = resource_limits()
    resource = report['resources']
    bounded = resource.get('ok') and resource.get('memory_max') != 'max'
    try:
        bounded = bounded and 0 < int(resource['memory_max']) <= manifest['resources']['memory_max_bytes']
    except (KeyError, TypeError, ValueError):
        bounded = False
    check(report, 'bounded', bounded)
    check(report, 'private_resolver_binding', resolver_valid(
        Path('/etc/resolv.conf').read_text(), Path('/etc/nsswitch.conf').read_text(), LISTEN))
    if not all(value['ok'] for value in report['checks'].values()):
        raise RuntimeError('preview_preflight_failed')
    return manifest, url, host


async def visit(report, output, phase, url, host):
    from playwright.async_api import async_playwright
    lifecycle = Lifecycle(report, event_path=output / 'lifecycle-events.jsonl')
    events, admitted, failures, redirects = [], [], [], []
    byte_count = response_count = page_errors = 0
    started = time.monotonic()
    netlog = output / 'netlog.json'

    def emit(kind, **values):
        if len(events) < 1024:
            events.append({'kind': kind, 'elapsed_ms': round((time.monotonic() - started) * 1000, 3), **values})
        else:
            check(report, 'event_budget', False)

    try:
        ok, driver = await lifecycle.stage('driver_start', async_playwright().start)
        if not ok:
            raise RuntimeError('driver_start_failed')
        lifecycle.driver = driver
        ok, browser = await lifecycle.stage('browser_launch', lambda: driver.chromium.launch(
            headless=True, chromium_sandbox=True, timeout=30000,
            args=['--disable-quic', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
                  '--log-net-log=' + str(netlog)]))
        if not ok:
            raise RuntimeError('browser_launch_failed')
        lifecycle.browser = browser
        await lifecycle.capture_browser_identity()
        report['browser_process'] = await _browser_process_evidence(browser)
        report['browser_version'] = browser.version
        check(report, 'owned_sandbox_requested', report['browser_process']['ok'])
        guard = await RedirectGuard.start(browser)
        lifecycle.guard = guard
        context = await browser.new_context(viewport={'width': 1365, 'height': 768},
            locale='en-US', timezone_id='UTC', accept_downloads=False,
            service_workers='block', ignore_https_errors=False)
        lifecycle.context = context
        page = await context.new_page()
        await page.goto('about:blank')
        check(report, 'renderer_sandbox', await _sandbox_evidence(browser))
        if not all(value['ok'] for value in report['checks'].values()):
            raise RuntimeError('browser_preflight_failed')

        async def route(handler):
            request = handler.request
            if request_allowed(request.url, request.method, owned_url=url,
                    navigation=request.is_navigation_request(), main_frame=request.frame == page.main_frame,
                    admitted_count=len(admitted), completed_bytes=byte_count):
                row = {'url': safe_url(request.url), 'method': request.method, 'resource_type': request.resource_type}
                admitted.append(row)
                emit('request_admitted', **row)
                await handler.continue_()
            else:
                emit('request_blocked', url=safe_url(request.url))
                await handler.abort()

        async def redirect(target, paused):
            redirects.append(safe_url(target))
            emit('redirect_blocked', target=safe_url(target))
            return False

        async def guard_failure(reason):
            failures.append(reason)
            await context.close()

        async def websocket(connection):
            emit('websocket_blocked')
            await connection.close()

        await context.route('**/*', route)
        await context.route_web_socket('**/*', websocket)
        context.on('page', lambda popup: asyncio.create_task(popup.close()))
        page.on('dialog', lambda dialog: asyncio.create_task(dialog.dismiss()))
        page.on('download', lambda download: asyncio.create_task(download.cancel()))

        def page_error(error):
            nonlocal page_errors
            page_errors += 1

        page.on('pageerror', page_error)
        lifecycle.owner = await guard.register(page, redirect, guard_failure)
        session = await context.new_cdp_session(page)
        await session.send('Network.enable', {'maxTotalBufferSize': 1_000_000, 'maxResourceBufferSize': 100_000})

        def response(event):
            nonlocal response_count
            response_count += 1
            value = event['response']
            emit('response', url=safe_url(value['url']), status=value['status'], protocol=value.get('protocol'),
                 headers=header_features(value.get('headers', {})))

        def finished(event):
            nonlocal byte_count
            byte_count += event.get('encodedDataLength', 0)
            emit('finished', encoded_bytes=event.get('encodedDataLength'))

        session.on('Network.responseReceived', response)
        session.on('Network.loadingFinished', finished)
        status = error_type = native_code = None
        try:
            main = await page.goto(url, wait_until='domcontentloaded', timeout=30000)
            status = main.status if main else None
            if main:
                report['browser_tls'] = await main.security_details()
                report['main_headers'] = header_features(await main.all_headers())
            await asyncio.sleep(10)
            report['dom'] = await page.evaluate(DOM_SCRIPT, 100000)
        except Exception as error:
            error_type, native_code = type(error).__name__, dns_failure_code(str(error))
        report['navigation'] = {'status': status, 'error_type': error_type, 'native_dns_error': native_code}
        if phase in {'normal', 'restored'}:
            check(report, 'owned_https_200', status == 200 and error_type is None and page.url == url)
            details = report.get('browser_tls') or {}
            check(report, 'system_trusted_tls', bool(details.get('protocol')) and bool(details.get('subjectName')))
            check(report, 'traffic_recorded', response_count > 1)
        else:
            check(report, 'no_http_response_during_blackout', status is None and response_count == 0 and error_type != 'TimeoutError')
        check(report, 'guard_healthy', not failures and not guard.failed)
        check(report, 'no_redirects', not redirects)
    finally:
        await lifecycle.cleanup()
        report['network'] = {'admitted_requests': len(admitted), 'response_count': response_count,
            'completed_encoded_bytes': byte_count, 'methods': dict(Counter(row['method'] for row in admitted)),
            'resource_types': dict(Counter(row['resource_type'] for row in admitted)), 'page_errors': page_errors,
            'body_policy': 'never_persisted', 'byte_cap_is_soft': True}
        with (output / 'events.jsonl').open('x') as stream:
            for event in events:
                stream.write(json.dumps(event) + '\n')
    if netlog.exists():
        data = json.loads(netlog.read_text())
        report['netlog_dns'] = netlog_dns(data, LISTEN, host)
        check(report, 'only_local_effective_dns', report['netlog_dns']['ok'])
        if phase == 'blocked':
            report['correlated_dns_failure'] = native_dns_evidence(data, host)
            check(report, 'native_dns_blackout', blackout_proved(
                report['navigation'], report['network'], report['correlated_dns_failure']))
    else:
        check(report, 'only_local_effective_dns', False, reason='netlog_missing')


def denial(report, case):
    address, port, family, kind = DENIALS[case]
    denied, code = False, None
    try:
        with socket.socket(family, kind) as connection:
            connection.settimeout(2)
            connection.connect((address, port))
            if kind == socket.SOCK_DGRAM:
                connection.send(b'OWNED CONTROL')
                connection.recv(128)
    except TimeoutError:
        code = 'timeout_inconclusive'
    except OSError as error:
        code = errno.errorcode.get(error.errno, 'UNKNOWN')
        denied = error.errno in {errno.EACCES, errno.EPERM, errno.ECONNREFUSED, errno.ENETUNREACH, errno.EHOSTUNREACH}
        if case == 'ipv6' and error.errno == errno.EAFNOSUPPORT:
            denied = True  # The measured service address-family policy denied socket creation.
    report['denial'] = {'case': case, 'errno': code, 'denied': denied}
    check(report, 'categorical_denial', denied)


async def run(report, args):
    _, url, host = preflight(report, args.bundle)
    if args.phase == 'denied':
        denial(report, args.case)
    else:
        await visit(report, args.output, args.phase, url, host)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--phase', choices=PHASES, required=True)
    parser.add_argument('--case', choices=tuple(DENIALS))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    validate_phase(args.phase, args.case)
    if (args.output.exists() or args.output.is_symlink()
            or not args.output.resolve().is_relative_to(OUTPUT_ROOT)):
        raise SystemExit('fresh_private_output_required')
    args.output.mkdir(mode=0o700)
    report = {'started_at': datetime.now(timezone.utc).isoformat(), 'phase': args.phase, 'case': args.case,
        'status': 'failed', 'schema_version': 2, 'verification_profile': PROFILE, 'checks': {},
        'research_eligible': False, 'network_isolation_verified': False, 'research_collection_count': 0,
        'activation_allowed': False, 'full_production_verification': False, 'public_dns_verified': False,
        'public_tls_verified': False, 'resolver_vantage': 'local_forwarder_via_VM_system_stub'}
    try:
        run_bounded(run(report, args), timeout=90, cleanup_seconds=60, report=report)
        stages = report.get('lifecycle', {}).get('stages', [])
        if report['checks'] and all(value['ok'] for value in report['checks'].values()) and all(stage['ok'] for stage in stages):
            report['status'] = 'passed'
    except BaseException as error:
        report['error_type'] = type(error).__name__
    report['finished_at'] = datetime.now(timezone.utc).isoformat()
    (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'phase': args.phase, 'case': args.case, 'status': report['status']}))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
