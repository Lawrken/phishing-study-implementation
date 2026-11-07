"""Bounded live-browser supervision; fixture behavior remains compatible."""
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import uuid

from .browser_lifecycle import Lifecycle


class ObservationStopped(RuntimeError):
    """The run stopped before an observation could be committed."""


async def observe_until_stop(operation, stop, *, timeout, cleanup_seconds=15):
    task = asyncio.create_task(operation)
    stopped = asyncio.create_task(stop.wait())
    try:
        done, _ = await asyncio.wait({task, stopped}, timeout=timeout,
                                     return_when=asyncio.FIRST_COMPLETED)
        if task in done and not stop.is_set():
            return task.result()
        task.cancel()
        done, _ = await asyncio.wait({task}, timeout=cleanup_seconds)
        if task not in done:
            raise TimeoutError('observation_cleanup_deadline')
        # Retrieve cancellation/errors without turning an interrupted visit into a capture.
        await asyncio.gather(task, return_exceptions=True)
        if stop.is_set():
            raise ObservationStopped('run_stop_requested')
        raise TimeoutError('observation_deadline')
    finally:
        if not task.done():
            task.cancel()
            await asyncio.wait({task}, timeout=cleanup_seconds)
            if not task.done():
                def consume(completed):
                    try:
                        completed.exception()
                    except BaseException:
                        pass
                task.add_done_callback(consume)
        stopped.cancel()
        await asyncio.gather(stopped, return_exceptions=True)


@asynccontextmanager
async def browser_session(queue, config):
    from playwright.async_api import async_playwright
    if config.profile == 'fixture':
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True, chromium_sandbox=False,
                                                        proxy=config.proxy())
            yield browser, None
        return
    from .deployment_checks import _browser_process_evidence, _sandbox_evidence
    folder = Path(queue.root) / 'lifecycle'
    folder.mkdir(mode=0o700, exist_ok=True)
    token = uuid.uuid4().hex
    report = {'started_at': datetime.now(timezone.utc).isoformat(), 'status': 'failed',
              'config_hash': config.fingerprint, 'checks': {}}
    lifecycle = Lifecycle(report, event_path=folder / (token + '.jsonl'))
    try:
        ok, driver = await lifecycle.stage('driver_start', async_playwright().start)
        if not ok:
            raise RuntimeError('playwright_start_failed')
        lifecycle.driver = driver
        ok, browser = await lifecycle.stage('browser_launch', lambda: driver.chromium.launch(
            headless=True, chromium_sandbox=True, proxy=config.proxy(), timeout=30000,
            args=['--disable-quic', '--force-webrtc-ip-handling-policy=disable_non_proxied_udp']))
        if not ok:
            raise RuntimeError('browser_launch_failed')
        lifecycle.browser = browser
        await lifecycle.capture_browser_identity()
        report['browser_process'] = await _browser_process_evidence(browser)
        report['checks']['owned_sandbox_requested'] = {'ok': report['browser_process']['ok']}
        context = await browser.new_context(service_workers='block')
        lifecycle.context = context
        page = await context.new_page()
        await page.goto('about:blank')
        report['checks']['renderer_sandbox'] = {'ok': await _sandbox_evidence(browser)}
        ok, _ = await lifecycle.stage('context_close', context.close)
        if ok:
            lifecycle.context = None
        if not ok or not all(value['ok'] for value in report['checks'].values()):
            raise RuntimeError('live_browser_preflight_failed')
        yield browser, lifecycle
    finally:
        await lifecycle.cleanup()
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        report['status'] = 'passed' if report['checks'] and all(value['ok'] for value in report['checks'].values()) else 'failed'
        with (folder / (token + '.json')).open('x') as stream:
            json.dump(report, stream, indent=2)
            stream.write('\n')
        if report['status'] != 'passed':
            raise RuntimeError('live_browser_lifecycle_failed')
