"""Deadline/health failures cannot become committed captures or later work."""
import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from study.config import Config
from study.queue import Queue
from study.runtime_lifecycle import observe_until_stop, ObservationStopped
from study.runner import collect


class ObservationSupervisionTests(unittest.IsolatedAsyncioTestCase):
    async def test_success_returns_exact_result(self):
        async def work():
            return {'result': 1}
        result = await observe_until_stop(work(), asyncio.Event(), timeout=1)
        self.assertEqual(result, {'result': 1})

    async def test_stop_cancels_and_drains_active_observation(self):
        stop = asyncio.Event()
        closed = asyncio.Event()
        async def work():
            try:
                stop.set()
                await asyncio.sleep(30)
            finally:
                closed.set()
        with self.assertRaises(ObservationStopped):
            await observe_until_stop(work(), stop, timeout=1, cleanup_seconds=.1)
        self.assertTrue(closed.is_set())

    async def test_timeout_is_failure_and_does_not_return_capture(self):
        cancelled = asyncio.Event()
        async def work():
            try:
                await asyncio.sleep(30)
            finally:
                cancelled.set()
        with self.assertRaisesRegex(TimeoutError, 'observation_deadline'):
            await observe_until_stop(work(), asyncio.Event(), timeout=.01, cleanup_seconds=.1)
        self.assertTrue(cancelled.is_set())

    async def test_outer_cancellation_cancels_child_work(self):
        started, closed = asyncio.Event(), asyncio.Event()
        async def work():
            try:
                started.set()
                await asyncio.sleep(30)
            finally:
                closed.set()
        supervisor = asyncio.create_task(observe_until_stop(work(), asyncio.Event(), timeout=30, cleanup_seconds=.1))
        await started.wait()
        supervisor.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await supervisor
        self.assertTrue(closed.is_set())

    async def test_health_failure_prevents_first_claim(self):
        # Reuse the deliberately synthetic integration browser; no real network.
        from test_runner import Playwright, SyntheticCollector, Guard
        with tempfile.TemporaryDirectory() as directory:
            queue = Queue(directory)
            queue.ingest([{'url': 'http://127.0.0.1:8123/x', 'label': 'legitimate'}])
            config = Config(profile='fixture', fixture_origins=['http://127.0.0.1:8123'], min_free_disk_bytes=0)
            async def unhealthy():
                return False
            with patch('playwright.async_api.async_playwright', return_value=Playwright()), \
                 patch('study.runner.Collector', SyntheticCollector), patch('study.runner.RedirectGuard', Guard):
                await collect(queue, config, health_check=unhealthy)
            self.assertEqual(queue.status()['attempts'], 0)
            self.assertEqual(queue.status()['runs'][0]['stop_reason'], 'service_health_failure')


if __name__ == '__main__':
    unittest.main()
