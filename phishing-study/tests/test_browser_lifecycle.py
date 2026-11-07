"""Bounded lifecycle regressions: no browser or network changes."""
import asyncio
import copy
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, patch

from study.browser_lifecycle import Lifecycle, process_identity_state, run_bounded


class Resource:
    def __init__(self, name, order, *, error=False, hang=False):
        self.name, self.order, self.error, self.hang = name, order, error, hang
        self.connected = True
        self.cancelled = False

    async def close(self):
        self.order.append(self.name)
        if self.error:
            raise RuntimeError("categorical_only")
        if self.hang:
            try:
                await asyncio.Event().wait()
            finally:
                self.cancelled = True
        self.connected = False

    stop = close

    def is_connected(self):
        return self.connected


class Guard(Resource):
    def __init__(self, order):
        super().__init__("guard", order)
        self._closed, self.failed, self.failure_reason = False, False, None
        self._owners = {"owner"}
        self._contexts = {1: "owner"}
        self._frames = self._tasks = self._pending = self._task_owners = {}
        self.direct_unregister_count = 0

    async def unregister(self, owner):
        self.order.append("owner")
        self.direct_unregister_count += 1
        self._owners.clear()
        self._contexts.clear()

    async def close(self):
        self.order.append("guard")
        self._owners.clear()
        self._contexts.clear()
        self._closed = True


IDENTITY = {"pid": 1111, "start_time": "789", "uid": 999,
            "executable": "/pinned/headless-shell", "netns": "net:[1234]",
            "cgroup": ["0::/system.slice/test-only.service"]}


class LifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_modern_guard_is_retained_until_bounded_browser_exit(self):
        life, report, order = self.setup_life()
        def prepare():
            order.append('guard_retained')
        async def finish():
            self.assertFalse(life.browser.is_connected())
            await life.guard.close()
        life.guard.prepare_browser_shutdown = prepare
        life.guard.close_after_browser = finish
        with patch('study.browser_lifecycle.process_identity_state', return_value={'gone': True, 'reason': 'absent'}):
            await life.cleanup()
        self.assertEqual(order, ['context', 'owner', 'guard_retained', 'browser', 'guard', 'driver'])
        self.assertTrue(all(item['ok'] for item in report['checks'].values()))

    async def test_failed_browser_exit_never_releases_modern_interception(self):
        life, report, order = self.setup_life()
        life.browser.hang = True
        life.guard.prepare_browser_shutdown = lambda: order.append('guard_retained')
        life.guard.close_after_browser = AsyncMock()
        with patch('study.browser_lifecycle.process_identity_state', return_value={'gone': True, 'reason': 'absent'}):
            await life.cleanup()
        life.guard.close_after_browser.assert_not_awaited()
        self.assertFalse(report['checks']['browser_closed']['ok'])
        self.assertFalse(report['checks']['guard_cleanly_closed']['ok'])

    def setup_life(self):
        report, order = {"checks": {}, "events": []}, []
        life = Lifecycle(report, stage_timeouts={name: 0.01 for name in
            ("context_close", "owner_unregister", "guard_close", "browser_close", "driver_stop", "process_exit")})
        life.context = Resource("context", order)
        life.guard = Guard(order)
        life.owner = "owner"
        life.browser = Resource("browser", order)
        life.driver = Resource("driver", order)
        life.identity = copy.deepcopy(IDENTITY)
        return life, report, order

    async def test_normal_order_and_instrumentation(self):
        life, report, order = self.setup_life()
        with patch("study.browser_lifecycle.process_identity_state", return_value={"gone": True, "reason": "absent"}):
            await life.cleanup()
        self.assertEqual(order, ["context", "owner", "guard", "browser", "driver"])
        self.assertTrue(all(value["ok"] for value in report["checks"].values()))
        for stage in report["lifecycle"]["stages"]:
            self.assertIn("started_at", stage)
            self.assertIn("finished_at", stage)
            self.assertGreaterEqual(stage["duration_seconds"], 0)
            self.assertGreaterEqual(stage["finished_monotonic"], stage["started_monotonic"])

    async def test_close_error_cannot_be_hidden_by_driver_cleanup(self):
        life, report, order = self.setup_life()
        life.browser.error = True
        with patch("study.browser_lifecycle.process_identity_state", return_value={"gone": True, "reason": "absent"}):
            await life.cleanup()
        self.assertFalse(report["checks"]["browser_closed"]["ok"])
        self.assertTrue(report["checks"]["driver_stopped"]["ok"])
        self.assertTrue(report["checks"]["owned_browser_process_gone"]["ok"])
        self.assertEqual(report["lifecycle"]["stages"][-2]["error_type"], "RuntimeError")

    async def test_browser_close_hang_is_bounded_and_remains_failed(self):
        life, report, order = self.setup_life()
        life.browser.hang = True
        with patch("study.browser_lifecycle.process_identity_state", return_value={"gone": True, "reason": "absent"}):
            await life.cleanup()
        self.assertFalse(report["checks"]["browser_closed"]["ok"])
        self.assertFalse(report["checks"]["no_abandoned_cleanup_stage"]["ok"])
        self.assertTrue(life.browser.cancelled)
        self.assertIn("driver", order)

    async def test_driver_stop_hang_is_bounded_and_failed(self):
        life, report, order = self.setup_life()
        life.driver.hang = True
        with patch("study.browser_lifecycle.process_identity_state", return_value={"gone": True, "reason": "absent"}):
            await life.cleanup()
        self.assertFalse(report["checks"]["driver_stopped"]["ok"])
        self.assertEqual(report["lifecycle"]["stages"][-1]["error_type"], "DeadlineExceeded")

    async def test_context_failure_keeps_owner_installed_until_guard_close(self):
        life, report, order = self.setup_life()
        life.context.error = True
        with patch("study.browser_lifecycle.process_identity_state", return_value={"gone": True, "reason": "absent"}):
            await life.cleanup()
        self.assertEqual(life.guard.direct_unregister_count, 0)
        self.assertNotIn("owner", order)
        self.assertFalse(report["checks"]["context_closed"]["ok"])
        self.assertFalse(report["checks"]["owner_unregistered_after_context"]["ok"])
        self.assertIn("guard", order)

    async def test_partial_launch_still_stops_driver(self):
        life, report, order = self.setup_life()
        life.browser = life.guard = life.context = life.owner = None
        await life.cleanup()
        self.assertEqual(order, ["driver"])
        self.assertTrue(report["checks"]["driver_stopped"]["ok"])

    async def test_early_failure_before_any_resource_is_safe(self):
        report = {"checks": {}, "events": []}
        await Lifecycle(report).cleanup()
        self.assertTrue(report["checks"]["lifecycle_cleanup_completed"]["ok"])

    async def test_launch_failure_records_stage_and_still_stops_driver(self):
        life, report, order = self.setup_life()
        life.browser = life.guard = life.context = life.owner = None

        async def launch():
            raise RuntimeError("launch_failed")

        ok, value = await life.stage("browser_launch", launch)
        self.assertFalse(ok)
        self.assertIsNone(value)
        await life.cleanup()
        self.assertEqual(order, ["driver"])
        self.assertEqual(report["lifecycle"]["stages"][0]["name"], "browser_launch")
        self.assertEqual(report["lifecycle"]["stages"][0]["error_type"], "RuntimeError")

    async def test_identity_capture_and_durable_event_never_include_commands(self):
        report = {"checks": {}, "events": []}
        session = type("Session", (), {})()
        session.send = AsyncMock(return_value={"processInfo": [{"type": "browser", "id": IDENTITY["pid"]}]})
        session.detach = AsyncMock()
        browser = type("Browser", (), {})()
        browser.new_browser_cdp_session = AsyncMock(return_value=session)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lifecycle-events.jsonl"
            life = Lifecycle(report, event_path=path)
            with patch("study.browser_lifecycle.read_process_identity", return_value=copy.deepcopy(IDENTITY)), patch("study.browser_lifecycle.os.geteuid", return_value=999, create=True):
                result = await life.capture_browser_identity(browser)
            self.assertTrue(result["ok"])
            self.assertEqual(life.identity, IDENTITY)
            self.assertIn("captured_browser_identity", path.read_text())
            self.assertNotIn("cmdline", path.read_text())
            self.assertNotIn("command", path.read_text())
            self.assertTrue(report["checks"]["identity_session_detached"]["ok"])

    async def test_identity_capture_failure_is_explicit(self):
        life, report, order = self.setup_life()
        browser = type("Browser", (), {})()
        browser.new_browser_cdp_session = AsyncMock(side_effect=RuntimeError)
        result = await life.capture_browser_identity(browser)
        self.assertFalse(result["ok"])
        self.assertFalse(report["checks"]["owned_browser_identity_captured"]["ok"])

    async def test_cancellation_shields_one_cleanup_and_records_failure(self):
        life, report, order = self.setup_life()
        entered, release = asyncio.Event(), asyncio.Event()

        async def delayed():
            order.append("context")
            entered.set()
            await release.wait()

        life.context.close = delayed
        with patch("study.browser_lifecycle.process_identity_state", return_value={"gone": True, "reason": "absent"}):
            task = asyncio.create_task(life.cleanup())
            await entered.wait()
            task.cancel()
            release.set()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertFalse(report["checks"]["lifecycle_not_cancelled"]["ok"])
        self.assertEqual(order.count("context"), 1)
        self.assertEqual(order.count("driver"), 1)
        self.assertTrue(report["checks"]["lifecycle_cleanup_completed"]["ok"])

    async def test_cleanup_repeated_does_not_close_twice(self):
        life, report, order = self.setup_life()
        with patch("study.browser_lifecycle.process_identity_state", return_value={"gone": True, "reason": "absent"}):
            await life.cleanup()
            await life.cleanup()
        self.assertEqual(order.count("driver"), 1)

    async def test_cancellation_during_launch_remains_failed_after_cleanup(self):
        report = {"checks": {}, "events": []}
        life = Lifecycle(report)
        entered = asyncio.Event()

        async def launch():
            entered.set()
            await asyncio.Event().wait()

        task = asyncio.create_task(life.stage("browser_launch", launch))
        await entered.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        await life.cleanup()
        self.assertFalse(report["checks"]["lifecycle_not_cancelled"]["ok"])
        self.assertTrue(report["lifecycle"]["cancelled"])
        self.assertEqual(report["lifecycle"]["stages"][0]["error_type"], "CancelledError")

    async def test_event_log_failure_cannot_be_overwritten_by_clean_cleanup(self):
        report = {"checks": {}, "events": []}
        with tempfile.TemporaryDirectory() as directory:
            life = Lifecycle(report, event_path=Path(directory) / "missing-parent" / "events.jsonl")
            await life.stage("driver_start", AsyncMock(return_value="started"))
            await life.cleanup()
        self.assertFalse(report["checks"]["lifecycle_event_log_written"]["ok"])
        self.assertTrue(report["checks"]["lifecycle_cleanup_completed"]["ok"])

    async def test_disconnected_browser_flag_is_not_process_exit_proof(self):
        life, report, order = self.setup_life()
        with patch("study.browser_lifecycle.process_identity_state", return_value={"gone": False, "reason": "still_alive"}):
            await life.cleanup()
        self.assertTrue(report["checks"]["browser_closed"]["ok"])
        self.assertFalse(report["checks"]["owned_browser_process_gone"]["ok"])


class IdentityTests(unittest.TestCase):
    def test_stale_pid_reuse_is_exit_proof_but_does_not_signal(self):
        current = {**IDENTITY, "start_time": "999"}
        with patch("study.browser_lifecycle.read_process_identity", return_value=current):
            result = process_identity_state(IDENTITY)
        self.assertTrue(result["gone"])
        self.assertEqual(result["reason"], "pid_reused_original_process_exited")

    def test_changed_executable_with_same_start_is_not_exit_proof(self):
        with patch("study.browser_lifecycle.read_process_identity", return_value={**IDENTITY, "executable": "/other"}):
            self.assertFalse(process_identity_state(IDENTITY)["gone"])

    def test_missing_identity_cannot_pass(self):
        self.assertFalse(process_identity_state(None)["gone"])
        self.assertFalse(process_identity_state({"pid": 1})["gone"])

    def test_unreadable_identity_cannot_pass(self):
        with patch("study.browser_lifecycle.read_process_identity", side_effect=PermissionError):
            self.assertFalse(process_identity_state(IDENTITY)["gone"])


class BoundedRunnerTests(unittest.TestCase):
    def test_cancel_resistant_operation_does_not_hold_runner_forever(self):
        report, pending = {"checks": {}, "events": []}, []

        async def resistant():
            while True:
                try:
                    await asyncio.sleep(60)
                except asyncio.CancelledError:
                    pass

        async def body():
            life = Lifecycle(report, stage_timeouts={"driver_stop": 0.01})
            life.driver = type("Driver", (), {"stop": staticmethod(resistant)})()
            pending.append(life)
            await life.cleanup()

        started = time.monotonic()
        # The controller kills the dedicated service after this process exits.
        # Silence only expected pending-task diagnostics from this synthetic case.
        with patch("asyncio.base_events.BaseEventLoop.call_exception_handler"):
            run_bounded(body(), timeout=1, report=report, cleanup_seconds=0.1)
        self.assertLess(time.monotonic() - started, 0.5)
        self.assertFalse(report["checks"]["driver_stopped"]["ok"])
        self.assertFalse(report["checks"]["event_loop_quiescent"]["ok"])
        self.assertEqual(report["lifecycle"]["pending_tasks_at_loop_close"], 1)
        for life in pending:
            for task in life._abandoned:
                task._log_destroy_pending = False


if __name__ == "__main__":
    unittest.main()
