"""CDP adapter checks for redirect admission and fail-closed lifecycle behavior.

Real Chromium fixture tests remain necessary to verify browser integration.
"""
import asyncio
import unittest
from unittest.mock import patch

from study.redirects import RedirectGuard, redirect_target, shutdown_browser


def paused(request_id="redirect-1", frame="frame-a", location="/next", status=302):
    return {"requestId": request_id, "frameId": frame,
            "request": {"url": "http://127.0.0.1:8123/start", "method": "GET"},
            "responseStatusCode": status,
            "responseHeaders": [{"name": "Location", "value": location}]}


class Session:
    def __init__(self, frame=None, context_id=None):
        self.frame, self.context_id = frame, context_id
        self.handlers, self.calls, self.targets = {}, [], {}
        self.children, self.fail_methods = [], {}
        self.detached = False

    def on(self, name, handler):
        self.handlers.setdefault(name, []).append(handler)

    def remove_listener(self, name, handler):
        self.handlers[name].remove(handler)

    def emit(self, name, event):
        for handler in list(self.handlers.get(name, [])):
            handler(event)

    async def send(self, method, params):
        self.calls.append((method, params))
        if method in self.fail_methods:
            raise self.fail_methods[method]
        if method == "Target.getTargetInfo":
            if "targetId" in params:
                if params["targetId"] not in self.targets:
                    raise RuntimeError("target unavailable")
                return {"targetInfo": self.targets[params["targetId"]]}
            return {"targetInfo": {"targetId": self.frame, "browserContextId": self.context_id}}
        if method == "Page.getFrameTree":
            return {"frameTree": {"frame": {"id": self.frame},
                                  "childFrames": [{"frame": {"id": child}} for child in self.children]}}
        return {}

    async def detach(self):
        self.detached = True


class Context:
    def __init__(self, session):
        self.session, self.closed = session, False

    async def new_cdp_session(self, page):
        return self.session

    async def close(self):
        self.closed = True


class Page:
    def __init__(self, frame, context_id):
        self.context = Context(Session(frame, context_id))


class Browser:
    def __init__(self):
        self.session, self.closed = Session(), False

    async def new_browser_cdp_session(self):
        return self.session

    async def close(self):
        self.closed = True

    def is_connected(self):
        return not self.closed


class DisconnectedGuardCleanupTests(unittest.IsolatedAsyncioTestCase):
    async def test_fixture_and_smoke_shutdown_use_the_same_retained_interception(self):
        browser = Browser()
        guard = await RedirectGuard.start(browser)
        await shutdown_browser(browser, guard)
        self.assertTrue(browser.closed)
        self.assertTrue(guard._closed)
        self.assertFalse(any(method == 'Fetch.disable' for method, _ in browser.session.calls))

    async def test_live_browser_cannot_release_guard_with_disconnected_cleanup(self):
        browser = Browser()
        guard = await RedirectGuard.start(browser)
        with self.assertRaisesRegex(RuntimeError, 'browser_must_disconnect'):
            await guard.close_after_browser()
        self.assertFalse(guard._closed)
        self.assertFalse(any(method == 'Fetch.disable' for method, _ in browser.session.calls))
        await guard.close()

    async def test_browser_exit_keeps_fetch_installed_and_preserves_prior_failures(self):
        browser = Browser()
        guard = await RedirectGuard.start(browser)
        guard.prepare_browser_shutdown()
        guard.failed, guard.failure_reason = True, 'prior_transport_failure'
        await browser.close()
        await guard.close_after_browser()
        self.assertTrue(guard._closed)
        self.assertTrue(guard.failed)
        self.assertEqual(guard.failure_reason, 'prior_transport_failure')
        self.assertFalse(any(method == 'Fetch.disable' for method, _ in browser.session.calls))


class RedirectLocationTests(unittest.TestCase):
    def test_relative_and_absolute_targets_keep_query_and_drop_fragment(self):
        self.assertEqual(redirect_target(paused(location=" ../login?x=1#secret ")),
                         "http://127.0.0.1:8123/login?x=1")
        self.assertEqual(redirect_target(paused(location="https://example.test/next")),
                         "https://example.test/next")

    def test_non_redirect_status_or_missing_location_has_no_next_hop(self):
        self.assertIsNone(redirect_target(paused(status=200)))
        event = paused()
        event["responseHeaders"] = []
        self.assertIsNone(redirect_target(event))

    def test_parser_ambiguity_invalid_authorities_and_duplicate_headers_rejected(self):
        for location in ("\\\\outside.test/path", "///outside.test/path", "http:////outside.test",
                         "/line\nbreak", "/nul\0byte", "file:///etc/passwd",
                         "https://user:pass@example.test/", "https://example.test:99999/", ""):
            with self.subTest(location=repr(location)), self.assertRaises(ValueError):
                redirect_target(paused(location=location))
        event = paused()
        event["responseHeaders"].append({"name": "location", "value": "https://outside.test/"})
        with self.assertRaises(ValueError):
            redirect_target(event)


class RedirectGuardTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.browser = Browser()
        self.guard = await RedirectGuard.start(self.browser)
        self.addAsyncCleanup(self.guard.close)
        self.targets, self.failures = [], []

    async def register(self, frame="frame-a", context_id="context-a", allowed=True):
        page = Page(frame, context_id)

        async def admit(target, event):
            self.targets.append(target)
            return allowed

        async def fail(reason):
            self.failures.append(reason)
            await page.context.close()

        owner = await self.guard.register(page, admit, fail)
        return page, owner

    async def settle(self):
        while self.guard._tasks:
            await asyncio.gather(*list(self.guard._tasks), return_exceptions=True)
            await asyncio.sleep(0)

    def decisions(self):
        return [(method, params) for method, params in self.browser.session.calls
                if method in {"Fetch.failRequest", "Fetch.continueResponse"}]

    async def test_native_allowed_redirect_does_not_modify_or_fetch_response(self):
        await self.register()
        self.browser.session.emit("Fetch.requestPaused", paused())
        await self.settle()
        self.assertEqual(self.targets, ["http://127.0.0.1:8123/next"])
        self.assertEqual(self.decisions(), [("Fetch.continueResponse", {"requestId": "redirect-1"})])
        self.assertFalse(self.failures)
        self.assertEqual(self.browser.session.calls[0], ("Fetch.enable", {
            "patterns": [{"urlPattern": "*", "requestStage": "Response"}],
        }))

    async def test_denied_next_hop_is_aborted_without_native_follow(self):
        await self.register(allowed=False)
        self.browser.session.emit("Fetch.requestPaused", paused())
        await self.settle()
        self.assertEqual(self.decisions(), [("Fetch.failRequest", {
            "requestId": "redirect-1", "errorReason": "BlockedByClient",
        })])
        self.assertFalse(self.failures)  # Admission callback owns policy classification.

    async def test_ordinary_response_never_calls_redirect_admission(self):
        self.browser.session.emit("Fetch.requestPaused", paused(status=200, frame="unowned"))
        await self.settle()
        self.assertFalse(self.targets)
        self.assertEqual(self.decisions()[0][0], "Fetch.continueResponse")

    async def test_attached_and_refreshed_frames_and_worker_context_have_correct_owner(self):
        page, owner = await self.register()
        page.context.session.emit("Page.frameAttached", {"frameId": "attached", "parentFrameId": "frame-a"})
        self.browser.session.emit("Fetch.requestPaused", paused("attached-request", "attached"))
        page.context.session.children.append("racing-frame")
        self.browser.session.emit("Fetch.requestPaused", paused("racing-request", "racing-frame"))
        self.browser.session.targets["worker"] = {"browserContextId": "context-a", "type": "worker"}
        self.browser.session.emit("Fetch.requestPaused", paused("worker-request", "worker"))
        await self.settle()
        self.assertEqual(len(self.targets), 3)
        self.assertTrue({"attached", "racing-frame", "worker"}.issubset(owner.frame_ids))
        self.assertFalse(self.failures)

    async def test_unknown_redirect_owner_closes_observations_and_refuses_registration(self):
        page, _ = await self.register()
        self.browser.session.emit("Fetch.requestPaused", paused(frame="unknown"))
        await self.settle()
        self.assertTrue(page.context.closed)
        self.assertTrue(self.guard.failed)
        self.assertEqual(self.failures, ["redirect_owner_unknown"])
        self.assertFalse(self.targets)
        self.assertEqual(self.decisions()[0][0], "Fetch.failRequest")
        with self.assertRaises(RuntimeError):
            await self.register("frame-b", "context-b")

    async def test_duplicate_pause_invokes_admission_and_reserves_only_once(self):
        await self.register()
        event = paused()
        self.browser.session.emit("Fetch.requestPaused", event)
        self.browser.session.emit("Fetch.requestPaused", event)
        await self.settle()
        self.browser.session.emit("Fetch.requestPaused", event)
        await self.settle()
        self.assertEqual(len(self.targets), 1)
        self.assertEqual(len(self.decisions()), 1)

    async def test_concurrent_attempts_use_their_own_reservations(self):
        counts = {"a": 0, "b": 0}
        for name in counts:
            page = Page("frame-" + name, "context-" + name)

            async def reserve(target, event, name=name):
                if counts[name] >= 2:
                    return False
                counts[name] += 1  # Reserve before awaiting the destination check.
                await asyncio.sleep(.001)
                return True

            async def fail(reason):
                self.failures.append(reason)

            await self.guard.register(page, reserve, fail)
        for name in counts:
            for index in range(3):
                self.browser.session.emit("Fetch.requestPaused", paused(f"{name}-{index}", "frame-" + name))
        await self.settle()
        self.assertEqual(counts, {"a": 2, "b": 2})
        self.assertEqual(sum(method == "Fetch.continueResponse" for method, _ in self.decisions()), 4)
        self.assertEqual(sum(method == "Fetch.failRequest" for method, _ in self.decisions()), 2)

    async def test_ambiguous_location_aborts_and_reports_only_category(self):
        page, _ = await self.register()
        self.browser.session.emit("Fetch.requestPaused", paused(location="\\\\SECRET-target/path"))
        await self.settle()
        self.assertTrue(page.context.closed)
        self.assertEqual(self.failures, ["invalid_redirect_location"])
        self.assertFalse(self.targets)
        self.assertEqual(self.decisions()[0][0], "Fetch.failRequest")

    async def test_callback_error_and_cancellation_do_not_continue_redirect(self):
        page, owner = await self.register()

        async def broken(target, event):
            raise RuntimeError("SECRET-exception")

        owner.on_redirect = broken
        self.browser.session.emit("Fetch.requestPaused", paused())
        await self.settle()
        self.assertTrue(page.context.closed)
        self.assertEqual(self.failures, ["redirect_guard_error"])
        self.assertEqual(self.decisions()[0][0], "Fetch.failRequest")

        ready = asyncio.Event()

        async def waiting(target, event):
            ready.set()
            await asyncio.Event().wait()

        owner.on_redirect = waiting
        self.browser.session.emit("Fetch.requestPaused", paused("cancelled"))
        await ready.wait()
        for task in list(self.guard._tasks):
            task.cancel()
        await self.settle()
        self.assertFalse(any(method == "Fetch.continueResponse" for method, _ in self.decisions()))

    async def test_transport_failure_closes_browser_instead_of_releasing_pause(self):
        await self.register(allowed=False)
        self.browser.session.fail_methods["Fetch.failRequest"] = RuntimeError("transport closed")
        self.browser.session.emit("Fetch.requestPaused", paused())
        await self.settle()
        self.assertTrue(self.browser.closed)
        self.assertTrue(self.guard.failed)
        self.assertFalse(any(method == "Fetch.continueResponse" for method, _ in self.decisions()))

    async def test_stale_pause_after_native_cancellation_does_not_kill_other_contexts(self):
        await self.register(allowed=False)
        self.browser.session.fail_methods["Fetch.failRequest"] = RuntimeError("Invalid InterceptionId.")
        self.browser.session.emit("Fetch.requestPaused", paused())
        await self.settle()
        self.assertFalse(self.browser.closed)
        self.assertFalse(self.guard.failed)

    async def test_normal_response_removed_while_continuing_does_not_fail_other_attempt(self):
        page, _ = await self.register()
        other, _ = await self.register("frame-b", "context-b")
        entered, released = asyncio.Event(), asyncio.Event()
        send = self.browser.session.send

        async def in_flight(method, params):
            if method == "Fetch.continueResponse":
                entered.set()
                await released.wait()
                raise RuntimeError("Protocol error (Fetch.continueResponse): Invalid InterceptionId.")
            return await send(method, params)

        self.browser.session.send = in_flight
        self.browser.session.emit("Fetch.requestPaused", paused(status=200))
        await entered.wait()
        await page.context.close()
        cleanup = asyncio.create_task(self.guard.unregister(
            next(owner for owner in self.guard._owners if owner.page is page)))
        await asyncio.sleep(0)
        released.set()
        await cleanup
        await self.settle()
        self.assertFalse(self.guard.failed)
        self.assertFalse(self.failures)
        self.assertFalse(self.browser.closed)
        self.assertFalse(other.context.closed)
        self.assertFalse(any(method == "Fetch.failRequest" for method, _ in self.decisions()))

    async def test_real_continue_transport_failure_still_fails_all_attempts(self):
        page, _ = await self.register()
        self.browser.session.fail_methods["Fetch.continueResponse"] = RuntimeError("CDP transport closed")
        self.browser.session.emit("Fetch.requestPaused", paused(status=200))
        await self.settle()
        self.assertTrue(self.guard.failed)
        self.assertTrue(page.context.closed)
        self.assertEqual(self.failures, ["redirect_guard_transport_failed"])
        self.assertEqual(self.decisions()[-1][0], "Fetch.failRequest")

    async def test_unregister_waits_for_own_normal_response_and_keeps_maps_until_done(self):
        page, owner = await self.register()
        entered, released = asyncio.Event(), asyncio.Event()
        send = self.browser.session.send

        async def in_flight(method, params):
            if method == "Fetch.continueResponse":
                entered.set()
                await released.wait()
            return await send(method, params)

        self.browser.session.send = in_flight
        self.browser.session.emit("Fetch.requestPaused", paused(status=200))
        await entered.wait()
        await page.context.close()
        cleanup = asyncio.create_task(self.guard.unregister(owner))
        await asyncio.sleep(0)
        self.assertFalse(owner.active)
        self.assertFalse(cleanup.done())
        self.assertIs(self.guard._frames["frame-a"], owner)
        released.set()
        await cleanup
        await self.settle()
        self.assertNotIn("frame-a", self.guard._frames)
        self.assertFalse(self.guard.failed)

    async def test_unregister_cancels_pending_own_admission_with_bounded_wait(self):
        page, owner = await self.register()
        entered, cancelled = asyncio.Event(), asyncio.Event()

        async def blocked(target, event):
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        owner.on_redirect = blocked
        self.browser.session.emit("Fetch.requestPaused", paused())
        await entered.wait()
        await page.context.close()
        with patch("study.redirects.COMMAND_SECONDS", .02):
            await asyncio.wait_for(self.guard.unregister(owner), .5)
        await self.settle()
        self.assertTrue(cancelled.is_set())
        self.assertFalse(self.guard._tasks)
        self.assertFalse(self.guard._task_owners)
        self.assertFalse(self.guard.failed)
        self.assertFalse(self.failures)

    async def test_admission_callback_unregister_does_not_wait_for_its_own_parent(self):
        page, owner = await self.register()

        async def teardown(target, event):
            await page.context.close()
            await self.guard.unregister(owner)
            return False

        owner.on_redirect = teardown
        self.browser.session.emit("Fetch.requestPaused", paused())
        await asyncio.wait_for(self.settle(), .5)
        self.assertFalse(self.guard._owners)
        self.assertFalse(self.guard.failed)
        self.assertEqual(self.decisions()[-1][0], "Fetch.failRequest")

    async def test_vanished_unknown_and_malformed_redirects_do_not_fail_active_attempts(self):
        page, _ = await self.register()
        self.browser.session.fail_methods["Fetch.failRequest"] = RuntimeError("Invalid RequestId.")
        self.browser.session.emit("Fetch.requestPaused", paused("gone-redirect", frame="closed-frame"))
        self.browser.session.emit("Fetch.requestPaused", paused("gone-malformed", frame="closed-frame", location="///outside.test"))
        await self.settle()
        self.assertFalse(page.context.closed)
        self.assertFalse(self.guard.failed)
        self.assertFalse(self.failures)

    async def test_context_and_browser_close_failure_keeps_guard_and_ownership_installed(self):
        page, owner = await self.register()
        context_close, browser_close = page.context.close, self.browser.close

        async def cannot_close():
            raise RuntimeError("cleanup failed")

        page.context.close = self.browser.close = cannot_close
        try:
            with self.assertRaises(RuntimeError):
                await self.guard.close()
            self.assertTrue(self.guard.failed)
            self.assertTrue(self.guard._closing)
            self.assertIn(owner, self.guard._owners)
            self.assertIs(self.guard._frames["frame-a"], owner)
            self.assertFalse(self.browser.session.detached)
            self.assertFalse(any(method == "Fetch.disable" for method, _ in self.browser.session.calls))
        finally:
            page.context.close, self.browser.close = context_close, browser_close

    async def test_context_close_failure_requires_browser_close_before_disabling_fetch(self):
        page, _ = await self.register()

        async def cannot_close():
            raise RuntimeError("context cleanup failed")

        page.context.close = cannot_close
        await self.guard.close()
        self.assertTrue(self.browser.closed)
        self.assertTrue(self.guard.failed)
        self.assertFalse(self.guard._owners)
        self.assertTrue(any(method == "Fetch.disable" for method, _ in self.browser.session.calls))

    async def test_fetch_disable_failure_marks_cleanup_failed_before_browser_fallback(self):
        page, _ = await self.register()
        self.browser.session.fail_methods["Fetch.disable"] = RuntimeError("CDP command failed")
        await self.guard.close()
        self.assertTrue(page.context.closed)
        self.assertTrue(self.browser.closed)
        self.assertTrue(self.guard.failed)
        self.assertEqual(self.guard.failure_reason, "redirect_guard_cleanup_failed")
        self.assertFalse(self.browser.session.detached)
        self.assertFalse(self.guard._owners)

    async def test_browser_session_detach_failure_marks_cleanup_failed_before_browser_fallback(self):
        page, _ = await self.register()

        async def cannot_detach():
            raise RuntimeError("CDP detach failed")

        self.browser.session.detach = cannot_detach
        await self.guard.close()
        self.assertTrue(page.context.closed)
        self.assertTrue(self.browser.closed)
        self.assertTrue(self.guard.failed)
        self.assertEqual(self.guard.failure_reason, "redirect_guard_cleanup_failed")
        self.assertTrue(any(method == "Fetch.disable" for method, _ in self.browser.session.calls))
        self.assertFalse(self.guard._owners)

    async def test_close_shuts_context_before_disabling_guard_and_is_idempotent(self):
        page, _ = await self.register()
        await self.guard.close()
        self.assertTrue(page.context.closed)
        self.assertTrue(self.browser.session.detached)
        self.assertFalse(any(self.browser.session.handlers.values()))
        disable_count = sum(method == "Fetch.disable" for method, _ in self.browser.session.calls)
        await self.guard.close()
        self.assertEqual(sum(method == "Fetch.disable" for method, _ in self.browser.session.calls), disable_count)

    async def test_unregister_removes_frame_ownership_and_page_listeners(self):
        page, owner = await self.register()
        await page.context.close()
        await self.guard.unregister(owner)
        self.assertFalse(owner.active)
        self.assertTrue(page.context.session.detached)
        self.assertFalse(any(page.context.session.handlers.values()))
        self.browser.session.emit("Fetch.requestPaused", paused())
        await self.settle()
        self.assertTrue(self.guard.failed)
        self.assertEqual(self.decisions()[0][0], "Fetch.failRequest")
