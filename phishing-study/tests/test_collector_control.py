"""Adapter simulations exercise cancellation, request races, and redaction without Chromium.

These tests validate collector control flow, not browser rendering or browser API compatibility.
"""
import asyncio
from dataclasses import replace
import json
import unittest
from unittest.mock import AsyncMock, patch
from study.config import Config
from study.collector import Collector
from study.urls import digest


class Request:
    method = "GET"
    resource_type = "document"
    redirected_from = None
    failure = None
    def __init__(self, url, page):
        self.url, self.frame = url, page.main_frame
    def is_navigation_request(self):
        return True
    async def sizes(self):
        return {"requestBodySize":0,"requestHeadersSize":100,"responseBodySize":100,"responseHeadersSize":100}


class Response:
    status = 200
    def __init__(self, request):
        self.request, self.url = request, request.url
    async def all_headers(self):
        return {"content-type":"text/html", "set-cookie":"token=SECRET-COOKIE; HttpOnly", "x-frame-options":"DENY"}
    async def security_details(self):
        return None


class Route:
    def __init__(self):
        self.allowed = False
    async def continue_(self):
        self.allowed = True
    async def abort(self):
        self.allowed = False


class Page:
    def __init__(self, context):
        self.context, self.handlers, self.main_frame = context, {}, object()
        self.url, self.closed = "about:blank", False
    def on(self, event, fn):
        self.handlers[event] = fn
    async def goto(self, url, **kwargs):
        if self.context.hang:
            await asyncio.Event().wait()
        self.url = url
        async def request_one(i):
            req = Request(url+f"?secret=SECRET-{i}", self)
            route = Route()
            await self.context.handler(route, req)
            if route.allowed:
                self.context.handlers["response"](Response(req))
                self.context.handlers["requestfinished"](req)
        await asyncio.gather(*(request_one(i) for i in range(self.context.fanout)))
    async def wait_for_timeout(self, _):
        await asyncio.sleep(0)
    async def evaluate(self, *_):
        return {"measured":True,"node_count":10,"truncated":False,"form_count":0,"password_input_count":0,
                "input_count":0,"iframe_count":0,"cross_origin_form_count":0,"post_form_count":0,
                "script_count":0,"inline_script_count":0,"external_script_count":0,"cross_origin_script_count":0,
                "storage_key_count":0,"disposition_flags":{"challenge":False,"takedown":False,"parked":False}}
    async def close(self):
        self.closed = True


class Context:
    def __init__(self, hang=False, fanout=1):
        self.hang, self.fanout, self.closed = hang, fanout, False
        self.handlers = {}
    def on(self, event, fn):
        self.handlers[event] = fn
    async def new_page(self):
        self.page = Page(self)
        return self.page
    async def route(self, _, handler):
        self.handler = handler
    async def route_web_socket(self, *_):
        pass
    async def close(self):
        self.closed = True


class Browser:
    version = "adapter-simulation"
    def __init__(self, **kwargs):
        self.options, self.contexts = kwargs, []
    async def new_context(self, **kwargs):
        context = Context(**self.options)
        self.contexts.append(context)
        return context


class Guard:
    # Deliberate adapter double; browser guard behavior has separate tests.
    failed = False
    failure_reason = None
    async def register(self, page, on_redirect, on_failure):
        return page
    async def unregister(self, owner):
        pass


class CollectorControlTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.c = Config(profile="fixture",fixture_origins=["http://127.0.0.1:8123"],observation_seconds=0)
        self.item = {"url":"http://127.0.0.1:8123/a","id":digest("candidate"),"attempt_id":digest("attempt")}

    async def test_passive_capture_has_eight_groups_and_redacted_events(self):
        browser = Browser()
        record, events = await Collector(browser, self.c, Guard()).observe(self.item)
        self.assertEqual(record["outcome"], "captured")
        self.assertEqual(len(record["groups"]), 8)
        self.assertTrue(record["eligible"])
        self.assertNotIn("SECRET", json.dumps([record,events]))
        self.assertTrue(browser.contexts[0].closed)
        self.assertEqual(record["groups"]["interaction"]["missing_reason"], "passive_policy_no_actions")

    async def test_parallel_dns_checks_cannot_exceed_request_cap(self):
        async def slow_policy(_, url):
            await asyncio.sleep(.01)
            return True, "test"
        browser = Browser(fanout=20)
        with patch("study.collector.Policy.check", slow_policy):
            record, _ = await Collector(browser, replace(self.c,max_requests=5), Guard()).observe(self.item)
        self.assertEqual(record["groups"]["network"]["request_count"], 5)
        self.assertEqual(record["outcome"], "budget_truncated")

    async def test_cancelled_visit_closes_context(self):
        browser = Browser(hang=True)
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(Collector(browser,self.c,Guard()).observe(self.item),timeout=.02)
        self.assertTrue(browser.contexts[0].closed)

    async def test_policy_rejection_creates_no_context(self):
        browser = Browser()
        item = self.item | {"url":"http://169.254.169.254/"}
        record, _ = await Collector(browser,self.c,Guard()).observe(item)
        self.assertEqual(record["outcome"], "policy_blocked")
        self.assertEqual(browser.contexts, [])

    async def test_failure_during_guard_teardown_revokes_capture(self):
        class LateFailureGuard(Guard):
            async def register(self, page, on_redirect, on_failure):
                self.on_failure = on_failure
                return page
            async def unregister(self, owner):
                await self.on_failure("redirect_guard_error")

        record, events = await Collector(Browser(), self.c, LateFailureGuard()).observe(self.item)
        self.assertEqual(record["outcome"], "policy_blocked")
        self.assertEqual(record["policy_reason"], "redirect_guard_error")
        self.assertFalse(record["eligible"])
        self.assertFalse(record["transient"])
        self.assertTrue(any(e.get("reason") == "redirect_guard_error" for e in events))

    async def test_native_ambiguous_redirect_failure_is_permanent_and_redacted(self):
        class Error(Exception):
            pass

        for failure, outcome, transient in (
                ("net::ERR_RESPONSE_HEADERS_MULTIPLE_LOCATION", "policy_blocked", False),
                ("net::ERR_CONNECTION_RESET", "navigation_error", True)):
            with self.subTest(failure=failure):
                async def failed_navigation(page, url, **kwargs):
                    request, route = Request(url, page), Route()
                    request.failure = failure
                    await page.context.handler(route, request)
                    page.context.handlers["requestfailed"](request)
                    raise Error("navigation failed for SECRET-URL")

                with patch.object(Page, "goto", failed_navigation):
                    record, events = await Collector(Browser(), self.c, Guard()).observe(self.item)
                self.assertEqual(record["outcome"], outcome)
                self.assertEqual(record["transient"], transient)
                self.assertFalse(record["eligible"])
                self.assertEqual(record["groups"]["network"]["failed_request_count"], 1)
                self.assertEqual(record["groups"]["network"]["request_count"], 1)
                self.assertEqual(any(e.get("reason") == "invalid_redirect_location" for e in events), not transient)
                self.assertNotIn("SECRET", json.dumps([record, events]))
                self.assertNotIn(failure, json.dumps([record, events]))

    async def test_failed_context_close_stops_browser_before_unregister(self):
        browser, guard = Browser(), Guard()
        order = []
        async def create_context(**kwargs):
            context = Context()
            context.close = AsyncMock(side_effect=RuntimeError("context close failed"))
            browser.contexts.append(context)
            return context
        async def close_browser():
            order.append("browser_closed")
        async def unregister(owner):
            order.append("unregistered")
        browser.new_context = create_context
        browser.close = AsyncMock(side_effect=close_browser)
        guard.unregister = AsyncMock(side_effect=unregister)
        record, _ = await Collector(browser, self.c, guard).observe(self.item)
        self.assertEqual(order, ["browser_closed", "unregistered"])
        self.assertEqual(record["outcome"], "policy_blocked")
        self.assertEqual(record["policy_reason"], "context_teardown_failed")
        self.assertFalse(record["eligible"])
        self.assertFalse(record["transient"])

    async def test_failed_browser_close_keeps_guard_ownership(self):
        browser, guard = Browser(), Guard()
        async def create_context(**kwargs):
            context = Context()
            context.close = AsyncMock(side_effect=RuntimeError("context close failed"))
            browser.contexts.append(context)
            return context
        browser.new_context = create_context
        browser.close = AsyncMock(side_effect=RuntimeError("browser close failed"))
        guard.unregister = AsyncMock()
        with self.assertRaisesRegex(RuntimeError, "browser close failed"):
            await Collector(browser, self.c, guard).observe(self.item)
        guard.unregister.assert_not_awaited()
        self.assertTrue(guard.failed)
