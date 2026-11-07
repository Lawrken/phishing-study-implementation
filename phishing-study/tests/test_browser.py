"""Real Chromium checks; STUDY_REQUIRE_BROWSER=1 prohibits browser skips."""
import asyncio
from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch
from study.config import Config
from study.collector import Collector
from study.fixtures import FixtureServer
from study.redirects import RedirectGuard, shutdown_browser
from study.urls import digest


class BrowserTests(unittest.IsolatedAsyncioTestCase):
    async def test_replace_only_live_view_preserves_passive_capture(self):
        before, _ = await self.observe('/redirect')
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as directory:
            os.chmod(directory, 0o700)
            with patch.dict(os.environ, {'STUDY_LIVE_VIEW': directory}):
                after, _ = await self.observe('/redirect', replace(self.c, observation_seconds=3))
            image = Path(directory)/'latest.jpg'
            self.assertTrue(image.read_bytes().startswith(b'\xff\xd8'))
            self.assertLessEqual(image.stat().st_size, 524288)
            state = json.loads((Path(directory)/'status.json').read_text())
            self.assertEqual(state['stage'], 'visit finished')
            self.assertEqual(state['outcome'], 'captured')
            self.assertNotIn('url', state)
            self.assertEqual(state['signals']['requests'], after['groups']['network']['request_count'])
            self.assertEqual(state['signals']['dom']['form_count'], after['groups']['dom']['form_count'])
            self.assertTrue(state['signals']['traffic'])
            self.assertEqual(after['groups']['network']['request_count'], before['groups']['network']['request_count'])
            self.assertEqual(after['groups']['dom']['form_count'], before['groups']['dom']['form_count'])
            self.assertEqual(after['outcome'], before['outcome'])
    async def asyncSetUp(self):
        from playwright.async_api import async_playwright
        self.p = None
        self.browser = None
        self.guard = None
        try:
            self.p = await async_playwright().start()
            self.browser = await self.p.chromium.launch(headless=True)
        except Exception as exc:
            if self.browser:
                await self.browser.close()
            if self.p:
                await self.p.stop()
                self.p = None
            if os.environ.get("STUDY_REQUIRE_BROWSER") == "1":
                raise RuntimeError("Chromium is required; browser behavior was not verified") from exc
            self.skipTest(f"Chromium unavailable ({type(exc).__name__}); browser behavior not verified")
        try:
            self.guard = await RedirectGuard.start(self.browser)
        except BaseException:
            await self.browser.close()
            await self.p.stop()
            raise
        self.fixture = FixtureServer().__enter__()
        self.c = Config(profile="fixture", fixture_origins=[self.fixture.url], observation_seconds=.5,
                        navigation_seconds=5, attempt_seconds=15, lease_seconds=45, min_free_disk_bytes=0)

    async def asyncTearDown(self):
        if hasattr(self, "fixture"):
            self.fixture.__exit__(None,None,None)
        if self.guard:
            await shutdown_browser(self.browser, self.guard)
        elif self.browser:
            await self.browser.close()
        if self.p:
            await self.p.stop()

    async def observe(self, path, config=None):
        url = self.fixture.url+path
        item = {"url":url,"id":digest(url),"attempt_id":digest(path)}
        return await Collector(self.browser, config or self.c, redirect_guard=self.guard).observe(item)

    async def test_headers_dom_javascript_network_and_redirects(self):
        record, events = await self.observe("/redirect?token=SECRET-INPUT")
        self.assertEqual(record["outcome"], "captured")
        self.assertEqual(record["groups"]["redirects"]["http_redirect_count"], 2)
        self.assertEqual([hop["status"] for hop in record["groups"]["redirects"]["chain"]], [302, 301, 200])
        self.assertEqual(record["groups"]["redirects"]["main_document_count"], 3)
        self.assertEqual(record["groups"]["dom"]["password_input_count"], 1)
        self.assertEqual(record["groups"]["dom"]["form_count"], 1)
        self.assertEqual(record["groups"]["http"]["security_header_count"], 2)
        self.assertEqual(record["groups"]["http"]["status"], 200)
        self.assertTrue(record["groups"]["http"]["presence"]["x-content-type-options"])
        self.assertEqual(record["groups"]["javascript"]["external_script_count"], 1)
        self.assertGreaterEqual(record["groups"]["network"]["request_count"], 5)
        self.assertTrue(any(event.get("resource_type") == "fetch" for event in events))
        self.assertEqual(sum(event["kind"] == "request" for event in events), record["groups"]["network"]["request_count"])
        self.assertFalse(any(event.get("method") == "POST" for event in events))
        self.assertNotIn("SECRET", json.dumps([record, events]))

    async def test_fixture_interaction_only(self):
        record, events = await self.observe("/legitimate/login", replace(self.c, interaction="fixture_submit"))
        self.assertTrue(record["groups"]["interaction"]["measured"])
        self.assertGreaterEqual(record["groups"]["interaction"]["new_request_count"], 1)
        self.assertTrue(any(e.get("method") == "POST" for e in events))
        self.assertNotIn("SYNTHETIC-INVALID", json.dumps([record,events]))

    async def test_non_active_dispositions(self):
        for path, outcome in (("/challenge","challenge"),("/takedown","takedown"),("/parked","parked")):
            record, _ = await self.observe(path)
            self.assertEqual(record["outcome"], outcome)
            self.assertFalse(record["eligible"])

    async def test_redirect_to_private_target_is_blocked(self):
        record, events = await self.observe("/escape")
        self.assertEqual(record["outcome"], "policy_blocked")
        self.assertFalse(record["eligible"])
        self.assertFalse(record["transient"])
        self.assertEqual(self.fixture.denied_hits, 0)
        self.assertTrue(any(e["kind"] == "blocked" and e["reason"] == "outside_fixture_origin" for e in events))
        self.assertEqual(record["groups"]["network"]["request_count"], 1)

    async def test_request_budget(self):
        record, _ = await self.observe("/fanout", replace(self.c, max_requests=5))
        self.assertEqual(record["outcome"], "budget_truncated")
        self.assertLessEqual(record["groups"]["network"]["request_count"], 5)

    async def test_timeout_and_retry_after(self):
        record, _ = await self.observe("/slow", replace(self.c, navigation_seconds=.1))
        self.assertEqual(record["outcome"], "timeout")
        self.assertTrue(record["transient"])
        rate, _ = await self.observe("/rate-limit")
        self.assertEqual(rate["outcome"], "http_transient")
        self.assertEqual(rate["retry_after"], 1)

    async def test_fresh_storage_context(self):
        first, _ = await self.observe("/legitimate/login", replace(self.c, interaction="fixture_submit"))
        self.assertEqual(first["groups"]["interaction"]["storage_key_count_delta"], 1)
        second, _ = await self.observe("/clean")
        self.assertEqual(second["groups"]["dom"]["storage_key_count"], 0)

    async def test_allowed_subresource_redirects_are_recorded(self):
        for path, final_type in (("/redirect-fetch", "fetch"), ("/redirect-frame", "document")):
            with self.subTest(path=path):
                record, events = await self.observe(path)
                self.assertEqual(record["outcome"], "captured")
                requests = [event for event in events if event["kind"] == "request"]
                responses = [event for event in events if event["kind"] == "response"]
                self.assertEqual(len(requests), record["groups"]["network"]["request_count"])
                self.assertTrue(any(event["status"] == 302 for event in responses))
                self.assertGreaterEqual(sum(event["status"] == 200 for event in responses), 2)
                self.assertGreaterEqual(sum(event["resource_type"] == final_type for event in requests), 2)
                self.assertEqual(record["groups"]["redirects"]["http_redirect_count"], 0)
                self.assertNotIn("SECRET", json.dumps([record, events]))

    async def test_denied_subresource_redirects_are_ineligible(self):
        for path in ("/escape-fetch", "/escape-frame"):
            with self.subTest(path=path):
                record, events = await self.observe(path)
                self.assertEqual(record["outcome"], "policy_blocked")
                self.assertFalse(record["eligible"])
                self.assertFalse(record["transient"])
                self.assertTrue(any(event["kind"] == "blocked" for event in events))
                self.assertEqual(self.fixture.denied_hits, 0)
                self.assertFalse(any(event["kind"] == "request" and event["url"].get("origin") == self.fixture.denied_url.rsplit("/", 1)[0] for event in events))

    async def test_browser_url_normalization_preserves_redirect_measurements(self):
        record, events = await self.observe("/redirect-normalized-fetch")
        self.assertEqual(record["outcome"], "captured")
        self.assertTrue(record["eligible"])
        requests = [event for event in events if event["kind"] == "request"]
        responses = [event for event in events if event["kind"] == "response"]
        self.assertEqual(len(requests), record["groups"]["network"]["request_count"])
        self.assertGreaterEqual(sum(event["resource_type"] == "fetch" for event in requests), 4)
        self.assertEqual(sum(event["status"] == 302 for event in responses), 2)
        self.assertGreaterEqual(sum(event["status"] == 200 for event in responses), 3)
        hits = self.fixture.hit_snapshot()
        self.assertEqual(hits.get(("GET", "/api/status")), 1)
        self.assertEqual(sum(count for (method, path), count in hits.items() if method == "GET" and path.startswith("/api/normalization/")), 1)
        self.assertEqual(self.fixture.denied_hits, 0)

    async def test_popup_cannot_escape_owned_origins(self):
        await self.observe("/escape-popup")
        self.assertEqual(self.fixture.denied_hits, 0)
        self.assertEqual(len(self.browser.contexts), 0)

    async def test_ambiguous_redirect_is_rejected(self):
        record, events = await self.observe("/ambiguous-redirect")
        self.assertEqual(record["outcome"], "policy_blocked")
        self.assertFalse(record["transient"])
        self.assertFalse(record["eligible"])
        self.assertTrue(any(event["kind"] == "blocked" for event in events))
        self.assertEqual(self.fixture.denied_hits, 0)
        self.assertEqual(record["groups"]["network"]["request_count"], 1)

    async def test_redirect_budget_counts_every_hop(self):
        record, _ = await self.observe("/redirect-chain/4", replace(self.c, max_requests=2))
        self.assertEqual(record["outcome"], "budget_truncated")
        self.assertFalse(record["eligible"])
        self.assertFalse(record["transient"])
        self.assertEqual(record["groups"]["network"]["request_count"], 2)
        hits = self.fixture.hit_snapshot()
        self.assertEqual(hits.get(("GET", "/redirect-chain/4")), 1)
        self.assertEqual(hits.get(("GET", "/redirect-chain/3")), 1)
        self.assertEqual(hits.get(("GET", "/redirect-chain/2"), 0), 0)

    async def test_concurrent_attempt_budgets_are_independent(self):
        bounded = replace(self.c, max_requests=5)
        results = await asyncio.gather(self.observe("/fanout?attempt=first", bounded), self.observe("/fanout?attempt=second", bounded))
        for record, events in results:
            self.assertEqual(record["outcome"], "budget_truncated")
            self.assertFalse(record["transient"])
            self.assertFalse(record["eligible"])
            self.assertEqual(record["groups"]["network"]["request_count"], 5)
            self.assertEqual(sum(event["kind"] == "request" for event in events), 5)
        self.assertEqual(len(self.browser.contexts), 0)

    async def test_concurrent_redirect_budgets_are_independent(self):
        bounded = replace(self.c, max_requests=2)
        results = await asyncio.gather(self.observe("/redirect-chain/4?attempt=first", bounded), self.observe("/redirect-chain/4?attempt=second", bounded))
        for record, events in results:
            self.assertEqual(record["outcome"], "budget_truncated")
            self.assertEqual(record["groups"]["network"]["request_count"], 2)
            self.assertEqual(sum(event["kind"] == "request" for event in events), 2)
        hits = self.fixture.hit_snapshot()
        self.assertEqual(hits.get(("GET", "/redirect-chain/4")), 2)
        self.assertEqual(hits.get(("GET", "/redirect-chain/3")), 2)
        self.assertEqual(hits.get(("GET", "/redirect-chain/2"), 0), 0)

    async def test_guard_failure_stops_browsing_and_invalidates_capture(self):
        with patch.object(self.guard, "_owner_for", AsyncMock(side_effect=RuntimeError("controlled guard failure"))):
            record, events = await self.observe("/redirect")
        self.assertEqual(record["outcome"], "policy_blocked")
        self.assertFalse(record["eligible"])
        self.assertFalse(record["transient"])
        self.assertEqual(self.fixture.hit_snapshot().get(("GET", "/redirect2"), 0), 0)
        self.assertTrue(any(event["kind"] == "blocked" for event in events))
        self.assertEqual(len(self.browser.contexts), 0)
        self.assertFalse(self.guard._owners)

    async def test_redirects_preserve_native_post_method_behavior(self):
        for status, final_method in ((303, "GET"), (307, "POST")):
            with self.subTest(status=status):
                before = self.fixture.hit_snapshot().get((final_method, "/method/final"), 0)
                record, events = await self.observe(f"/method-test/{status}")
                self.assertEqual(record["outcome"], "captured")
                self.assertTrue(any(event["kind"] == "response" and event["status"] == status for event in events))
                self.assertEqual(self.fixture.hit_snapshot().get((final_method, "/method/final")), before + 1)
                self.assertNotIn("synthetic=invalid", json.dumps([record, events]))

    async def test_cancellation_releases_context_and_guard_registration(self):
        pending = asyncio.create_task(self.observe("/slow"))
        try:
            async with asyncio.timeout(5):
                while not self.fixture.hit_snapshot().get(("GET", "/slow")):
                    await asyncio.sleep(.01)
            pending.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await pending
        finally:
            if not pending.done():
                pending.cancel()
                await asyncio.gather(pending, return_exceptions=True)
        self.assertEqual(len(self.browser.contexts), 0)
        self.assertFalse(self.guard._owners)
        self.assertFalse(self.guard._contexts)
        record, _ = await self.observe("/redirect-fetch")
        self.assertEqual(record["outcome"], "captured")
        self.assertEqual(self.fixture.denied_hits, 0)

    async def test_cancellation_with_pending_policy_checks_keeps_guard_clean(self):
        from study.policy import Policy
        original = Policy.check
        entered = asyncio.Event()
        release = asyncio.Event()
        waiting = 0
        async def pending_check(policy, url):
            nonlocal waiting
            if '/api/status?' in url:
                waiting += 1
                if waiting >= 16:
                    entered.set()
                await release.wait()
            return await original(policy, url)
        with patch.object(Policy, 'check', pending_check):
            pending = asyncio.create_task(self.observe('/fanout', replace(self.c, observation_seconds=30)))
            try:
                await asyncio.wait_for(entered.wait(), timeout=5)
                pending.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(pending, timeout=12)
            finally:
                release.set()
                if not pending.done():
                    pending.cancel()
                await asyncio.gather(pending, return_exceptions=True)
        self.assertGreaterEqual(waiting, 16)
        self.assertEqual(len(self.browser.contexts), 0)
        self.assertFalse(self.guard.failed, self.guard.failure_reason)
        self.assertFalse(self.guard._owners)
        self.assertFalse(self.guard._contexts)
        self.assertEqual(self.fixture.hit_snapshot().get(('GET', '/api/status'), 0), 0)
        self.assertEqual(self.fixture.denied_hits, 0)
