"""Queue/supervisor integration with a synthetic collector, independent of Chromium."""
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from study.config import Config
from study.queue import Queue
from study.runner import collect
from study.unattended import run


class Browser:
    async def close(self):
        pass


class Chromium:
    async def launch(self, **kwargs):
        return Browser()


class Playwright:
    chromium = Chromium()
    async def __aenter__(self):
        return self
    async def __aexit__(self,*_):
        pass


class SyntheticCollector:
    def __init__(self,browser,config,redirect_guard=None):
        self.config = config
    async def observe(self,item):
        c = self.config
        return {"attempt_id":item["attempt_id"],"candidate_id":item["id"],"groups":{},"eligible":True,
                "outcome":"captured","transient":False,"retry_after":0,"profile":"fixture",
                "config_hash":c.fingerprint,"route_id":c.route_id,"region":"local",
                "captured_at":datetime.now(timezone.utc).isoformat()}, []


class Guard:
    failed = False
    @classmethod
    async def start(cls, browser):
        return cls()
    async def close(self):
        pass


class RunnerTests(unittest.IsolatedAsyncioTestCase):
    async def check_run(self, config, guard_class=Guard):
        with tempfile.TemporaryDirectory() as temp:
            q = Queue(temp)
            q.ingest([{"url":f"http://127.0.0.1:8123/{i}","label":"phishing" if i%2 else "legitimate","source":"synthetic-supervisor-test"} for i in range(6)])
            with patch("playwright.async_api.async_playwright",return_value=Playwright()), patch("study.runner.Collector",SyntheticCollector), patch("study.runner.RedirectGuard",guard_class):
                rid = await collect(q,config)
            status = q.status()
            self.assertEqual(status["runs"][0]["id"],rid)
            self.assertTrue((Path(temp)/"status.json").exists())
            return status

    def config(self,**kwargs):
        return Config(profile="fixture",fixture_origins=["http://127.0.0.1:8123"],domain_cooldown_seconds=0,min_free_disk_bytes=0,**kwargs)

    async def test_finite_queue_run_and_checkpoint(self):
        status = await self.check_run(self.config())
        self.assertEqual(status["attempts"],6)
        self.assertEqual(status["usable"],6)
        self.assertEqual(status["runs"][0]["stop_reason"],"queue_exhausted")

    async def test_total_attempt_budget_includes_all_workers(self):
        status = await self.check_run(self.config(max_attempts=2))
        self.assertEqual(status["attempts"],2)
        self.assertEqual(status["runs"][0]["stop_reason"],"attempt_budget")

    async def test_class_caps_stop_job(self):
        status = await self.check_run(self.config(usable_per_class=1))
        self.assertEqual(status["usable"],2)
        self.assertEqual(status["runs"][0]["stop_reason"],"class_caps")

    async def test_guard_cleanup_failure_is_saved_as_stop_reason(self):
        class CleanupFailureGuard(Guard):
            async def close(self):
                self.failed = True
        status = await self.check_run(self.config(), CleanupFailureGuard)
        self.assertEqual(status["runs"][0]["stop_reason"], "redirect_guard_failure")

    async def test_unattended_preflight_fails_before_intake_or_run(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp)/"config.toml"
            config.write_text('wait_for_sources=true\n')
            with patch("study.cli.doctor",return_value={"ready":False}), patch("study.unattended.ingest_batches") as intake:
                with self.assertRaises(RuntimeError):
                    await run(Path(temp)/"data",config,"absent.csv")
                intake.assert_not_called()
                self.assertFalse((Path(temp)/"data/study.sqlite").exists())
