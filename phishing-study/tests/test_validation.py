"""Validation must reject missing browser evidence and incorrect saved fixture artifacts."""
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch
from study.cli import doctor
from study.config import Config
from study.selftest import EXPECTED_PATHS, validate_artifacts
from study.urls import digest, safe_url

spec = importlib.util.spec_from_file_location("study_test_verifier", Path(__file__).resolve().parents[1] / "scripts" / "verify.py")
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


def browser_suite(skip=None, fail=None):
    def method(index):
        def check(self):
            self.assertEqual(os.environ.get("STUDY_REQUIRE_BROWSER"), "1")
            if index == skip:
                self.skipTest("synthetic unavailable browser")
            if index == fail:
                self.fail("synthetic browser regression")
        return check
    case = type("BrowserEvidence", (unittest.TestCase,), {f"test_{index}": method(index) for index in range(7)})
    case.__module__ = "test_browser"
    return unittest.defaultTestLoader.loadTestsFromTestCase(case)


class VerificationTests(unittest.TestCase):
    def test_strict_report_requires_browser_tests_to_exist(self):
        suite = unittest.TestSuite([unittest.FunctionTestCase(lambda: None)])
        with tempfile.TemporaryDirectory() as temp:
            report = verify.run(temp, True, suite)
        self.assertFalse(report["successful"])
        self.assertFalse(report["browser_verified"])
        self.assertEqual(report["browser_tests"]["discovered"], 0)

    def test_strict_report_rejects_browser_skip(self):
        with tempfile.TemporaryDirectory() as temp:
            report = verify.run(temp, True, browser_suite(skip=3))
        self.assertFalse(report["successful"])
        self.assertFalse(report["browser_verified"])
        self.assertEqual(report["browser_tests"]["skipped"], 1)

    def test_strict_report_rejects_browser_failure_without_skips(self):
        with tempfile.TemporaryDirectory() as temp:
            report = verify.run(temp, True, browser_suite(fail=3))
        self.assertFalse(report["successful"])
        self.assertFalse(report["browser_verified"])
        self.assertEqual(report["browser_tests"]["skipped"], 0)
        self.assertEqual(report["browser_tests"]["failures"], 1)

    def test_passing_report_is_saved_and_environment_restored(self):
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"STUDY_REQUIRE_BROWSER": "prior-value"}):
            report = verify.run(Path(temp) / "reports", True, browser_suite())
            saved = json.loads((Path(temp) / "reports" / "test-report.json").read_text())
            self.assertEqual(os.environ["STUDY_REQUIRE_BROWSER"], "prior-value")
        self.assertEqual(saved, report)
        self.assertTrue(report["browser_verified"])
        self.assertTrue(report["successful"])
        self.assertEqual(report["browser_tests"]["executed"], 7)

    def test_incomplete_execution_does_not_verify_discovered_suite(self):
        suite = browser_suite()
        discovered = list(verify.test_ids(suite))
        result = verify.RecordingResult(io.StringIO(), True, 0)
        result.executed_test_ids = discovered[:6]
        result.testsRun = 6
        report = verify.build_report(result, discovered, 0, True)
        self.assertFalse(report["browser_verified"])
        self.assertEqual(report["browser_tests"]["missing"], discovered[6:])

    def test_default_mode_preserves_success_with_skips_and_marks_browser_unverified(self):
        @unittest.skip("synthetic unavailable browser")
        def check(self):
            pass
        case = type("SkippedBrowser", (unittest.TestCase,), {"test_check": check})
        case.__module__ = "test_browser"
        with tempfile.TemporaryDirectory() as temp:
            report = verify.run(temp, suite=unittest.defaultTestLoader.loadTestsFromTestCase(case))
        self.assertTrue(report["successful"])
        self.assertFalse(report["browser_verified"])


def write_artifact(directory, name, record, events):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{name}.json").write_text(json.dumps(record), encoding="utf-8")
    with gzip.open(directory / f"{name}.events.jsonl.gz", "wt", encoding="utf-8") as stream:
        for event in events:
            stream.write(json.dumps(event) + "\n")


def fixture_artifacts(root):
    exported = []
    for index, path in enumerate(EXPECTED_PATHS):
        captured = index < 3
        outcome = "captured" if captured else path[1:]
        record = {"input": safe_url("http://127.0.0.1:8000" + path), "outcome": outcome, "profile": "fixture",
                  "groups": {"http": {"security_header_count": 0 if path == "/phishing/login" else 2},
                             "dom": {"form_count": 1, "password_input_count": 1},
                             "javascript": {"external_script_count": 1},
                             "interaction": {"measured": True, "policy": "owned_fixture_submit", "new_request_count": 1},
                             "redirects": {"http_redirect_count": 2, "main_document_count": 3,
                                           "chain": [{"status": status} for status in (302, 301, 200)]}}}
        events = [{"kind": "request", "resource_type": resource, "method": method,
                   "url": safe_url("http://127.0.0.1:8000" + target)}
                  for resource, method, target in (("script", "GET", "/script.js"), ("fetch", "GET", "/api/status"), ("fetch", "POST", "/submit"))]
        write_artifact(root / "dataset" / "observations", str(index), record, events)
        exported.append({"profile": "fixture", "capture_eligible": captured, "research_eligible": False})
    first = {"input": safe_url("http://127.0.0.1:8000/legitimate/login"), "outcome": "captured",
             "groups": {"interaction": {"storage_key_count_delta": 1}}}
    second = {"input": safe_url("http://127.0.0.1:8000/clean"), "outcome": "captured",
              "groups": {"dom": {"storage_key_count": 0}, "interaction": {"missing_reason": "passive_policy_no_actions"}}}
    write_artifact(root / "storage-probe" / "observations", "first", first, [])
    write_artifact(root / "storage-probe" / "observations", "second", second, [])
    return {"rows": 6, "capture_eligible": 3, "research_eligible": 0}, exported


class FixtureAcceptanceTests(unittest.TestCase):
    def check_artifacts(self, change=None):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest, exported = fixture_artifacts(root)
            if change:
                change(root, manifest, exported)
            return validate_artifacts(root, manifest, exported, "insufficient_reviewed_live_data")

    def test_complete_saved_fixture_evidence_passes(self):
        report = self.check_artifacts()
        self.assertEqual(report["status"], "passed")
        self.assertTrue(all(report["checks"].values()))

    def test_manifest_does_not_hide_missing_export_rows(self):
        report = self.check_artifacts(lambda root, manifest, rows: rows.pop())
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["checks"]["six_exported_rows"])

    def test_missing_redirect_hop_fails_saved_evidence(self):
        def change(root, *_):
            path = root / "dataset" / "observations" / "2.json"
            record = json.loads(path.read_text())
            record["groups"]["redirects"]["chain"].pop(0)
            path.write_text(json.dumps(record))
        report = self.check_artifacts(change)
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["checks"]["two_redirect_hops"])

    def test_secret_in_saved_event_fails_without_echoing_value(self):
        def change(root, *_):
            with gzip.open(root / "dataset" / "observations" / "0.events.jsonl.gz", "at", encoding="utf-8") as stream:
                stream.write(json.dumps({"kind": "response", "secret": "SECRET-COOKIE"}) + "\n")
        report = self.check_artifacts(change)
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["checks"]["saved_artifacts_redacted"])
        self.assertNotIn("SECRET-COOKIE", json.dumps(report))

    def test_storage_carried_to_next_visit_fails(self):
        def change(root, *_):
            path = root / "storage-probe" / "observations" / "second.json"
            record = json.loads(path.read_text())
            record["groups"]["dom"]["storage_key_count"] = 1
            path.write_text(json.dumps(record))
        report = self.check_artifacts(change)
        self.assertFalse(report["checks"]["fresh_storage_on_next_visit"])
        self.assertEqual(report["status"], "failed")

    def test_post_during_passive_visit_fails(self):
        def change(root, *_):
            with gzip.open(root / "storage-probe" / "observations" / "second.events.jsonl.gz", "at", encoding="utf-8") as stream:
                stream.write(json.dumps({"kind": "request", "method": "POST"}) + "\n")
        report = self.check_artifacts(change)
        self.assertFalse(report["checks"]["passive_visit_has_no_post"])
        self.assertEqual(report["status"], "failed")


class DoctorSmokeTests(unittest.TestCase):
    def smoke(self, guard_error=None, cleanup_failure=False):
        browser = SimpleNamespace(version="fixture-browser", close=AsyncMock())
        chromium = SimpleNamespace(executable_path="fixture-browser", launch=AsyncMock(return_value=browser))
        playwright = SimpleNamespace(chromium=chromium)
        # Special methods are looked up on the type, so supply a small context class.
        class Manager:
            async def __aenter__(self):
                return playwright
            async def __aexit__(self, *_):
                return False
        def run_immediate_mocks(coroutine):
            # All awaited dependencies are immediate mocks; do not create an OS event loop.
            try:
                coroutine.send(None)
            except StopIteration as complete:
                return complete.value
            finally:
                coroutine.close()
            raise AssertionError("mock smoke unexpectedly required scheduled I/O")
        module = ModuleType("playwright.async_api")
        module.async_playwright = Manager
        guard = SimpleNamespace(close=AsyncMock(), failed=False)
        if cleanup_failure:
            def mark_cleanup_failure():
                guard.failed = True
            guard.close.side_effect = mark_cleanup_failure
        guard_type = SimpleNamespace(start=AsyncMock(return_value=guard, side_effect=guard_error))
        guard_module = ModuleType("study.redirects")
        guard_module.RedirectGuard = guard_type
        config = Config(profile="fixture", fixture_origins=["http://127.0.0.1:8000"], proxy_required=True, route_id="approved")
        environment = {"STUDY_PROXY_SERVER": "http://approved.example:8080", "STUDY_PROXY_PASSWORD": "PRIVATE-PROXY-PASSWORD"}
        with patch.dict(os.environ, environment), patch("study.cli.importlib.util.find_spec", return_value=object()), \
                patch("study.policy.check_live_environment"), patch("study.cli.os.geteuid", return_value=1000, create=True), \
                patch("study.cli.Path.exists", return_value=True), \
                patch("study.cli.asyncio.run", side_effect=run_immediate_mocks), \
                patch.dict(sys.modules, {"playwright": ModuleType("playwright"), "playwright.async_api": module, "study.redirects": guard_module}):
            report = doctor(config, True)
        return report, browser, chromium, guard, guard_type

    def test_smoke_uses_proxy_and_checks_redirect_guard(self):
        report, browser, chromium, guard, guard_type = self.smoke()
        self.assertTrue(report["ready"])
        self.assertEqual(chromium.launch.await_args.kwargs["proxy"], {"server": "http://approved.example:8080", "password": "PRIVATE-PROXY-PASSWORD"})
        guard_type.start.assert_awaited_once_with(browser)
        guard.close.assert_awaited_once()
        browser.close.assert_awaited_once()
        self.assertNotIn("PRIVATE-PROXY-PASSWORD", json.dumps(report))

    def test_guard_failure_fails_smoke_and_closes_browser(self):
        report, browser, _, _, _ = self.smoke(RuntimeError("SECRET-DRIVER-DIAGNOSTIC"))
        self.assertFalse(report["ready"])
        self.assertEqual(report["checks"]["chromium"]["error_type"], "RuntimeError")
        browser.close.assert_awaited_once()
        self.assertNotIn("SECRET-DRIVER-DIAGNOSTIC", json.dumps(report))

    def test_guard_cleanup_failure_does_not_report_ready(self):
        report, browser, _, guard, _ = self.smoke(cleanup_failure=True)
        self.assertFalse(report["ready"])
        guard.close.assert_awaited_once()
        browser.close.assert_awaited_once()
