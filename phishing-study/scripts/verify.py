"""Run the suite and save an auditable report, optionally requiring real Chromium."""
import argparse
from datetime import datetime, timezone
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
MIN_BROWSER_TESTS = 7


class RecordingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed_test_ids = []
        self.successful_test_ids = []

    def startTest(self, test):
        self.executed_test_ids.append(test.id())
        super().startTest(test)

    def addSuccess(self, test):
        self.successful_test_ids.append(test.id())
        super().addSuccess(test)


def test_ids(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from test_ids(test)
        else:
            yield test.id()


def is_browser_test(identifier):
    return "test_browser" in identifier.split(".")


def build_report(result, discovered_ids, elapsed, require_browser=False):
    discovered = {identifier for identifier in discovered_ids if is_browser_test(identifier)}
    executed = {identifier for identifier in result.executed_test_ids if is_browser_test(identifier)}
    passed = {identifier for identifier in result.successful_test_ids if is_browser_test(identifier)}
    browser_skips = sum(is_browser_test(test.id()) for test, _ in result.skipped)
    browser_failures = sum(is_browser_test(test.id()) for test, _ in result.failures)
    browser_errors = sum(is_browser_test(test.id()) for test, _ in result.errors)
    browser_expected_failures = sum(is_browser_test(test.id()) for test, _ in result.expectedFailures)
    browser_unexpected_successes = sum(is_browser_test(test.id()) for test in result.unexpectedSuccesses)
    browser_verified = (len(discovered) >= MIN_BROWSER_TESTS and discovered == executed == passed
                        and not (browser_skips or browser_failures or browser_errors
                                 or browser_expected_failures or browser_unexpected_successes))
    versions = {}
    for package in ("playwright", "tldextract", "dnspython", "pyarrow", "pandas", "scipy", "scikit-learn"):
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = None
    successful = result.wasSuccessful() and (not require_browser or browser_verified)
    return {"generated_at": datetime.now(timezone.utc).isoformat(), "python": platform.python_version(),
            "versions": versions, "tests_run": result.testsRun,
            "passed": len(result.successful_test_ids),
            "skipped": [{"test": str(test), "reason": reason} for test, reason in result.skipped],
            "failures": len(result.failures), "errors": len(result.errors),
            "expected_failures": len(result.expectedFailures), "unexpected_successes": len(result.unexpectedSuccesses),
            "successful": successful, "browser_required": require_browser, "browser_verified": browser_verified,
            "browser_tests": {"discovered": len(discovered), "executed": len(executed), "passed": len(passed),
                              "skipped": browser_skips, "failures": browser_failures, "errors": browser_errors,
                              "missing": sorted(discovered - executed)},
            "elapsed_seconds": round(elapsed, 3)}


def run(destination, require_browser=False, suite=None):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    previous = os.environ.get("STUDY_REQUIRE_BROWSER")
    try:
        if require_browser:
            os.environ["STUDY_REQUIRE_BROWSER"] = "1"
        if suite is None:
            suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
        discovered_ids = list(test_ids(suite))
        with (destination / "tests.txt").open("w", encoding="utf-8") as log:
            result = unittest.TextTestRunner(stream=log, verbosity=2, resultclass=RecordingResult).run(suite)
    finally:
        if require_browser:
            if previous is None:
                os.environ.pop("STUDY_REQUIRE_BROWSER", None)
            else:
                os.environ["STUDY_REQUIRE_BROWSER"] = previous
    report = build_report(result, discovered_ids, time.monotonic() - started, require_browser)
    if require_browser and not report["browser_verified"]:
        report["browser_requirement_failure"] = "At least seven real Chromium tests must all execute successfully without skips."
    (destination / "test-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-browser", action="store_true", help="fail unless all Chromium checks run and pass")
    parser.add_argument("--output", type=Path, default=ROOT / "validation", help="report directory (default: validation)")
    args = parser.parse_args(argv)
    report = run(args.output, args.require_browser)
    print(json.dumps(report, indent=2))
    return 0 if report["successful"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
