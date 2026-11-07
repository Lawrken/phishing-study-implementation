"""Owned-browser fixture workflow with explicit, saved acceptance assertions."""
import asyncio
from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
import gzip
import importlib.metadata
import json
from pathlib import Path
import platform
import time
from .urls import digest

EXPECTED_OUTCOMES = {"captured": 3, "challenge": 1, "takedown": 1, "parked": 1}
EXPECTED_PATHS = ("/legitimate/login", "/phishing/login", "/redirect", "/challenge", "/takedown", "/parked")
SECRET_MARKERS = ("SECRET", "SYNTHETIC-INVALID", "research-invalid@example.invalid")


def _artifacts(directory):
    records, events, text = [], {}, []
    for path in sorted(Path(directory).glob("*.json")):
        raw = path.read_text(encoding="utf-8")
        records.append(json.loads(raw))
        text.append(raw)
        event_path = path.with_suffix(".events.jsonl.gz")
        with gzip.open(event_path, "rt", encoding="utf-8") as stream:
            raw_events = stream.read()
        events[records[-1].get("input", {}).get("path_hash")] = [json.loads(line) for line in raw_events.splitlines()]
        text.append(raw_events)
    return records, events, text


def validate_artifacts(root, manifest, exported_rows, analysis_status):
    """Inspect persisted JSON/events and the actual export, rather than trusting exit codes."""
    root = Path(root)
    records, events, saved_text = _artifacts(root / "dataset" / "observations")
    probes, probe_events, probe_text = _artifacts(root / "storage-probe" / "observations")
    by_path = {row.get("input", {}).get("path_hash"): row for row in records}
    captured = [row for row in records if row.get("outcome") == "captured"]
    redirects = by_path.get(digest("/redirect"), {}).get("groups", {}).get("redirects", {})
    checks = {
        "six_expected_observations": len(records) == 6 and set(by_path) == {digest(path) for path in EXPECTED_PATHS},
        "expected_outcomes": dict(Counter(row.get("outcome") for row in records)) == EXPECTED_OUTCOMES,
        "six_exported_rows": len(exported_rows) == manifest.get("rows") == 6,
        "three_usable_fixture_rows": manifest.get("capture_eligible") == 3
            and sum(bool(row.get("capture_eligible")) for row in exported_rows) == 3,
        "fixture_data_excluded_from_research": manifest.get("research_eligible") == 0
            and all(row.get("profile") == "fixture" and not row.get("research_eligible") for row in exported_rows)
            and analysis_status == "insufficient_reviewed_live_data",
        "two_redirect_hops": redirects.get("http_redirect_count") == 2 and redirects.get("main_document_count") == 3
            and [hop.get("status") for hop in redirects.get("chain", [])] == [302, 301, 200],
        "expected_security_headers": all(by_path.get(digest(path), {}).get("groups", {}).get("http", {}).get("security_header_count") == count
            for path, count in (("/legitimate/login", 2), ("/phishing/login", 0), ("/redirect", 2))),
        "forms_and_password_inputs": len(captured) == 3 and all(
            row.get("groups", {}).get("dom", {}).get("form_count") == 1
            and row.get("groups", {}).get("dom", {}).get("password_input_count") == 1 for row in captured),
        "external_script_and_fetch": len(captured) == 3 and all(
            row.get("groups", {}).get("javascript", {}).get("external_script_count", 0) >= 1
            and any(event.get("kind") == "request" and event.get("resource_type") == "script"
                    and event.get("url", {}).get("path_hash") == digest("/script.js")
                    for event in events.get(row.get("input", {}).get("path_hash"), []))
            and any(event.get("kind") == "request" and event.get("resource_type") == "fetch"
                    and event.get("url", {}).get("path_hash") == digest("/api/status")
                    for event in events.get(row.get("input", {}).get("path_hash"), [])) for row in captured),
        "fixture_only_synthetic_post": len(captured) == 3 and all(
            row.get("profile") == "fixture" and row.get("groups", {}).get("interaction", {}).get("measured")
            and row["groups"]["interaction"].get("policy") == "owned_fixture_submit"
            and row["groups"]["interaction"].get("new_request_count", 0) >= 1
            and any(event.get("kind") == "request" and event.get("method") == "POST"
                    and event.get("url", {}).get("path_hash") == digest("/submit")
                    for event in events.get(row.get("input", {}).get("path_hash"), [])) for row in captured),
    }
    storage = {row.get("input", {}).get("path_hash"): row for row in probes}
    first, second = storage.get(digest("/legitimate/login"), {}), storage.get(digest("/clean"), {})
    checks["fresh_storage_on_next_visit"] = (len(probes) == 2 and first.get("outcome") == second.get("outcome") == "captured"
        and first.get("groups", {}).get("interaction", {}).get("storage_key_count_delta") == 1
        and second.get("groups", {}).get("dom", {}).get("storage_key_count") == 0
        and second.get("groups", {}).get("interaction", {}).get("missing_reason") == "passive_policy_no_actions")
    checks["passive_visit_has_no_post"] = bool(second) and not any(
        event.get("kind") == "request" and event.get("method") == "POST"
        for event in probe_events.get(digest("/clean"), []))
    public_text = "\n".join(saved_text + probe_text + [json.dumps(exported_rows), json.dumps(manifest)])
    checks["saved_artifacts_redacted"] = all(marker not in public_text for marker in SECRET_MARKERS)
    return {"status": "passed" if all(checks.values()) else "failed", "fixture_verified": all(checks.values()),
            "checks": checks, "rows": len(exported_rows), "outcomes": dict(Counter(row.get("outcome") for row in records)),
            "analysis_status": analysis_status}


async def _collect_and_probe(queue, config, fixture_origin, root):
    from playwright.async_api import async_playwright
    from .collector import Collector, save
    from .redirects import RedirectGuard, shutdown_browser
    from .runner import collect
    run_id = await collect(queue, config)
    probe_root = root / "storage-probe"
    probe_root.mkdir(mode=0o700)
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True, chromium_sandbox=False, proxy=config.proxy())
        guard = None
        try:
            guard = await RedirectGuard.start(browser)
            for path, interaction in (("/legitimate/login?token=SECRET-INPUT", "fixture_submit"), ("/clean", "none")):
                url = fixture_origin + path
                item = {"url": url, "id": digest(url), "attempt_id": digest("storage-probe:" + url)}
                record, events = await Collector(browser, replace(config, interaction=interaction), redirect_guard=guard).observe(item)
                save(probe_root, record, events)
        finally:
            await shutdown_browser(browser, guard)
        if guard.failed:
            raise RuntimeError("redirect_guard_unavailable")
    return run_id


def run(destination):
    from .analysis import analyze
    from .cli import doctor
    from .config import load
    from .export import export
    from .fixtures import FixtureServer
    from .queue import Queue
    from .sources import read_csv
    started = time.monotonic()
    chromium_version = None
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=True)
    def finish(report, save=True):
        versions = {"python": platform.python_version(), "chromium": chromium_version}
        for package in ("playwright", "tldextract", "dnspython", "pyarrow", "pandas", "scipy", "scikit-learn"):
            try:
                versions[package] = importlib.metadata.version(package)
            except importlib.metadata.PackageNotFoundError:
                versions[package] = None
        report.update({"generated_at": datetime.now(timezone.utc).isoformat(),
                       "elapsed_seconds": round(time.monotonic() - started, 3),
                       "versions": versions})
        if save:
            (root / "fixture-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report
    if (root / "dataset" / "study.sqlite").exists() or (root / "storage-probe").exists():
        return finish({"status": "blocked", "reason": "Use a fresh selftest output directory; an existing dataset or storage probe was found."}, save=False)
    try:
        with FixtureServer() as fixture:
            inputs = fixture.write_inputs(root / "inputs")
            config = load(inputs["config"])
            ready = doctor(config, True)
            chromium_version = ready.get("checks", {}).get("chromium", {}).get("version")
            (root / "doctor.json").write_text(json.dumps(ready, indent=2), encoding="utf-8")
            if not ready["ready"]:
                report = {"status": "blocked", "reason": "fixture browser preflight failed", "checks": ready}
            else:
                queue = Queue(root / "dataset")
                queue.ingest(read_csv(inputs["candidates"]))
                run_id = asyncio.run(_collect_and_probe(queue, config, fixture.url, root))
                manifest = export(queue, root / "export")
                quality = analyze(root / "export" / "features.parquet", root / "report", config.seed)
                import pyarrow.parquet as pq
                exported_rows = pq.read_table(root / "export" / "features.parquet").to_pylist()
                report = validate_artifacts(root, manifest, exported_rows, quality["status"])
                report.update({"run_id": run_id, "export": manifest})
    except Exception as exc:
        # Exceptions can contain URLs or environment secrets; keep only the category.
        report = {"status": "failed", "error_type": type(exc).__name__, "reason": "fixture validation did not complete"}
    return finish(report)
