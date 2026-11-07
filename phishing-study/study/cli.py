import argparse
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import sys
from .config import load
from .queue import Queue


def doctor(config, smoke=False):
    from .policy import check_live_environment
    report = {"profile": config.profile, "config_hash": config.fingerprint, "checks": {}, "ready": True}
    for package in ("playwright", "tldextract", "dns", "pyarrow"):
        available = importlib.util.find_spec(package) is not None
        report["checks"][package] = {"ok": available}
        report["ready"] &= available
    try:
        check_live_environment(config)
        report["checks"]["deployment"] = {"ok": True, "non_root": os.geteuid()!=0, "network_isolation_verified": config.network_isolation_verified}
    except (RuntimeError, ValueError) as exc:
        report["checks"]["deployment"] = {"ok": False, "reason": str(exc), "non_root": os.geteuid()!=0, "network_isolation_verified": config.network_isolation_verified}
        report["ready"] = False
    if report["checks"]["playwright"]["ok"]:
        async def browser_check():
            from playwright.async_api import async_playwright
            async with async_playwright() as p:
                executable = Path(p.chromium.executable_path)
                result = {"ok": executable.exists(), "version": None}
                if smoke and result["ok"]:
                    b = await p.chromium.launch(headless=True, chromium_sandbox=config.profile == "live", proxy=config.proxy())
                    guard = None
                    try:
                        from .redirects import RedirectGuard
                        guard = await RedirectGuard.start(b)
                        result["version"] = b.version
                        result["redirect_guard"] = {"ok": True}
                    finally:
                        if guard is not None and callable(getattr(guard, 'close_after_browser', None)):
                            from .redirects import shutdown_browser
                            await shutdown_browser(b, guard)
                        else:
                            # Retain compatibility with older immediate adapters.
                            try:
                                if guard is not None:
                                    await guard.close()
                            finally:
                                await b.close()
                    if guard.failed:
                        raise RuntimeError("redirect_guard_unavailable")
                return result
        try:
            result = asyncio.run(browser_check())
        except Exception as exc:
            result = {"ok": False, "error_type": type(exc).__name__, "reason": "browser driver, Chromium, or redirect guard unavailable"}
        report["checks"]["chromium"] = result
        report["ready"] &= result["ok"]
    return report


def parser():
    p = argparse.ArgumentParser(description="Application-layer phishing research pipeline")
    p.add_argument("--data", default="data", help="restricted local dataset directory")
    p.add_argument("--config", help="versioned TOML configuration")
    sub = p.add_subparsers(dest="command", required=True)
    d = sub.add_parser("doctor")
    d.add_argument("--smoke", action="store_true")
    d.add_argument("--output")
    sub.add_parser("init")
    i = sub.add_parser("ingest")
    i.add_argument("source", choices=["csv", "phishtank", "openphish", "tranco"])
    i.add_argument("--file")
    i.add_argument("--limit", type=int)
    sub.add_parser("status")
    sub.add_parser("collect")
    r = sub.add_parser("resume")
    r.add_argument("run_id")
    e = sub.add_parser("export")
    e.add_argument("--output", default="data/export")
    e.add_argument("--format", choices=["parquet", "csv"], default="parquet")
    for name in ("analyze", "train"):
        a = sub.add_parser(name)
        a.add_argument("file")
        a.add_argument("--output", default="data/report")
    review = sub.add_parser("review")
    review.add_argument("candidate_id")
    review.add_argument("disposition", choices=["active", "challenge", "takedown", "parked", "unknown"])
    review.add_argument("--split-group")
    fixture = sub.add_parser("fixtures")
    fixture.add_argument("--output", default="data/fixture-inputs")
    demo = sub.add_parser("selftest")
    demo.add_argument("--output", default="data/selftest")
    return p


def main(argv=None):
    os.umask(0o077)
    args = parser().parse_args(argv)
    try:
        config = load(args.config)
        if args.command == "doctor":
            report = doctor(config, args.smoke)
            if args.output:
                Path(args.output).parent.mkdir(parents=True, exist_ok=True)
                Path(args.output).write_text(json.dumps(report, indent=2))
            print(json.dumps(report, indent=2))
            return 0 if report["ready"] else 2
        if args.command == "fixtures":
            from .fixtures import FixtureServer
            with FixtureServer() as fixture:
                print(json.dumps(fixture.write_inputs(args.output)), flush=True)
                try:
                    import threading
                    threading.Event().wait()
                except KeyboardInterrupt:
                    pass
            return 0
        if args.command == "selftest":
            from .selftest import run
            report = run(args.output)
            print(json.dumps(report, indent=2))
            return 0 if report["status"] == "passed" else 2
        queue = Queue(args.data)
        if args.command == "init":
            result = {"status": "initialized"}
        elif args.command == "status":
            result = queue.status()
        elif args.command == "ingest":
            from .sources import records
            if args.source == "csv" and not args.file:
                raise ValueError("--file required for CSV")
            if args.limit is not None and args.limit <= 0:
                raise ValueError("--limit must be positive")
            batch, result = [], {"new": 0, "duplicate": 0, "conflict": 0}
            for row in records(args.source, args.file, args.limit):
                batch.append(row)
                if len(batch) == 1000:
                    for k, v in queue.ingest(batch).items():
                        result[k] += v
                    batch = []
            if batch:
                for k, v in queue.ingest(batch).items():
                    result[k] += v
        elif args.command in {"collect", "resume"}:
            from .runner import collect
            result = {"run_id": asyncio.run(collect(queue, config, getattr(args, "run_id", None)))}
        elif args.command == "review":
            queue.review(args.candidate_id, args.disposition, args.split_group)
            result = {"candidate_id": args.candidate_id, "disposition": args.disposition}
        elif args.command == "export":
            from .export import export
            result = export(queue, args.output, args.format)
        elif args.command == "analyze":
            from .analysis import analyze
            result = analyze(args.file, args.output, config.seed)
        elif args.command == "train":
            from .analysis import train
            result = train(args.file, args.output, config.seed)
        print(json.dumps(result, indent=2))
        return 0
    except (KeyboardInterrupt, BrokenPipeError):
        return 130
    except Exception as exc:
        # Feed/browser exceptions can include secret-bearing URLs. Log only type.
        print(json.dumps({"status": "error", "error_type": type(exc).__name__,
                          "reason": "operation failed; check input, configuration, and prerequisites"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
