"""Finite resumable runs; each job owns a separate browser context."""
import asyncio
from datetime import datetime, timezone
import json
import shutil
import signal
import time
from .collector import Collector, save
from .policy import check_live_environment
from .redirects import RedirectGuard, shutdown_browser
from .runtime_lifecycle import browser_session, observe_until_stop, ObservationStopped


async def collect(queue, config, resume=None, health_check=None):
    # One collector supervisor per dataset; feed imports remain independently usable.
    import fcntl
    with (queue.root / "collector.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("another collector is active for this dataset") from None
        try:
            return await _collect(queue, config, resume, health_check)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


async def _collect(queue, config, resume=None, health_check=None):
    check_live_environment(config)
    stop = asyncio.Event()
    reason = "queue_exhausted"
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):
            pass
    # Launch before recording a run, so missing executables do not create fake runs.
    async with browser_session(queue, config) as (browser, lifecycle):
        try:
            redirect_guard = await RedirectGuard.start(browser)
            if lifecycle is not None:
                lifecycle.guard = redirect_guard
        except BaseException:
            if lifecycle is None:
                await browser.close()
            raise
        try:
            rid = queue.start_run(config, resume)
            queue.recover(retries=config.retries)
            with queue.connect() as db:
                run_started = db.execute("SELECT started FROM runs WHERE id=?", (rid,)).fetchone()[0]
            probe = Collector(browser, config, redirect_guard=redirect_guard)
        except BaseException:
            if lifecycle is None:
                await shutdown_browser(browser, redirect_guard)
            raise
        reserved_bytes = 0
        artifact_bytes = sum(f.stat().st_size for f in queue.root.rglob("*") if f.is_file())

        async def watch_run():
            nonlocal reason
            while not stop.is_set():
                if time.time() - run_started >= config.max_hours * 3600:
                    reason = "time_budget"
                    stop.set()
                    return
                if health_check is not None:
                    try:
                        healthy = await health_check()
                    except Exception:
                        healthy = False
                    if not healthy:
                        reason = "service_health_failure"
                        stop.set()
                        return
                try:
                    await asyncio.wait_for(stop.wait(), timeout=1)
                except asyncio.TimeoutError:
                    pass

        async def worker():
            nonlocal reason, artifact_bytes, reserved_bytes
            while not stop.is_set():
                if redirect_guard.failed:
                    reason = "redirect_guard_failure"
                    stop.set()
                    break
                if time.time() - run_started >= config.max_hours * 3600:
                    reason = "time_budget"
                    stop.set()
                    break
                if shutil.disk_usage(queue.root).free < config.min_free_disk_bytes:
                    reason = "free_disk_floor"
                    stop.set()
                    break
                # Reserve a conservative metadata allowance per active job.
                allowance = config.max_requests * 4096 + 1_000_000
                if artifact_bytes + reserved_bytes + allowance > config.max_artifact_bytes:
                    reason = "artifact_budget"
                    stop.set()
                    break
                item = queue.claim(rid, config)
                if item is None:
                    with queue.connect() as db:
                        attempts = db.execute("SELECT attempts FROM runs WHERE id=?", (rid,)).fetchone()[0]
                        active = db.execute("SELECT COUNT(*) FROM candidates WHERE state='running'").fetchone()[0]
                        pending = db.execute("SELECT COUNT(*) FROM candidates WHERE state='pending' AND attempts<=?", (config.retries,)).fetchone()[0]
                        capped = all(db.execute("SELECT COUNT(*) FROM candidates WHERE label=? AND eligible=1 AND state='done'", (label,)).fetchone()[0] >= config.usable_per_class for label in ("legitimate", "phishing"))
                    if attempts >= config.max_attempts:
                        reason = "attempt_budget"
                        stop.set()
                        break
                    if capped:
                        reason = "class_caps"
                        stop.set()
                        break
                    if not active and not pending and not config.wait_for_sources:
                        break
                    # A class may be capped while the other has no candidates.
                    with queue.connect() as db:
                        available_labels = [r[0] for r in db.execute("SELECT DISTINCT label FROM candidates WHERE state='pending' AND attempts<=?", (config.retries,))]
                        all_pending_capped = available_labels and all(db.execute("SELECT COUNT(*) FROM candidates WHERE label=? AND eligible=1 AND state='done'", (label,)).fetchone()[0] >= config.usable_per_class for label in available_labels)
                    if not active and all_pending_capped:
                        reason = "available_class_caps"
                        break
                    try:
                        await asyncio.wait_for(stop.wait(), timeout=1)
                    except asyncio.TimeoutError:
                        pass
                    queue.recover(retries=config.retries)
                    continue
                reserved_bytes += allowance
                async def keep_lease():
                    while True:
                        await asyncio.sleep(min(30, config.lease_seconds / 3))
                        if not queue.heartbeat(item, config.lease_seconds):
                            return
                heartbeat = asyncio.create_task(keep_lease())
                try:
                    # Outer guard includes metadata, event teardown, and context setup.
                    record, events = await observe_until_stop(probe.observe(item), stop,
                                                               timeout=config.attempt_seconds + 15)
                    artifact = save(queue.root, record, events)
                    artifact_bytes += (queue.root / artifact).stat().st_size + (queue.root / artifact).with_suffix(".events.jsonl.gz").stat().st_size
                    queue.finish(item, record["outcome"], record["eligible"], artifact, config, record["transient"], record["retry_after"])
                    print(json.dumps({"run_id": rid, "candidate_id": item["id"], "attempt": item["attempt_number"],
                                      "outcome": record["outcome"], "capture_eligible": record["eligible"]}), flush=True)
                except asyncio.CancelledError:
                    raise
                except ObservationStopped:
                    queue.finish(item, "interrupted", False, None, config, transient=False)
                except Exception as exc:
                    # Do not print exception messages, which may expose URLs or proxy credentials.
                    outcome = "policy_blocked" if redirect_guard.failed else "worker_error"
                    if isinstance(exc, TimeoutError) and str(exc) == "observation_cleanup_deadline":
                        redirect_guard.failed = True
                        reason = "observation_cleanup_failure"
                        stop.set()
                        outcome = "policy_blocked"
                    queue.finish(item, outcome, False, None, config, transient=not redirect_guard.failed)
                    print(json.dumps({"run_id": rid, "candidate_id": item["id"], "outcome": outcome, "error_type": type(exc).__name__}), flush=True)
                finally:
                    heartbeat.cancel()
                    await asyncio.gather(heartbeat, return_exceptions=True)
                    reserved_bytes -= allowance
                checkpoint(queue, rid)

        completed = False
        watcher = asyncio.create_task(watch_run())
        try:
            await asyncio.gather(*(worker() for _ in range(config.workers)))
            if stop.is_set() and reason == "queue_exhausted":
                reason = "signal"
            completed = True
        finally:
            watcher.cancel()
            await asyncio.gather(watcher, return_exceptions=True)
            try:
                if lifecycle is None:
                    await shutdown_browser(browser, redirect_guard)
                else:
                    await lifecycle.cleanup()
                    if not all(value['ok'] for value in lifecycle.report['checks'].values()):
                        reason = "browser_lifecycle_failure"
            finally:
                for sig in (signal.SIGINT, signal.SIGTERM):
                    try:
                        loop.remove_signal_handler(sig)
                    except (NotImplementedError, RuntimeError):
                        pass
                if completed:
                    queue.finish_run(rid, "redirect_guard_failure" if redirect_guard.failed else reason)
                checkpoint(queue, rid)
        return rid


def checkpoint(queue, rid):
    status = queue.status()
    status["generated_at"] = datetime.now(timezone.utc).isoformat()
    status["current_run"] = rid
    path = queue.root / "status.json"
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(status, indent=2), encoding="utf-8")
    temp.replace(path)
