"""Bounded browser lifecycle for owned-control verification previews.

No process is killed here. The dedicated service controller owns that decision.
This module does not grant research eligibility or change deployment gates.
Identity evidence excludes raw command lines. Timed-out operations remain failed
even if a later driver shutdown manages to release their resources.
"""
import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time


DEFAULT_TIMEOUTS = {"context_close": 12, "owner_unregister": 15,
                    "guard_close": 20, "browser_close": 12, "driver_stop": 5,
                    "identity_capture": 5, "identity_detach": 5,
                    "process_exit": 2, "driver_start": 30, "browser_launch": 30}


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def guard_state(guard):
    return {"closed": guard._closed, "failed": guard.failed,
            "failure_reason": guard.failure_reason,
            **{name: len(getattr(guard, "_" + name)) for name in
               ("owners", "contexts", "frames", "tasks", "pending", "task_owners")}}


def read_process_identity(pid, proc_root="/proc"):
    """Read a stable owned identity. Never read or persist cmdline."""
    if type(pid) is not int or pid <= 0:
        raise ValueError("invalid_pid")
    proc = Path(proc_root) / str(pid)
    started = (proc / "stat").read_text().rsplit(")", 1)[1].split()[19]
    status = dict(line.split(":", 1) for line in (proc / "status").read_text().splitlines() if ":" in line)
    uids = [int(value) for value in status["Uid"].split()]
    if len(uids) != 4 or len(set(uids)) != 1:
        raise ValueError("ambiguous_uid")
    result = {"pid": pid, "start_time": started, "uid": uids[0],
              "executable": str((proc / "exe").resolve(strict=True)),
              "netns": os.readlink(proc / "ns/net"),
              "cgroup": (proc / "cgroup").read_text().splitlines()}
    if (proc / "stat").read_text().rsplit(")", 1)[1].split()[19] != started:
        raise ValueError("process_changed_during_inspection")
    return result


def process_identity_state(identity, proc_root="/proc"):
    """PID reuse proves the original exited; it never authorizes a signal."""
    required = {"pid", "start_time", "uid", "executable", "netns", "cgroup"}
    if not isinstance(identity, dict) or not required.issubset(identity):
        return {"gone": False, "reason": "captured_identity_missing"}
    try:
        current = read_process_identity(identity["pid"], proc_root)
    except FileNotFoundError:
        # An absent exe symlink can mean a zombie. Check stat existence too.
        if not (Path(proc_root) / str(identity["pid"]) / "stat").exists():
            return {"gone": True, "reason": "captured_process_absent"}
        return {"gone": False, "reason": "process_still_present_or_uninspectable"}
    except (OSError, ValueError, KeyError, IndexError):
        return {"gone": False, "reason": "process_identity_unavailable"}
    if current["start_time"] != identity["start_time"]:
        return {"gone": True, "reason": "pid_reused_original_process_exited"}
    same = all(current[name] == identity[name] for name in required)
    return {"gone": False, "reason": "captured_process_still_alive" if same
            else "same_start_time_identity_changed_not_exit_proof"}


def _consume(task):
    try:
        task.exception()
    except BaseException:
        pass


class Lifecycle:
    """Set resource attributes immediately after creation, then cleanup once.

    `await capture_browser_identity()` runs immediately after assigning browser.
    `await cleanup()` shields one cleanup task from caller cancellation. A caller
    cancellation is re-raised only after that bounded cleanup finishes.
    """
    def __init__(self, report, *, stage_timeouts=None, proc_root="/proc", event_path=None):
        self.report = report
        self.timeouts = {**DEFAULT_TIMEOUTS, **(stage_timeouts or {})}
        self.proc_root = proc_root
        self.event_path = Path(event_path) if event_path is not None else None
        self.driver = self.browser = self.guard = self.context = self.owner = None
        self.identity = None
        self._cleanup_task = None
        self._abandoned = []
        self.cancelled = False
        self.report.setdefault("checks", {})
        self.report.setdefault("events", [])
        self.record = self.report.setdefault("lifecycle", {
            "schema_version": 1, "stages": [], "abandoned_stages": [],
            "captured_browser_identity": None, "cancelled": False})

    def _check(self, name, ok, **details):
        self.report["checks"][name] = {"ok": bool(ok), **details}

    def _event(self, kind, **details):
        item = {"at": timestamp(), "monotonic": time.monotonic(), "kind": kind, **details}
        self.report["events"].append(item)
        if self.event_path is not None:
            try:
                with self.event_path.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(item, sort_keys=True) + "\n")
                    stream.flush()
                    # A synchronous fsync here blocks every asyncio timeout,
                    # including the very browser deadline being measured. The
                    # controller freezes/hashes these flushed diagnostic logs
                    # after process exit. DNS query durability is separately
                    # enforced by the dedicated logging resolver.
            except OSError as exc:
                self._check("lifecycle_event_log_written", False, error_type=type(exc).__name__)

    async def stage(self, name, operation):
        """Use wait(), not wait_for(): cancellation resistance cannot extend a deadline."""
        start = time.monotonic()
        entry = {"name": name, "started_at": timestamp(), "started_monotonic": start,
                 "deadline_seconds": self.timeouts[name], "ok": False}
        self.record["stages"].append(entry)
        self._event("lifecycle_stage_started", stage=name)
        task = None
        try:
            task = asyncio.create_task(operation())
            done, _ = await asyncio.wait({task}, timeout=self.timeouts[name])
            if task not in done:
                entry["error_type"] = "DeadlineExceeded"
                self.record["abandoned_stages"].append(name)
                self._abandoned.append(task)
                task.cancel()
                task.add_done_callback(_consume)
                return False, None
            value = task.result()
            entry["ok"] = True
            return True, value
        except asyncio.CancelledError:
            entry["error_type"] = "CancelledError"
            self.cancelled = True
            self.record["cancelled"] = True
            self._check("lifecycle_not_cancelled", False)
            if task is not None and not task.done():
                task.cancel()
                task.add_done_callback(_consume)
                self._abandoned.append(task)
            raise
        except Exception as exc:
            entry["error_type"] = type(exc).__name__
            return False, None
        finally:
            entry["finished_at"] = timestamp()
            entry["finished_monotonic"] = time.monotonic()
            entry["duration_seconds"] = round(entry["finished_monotonic"] - start, 6)
            self._event("lifecycle_stage_finished", stage=name, ok=entry["ok"],
                        duration_seconds=entry["duration_seconds"],
                        error_type=entry.get("error_type"))

    async def capture_browser_identity(self, browser=None):
        if browser is not None:
            self.browser = browser
        session = None

        async def capture():
            nonlocal session
            session = await self.browser.new_browser_cdp_session()
            processes = (await session.send("SystemInfo.getProcessInfo"))["processInfo"]
            pids = [item["id"] for item in processes if item["type"] == "browser"]
            if len(pids) != 1:
                raise ValueError("browser_pid_ambiguous")
            identity = read_process_identity(pids[0], self.proc_root)
            if identity["uid"] != os.geteuid() or identity["uid"] == 0:
                raise ValueError("browser_not_owned_non_root")
            return identity

        ok, value = await self.stage("identity_capture", capture)
        if ok:
            self.identity = value
            self.record["captured_browser_identity"] = value
            self._event("captured_browser_identity", identity=value)
        self._check("owned_browser_identity_captured", ok)
        if session is not None:
            detached, _ = await self.stage("identity_detach", session.detach)
            self._check("identity_session_detached", detached)
        return {"ok": ok, **(value or {})}

    async def _cleanup(self):
        context_closed = self.context is None
        if self.context is not None:
            context_closed, _ = await self.stage("context_close", self.context.close)
        self._check("context_closed", context_closed, created=self.context is not None)
        browser_closed_first = False
        if self.guard is not None:
            if self.owner is not None and context_closed:
                unregistered, _ = await self.stage("owner_unregister", lambda: self.guard.unregister(self.owner))
                self._check("owner_unregistered_after_context", unregistered)
            elif self.owner is not None:
                self._check("owner_unregistered_after_context", False,
                            reason="context_close_failed_owner_retained_until_guard_close")
            # Keep Fetch installed through the actual browser exit. This avoids
            # a live Fetch.disable stall without relaxing any redirect policy.
            finalizer = getattr(self.guard, 'close_after_browser', None)
            modern = callable(finalizer) and callable(getattr(self.guard, 'prepare_browser_shutdown', None))
            if modern and self.browser is not None:
                self.guard.prepare_browser_shutdown()
                closed, _ = await self.stage('browser_close', self.browser.close)
                browser_closed_first = True
                disconnected = closed and not self.browser.is_connected()
                self._check('browser_closed', disconnected)
                if disconnected:
                    closed, _ = await self.stage('guard_close', finalizer)
                else:
                    closed = False  # Retain interception until service cleanup.
            else:
                closed, _ = await self.stage("guard_close", self.guard.close)
            state = guard_state(self.guard)
            self.report["guard_after_close"] = state
            clean = closed and state["closed"] and not state["failed"] and all(
                state[key] == 0 for key in ("owners", "contexts", "frames", "tasks", "pending", "task_owners"))
            self._check("guard_cleanly_closed", clean)
        if self.browser is not None and not browser_closed_first:
            closed, _ = await self.stage("browser_close", self.browser.close)
            self._check("browser_closed", closed and not self.browser.is_connected())
        if self.driver is not None:
            stopped, _ = await self.stage("driver_stop", self.driver.stop)
            self._check("driver_stopped", stopped)
        if self.browser is not None:
            state = process_identity_state(self.identity, self.proc_root)
            deadline = time.monotonic() + self.timeouts["process_exit"]
            while not state["gone"] and time.monotonic() < deadline:
                await asyncio.sleep(min(0.05, max(0, deadline - time.monotonic())))
                state = process_identity_state(self.identity, self.proc_root)
            self.record["owned_browser_process_after_cleanup"] = state
            self._check("owned_browser_process_gone", state["gone"], reason=state["reason"])
        self.record["pending_abandoned_stage_count"] = sum(not task.done() for task in self._abandoned)
        self._check("no_abandoned_cleanup_stage", not self.record["abandoned_stages"])
        self.record["cancelled"] = self.cancelled
        self._check("lifecycle_not_cancelled", not self.cancelled)

    async def cleanup(self):
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._cleanup())
        cancelled = False
        while True:
            try:
                await asyncio.shield(self._cleanup_task)
                break
            except asyncio.CancelledError:
                if self._cleanup_task.cancelled():
                    self._check("lifecycle_cleanup_completed", False, error_type="CancelledError")
                    raise
                cancelled = self.cancelled = True
                self.record["cancelled"] = True
                self._check("lifecycle_not_cancelled", False)
                self._event("lifecycle_caller_cancelled")
        self._check("lifecycle_cleanup_completed", True)
        if cancelled:
            raise asyncio.CancelledError


def run_bounded(coroutine, *, timeout, report, cleanup_seconds=75):
    """Bound the worker even when a library task resists cancellation.

    asyncio.run() waits indefinitely for resistant tasks on exit. This runner
    instead leaves those resources to the dedicated systemd service controller.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def supervise():
        task = asyncio.create_task(coroutine)
        done, _ = await asyncio.wait({task}, timeout=timeout)
        if task not in done:
            report.setdefault("checks", {})["worker_deadline"] = {"ok": False}
            task.cancel()
            done, _ = await asyncio.wait({task}, timeout=cleanup_seconds)
            if task not in done:
                raise TimeoutError("worker_cleanup_deadline")
        return task.result()

    try:
        return loop.run_until_complete(supervise())
    finally:
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(asyncio.wait(pending, timeout=0.1))
        remaining = [task for task in pending if not task.done()]
        report.setdefault("lifecycle", {})["pending_tasks_at_loop_close"] = len(remaining)
        if remaining:
            report.setdefault("checks", {})["event_loop_quiescent"] = {"ok": False}
        loop.close()
        asyncio.set_event_loop(None)
