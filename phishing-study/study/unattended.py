"""Rolling source intake plus one finite collector run, with persistent feed checkpoints."""
import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
from .config import load
from .queue import Queue
from .sources import records


def ingest_batches(queue, source, file=None, limit=None):
    batch, summary = [], {"new": 0, "duplicate": 0, "conflict": 0}
    for row in records(source, file, limit):
        batch.append(row)
        if len(batch) == 1000:
            for key, value in queue.ingest(batch).items():
                summary[key] += value
            batch = []
    if batch:
        for key, value in queue.ingest(batch).items():
            summary[key] += value
    return summary


async def run(data, config_path, legitimate_csv, sources=("openphish",), limit=10000, resume=None):
    from .cli import doctor
    from .runner import collect
    from .export import export
    from .analysis import analyze
    c = load(config_path)
    if not c.wait_for_sources:
        raise ValueError("unattended config must enable wait_for_sources")
    # doctor is synchronous; run its own event loop in a thread.
    preflight = await asyncio.to_thread(doctor, c, True)
    out = Path(data)
    out.mkdir(parents=True, exist_ok=True)
    (out / "doctor.json").write_text(json.dumps(preflight, indent=2))
    if not preflight["ready"]:
        raise RuntimeError("unattended preflight failed; see doctor.json")
    q = Queue(data)
    ingest_batches(q, "csv", legitimate_csv)
    intervals = {"phishtank": 3600, "openphish": 43200}
    stop = asyncio.Event()
    state_path = q.root / "feed-status.json"
    feed_state = json.loads(state_path.read_text()) if state_path.exists() else {}

    async def ingest_loop():
        while not stop.is_set():
            for source in sources:
                prior = feed_state.get(source, {})
                interval = intervals[source] if prior.get("ok") else 300
                if time.time() - prior.get("checked_epoch", 0) < interval:
                    continue
                entry = {"checked_at": datetime.now(timezone.utc).isoformat(), "checked_epoch": time.time()}
                try:
                    summary = await asyncio.to_thread(ingest_batches, q, source, None, limit)
                    entry.update({"ok": True, "summary": summary})
                except Exception as exc:
                    entry.update({"ok": False, "error_type": type(exc).__name__})
                feed_state[source] = entry
                temp = state_path.with_suffix(".tmp")
                temp.write_text(json.dumps(feed_state, indent=2))
                temp.replace(state_path)
                print(json.dumps({"source": source, **entry}), flush=True)
            try:
                await asyncio.wait_for(stop.wait(), timeout=5)
            except asyncio.TimeoutError:
                pass

    intake = asyncio.create_task(ingest_loop())
    try:
        rid = await collect(q, c, resume)
    finally:
        stop.set()
        await intake
    summary = export(q, q.root / "export")
    quality = analyze(q.root / "export/features.parquet", q.root / "report", c.seed)
    return {"run_id": rid, "export": summary, "analysis_status": quality["status"]}


def main():
    import argparse
    os.umask(0o077)
    p = argparse.ArgumentParser(description="Finite unattended research collection")
    p.add_argument("--data", default="data/overnight")
    p.add_argument("--config", default="configs/overnight.toml")
    p.add_argument("--legitimate-csv", required=True)
    p.add_argument("--source", action="append", choices=["openphish", "phishtank"])
    p.add_argument("--feed-limit", type=int, default=10000)
    p.add_argument("--resume")
    a = p.parse_args()
    if a.feed_limit <= 0:
        p.error("--feed-limit must be positive")
    try:
        print(json.dumps(asyncio.run(run(a.data, a.config, a.legitimate_csv, a.source or ["openphish"], a.feed_limit, a.resume)), indent=2))
    except Exception as exc:
        print(json.dumps({"status": "blocked", "error_type": type(exc).__name__, "reason": "see doctor.json and feed-status.json"}))
        raise SystemExit(2)


if __name__ == "__main__":
    main()
