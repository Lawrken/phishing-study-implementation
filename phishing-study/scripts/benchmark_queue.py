"""Synthetic intake stress check. Does not collect or label real websites."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sys
import tempfile
import time

root = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(root))
from study.queue import Queue
from study.config import Config

with tempfile.TemporaryDirectory() as temp:
    queue = Queue(temp)
    rows = [{"url":f"https://host{i}.invalid/login?row={i}","label":"phishing" if i%2 else "legitimate",
             "confidence":"candidate","source":"synthetic-load-check"} for i in range(10000)]
    start = time.monotonic()
    intake = queue.ingest(rows)
    elapsed = time.monotonic()-start
    duplicate = queue.ingest(rows)
    c = Config(domain_cooldown_seconds=0)
    rid = queue.start_run(c)
    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=6) as workers:
        items = list(workers.map(lambda _:queue.claim(rid,c), range(100)))
    claim_seconds = time.monotonic()-start
    assert intake["new"]==10000 and duplicate["duplicate"]==10000
    assert len({item["id"] for item in items})==100
    result = {"synthetic_rows":10000,"insert_seconds":round(elapsed,3),"duplicate_import":duplicate,
              "atomic_claims":100,"concurrent_claim_seconds":round(claim_seconds,3),
              "note":"Local SQLite intake/control-plane check only. Browser throughput and internet yield are unmeasured."}
    (root / "validation" / "queue-benchmark.json").write_text(json.dumps(result,indent=2))
    print(json.dumps(result,indent=2))
