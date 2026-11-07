"""SQLite WAL queue: atomic leases, global run budgets, independent labels."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import uuid
from .urls import canonical_url, digest, domain_group

SCHEMA = """
CREATE TABLE IF NOT EXISTS candidates (
 id TEXT PRIMARY KEY, url TEXT NOT NULL, domain_group TEXT NOT NULL,
 label TEXT NOT NULL, confidence TEXT NOT NULL, first_seen REAL NOT NULL,
 state TEXT NOT NULL DEFAULT 'pending', attempts INTEGER NOT NULL DEFAULT 0,
 next_at REAL NOT NULL DEFAULT 0, lease_until REAL, lease_token TEXT,
 last_started REAL, last_finished REAL, outcome TEXT, eligible INTEGER NOT NULL DEFAULT 0,
 review_disposition TEXT, split_group TEXT);
CREATE TABLE IF NOT EXISTS provenance (
 candidate_id TEXT NOT NULL REFERENCES candidates(id), source TEXT NOT NULL,
 source_id TEXT NOT NULL, observed_at TEXT NOT NULL, imported_at REAL NOT NULL,
 label TEXT NOT NULL, confidence TEXT NOT NULL,
 UNIQUE(candidate_id, source, source_id, observed_at, label, confidence));
CREATE TABLE IF NOT EXISTS attempts (
 id TEXT PRIMARY KEY, candidate_id TEXT NOT NULL REFERENCES candidates(id),
 run_id TEXT NOT NULL, lease_token TEXT NOT NULL, started REAL NOT NULL,
 finished REAL, outcome TEXT, eligible INTEGER NOT NULL DEFAULT 0,
 artifact TEXT, config_hash TEXT NOT NULL, route_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs (
 id TEXT PRIMARY KEY, started REAL NOT NULL, finished REAL, stop_reason TEXT,
 config_hash TEXT NOT NULL, config_json TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS pending_idx ON candidates(state, next_at, first_seen);
CREATE INDEX IF NOT EXISTS domain_idx ON candidates(domain_group, state, last_started);
CREATE INDEX IF NOT EXISTS class_idx ON candidates(label,state,eligible);
CREATE INDEX IF NOT EXISTS attempt_run_idx ON attempts(run_id,candidate_id);
CREATE INDEX IF NOT EXISTS attempt_candidate_idx ON attempts(candidate_id,started);
"""


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


class Queue:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        self.path = self.root / "study.sqlite"
        with self.connect() as db:
            db.executescript(SCHEMA)
        os.chmod(self.path, 0o600)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=30, factory=ClosingConnection)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    @contextmanager
    def transaction(self):
        db = self.connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def ingest(self, records):
        stats = {"new": 0, "duplicate": 0, "conflict": 0}
        with self.transaction() as db:
            for row in records:
                url = canonical_url(row["url"])
                label = row["label"]
                confidence = row.get("confidence", "candidate")
                if label not in {"legitimate", "phishing"} or confidence not in {"candidate", "feed", "verified", "dataset"}:
                    raise ValueError("invalid label/confidence")
                if confidence == "dataset" and (row.get("source") != "phiusiil-dataset"
                        or not re.fullmatch(r"[a-f0-9]{64}", str(row.get("source_id", "")))
                        or row.get("observed_at") != "unknown"):
                    raise ValueError("dataset confidence requires preserved PhiUSIIL source identity and unknown label time")
                cid = digest(url)
                prior = db.execute("SELECT * FROM candidates WHERE id=?", (cid,)).fetchone()
                if prior is None:
                    db.execute("INSERT INTO candidates(id,url,domain_group,label,confidence,first_seen) VALUES(?,?,?,?,?,?)",
                               (cid, url, domain_group(url), label, confidence, time.time()))
                    stats["new"] += 1
                else:
                    stats["duplicate"] += 1
                    if prior["label"] != label:
                        db.execute("UPDATE candidates SET state='conflict',eligible=0,lease_token=NULL,lease_until=NULL,outcome='label_conflict' WHERE id=?", (cid,))
                        db.execute("UPDATE attempts SET finished=?,outcome='label_conflict',eligible=0 WHERE candidate_id=? AND finished IS NULL", (time.time(), cid))
                        stats["conflict"] += 1
                    elif confidence == "verified" and prior["confidence"] != "verified":
                        db.execute("UPDATE candidates SET confidence='verified' WHERE id=?", (cid,))
                db.execute("INSERT OR IGNORE INTO provenance VALUES(?,?,?,?,?,?,?)",
                           (cid, row.get("source", "local"), str(row.get("source_id", cid)),
                            str(row.get("observed_at", "unknown")), time.time(), label, confidence))
        return stats

    def start_run(self, config, resume=None):
        from dataclasses import asdict
        with self.transaction() as db:
            if resume:
                run = db.execute("SELECT * FROM runs WHERE id=?", (resume,)).fetchone()
                if not run or run["config_hash"] != config.fingerprint:
                    raise ValueError("unknown run or configuration changed; start a new run")
                if run["finished"]:
                    raise ValueError("completed run cannot resume; start a new run")
                return resume
            rid = uuid.uuid4().hex
            db.execute("INSERT INTO runs(id,started,config_hash,config_json) VALUES(?,?,?,?)",
                       (rid, time.time(), config.fingerprint, json.dumps(asdict(config), sort_keys=True)))
            return rid

    def recover(self, now=None, retries=2):
        now = time.time() if now is None else now
        with self.transaction() as db:
            expired = db.execute("SELECT id,lease_token,attempts FROM candidates WHERE state='running' AND lease_until<?", (now,)).fetchall()
            for c in expired:
                db.execute("UPDATE attempts SET finished=?,outcome='interrupted' WHERE lease_token=? AND finished IS NULL", (now, c["lease_token"]))
                state = "pending" if c["attempts"] <= retries else "done"
                db.execute("UPDATE candidates SET state=?,outcome='interrupted',eligible=0,lease_token=NULL,lease_until=NULL,next_at=? WHERE id=?", (state, now, c["id"]))
            return len(expired)

    def claim(self, rid, config, now=None):
        now = time.time() if now is None else now
        with self.transaction() as db:
            run = db.execute("SELECT * FROM runs WHERE id=?", (rid,)).fetchone()
            if run["attempts"] >= config.max_attempts or now - run["started"] >= config.max_hours * 3600:
                return None
            # Interleave classes by attempt counts, rather than a source's input ordering.
            counts = dict(db.execute("SELECT c.label,COUNT(*) FROM attempts a JOIN candidates c ON c.id=a.candidate_id WHERE a.run_id=? GROUP BY c.label", (rid,)))
            order = sorted(("legitimate", "phishing"), key=lambda x: (counts.get(x, 0), x))
            for label in order:
                usable = db.execute("SELECT COUNT(*) FROM candidates WHERE label=? AND eligible=1 AND state='done'", (label,)).fetchone()[0]
                active = db.execute("SELECT COUNT(*) FROM candidates WHERE label=? AND state='running'", (label,)).fetchone()[0]
                if usable + active >= config.usable_per_class:
                    continue
                row = db.execute("""SELECT * FROM candidates c WHERE state='pending' AND label=? AND next_at<=? AND attempts<=?
                  AND NOT EXISTS (SELECT 1 FROM candidates d WHERE d.domain_group=c.domain_group AND
                    (d.state='running' OR d.last_started>?)) ORDER BY first_seen,id LIMIT 1""",
                                 (label, now, config.retries, now - config.domain_cooldown_seconds)).fetchone()
                if row:
                    token, aid = uuid.uuid4().hex, uuid.uuid4().hex
                    db.execute("UPDATE candidates SET state='running',attempts=attempts+1,last_started=?,lease_until=?,lease_token=? WHERE id=?",
                               (now, now + config.lease_seconds, token, row["id"]))
                    db.execute("INSERT INTO attempts(id,candidate_id,run_id,lease_token,started,config_hash,route_id) VALUES(?,?,?,?,?,?,?)",
                               (aid, row["id"], rid, token, now, config.fingerprint, config.route_id))
                    db.execute("UPDATE runs SET attempts=attempts+1 WHERE id=?", (rid,))
                    return dict(row) | {"attempt_id": aid, "lease_token": token, "attempt_number": row["attempts"] + 1}
            return None

    def finish(self, item, outcome, eligible, artifact, config, transient=False, retry_after=0):
        now = time.time()
        with self.transaction() as db:
            row = db.execute("SELECT * FROM candidates WHERE id=?", (item["id"],)).fetchone()
            if row["lease_token"] != item["lease_token"] or row["state"] != "running":
                return False  # Late worker may not overwrite a recovered/conflicted job.
            retry = transient and row["attempts"] <= config.retries
            state = "pending" if retry else "done"
            delay = max(retry_after, config.retry_base_seconds * 2 ** (row["attempts"] - 1)) if retry else 0
            db.execute("UPDATE candidates SET state=?,eligible=?,outcome=?,last_finished=?,next_at=?,lease_until=NULL,lease_token=NULL WHERE id=?",
                       (state, int(eligible), outcome, now, now + delay, item["id"]))
            db.execute("UPDATE attempts SET finished=?,outcome=?,eligible=?,artifact=? WHERE id=? AND lease_token=?",
                       (now, outcome, int(eligible), artifact, item["attempt_id"], item["lease_token"]))
            return True

    def heartbeat(self, item, lease_seconds, now=None):
        now = time.time() if now is None else now
        with self.transaction() as db:
            updated = db.execute("UPDATE candidates SET lease_until=? WHERE id=? AND state='running' AND lease_token=?",
                                 (now + lease_seconds, item["id"], item["lease_token"]))
            return updated.rowcount == 1

    def finish_run(self, rid, reason):
        with self.transaction() as db:
            db.execute("UPDATE runs SET finished=?,stop_reason=? WHERE id=?", (time.time(), reason, rid))

    def status(self):
        with self.connect() as db:
            return {"states": [dict(r) for r in db.execute("SELECT label,state,COUNT(*) count FROM candidates GROUP BY label,state")],
                    "outcomes": [dict(r) for r in db.execute("SELECT label,outcome,eligible,COUNT(*) count FROM candidates GROUP BY label,outcome,eligible")],
                    "runs": [dict(r) for r in db.execute("SELECT id,started,finished,stop_reason,attempts,config_hash FROM runs ORDER BY started DESC")],
                    "attempts": db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0],
                    "usable": db.execute("SELECT COUNT(*) FROM candidates WHERE eligible=1 AND state='done'").fetchone()[0]}

    def review(self, cid, disposition, split_group=None):
        if disposition not in {"active", "challenge", "takedown", "parked", "unknown"}:
            raise ValueError("invalid review disposition")
        with self.transaction() as db:
            if not db.execute("SELECT 1 FROM candidates WHERE id=?", (cid,)).fetchone():
                raise ValueError("candidate not found")
            db.execute("UPDATE candidates SET review_disposition=?,split_group=? WHERE id=?", (disposition, split_group, cid))
