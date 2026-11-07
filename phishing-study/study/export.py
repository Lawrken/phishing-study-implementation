import csv
import json
from pathlib import Path
import re
from .features import extract, FEATURES


def split_groups(rows):
    """Connected components of domains and optional manually reviewed template groups."""
    parents = {}
    def find(x):
        parents.setdefault(x, x)
        if parents[x] != x:
            parents[x] = find(parents[x])
        return parents[x]
    def union(a, b):
        a, b = find(a), find(b)
        parents[b] = a
    for row in rows:
        d = "domain:" + row["domain_group"]
        find(d)
        if row["manual_split_group"]:
            union(d, "manual:" + row["manual_split_group"])
    # Opaque stable IDs; preserve domains in metadata for auditing only.
    from .urls import digest
    for row in rows:
        row["split_group"] = digest(find("domain:" + row["domain_group"]))[:24]


def export(queue, destination, fmt="parquet"):
    dest = Path(destination)
    dest.mkdir(parents=True, exist_ok=True)
    with queue.connect() as db:
        candidates = [dict(r) for r in db.execute("SELECT * FROM candidates ORDER BY id")]
        attempts = {r["candidate_id"]: dict(r) for r in db.execute("SELECT * FROM attempts WHERE finished IS NOT NULL ORDER BY started,id")}
        dataset_sources = {}
        for source in db.execute("SELECT candidate_id,source,source_id,observed_at,label FROM provenance WHERE confidence='dataset' ORDER BY imported_at,source_id"):
            if (source['source'] == 'phiusiil-dataset' and source['observed_at'] == 'unknown'
                    and re.fullmatch(r'[a-f0-9]{64}', source['source_id'])):
                dataset_sources.setdefault((source['candidate_id'], source['label']), dict(source))
    rows = []
    for candidate in candidates:
        item = attempts.get(candidate["id"])
        if not item or not item["artifact"]:
            continue
        path = queue.root / item["artifact"]
        if not path.exists():
            continue
        record = json.loads(path.read_text())
        dataset_source = dataset_sources.get((candidate['id'], candidate['label']))
        # One latest committed observation per URL; exclude stale orphan artifacts.
        row = {"candidate_id": candidate["id"], "attempt_id": item["id"], "label": candidate["label"],
               "label_confidence": candidate["confidence"], "domain_group": candidate["domain_group"],
               "manual_split_group": candidate["split_group"], "review_disposition": candidate["review_disposition"],
               "captured_at": record["captured_at"], "config_hash": record["config_hash"],
               "profile": record["profile"], "route_id": record["route_id"], "region": record["region"],
               "outcome": candidate["outcome"], "capture_eligible": bool(candidate["eligible"]) and candidate["state"] == "done",
               "research_eligible": bool(candidate["eligible"]) and candidate["state"] == "done" and candidate["confidence"] == "verified"
                   and candidate["review_disposition"] == "active",
               "dataset_label_capture_eligible": bool(candidate["eligible"]) and candidate["state"] == "done"
                   and candidate["confidence"] == "dataset" and record["profile"] == "live" and dataset_source is not None,
               "label_source": dataset_source['source'] if dataset_source else None,
               "label_source_id": dataset_source['source_id'] if dataset_source else None,
               "label_observed_at": dataset_source['observed_at'] if dataset_source else None,
               **extract(record)}
        rows.append(row)
    split_groups(rows)
    name = dest / ("features.parquet" if fmt == "parquet" else "features.csv")
    if fmt == "parquet":
        import pyarrow as pa
        import pyarrow.parquet as pq
        if rows:
            pq.write_table(pa.Table.from_pylist(rows), name)
        else:
            pq.write_table(pa.table({"candidate_id": pa.array([], type=pa.string()), "label": pa.array([], type=pa.string())}), name)
    else:
        with name.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0]) if rows else ["candidate_id", "label"])
            writer.writeheader()
            writer.writerows(rows)
    dictionary = dest / "FEATURE_DICTIONARY.csv"
    with dictionary.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["feature", "record_path", "signal_group", "unit", "missing_policy"])
        for name, (path, group, unit) in FEATURES.items():
            writer.writerow([name, path, group, unit, "null + explicit missing reason; measured zero retained"])
    manifest = {"rows": len(rows), "capture_eligible": sum(r["capture_eligible"] for r in rows),
                "research_eligible": sum(r["research_eligible"] for r in rows), "format": fmt,
                "dataset_label_capture_eligible": sum(r["dataset_label_capture_eligible"] for r in rows),
                "dataset_label_policy": "Historical published labels are separate from independently verified current labels.",
                "config_hashes": sorted({r["config_hash"] for r in rows}), "policy": "one latest committed observation per URL"}
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2))
    return manifest
