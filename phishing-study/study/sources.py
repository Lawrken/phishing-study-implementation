"""Source candidates retain their source labels, independently of measured signals."""
import csv
from datetime import datetime, timezone
import gzip
import io
import json
import os
from pathlib import Path
import urllib.request
import zipfile


def now():
    return datetime.now(timezone.utc).isoformat()


def read_csv(path):
    with Path(path).open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not {"url", "label"}.issubset(reader.fieldnames or []):
            raise ValueError("CSV must contain url and label")
        for row in reader:
            yield {"url": row["url"], "label": row["label"], "source": row.get("source") or "local",
                   "source_id": row.get("source_id") or row["url"], "observed_at": row.get("observed_at") or "unknown",
                   "confidence": row.get("confidence") or "candidate"}


def read_dataset_intake(csv_path, manifest_path):
    """Read only a validated frozen reserve, without revisiting source endpoints."""
    from .phiusiil_intake import records_from_manifest, validate_intake
    manifest = validate_intake(csv_path, manifest_path)
    # Reconstruct the exact validated rows rather than reopen a mutable CSV.
    yield from records_from_manifest(manifest)


def fetch(url, max_bytes=250_000_000):
    # Feed endpoints are fixed by adapter, not supplied by arbitrary candidate URLs.
    request = urllib.request.Request(url, headers={"User-Agent": "ApplicationLayerResearch/0.1 (feed ingestion)"})
    with urllib.request.urlopen(request, timeout=30) as response:
        content = response.read(max_bytes + 1)
    if len(content) > max_bytes:
        raise ValueError("feed exceeds download budget")
    return content


def phishtank(content=None):
    key = os.environ.get("PHISHTANK_API_KEY")
    if content is None and not key:
        raise ValueError("PHISHTANK_API_KEY required; alternatively ingest a downloaded feed")
    if key and not key.isalnum():
        raise ValueError("invalid PhishTank API key")
    content = content if content is not None else fetch(f"https://data.phishtank.com/data/{key}/online-valid.json.gz")
    raw = gzip.decompress(content) if content[:2] == b"\x1f\x8b" else content
    if len(raw) > 500_000_000:
        raise ValueError("expanded feed too large")
    for row in json.loads(raw):
        if str(row.get("verified")).lower() in {"yes", "true"} and str(row.get("online")).lower() in {"yes", "true"}:
            yield {"url": row["url"], "label": "phishing", "confidence": "verified", "source": "phishtank",
                   "source_id": row["phish_id"], "observed_at": row.get("verification_time", "unknown")}


def openphish(content=None):
    content = content if content is not None else fetch("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt")
    fetched = now()
    for line in content.decode("utf-8-sig").splitlines():
        if line.strip():
            yield {"url": line.strip(), "label": "phishing", "confidence": "feed", "source": "openphish-community",
                   "source_id": line.strip(), "observed_at": fetched}


def tranco(content=None):
    content = content if content is not None else fetch("https://tranco-list.eu/top-1m.csv.zip")
    fetched = now()
    if content[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(content)) as z:
            names = [n for n in z.namelist() if n.endswith(".csv")]
            if len(names) != 1 or z.getinfo(names[0]).file_size > 250_000_000:
                raise ValueError("unexpected Tranco archive")
            content = z.read(names[0])
    for rank, domain in csv.reader(io.StringIO(content.decode("utf-8-sig"))):
        yield {"url": f"https://{domain}/", "label": "legitimate", "confidence": "candidate", "source": "tranco",
               "source_id": rank, "observed_at": fetched}


def records(source, file=None, limit=None):
    content = Path(file).read_bytes() if file and source != "csv" else None
    stream = read_csv(file) if source == "csv" else {"phishtank": phishtank, "openphish": openphish, "tranco": tranco}[source](content)
    # Batch imports in CLI; no million-row Python list necessary.
    for i, row in enumerate(stream):
        if limit is not None and i >= limit:
            break
        yield row
