"""Reproducible sampling and independent labels; never visits candidate endpoints."""
import csv
from contextlib import contextmanager
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import io
import ipaddress
import json
from pathlib import Path
import random
import re
import time
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlsplit
import zipfile

from .urls import canonical_url, domain_group

API = "https://tranco-list.eu/api/"
SEED = 20261010
BANDS = ((1, 10_000), (10_001, 100_000), (100_001, 1_000_000))
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_CSV_BYTES = 128 * 1024 * 1024
MAX_METADATA_BYTES = 1024 * 1024
MAX_REVIEW_BYTES = 16 * 1024 * 1024
MAX_REVIEW_ROWS = 10_000
MIN_REQUEST_INTERVAL = 1.1
MAX_RETRY_WAIT = 30.0
_last_fetch_time = None
CANDIDATE_FIELDS = ("candidate_domain", "rank", "stratum", "source", "source_id", "list_id")
REVIEW_FIELDS = CANDIDATE_FIELDS + ("endpoint_url", "service_category", "tenant_or_brand",
                                  "verdict", "reviewer", "reviewed_at", "evidence_reference",
                                  "independent_review")
EXPORT_FIELDS = ("url", "label", "confidence", "source", "source_id", "observed_at")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256(content):
    return hashlib.sha256(content).hexdigest()


def utc_time(value, field):
    """Review/download timestamps must be explicit UTC, never local or naive."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError):
        raise ValueError(f"{field} must be an ISO 8601 UTC timestamp") from None
    if parsed.tzinfo is None or parsed.utcoffset().total_seconds() != 0:
        raise ValueError(f"{field} must include UTC timezone")
    if parsed > datetime.now(timezone.utc):
        raise ValueError(f"{field} cannot be in the future")
    return parsed.isoformat()


def domain_name(value):
    if not isinstance(value, str) or value != value.strip() or not value or len(value) > 253:
        raise ValueError("invalid candidate domain")
    try:
        domain = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("invalid candidate domain") from None
    labels = domain.split(".")
    if len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in labels):
        raise ValueError("invalid candidate domain")
    if labels[-1].isdigit() or domain.endswith((".localhost", ".local", ".internal", ".invalid", ".test", ".example", ".home.arpa", ".onion", ".lan", ".corp")):
        raise ValueError("candidate domain must be a public domain name")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ValueError("candidate domain cannot be an IP address")


def metadata_identity(metadata, list_id=None):
    if not isinstance(metadata, dict) or not isinstance(metadata.get("list_id"), str):
        raise ValueError("Tranco metadata must contain list_id")
    permanent_id = metadata["list_id"]
    if not re.fullmatch(r"[A-Za-z0-9]{3,32}", permanent_id) or (list_id and permanent_id != list_id):
        raise ValueError("Tranco permanent list ID does not match metadata")
    if metadata.get("available") is not True or metadata.get("failed") is not False:
        raise ValueError("Tranco list is unavailable or failed")
    if not isinstance(metadata.get("configuration"), dict):
        raise ValueError("Tranco metadata must retain configuration")
    created = metadata.get("created_on")
    try:
        datetime.fromisoformat(created.replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError):
        raise ValueError("Tranco metadata must contain valid created_on") from None
    return permanent_id


def official_url(value):
    url = urljoin("https://tranco-list.eu/", value)
    parts = urlsplit(url)
    if (parts.scheme != "https" or parts.hostname != "tranco-list.eu" or parts.port not in {None, 443}
            or parts.username or parts.password or parts.fragment):
        raise ValueError("Tranco download must use its official HTTPS host")
    return url


class OfficialRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return super().redirect_request(req, fp, code, msg, headers, official_url(newurl))


def retry_after_seconds(value):
    if not value:
        return None
    try:
        delay = float(value)
        if delay < 0 or delay != delay or delay == float("inf"):
            return None
        return delay
    except ValueError:
        try:
            when = parsedate_to_datetime(value)
            if when.tzinfo is None:
                return None
            return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())
        except (ValueError, TypeError, OverflowError):
            return None


def fetch_official(url, max_bytes):
    """Pace the official API and honor bounded Retry-After without changing hosts."""
    global _last_fetch_time
    request = urllib.request.Request(official_url(url), headers={"User-Agent": "ApplicationLayerResearch/0.1 (sampling frame)"})
    opener = urllib.request.build_opener(OfficialRedirects())
    retry_delay = 0.0
    for attempt in range(3):
        spacing = 0.0 if _last_fetch_time is None else max(0.0, MIN_REQUEST_INTERVAL - (time.monotonic() - _last_fetch_time))
        pause = max(spacing, retry_delay)
        if pause:
            time.sleep(pause)
        _last_fetch_time = time.monotonic()
        try:
            with opener.open(request, timeout=60) as response:
                content = response.read(max_bytes + 1)
            if len(content) > max_bytes:
                raise ValueError("Tranco response exceeds size budget")
            return content
        except urllib.error.HTTPError as error:
            if error.code not in {429, 503} or attempt == 2:
                raise
            requested_delay = retry_after_seconds(error.headers.get("Retry-After"))
            retry_delay = requested_delay if requested_delay is not None else 2.0 ** (attempt + 1)
            if retry_delay > MAX_RETRY_WAIT:
                # Do not retry earlier than the server permits, or wait indefinitely.
                raise


def latest_source(fetcher=fetch_official):
    metadata_bytes = fetcher(API + "lists/date/latest", MAX_METADATA_BYTES)
    metadata = json.loads(metadata_bytes)
    list_id = metadata_identity(metadata)
    permanent_bytes = fetcher(API + "lists/id/" + list_id, MAX_METADATA_BYTES)
    permanent = json.loads(permanent_bytes)
    metadata_identity(permanent, list_id)
    if permanent.get("created_on") != metadata.get("created_on") or permanent.get("configuration") != metadata.get("configuration"):
        raise ValueError("Tranco permanent metadata changed during resolution")
    download = permanent.get("download")
    if not isinstance(download, str) or not download:
        raise ValueError("Tranco metadata has no download URL")
    content = fetcher(official_url(download), MAX_ARCHIVE_BYTES)
    return content, permanent, {"selection_metadata": metadata, "metadata_endpoint": API + "lists/id/" + list_id,
                                "selection_endpoint": API + "lists/date/latest", "download_url": official_url(download),
                                "downloaded_at": utc_now(), "mode": "latest-standard"}


def local_source(archive, metadata_file, list_id, downloaded_at):
    path = Path(archive)
    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("Tranco archive exceeds size budget")
    metadata_path = Path(metadata_file)
    if metadata_path.stat().st_size > MAX_METADATA_BYTES:
        raise ValueError("Tranco metadata exceeds size budget")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8-sig"))
    metadata_identity(metadata, list_id)
    return path.read_bytes(), metadata, {"mode": "local", "downloaded_at": utc_time(downloaded_at, "downloaded_at"),
                                         "local_archive_name": path.name, "local_metadata_name": metadata_path.name}


def source_format(content):
    return "zip" if content.startswith(b"PK") else "csv"


@contextmanager
def ranking_stream(content):
    if source_format(content) == "csv":
        if len(content) > MAX_CSV_BYTES:
            raise ValueError("Tranco CSV exceeds expanded size budget")
        with io.TextIOWrapper(io.BytesIO(content), encoding="utf-8-sig", newline="") as stream:
            yield stream
        return
    archive = zipfile.ZipFile(io.BytesIO(content))
    entries = archive.infolist()
    if (len(entries) != 1 or entries[0].is_dir() or not entries[0].filename.endswith(".csv")
            or entries[0].file_size > MAX_CSV_BYTES or entries[0].flag_bits & 1
            or "/" in entries[0].filename or "\\" in entries[0].filename):
        archive.close()
        raise ValueError("Tranco ZIP must contain exactly one bounded plain CSV")
    with archive, archive.open(entries[0]) as raw, io.TextIOWrapper(raw, encoding="utf-8-sig", newline="") as stream:
        yield stream


def sample_archive(content, list_id, per_band=50, seed=SEED):
    """Stream a strictly ordered ranking, using seeded reservoirs for each stratum."""
    if not 1 <= per_band <= 1000 or not isinstance(seed, int):
        raise ValueError("invalid sampling parameters")
    if len(content) > MAX_ARCHIVE_BYTES:
        raise ValueError("Tranco archive exceeds size budget")
    try:
        seen = set()
        exclusions = []
        counts = [0, 0, 0]
        sampled = [[], [], []]
        randoms = [random.Random(f"{seed}:{low}:{high}") for low, high in BANDS]
        previous_rank = 0
        with ranking_stream(content) as stream:
            for line_number, row in enumerate(csv.reader(stream, strict=True), 1):
                if len(row) != 2 or not re.fullmatch(r"[1-9][0-9]*", row[0]):
                    raise ValueError(f"malformed ranking at row {line_number}")
                rank = int(row[0])
                if rank <= previous_rank or rank > 1_000_000:
                    raise ValueError(f"ranks must increase uniquely within 1..1000000 at row {line_number}")
                previous_rank = rank
                placeholder = row[1].startswith("_wildcard_.")
                if placeholder:
                    # The official frame contains these suffix aggregation records.
                    # They describe no visitable domain; never invent a replacement.
                    domain_name("placeholder." + row[1][len("_wildcard_."):])
                    domain = row[1].lower()
                else:
                    domain = domain_name(row[1])
                if domain in seen:
                    raise ValueError(f"duplicate candidate domain at row {line_number}")
                seen.add(domain)
                if placeholder:
                    exclusions.append({"rank": rank, "source_domain": domain, "reason": "tranco_wildcard_placeholder"})
                    continue
                band = next(i for i, (low, high) in enumerate(BANDS) if low <= rank <= high)
                counts[band] += 1
                if len(sampled[band]) < per_band:
                    sampled[band].append((rank, domain))
                else:
                    position = randoms[band].randrange(counts[band])
                    if position < per_band:
                        sampled[band][position] = (rank, domain)
        if any(count < per_band for count in counts):
            raise ValueError("Tranco ranking has insufficient unique domains in a rank band")
    except (zipfile.BadZipFile, UnicodeDecodeError, csv.Error, RuntimeError, EOFError, OSError, NotImplementedError):
        raise ValueError("malformed or unreadable Tranco ZIP/CSV") from None
    rows = []
    for (low, high), sample in zip(BANDS, sampled):
        for rank, domain in sorted(sample):
            rows.append({"candidate_domain": domain, "rank": str(rank), "stratum": f"{low}-{high}",
                         "source": "tranco", "source_id": f"{list_id}:{rank}:{domain}", "list_id": list_id})
    return rows, {"rows_validated": len(seen), "eligible_domains": sum(counts), "excluded_records": exclusions,
                  "stratum_population_counts": counts,
                  "seed": seed, "per_band": per_band, "algorithm": "ordered-seeded-reservoir-v1",
                  "sampling_algorithm_runtime": "python-random-v3"}


def write_csv(path, fields, rows):
    with Path(path).open("x", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def prepare_shortlist(output, content, metadata, provenance, per_band=50, seed=SEED):
    output = Path(output)
    if output.exists():
        raise ValueError("output directory must be fresh")
    list_id = metadata_identity(metadata)
    downloaded_at = utc_time(provenance.get("downloaded_at"), "downloaded_at")
    rows, sampling = sample_archive(content, list_id, per_band, seed)
    output.mkdir(parents=True)
    format_name = source_format(content)
    source_filename = "source." + format_name
    (output / source_filename).write_bytes(content)
    (output / "source-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    write_csv(output / "candidates.csv", CANDIDATE_FIELDS, rows)
    pending = [{**row, **{field: "" for field in REVIEW_FIELDS if field not in row}, "verdict": "pending"} for row in rows]
    write_csv(output / "review-worksheet.csv", REVIEW_FIELDS, pending)
    write_csv(output / "shared-hosting-worksheet.csv", REVIEW_FIELDS, [])
    manifest = {"created_at": utc_now(), "list_id": list_id, "list_created_on": metadata["created_on"],
                "downloaded_at": downloaded_at, "source_sha256": sha256(content),
                "source_format": format_name, "source_filename": source_filename,
                "archive_sha256": sha256(content) if format_name == "zip" else None,
                "metadata_sha256": sha256((output / "source-metadata.json").read_bytes()),
                "candidate_count": len(rows), "candidate_endpoints_visited": 0,
                "label_confidence": "candidate", "sampling": sampling, "provenance": provenance}
    (output / "sampling-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def validate_endpoint(value):
    if not value or "\\" in value or any(c.isspace() for c in value):
        raise ValueError("endpoint_url must be a complete HTTP(S) URL without whitespace or backslashes")
    normalized = canonical_url(value)
    parts = urlsplit(normalized)
    if parts.port not in {None, 80, 443}:
        raise ValueError("endpoint_url must use a web port")
    try:
        address = ipaddress.ip_address(parts.hostname)
    except ValueError:
        domain_name(parts.hostname)
    else:
        if getattr(address, "ipv4_mapped", None):
            address = address.ipv4_mapped
        if not address.is_global:
            raise ValueError("endpoint_url cannot target non-public addresses")
    return normalized


def read_review(path):
    if Path(path).stat().st_size > MAX_REVIEW_BYTES:
        raise ValueError("review worksheet exceeds size budget")
    with Path(path).open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if set(reader.fieldnames or []) != set(REVIEW_FIELDS) or len(reader.fieldnames or []) != len(REVIEW_FIELDS):
            raise ValueError("review CSV must contain the exact worksheet columns")
        for number, row in enumerate(reader, 2):
            if number > MAX_REVIEW_ROWS + 1:
                raise ValueError("review worksheet exceeds row budget")
            if None in row or any(value is None for value in row.values()):
                raise ValueError(f"malformed review CSV row {number}")
            yield number, {key: value.strip() for key, value in row.items()}


def validate_review_records(records):
    accepted, accepted_reviews, ignored, urls, groups = [], [], {"pending": 0, "rejected": 0}, set(), set()
    for number, row in records:
        if not isinstance(row, dict) or set(row) != set(REVIEW_FIELDS) or any(not isinstance(value, str) for value in row.values()):
            raise ValueError(f"row {number}: review record has invalid worksheet fields")
        row = {key: value.strip() for key, value in row.items()}
        verdict = row["verdict"].lower()
        if verdict in {"", "pending", "rejected"}:
            ignored["rejected" if verdict == "rejected" else "pending"] += 1
            continue
        if verdict != "accepted":
            raise ValueError(f"row {number}: verdict must be pending, rejected or accepted")
        required = ("candidate_domain", "stratum", "source", "source_id", "endpoint_url", "service_category",
                    "tenant_or_brand", "reviewer", "reviewed_at", "evidence_reference", "independent_review")
        if any(not row[field] for field in required) or row["independent_review"].lower() != "true":
            raise ValueError(f"row {number}: accepted review must be complete and independently verified")
        if any(any(ord(c) < 32 for c in row[field]) for field in required):
            raise ValueError(f"row {number}: review fields cannot contain control characters")
        candidate = domain_name(row["candidate_domain"])
        endpoint = validate_endpoint(row["endpoint_url"])
        reviewed_at = utc_time(row["reviewed_at"], "reviewed_at")
        if domain_group("https://" + candidate) != domain_group(endpoint):
            raise ValueError(f"row {number}: reviewed endpoint must belong to the candidate domain/tenant")
        if row["source"] == "tranco":
            if not re.fullmatch(r"[A-Za-z0-9]{3,32}", row["list_id"]) or not re.fullmatch(r"[1-9][0-9]*", row["rank"]):
                raise ValueError(f"row {number}: Tranco review requires permanent list ID and rank")
            rank = int(row["rank"])
            band = next(((low, high) for low, high in BANDS if low <= rank <= high), None)
            if band is None or row["stratum"] != f"{band[0]}-{band[1]}" or row["source_id"] != f"{row['list_id']}:{rank}:{candidate}":
                raise ValueError(f"row {number}: Tranco rank/stratum/source identity mismatch")
        elif row["source"] != "shared-hosting" or row["stratum"] != "shared-hosting" or row["rank"] or row["list_id"]:
            raise ValueError(f"row {number}: shared-hosting review requires source/stratum shared-hosting and blank rank/list ID")
        if endpoint in urls:
            raise ValueError(f"row {number}: duplicate reviewed endpoint")
        urls.add(endpoint)
        groups.add(domain_group(endpoint))
        accepted_reviews.append(row)
        accepted.append({"url": endpoint, "label": "legitimate", "confidence": "verified",
                         "source": "independent-review:" + row["source"], "source_id": row["source_id"],
                         "observed_at": reviewed_at})
    return accepted, {"accepted": len(accepted), "excluded": ignored, "domain_or_tenant_groups": len(groups),
                      "candidate_endpoints_visited": 0, "review_basis": "human-independent-evidence",
                      "accepted_reviews": accepted_reviews}


def validate_reviews(paths):
    # Close worksheet files before validating, including on exceptions on Windows.
    records = [record for path in paths for record in read_review(path)]
    if len(records) > MAX_REVIEW_ROWS:
        raise ValueError("combined review worksheets exceed row budget")
    return validate_review_records(records)


def export_reviews(paths, output):
    paths = list(paths)
    if not paths:
        raise ValueError("at least one review worksheet is required")
    output = Path(output)
    if output.exists() or output.with_suffix(output.suffix + ".audit.json").exists():
        raise ValueError("export and audit paths must be fresh")
    rows, audit = validate_reviews(paths)
    output.parent.mkdir(parents=True, exist_ok=True)
    write_csv(output, EXPORT_FIELDS, rows)
    audit.update({"schema": "review-export-v1", "generated_at": utc_now(), "input_files": [{"name": Path(path).name, "sha256": sha256(Path(path).read_bytes())} for path in paths],
                  "export_sha256": sha256(output.read_bytes())})
    output.with_suffix(output.suffix + ".audit.json").write_text(json.dumps(audit, indent=2) + "\n", encoding="utf-8")
    return audit


def validate_export(csv_path, audit_path):
    """Bind ingestion rows to complete retained human reviews, without a network lookup."""
    csv_path, audit_path = Path(csv_path), Path(audit_path)
    if csv_path.stat().st_size > MAX_REVIEW_BYTES or audit_path.stat().st_size > MAX_REVIEW_BYTES:
        raise ValueError("review export or audit exceeds size budget")
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    if not isinstance(audit, dict) or audit.get("schema") != "review-export-v1" or audit.get("export_sha256") != sha256(csv_path.read_bytes()):
        raise ValueError("review export hash or audit schema mismatch")
    reviews = audit.get("accepted_reviews")
    if not isinstance(reviews, list) or len(reviews) > MAX_REVIEW_ROWS:
        raise ValueError("review export audit must retain accepted reviews")
    expected, replay = validate_review_records(enumerate(reviews, 1))
    if len(expected) != len(reviews) or audit.get("accepted") != len(expected) or audit.get("domain_or_tenant_groups") != replay["domain_or_tenant_groups"]:
        raise ValueError("review export count or retained review mismatch")
    with csv_path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames != list(EXPORT_FIELDS) or list(reader) != expected:
            raise ValueError("review export rows do not match independently accepted reviews")
    return audit
