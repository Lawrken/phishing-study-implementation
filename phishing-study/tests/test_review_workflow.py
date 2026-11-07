import csv
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import urllib.error
import zipfile

from study.review_workflow import (BANDS, CANDIDATE_FIELDS, EXPORT_FIELDS, REVIEW_FIELDS, SEED,
                                   domain_name, export_reviews, fetch_official, latest_source, local_source,
                                   metadata_identity, official_url, prepare_shortlist,
                                   sample_archive, sha256, utc_time, validate_endpoint,
                                   validate_export, validate_reviews, write_csv)


def archive(rows=None, entries=None):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zipped:
        if entries is None:
            text = io.StringIO(newline="")
            csv.writer(text).writerows(rows)
            zipped.writestr("top-1m.csv", text.getvalue())
        else:
            for name, content in entries:
                zipped.writestr(name, content)
    return buffer.getvalue()


def ranking(per_band=60):
    return [(low + i, f"site{low+i}.com") for low, _ in BANDS for i in range(per_band)]


def metadata(**extra):
    return {"list_id": "ABC12", "available": True, "failed": False,
            "created_on": "2026-10-01T00:00:00.000000", "configuration": {"filterPLD": "on"},
            "download": "https://tranco-list.eu/download/ABC12/1000000", **extra}


def accepted_review(domain="example.com", rank="1", **changes):
    row = {"candidate_domain": domain, "rank": rank, "stratum": "1-10000", "source": "tranco",
           "source_id": f"ABC12:{rank}:{domain}", "list_id": "ABC12", "endpoint_url": f"https://{domain}/account",
           "service_category": "account", "tenant_or_brand": "Example service", "verdict": "accepted",
           "reviewer": "reviewer-001", "reviewed_at": "2026-10-01T01:00:00Z",
           "evidence_reference": "research-log/official-account-evidence-001", "independent_review": "true"}
    return {**row, **changes}


class ShortlistTests(unittest.TestCase):
    def test_seeded_sampling_is_repeatable_and_stratified(self):
        content = archive(ranking())
        first, details = sample_archive(content, "ABC12")
        second, _ = sample_archive(content, "ABC12")
        self.assertEqual(first, second)
        self.assertEqual(len(first), 150)
        self.assertEqual(len({row["candidate_domain"] for row in first}), 150)
        self.assertEqual(details["stratum_population_counts"], [60, 60, 60])
        self.assertEqual(details["seed"], SEED)
        different, _ = sample_archive(content, "ABC12", seed=SEED + 1)
        self.assertNotEqual(first, different)
        for i, (low, high) in enumerate(BANDS):
            subset = first[i * 50:(i + 1) * 50]
            self.assertTrue(all(low <= int(row["rank"]) <= high for row in subset))
            self.assertEqual({row["stratum"] for row in subset}, {f"{low}-{high}"})

    def test_official_plain_csv_has_identical_sample_and_truthful_saved_format(self):
        text = io.StringIO(newline="")
        csv.writer(text).writerows(ranking())
        plain = text.getvalue().encode()
        zipped = archive(ranking())
        self.assertEqual(sample_archive(plain, "ABC12"), sample_archive(zipped, "ABC12"))
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "output"
            report = prepare_shortlist(output, plain, metadata(), {"mode": "latest-standard", "downloaded_at": "2026-10-01T00:00:00Z"})
            self.assertEqual(report["source_format"], "csv")
            self.assertEqual(report["source_sha256"], sha256(plain))
            self.assertIsNone(report["archive_sha256"])
            self.assertEqual((output / "source.csv").read_bytes(), plain)
            self.assertFalse((output / "source.zip").exists())

    def test_rank_boundaries_are_classified_exactly(self):
        rows = [(1, "a.com"), (10000, "b.com"), (10001, "c.com"), (100000, "d.com"),
                (100001, "e.com"), (1000000, "f.com")]
        result, _ = sample_archive(archive(rows), "ABC12", per_band=2)
        self.assertEqual([row["stratum"] for row in result], ["1-10000"] * 2 + ["10001-100000"] * 2 + ["100001-1000000"] * 2)

    def test_official_wildcard_placeholders_are_excluded_with_preserved_reason(self):
        rows = [(1, "_wildcard_.ph"), (2, "a.com"), (10001, "_wildcard_.com.ph"), (10002, "b.com"),
                (100001, "_wildcard_.xn--node"), (100002, "c.com")]
        result, report = sample_archive(archive(rows), "ABC12", per_band=1)
        self.assertEqual([row["candidate_domain"] for row in result], ["a.com", "b.com", "c.com"])
        self.assertEqual(report["rows_validated"], 6)
        self.assertEqual(report["eligible_domains"], 3)
        self.assertEqual(report["stratum_population_counts"], [1, 1, 1])
        self.assertEqual(report["excluded_records"][0], {"rank": 1, "source_domain": "_wildcard_.ph", "reason": "tranco_wildcard_placeholder"})
        with self.assertRaises(ValueError):
            sample_archive(archive([(1, "_other_.com")]), "ABC12", per_band=1)

    def test_duplicate_rank_or_normalized_domain_is_rejected(self):
        for rows in ([(1, "a.com"), (1, "b.com")], [(2, "a.com"), (1, "b.com")],
                     [(1, "Example.COM"), (2, "example.com")], [(1, "bücher.de"), (2, "xn--bcher-kva.de")]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                sample_archive(archive(rows), "ABC12", per_band=1)

    def test_malformed_csv_and_out_of_range_rank_rejected(self):
        for rows in ([(0, "a.com")], [(1000001, "a.com")], [("01", "a.com")], [("rank", "domain")],
                     [(1, "a.com", "extra")], [(1, "http://a.com")], [(1, "a.com ")], []):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                sample_archive(archive(rows), "ABC12", per_band=1)

    def test_malformed_zip_multiple_entries_and_paths_rejected(self):
        values = (b"not a zip", archive(entries=[("x.csv", "1,a.com"), ("y.csv", "2,b.com")]),
                  archive(entries=[("../x.csv", "1,a.com")]), archive(entries=[("x.txt", "1,a.com")]),
                  archive(entries=[("folder/x.csv", "1,a.com")]), archive(entries=[("x.csv", b"\xff\xfe")]))
        for content in values:
            with self.subTest(size=len(content)), self.assertRaises(ValueError):
                sample_archive(content, "ABC12", per_band=1)

    def test_size_limits_and_insufficient_band_population(self):
        content = archive(ranking(1))
        with patch("study.review_workflow.MAX_ARCHIVE_BYTES", 10), self.assertRaises(ValueError):
            sample_archive(content, "ABC12", per_band=1)
        with patch("study.review_workflow.MAX_CSV_BYTES", 10), self.assertRaises(ValueError):
            sample_archive(content, "ABC12", per_band=1)
        with self.assertRaises(ValueError):
            sample_archive(content, "ABC12", per_band=2)

    def test_latest_resolves_permanent_metadata_and_never_domains(self):
        calls = []
        content = archive(ranking())
        def fetch(url, limit):
            calls.append(url)
            return content if "/download/" in url else json.dumps(metadata()).encode()
        result, meta, source = latest_source(fetch)
        self.assertEqual(result, content)
        self.assertEqual(meta["list_id"], "ABC12")
        self.assertEqual(calls, ["https://tranco-list.eu/api/lists/date/latest", "https://tranco-list.eu/api/lists/id/ABC12",
                                 "https://tranco-list.eu/download/ABC12/1000000"])
        self.assertEqual(source["mode"], "latest-standard")
        self.assertEqual(source["selection_metadata"]["list_id"], "ABC12")

    def test_changed_permanent_metadata_and_unofficial_download_rejected(self):
        count = 0
        def fetch(url, limit):
            nonlocal count
            count += 1
            return json.dumps(metadata(created_on="2026-10-02T00:00:00" if count == 2 else "2026-10-01T00:00:00.000000")).encode()
        with self.assertRaises(ValueError):
            latest_source(fetch)
        for value in ("http://tranco-list.eu/file", "https://attacker.example/file", "https://user@tranco-list.eu/file"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                official_url(value)

    def test_local_provenance_and_fresh_outputs(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            content = archive(ranking())
            (root / "original.zip").write_bytes(content)
            (root / "original.json").write_text(json.dumps(metadata()))
            source = local_source(root / "original.zip", root / "original.json", "ABC12", "2026-10-01T01:00:00Z")
            report = prepare_shortlist(root / "output", *source)
            self.assertEqual(report["archive_sha256"], sha256(content))
            self.assertEqual(report["candidate_count"], 150)
            self.assertEqual((root / "output/source.zip").read_bytes(), content)
            self.assertEqual(report["candidate_endpoints_visited"], 0)
            with (root / "output/review-worksheet.csv").open(newline="") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 150)
            self.assertEqual({row["verdict"] for row in rows}, {"pending"})
            with (root / "output/shared-hosting-worksheet.csv").open(newline="") as f:
                self.assertEqual(list(csv.DictReader(f)), [])
            with self.assertRaises(ValueError):
                prepare_shortlist(root / "output", *source)
            with self.assertRaises(ValueError):
                local_source(root / "original.zip", root / "original.json", "WRONG", "2026-10-01T01:00:00Z")

    def test_metadata_requires_identity_availability_configuration_and_created_on(self):
        for change in ({"list_id": "../bad"}, {"available": False}, {"failed": True},
                       {"configuration": None}, {"created_on": "nonsense"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                metadata_identity(metadata(**change))

    def test_official_fetch_paces_requests_and_respects_retry_after(self):
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b"ok"
        opener = MagicMock()
        opener.open.side_effect = [urllib.error.HTTPError("https://tranco-list.eu/api/lists/date/latest", 429, "rate limited", {"Retry-After": "3"}, None), response, response]
        with patch("study.review_workflow._last_fetch_time", None), patch("study.review_workflow.time.monotonic", return_value=100.0), \
                patch("study.review_workflow.time.sleep") as sleep, patch("study.review_workflow.urllib.request.build_opener", return_value=opener):
            self.assertEqual(fetch_official("https://tranco-list.eu/api/lists/date/latest", 100), b"ok")
            self.assertEqual(fetch_official("https://tranco-list.eu/api/lists/id/ABC12", 100), b"ok")
            self.assertEqual([call.args[0] for call in sleep.call_args_list], [3.0, 1.1])
            self.assertEqual(opener.open.call_count, 3)

    def test_official_fetch_retries_are_bounded_and_long_retry_after_is_preserved(self):
        for code, retry_after, attempts in ((429, None, 3), (503, "2", 3), (429, "120", 1), (404, None, 1)):
            opener = MagicMock()
            opener.open.side_effect = urllib.error.HTTPError("https://tranco-list.eu/api/lists/date/latest", code, "unavailable", {"Retry-After": retry_after} if retry_after else {}, None)
            with self.subTest(code=code, retry_after=retry_after), patch("study.review_workflow._last_fetch_time", None), \
                    patch("study.review_workflow.time.monotonic", return_value=100.0), patch("study.review_workflow.time.sleep") as sleep, \
                    patch("study.review_workflow.urllib.request.build_opener", return_value=opener), self.assertRaises(urllib.error.HTTPError):
                fetch_official("https://tranco-list.eu/api/lists/date/latest", 100)
            self.assertEqual(opener.open.call_count, attempts)
            self.assertTrue(all(call.args[0] <= 30 for call in sleep.call_args_list))


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def worksheet(self, rows, name="review.csv"):
        path = self.root / name
        write_csv(path, REVIEW_FIELDS, rows)
        return path

    def test_export_accepts_only_complete_independent_reviews_and_replays(self):
        rows = [accepted_review(), accepted_review("pending.com", verdict="pending", independent_review=""),
                accepted_review("rejected.com", verdict="rejected", evidence_reference="")]
        path = self.worksheet(rows)
        output = self.root / "legitimate.csv"
        audit = export_reviews([path], output)
        replayed = validate_export(output, self.root / "legitimate.csv.audit.json")
        self.assertEqual(replayed, audit)
        self.assertEqual(audit["accepted"], 1)
        self.assertEqual(audit["excluded"], {"pending": 1, "rejected": 1})
        self.assertEqual(audit["input_files"][0]["sha256"], sha256(path.read_bytes()))
        with output.open(newline="") as f:
            reader = csv.DictReader(f)
            self.assertEqual(reader.fieldnames, list(EXPORT_FIELDS))
            exported = list(reader)
        self.assertEqual(exported[0]["label"], "legitimate")
        self.assertEqual(exported[0]["confidence"], "verified")
        self.assertEqual(exported[0]["observed_at"], "2026-10-01T01:00:00+00:00")
        with self.assertRaises(ValueError):
            export_reviews([path], output)

    def test_incomplete_or_nonindependent_accepted_reviews_fail_without_export(self):
        for field in ("endpoint_url", "service_category", "tenant_or_brand", "reviewer", "reviewed_at", "evidence_reference", "independent_review"):
            with self.subTest(field=field):
                path = self.worksheet([accepted_review(**{field: ""})], field + ".csv")
                with self.assertRaises(ValueError):
                    export_reviews([path], self.root / (field + "-export.csv"))
                self.assertFalse((self.root / (field + "-export.csv")).exists())
        with self.assertRaises(ValueError):
            validate_reviews([self.worksheet([accepted_review(independent_review="false")], "false.csv")])

    def test_invalid_timestamps_require_explicit_past_utc(self):
        for value in ("yesterday", "2026-10-01T00:00:00", "2026-10-01T00:00:00+08:00", "2099-01-01T00:00:00Z"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                utc_time(value, "reviewed_at")

    def test_private_local_userinfo_ports_and_ambiguous_urls_are_rejected(self):
        for value in ("http://127.0.0.1/", "http://10.0.0.1/", "http://169.254.169.254/", "http://[::ffff:127.0.0.1]/",
                      "http://[::1]/", "http://192.0.2.1/", "http://localhost/", "http://x.local/", "http://x.internal/",
                      "http://user:pass@example.com/", "https://example.com:444/", "file:///tmp/a", "https://example.com/a b",
                      "https://example.com\\@bad.com/", "https://example.com/\nsecret"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_endpoint(value)

    def test_identity_stratum_rank_and_unknown_verdict_rejected(self):
        for i, change in enumerate(({"rank": "10001"}, {"source_id": "unbound"}, {"stratum": "other"},
                                    {"list_id": ""}, {"source": "untrusted"}, {"verdict": "maybe"},
                                    {"endpoint_url": "https://unrelated.com/account"})):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_reviews([self.worksheet([accepted_review(**change)], f"bad{i}.csv")])

    def test_same_group_subdomain_allowed_duplicate_endpoint_rejected(self):
        accepted, audit = validate_reviews([self.worksheet([accepted_review(endpoint_url="https://accounts.example.com/login")])])
        self.assertEqual(audit["domain_or_tenant_groups"], 1)
        self.assertEqual(accepted[0]["url"], "https://accounts.example.com/login")
        with self.assertRaises(ValueError):
            validate_reviews([self.worksheet([accepted_review(), accepted_review(endpoint_url="https://EXAMPLE.com:443/account#fragment")], "duplicates.csv")])

    def test_shared_hosting_tenant_groups_and_cross_tenant_rejection(self):
        rows = [accepted_review("one.github.io", rank="", stratum="shared-hosting", source="shared-hosting", list_id="", source_id="log:one"),
                accepted_review("two.github.io", rank="", stratum="shared-hosting", source="shared-hosting", list_id="", source_id="log:two")]
        _, audit = validate_reviews([self.worksheet(rows)])
        self.assertEqual(audit["domain_or_tenant_groups"], 2)
        rows[0]["endpoint_url"] = "https://two.github.io/account"
        with self.assertRaises(ValueError):
            validate_reviews([self.worksheet(rows, "cross.csv")])

    def test_malformed_worksheet_extra_missing_columns_and_uneven_rows(self):
        for i, text in enumerate(("candidate_domain,verdict\nexample.com,accepted\n", ",".join(REVIEW_FIELDS) + "\na,b\n",
                                  ",".join(REVIEW_FIELDS) + ",extra\n")):
            path = self.root / f"malformed{i}.csv"
            path.write_text(text)
            with self.assertRaises(ValueError):
                validate_reviews([path])

    def test_export_tampering_or_changed_retained_review_is_rejected(self):
        path = self.worksheet([accepted_review()])
        output = self.root / "export.csv"
        audit = export_reviews([path], output)
        manifest = self.root / "export.csv.audit.json"
        original = output.read_bytes()
        output.write_bytes(original.replace(b"verified", b"candidate"))
        with self.assertRaises(ValueError):
            validate_export(output, manifest)
        output.write_bytes(original)
        audit["accepted_reviews"][0]["independent_review"] = "false"
        manifest.write_text(json.dumps(audit))
        with self.assertRaises(ValueError):
            validate_export(output, manifest)


if __name__ == "__main__":
    unittest.main()
