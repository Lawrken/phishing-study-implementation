import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import gzip
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

from study.config import Config, load
from study.urls import canonical_url, digest, domain_group, safe_url
from study.queue import Queue
from study.policy import Policy, public_ip, check_live_environment
from study.sources import phishtank, openphish, tranco, read_csv
from study.collector import header_features, save
from study.features import FEATURES, extract
from study.export import export, split_groups
from study.analysis import analyze, bh, train


def candidate(url="https://example.com/login", label="phishing", **extra):
    return {"url": url, "label": label, "confidence": "verified", "source": "test", **extra}


class URLTests(unittest.TestCase):
    def test_normalization(self):
        self.assertEqual(canonical_url(" HTTPS://Example.COM:443/a?b=2&a=1#frag "), "https://example.com/a?b=2&a=1")
        self.assertNotEqual(canonical_url("https://example.com/?a=1&b=2"), canonical_url("https://example.com/?b=2&a=1"))

    def test_userinfo_and_invalid_schemes(self):
        for value in ("https://user:pass@example.com", "file:///etc/passwd", "javascript:alert(1)", "https://example.com:bad", "https://example.com/\nsecret"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                canonical_url(value)

    def test_idn_and_ipv6(self):
        self.assertEqual(canonical_url("https://bücher.de"), "https://xn--bcher-kva.de/")
        self.assertEqual(canonical_url("http://[::1]:80"), "http://[::1]/")

    def test_domain_and_private_tenant_groups(self):
        self.assertEqual(domain_group("https://a.b.example.co.uk/"), "example.co.uk")
        self.assertNotEqual(domain_group("https://tenant1.github.io"), domain_group("https://tenant2.github.io"))

    def test_redacted_url(self):
        data = json.dumps(safe_url("https://example.com/SECRET-PATH?token=SECRET-QUERY#SECRET-FRAGMENT"))
        self.assertNotIn("SECRET", data)
        self.assertIn("example.com", data)


class ConfigTests(unittest.TestCase):
    def test_fingerprint(self):
        self.assertEqual(Config().fingerprint, Config().fingerprint)
        self.assertNotEqual(Config().fingerprint, replace(Config(), route_id="different").fingerprint)

    def test_fixture_validation(self):
        Config(profile="fixture", fixture_origins=["http://127.0.0.1:8000"]).validate()
        for c in (Config(profile="live", interaction="fixture_submit"), Config(workers=0),
                  Config(lease_seconds=100), Config(profile="fixture"), Config(proxy_required=True)):
            with self.assertRaises(ValueError):
                c.validate()

    def test_proxy_no_fallback_or_leaking_userinfo(self):
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(ValueError):
                Config(proxy_required=True, route_id="approved").proxy()
        with patch.dict("os.environ", {"STUDY_PROXY_SERVER": "http://secret:secret@example.com:8080"}, clear=True):
            with self.assertRaises(ValueError):
                Config(proxy_required=True, route_id="approved").proxy()

    def test_proxy_secret_not_fingerprinted(self):
        with patch.dict("os.environ", {"STUDY_PROXY_SERVER": "http://example.com:8080", "STUDY_PROXY_PASSWORD": "SECRET"}, clear=True):
            c = Config(proxy_required=True, route_id="approved")
            self.assertEqual(c.proxy()["password"], "SECRET")
            self.assertNotIn("SECRET", c.fingerprint)

    def test_live_preflight_requires_isolation(self):
        with patch("os.geteuid", return_value=1000):
            with self.assertRaises(RuntimeError):
                check_live_environment(Config(network_isolation_verified=False))


class PolicyTests(unittest.IsolatedAsyncioTestCase):
    def test_non_public_addresses(self):
        for address in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "0.0.0.0", "::1", "fc00::1", "::ffff:127.0.0.1", "192.0.2.1"):
            self.assertFalse(public_ip(address), address)
        self.assertTrue(public_ip("8.8.8.8"))

    async def test_fixture_origin_guard(self):
        p = Policy(Config(profile="fixture", fixture_origins=["http://127.0.0.1:8000"]))
        self.assertTrue((await p.check("http://127.0.0.1:8000/a"))[0])
        for url in ("http://127.0.0.1:8001/a", "http://169.254.169.254/a", "https://example.com", "file:///etc/passwd"):
            self.assertFalse((await p.check(url))[0])

    async def test_mixed_dns_fails_closed(self):
        addresses = [(2,1,6,"",("8.8.8.8",443)), (2,1,6,"",("10.0.0.1",443))]
        with patch("study.policy.socket.getaddrinfo", return_value=addresses):
            self.assertFalse((await Policy(Config()).check("https://example.com/"))[0])

    async def test_public_dns(self):
        with patch("study.policy.socket.getaddrinfo", return_value=[(2,1,6,"",("8.8.8.8",443))]):
            self.assertTrue((await Policy(Config()).check("https://example.com/"))[0])

    async def test_dns_error(self):
        with patch("study.policy.socket.getaddrinfo", side_effect=OSError):
            self.assertEqual((await Policy(Config()).check("https://example.com/"))[1], "dns_unavailable")


class QueueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.q = Queue(self.temp.name)
        self.c = Config(domain_cooldown_seconds=0, retry_base_seconds=0)
        self.rid = self.q.start_run(self.c)

    def tearDown(self):
        self.temp.cleanup()

    def test_duplicate_preserves_provenance(self):
        self.q.ingest([candidate()])
        stats = self.q.ingest([candidate(source="second")])
        self.assertEqual(stats["duplicate"], 1)
        with self.q.connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM candidates").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM provenance").fetchone()[0], 2)

    def test_conflict_is_quarantined(self):
        self.q.ingest([candidate()])
        self.q.ingest([candidate(label="legitimate")])
        self.assertIsNone(self.q.claim(self.rid, self.c))
        self.assertEqual(self.q.status()["states"][0]["state"], "conflict")

    def test_atomic_batch_validation(self):
        with self.assertRaises(ValueError):
            self.q.ingest([candidate(), candidate("file:///bad")])
        self.assertEqual(self.q.status()["states"], [])

    def test_candidate_label_upgrade_independent_of_review(self):
        self.q.ingest([candidate(confidence="candidate")])
        self.q.ingest([candidate()])
        with self.q.connect() as db:
            row = db.execute("SELECT * FROM candidates").fetchone()
            self.assertEqual(row["confidence"], "verified")
            self.assertIsNone(row["review_disposition"])

    def test_one_active_per_domain(self):
        self.q.ingest([candidate(), candidate("https://sub.example.com/other")])
        self.assertIsNotNone(self.q.claim(self.rid, self.c))
        self.assertIsNone(self.q.claim(self.rid, self.c))

    def test_atomic_claim_under_concurrent_workers(self):
        self.q.ingest([candidate(f"https://d{i}.example/login") for i in range(10)])
        with ThreadPoolExecutor(max_workers=6) as pool:
            items = list(pool.map(lambda _: self.q.claim(self.rid, self.c), range(10)))
        ids = [r["id"] for r in items if r]
        self.assertEqual(len(ids), 10)
        self.assertEqual(len(set(ids)), 10)

    def test_class_interleaving(self):
        self.q.ingest([candidate("https://phish.example/a"), candidate("https://legit.example/a", "legitimate")])
        first = self.q.claim(self.rid, self.c)
        second = self.q.claim(self.rid, self.c)
        self.assertNotEqual(first["label"], second["label"])

    def test_retry_limit(self):
        self.q.ingest([candidate()])
        for n in range(3):
            item = self.q.claim(self.rid, self.c, now=time.time()+1)
            self.assertEqual(item["attempt_number"], n+1)
            self.q.finish(item, "timeout", False, None, self.c, transient=True)
        self.assertIsNone(self.q.claim(self.rid, self.c, now=time.time()+1))
        self.assertEqual(self.q.status()["attempts"], 3)

    def test_retry_after(self):
        self.q.ingest([candidate()])
        item = self.q.claim(self.rid, self.c)
        self.q.finish(item, "http_transient", False, None, self.c, transient=True, retry_after=100)
        self.assertIsNone(self.q.claim(self.rid, self.c, now=time.time()+2))

    def test_interrupted_recovery_and_stale_worker(self):
        self.q.ingest([candidate()])
        old = self.q.claim(self.rid, self.c)
        now = time.time()+self.c.lease_seconds+1
        self.assertEqual(self.q.recover(now), 1)
        new = self.q.claim(self.rid, self.c, now)
        self.assertFalse(self.q.finish(old, "captured", True, "old.json", self.c))
        self.assertTrue(self.q.finish(new, "captured", True, "new.json", self.c))

    def test_last_interruption_exhausts_retry_budget(self):
        c = replace(self.c, retries=0)
        self.q.ingest([candidate()])
        self.q.claim(self.rid, c)
        self.q.recover(time.time()+self.c.lease_seconds+1, retries=0)
        self.assertEqual(self.q.status()["states"][0]["state"], "done")

    def test_heartbeat_keeps_current_lease_and_rejects_stale_token(self):
        self.q.ingest([candidate()])
        item = self.q.claim(self.rid,self.c)
        future = time.time()+self.c.lease_seconds
        self.assertTrue(self.q.heartbeat(item,self.c.lease_seconds,now=future))
        self.assertEqual(self.q.recover(future+1),0)
        self.q.finish(item,"captured",True,None,self.c)
        self.assertFalse(self.q.heartbeat(item,self.c.lease_seconds))

    def test_global_attempt_budget(self):
        c = replace(self.c, max_attempts=1)
        self.q.ingest([candidate(), candidate("https://other.example/a")])
        self.assertIsNotNone(self.q.claim(self.rid, c))
        self.assertIsNone(self.q.claim(self.rid, c))

    def test_usable_class_cap(self):
        c = replace(self.c, usable_per_class=1)
        self.q.ingest([candidate(), candidate("https://other.example/a")])
        item = self.q.claim(self.rid, c)
        self.q.finish(item, "captured", True, None, c)
        self.assertIsNone(self.q.claim(self.rid, c))

    def test_resume_requires_same_config(self):
        self.assertEqual(self.q.start_run(self.c, self.rid), self.rid)
        with self.assertRaises(ValueError):
            self.q.start_run(replace(self.c, workers=3), self.rid)
        self.q.finish_run(self.rid, "done")
        with self.assertRaises(ValueError):
            self.q.start_run(self.c, self.rid)


class SourceTests(unittest.TestCase):
    def test_phishtank_filters_verified_online(self):
        rows = [{"url": "https://example.com", "phish_id": 1, "verified": "yes", "online": "yes"},
                {"url": "https://bad.example", "phish_id": 2, "verified": "no", "online": "yes"}]
        result = list(phishtank(gzip.compress(json.dumps(rows).encode())))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["confidence"], "verified")

    def test_openphish_keeps_feed_confidence(self):
        result = list(openphish(b"https://example.com/a\n\nhttps://example.org/b\n"))
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["confidence"], "feed")

    def test_tranco_is_candidate_and_accepts_zip(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("top-1m.csv", "1,example.com\n2,example.org\n")
        result = list(tranco(stream.getvalue()))
        self.assertEqual(result[0]["confidence"], "candidate")
        self.assertEqual(result[0]["url"], "https://example.com/")

    def test_csv_defaults(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)/"c.csv"
            path.write_text("url,label\nhttps://example.com,legitimate\n")
            self.assertEqual(list(read_csv(path))[0]["confidence"], "candidate")


class ExportTests(unittest.TestCase):
    def test_headers_and_events_redact_secrets(self):
        features = header_features({"Set-Cookie":"session=SECRET; Secure; HttpOnly", "Authorization":"SECRET", "Location":"/SECRET?token=SECRET", "Content-Type":"text/html"})
        self.assertNotIn("SECRET", json.dumps(features))
        self.assertTrue(features["cookie_secure_present"])

    def test_missing_is_not_zero(self):
        result = extract({"groups": {"dom": {"measured": True, "form_count": 0}, "tls": {"measured": False, "missing_reason": "not_https", "san_count": 0}}})
        self.assertEqual(result["form_count"], 0)
        self.assertIsNone(result["tls_san_count"])
        self.assertEqual(result["tls_san_count__missing_reason"], "not_https")

    def test_group_components_prevent_domain_and_template_leakage(self):
        rows = [{"domain_group":"a.com","manual_split_group":"template1"}, {"domain_group":"b.com","manual_split_group":"template1"},
                {"domain_group":"b.com","manual_split_group":"template2"}, {"domain_group":"c.com","manual_split_group":"template2"}, {"domain_group":"d.com","manual_split_group":None}]
        split_groups(rows)
        self.assertEqual(len({r["split_group"] for r in rows[:4]}), 1)
        self.assertNotEqual(rows[0]["split_group"], rows[4]["split_group"])

    def test_export_review_gate_and_analysis_no_claims(self):
        with tempfile.TemporaryDirectory() as temp:
            q = Queue(Path(temp)/"data")
            c = Config(domain_cooldown_seconds=0)
            q.ingest([candidate()])
            item = q.claim(q.start_run(c), c)
            record = {"attempt_id": item["attempt_id"], "captured_at":"2026-10-10T00:00:00Z", "config_hash":c.fingerprint,
                      "profile":"fixture", "route_id":"direct", "region":"local", "groups":{"dom":{"measured":True,"form_count":0}}}
            artifact = save(q.root, record, [{"kind":"request","url":safe_url("https://example.com/SECRET?token=SECRET")}])
            q.finish(item, "captured", True, artifact, c)
            dest = Path(temp)/"export"
            self.assertEqual(export(q, dest)["research_eligible"], 0)
            q.review(item["id"], "active")
            self.assertEqual(export(q, dest)["research_eligible"], 1)
            report = analyze(dest/"features.parquet", Path(temp)/"report", bootstrap=10)
            self.assertEqual(report["real_reviewed_rows"], 0)
            self.assertEqual(report["status"], "insufficient_reviewed_live_data")
            self.assertNotIn("SECRET", (dest/"features.parquet").read_bytes().decode("latin1"))
            with self.assertRaises(ValueError):
                train(dest/"features.parquet", Path(temp)/"models")

    def test_fdr_adjustment(self):
        result = bh([.01, .04, .03])
        self.assertAlmostEqual(result[0], .03)
        self.assertAlmostEqual(result[1], .04)


if __name__ == "__main__":
    unittest.main()
