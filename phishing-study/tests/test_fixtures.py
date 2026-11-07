import json
import http.client
import unittest
import urllib.request
from urllib.parse import urlsplit
from study.fixtures import FixtureServer


class FixtureHTTPTests(unittest.TestCase):
    def test_fixture_server_redirect_and_script(self):
        with FixtureServer() as fixture:
            with urllib.request.urlopen(fixture.url+"/redirect", timeout=3) as response:
                self.assertEqual(response.status, 200)
                self.assertIn("password", response.read().decode())
                self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
            with urllib.request.urlopen(fixture.url+"/script.js", timeout=3) as response:
                self.assertIn("fetch", response.read().decode())

    def test_fixture_synthetic_post(self):
        with FixtureServer() as fixture:
            request = urllib.request.Request(fixture.url+"/submit", data=b"synthetic=invalid", method="POST")
            with urllib.request.urlopen(request, timeout=3) as response:
                self.assertEqual(json.loads(response.read()), {"synthetic":True})

    def test_escape_target_is_owned_loopback_with_counted_requests(self):
        with FixtureServer() as fixture:
            target = urlsplit(fixture.denied_url)
            self.assertEqual(target.hostname, "127.0.0.1")
            self.assertNotEqual(target.port, urlsplit(fixture.url).port)
            self.assertEqual(fixture.denied_hits, 0)
            connection = http.client.HTTPConnection("127.0.0.1", urlsplit(fixture.url).port, timeout=3)
            try:
                connection.request("GET", "/escape")
                response = connection.getresponse()
                self.assertEqual(response.status, 302)
                self.assertEqual(response.getheader("Location"), fixture.denied_url)
                response.read()
            finally:
                connection.close()
            self.assertEqual(fixture.denied_hits, 0)
            with urllib.request.urlopen(fixture.denied_url, timeout=3) as response:
                self.assertEqual(response.status, 200)
            self.assertEqual(fixture.denied_hits, 1)
            with self.assertRaises(AttributeError):
                fixture.denied_url = "http://example.invalid/"

    def test_chain_and_duplicate_locations_are_only_owned(self):
        with FixtureServer() as fixture:
            with urllib.request.urlopen(fixture.url + "/redirect-chain/4", timeout=3) as response:
                self.assertEqual(response.status, 200)
            hits = fixture.hit_snapshot()
            self.assertTrue(all(hits.get(("GET", f"/redirect-chain/{remaining}")) == 1 for remaining in range(5)))
            connection = http.client.HTTPConnection("127.0.0.1", urlsplit(fixture.url).port, timeout=3)
            try:
                connection.request("GET", "/ambiguous-redirect")
                response = connection.getresponse()
                self.assertEqual(response.status, 302)
                locations = [value for name, value in response.getheaders() if name.lower() == "location"]
                self.assertEqual(locations, ["/clean", fixture.denied_url])
                response.read()
            finally:
                connection.close()
            self.assertEqual(fixture.denied_hits, 0)
