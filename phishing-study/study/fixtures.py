"""Owned synthetic endpoints. Nothing served here is a real phishing website."""
import csv
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
import time
from urllib.parse import urlsplit

LOGIN = """<!doctype html><html><head><title>Owned research fixture</title><script src='/script.js' defer></script></head>
<body data-study-fixture><h1>Synthetic {kind} fixture</h1><form method='post' action='/submit'>
<label>Email <input type='email' name='email'></label><label>Password <input type='password' name='password'></label>
<button type='submit'>Submit synthetic values</button></form><div id='result'></div></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, body, content_type="text/html", extra=None):
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        path = urlsplit(self.path).path
        self.server.fixture.record_hit("GET", path)
        if path == "/redirect":
            self.reply(302, "", extra={"Location": "/redirect2?token=SECRET-REDIRECT"})
        elif path == "/redirect2":
            self.reply(301, "", extra={"Location": "/legitimate/login"})
        elif path in {"/legitimate/login", "/phishing/login"}:
            headers = {"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"} if path.startswith("/legitimate") else {}
            headers["Set-Cookie"] = "fixture_token=SECRET-COOKIE; HttpOnly; SameSite=Lax"
            self.reply(200, LOGIN.format(kind="legitimate" if path.startswith("/legitimate") else "phishing"), extra=headers)
        elif path == "/script.js":
            self.reply(200, """fetch('/api/status?token=SECRET-QUERY');
const f=document.querySelector('form'); if(f) f.addEventListener('submit',async e=>{e.preventDefault();
await fetch('/submit',{method:'POST',body:new FormData(f)});localStorage.setItem('fixture','synthetic');
document.querySelector('#result').textContent='Synthetic submission recorded';});""", "application/javascript")
        elif path == "/api/status" or path.startswith("/api/normalization/"):
            self.reply(200, '{"fixture":true}', "application/json")
        elif path == "/challenge":
            self.reply(200, "<title>Just a moment</title><p>Verify you are human</p>")
        elif path == "/takedown":
            self.reply(200, "<p>This site has been taken down</p>")
        elif path == "/parked":
            self.reply(200, "<p>This domain is for sale</p>")
        elif path == "/rate-limit":
            self.reply(429, "<p>Try later</p>", extra={"Retry-After": "1"})
        elif path == "/fanout":
            self.reply(200, "<script>for(let i=0;i<100;i++)fetch('/api/status?i='+i)</script><p>Budget fixture</p>")
        elif path == "/escape":
            # The policy-denied destination is another server we own. Even a
            # broken guard never sends a fixture request outside loopback.
            self.reply(302, "", extra={"Location": self.server.fixture.denied_url})
        elif path in {"/redirect-fetch", "/escape-fetch"}:
            target = "/redirect-api" if path == "/redirect-fetch" else "/escape"
            self.reply(200, f"<script>fetch('{target}').catch(()=>{{}})</script><p>Fetch redirect fixture</p>")
        elif path == "/redirect-api":
            self.reply(302, "", extra={"Location": "/api/status?token=SECRET-REDIRECT-FETCH"})
        elif path == "/redirect-normalized-fetch":
            self.reply(200, "<script>Promise.all([fetch('/normalized-query-redirect'),fetch('/normalized-path-redirect')]).catch(()=>{})</script><p>Browser URL normalization fixture</p>")
        elif path == "/normalized-query-redirect":
            self.reply(302, "", extra={"Location": "/api/status?note=space value"})
        elif path == "/normalized-path-redirect":
            self.reply(302, "", extra={"Location": "/api/normalization/café?note=space value"})
        elif path in {"/redirect-frame", "/escape-frame"}:
            target = "/frame-redirect" if path == "/redirect-frame" else "/escape"
            self.reply(200, f"<iframe src='{target}'></iframe><p>Frame redirect fixture</p>")
        elif path == "/frame-redirect":
            self.reply(302, "", extra={"Location": "/clean"})
        elif path == "/escape-popup":
            self.reply(200, "<script>window.open('/escape')</script><p>Popup redirect fixture</p>")
        elif path == "/ambiguous-redirect":
            self.send_response(302)
            self.send_header("Location", "/clean")
            self.send_header("Location", self.server.fixture.denied_url)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path.startswith("/redirect-chain/"):
            try:
                remaining = int(path.rsplit("/", 1)[1])
            except ValueError:
                self.reply(400, "<p>Invalid fixture chain</p>")
                return
            if 0 < remaining <= 20:
                self.reply(302, "", extra={"Location": f"/redirect-chain/{remaining - 1}"})
            elif remaining == 0:
                self.reply(200, "<p>End of owned redirect chain</p>")
            else:
                self.reply(400, "<p>Invalid fixture chain</p>")
        elif path.startswith("/method-test/") and path.rsplit("/", 1)[1] in {"303", "307"}:
            status = path.rsplit("/", 1)[1]
            self.reply(200, f"<script>fetch('/method/{status}',{{method:'POST',body:'synthetic=invalid'}}).then(r=>r.json()).catch(()=>{{}})</script><p>Native redirect method fixture</p>")
        elif path == "/method/final":
            self.reply(200, '{"synthetic":true}', "application/json")
        elif path == "/slow":
            time.sleep(2)
            self.reply(200, "<p>Slow fixture</p>")
        elif path == "/clean":
            self.reply(200, "<p>Clean context fixture</p>")
        else:
            self.reply(404, "<p>Missing fixture</p>")

    def do_POST(self):
        # Discard synthetic input; no body, credential, or auth logging.
        path = urlsplit(self.path).path
        self.server.fixture.record_hit("POST", path)
        self.rfile.read(min(10000, int(self.headers.get("Content-Length", 0))))
        if path in {"/method/303", "/method/307"}:
            self.reply(int(path.rsplit("/", 1)[1]), "", extra={"Location": "/method/final"})
        else:
            self.reply(200, '{"synthetic":true}', "application/json")


class DeniedHandler(BaseHTTPRequestHandler):
    """Count escape requests without storing bodies, headers, or query values."""

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.fixture.record_denied_hit()
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        self.rfile.read(min(10000, int(self.headers.get("Content-Length", 0))))
        self.do_GET()


class FixtureServer:
    def __enter__(self):
        self._lock = threading.Lock()
        self._hits = Counter()
        self._denied_hits = 0
        self.denied_server = ThreadingHTTPServer(("127.0.0.1", 0), DeniedHandler)
        self.denied_server.fixture = self
        self.denied_server.daemon_threads = True
        self.denied_thread = threading.Thread(target=self.denied_server.serve_forever, daemon=True)
        self.denied_thread.start()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.fixture = self
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.denied_server.shutdown()
        self.denied_server.server_close()
        self.denied_thread.join(timeout=3)

    def record_hit(self, method, path):
        with self._lock:
            self._hits[(method, path)] += 1

    def record_denied_hit(self):
        with self._lock:
            self._denied_hits += 1

    @property
    def denied_url(self):
        return f"http://127.0.0.1:{self.denied_server.server_port}/blocked-destination"

    @property
    def denied_hits(self):
        with self._lock:
            return self._denied_hits

    def hit_snapshot(self):
        with self._lock:
            return dict(self._hits)

    def write_inputs(self, destination):
        out = Path(destination)
        out.mkdir(parents=True, exist_ok=True)
        with (out / "candidates.csv").open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["url", "label", "confidence", "source"])
            writer.writeheader()
            for path, label in (("/legitimate/login", "legitimate"), ("/phishing/login", "phishing"), ("/redirect", "legitimate"),
                                ("/challenge", "phishing"), ("/takedown", "phishing"), ("/parked", "phishing")):
                writer.writerow({"url": self.url+path, "label": label, "confidence": "verified", "source": "owned-synthetic-fixture"})
        config = f'''profile = "fixture"
fixture_origins = ["{self.url}"]
workers = 2
navigation_seconds = 5
observation_seconds = 0.5
attempt_seconds = 15
lease_seconds = 45
domain_cooldown_seconds = 0
retry_base_seconds = 0.1
max_hours = 0.05
max_attempts = 20
usable_per_class = 50
min_free_disk_bytes = 1000000
interaction = "fixture_submit"
'''
        (out / "fixture.toml").write_text(config)
        return {"origin": self.url, "config": str(out / "fixture.toml"), "candidates": str(out / "candidates.csv")}
