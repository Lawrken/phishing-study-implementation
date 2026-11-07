"""One versioned configuration for both classes. Secrets come from environment."""
from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path
import tomllib
from urllib.parse import urlsplit


@dataclass
class Config:
    profile: str = "live"
    workers: int = 2
    navigation_seconds: float = 30
    observation_seconds: float = 10
    attempt_seconds: float = 90
    lease_seconds: float = 180
    domain_cooldown_seconds: float = 10
    retries: int = 2
    retry_base_seconds: float = 60
    max_hours: float = 6
    max_attempts: int = 5000
    usable_per_class: int = 1000
    max_requests: int = 2000
    max_transfer_bytes: int = 50_000_000
    max_artifact_bytes: int = 10_000_000_000
    min_free_disk_bytes: int = 5_000_000_000
    max_dom_nodes: int = 100000
    viewport_width: int = 1365
    viewport_height: int = 768
    locale: str = "en-US"
    timezone: str = "UTC"
    proxy_required: bool = False
    route_id: str = "direct"
    region: str = "unspecified"
    network_isolation_verified: bool = False
    wait_for_sources: bool = False
    fixture_origins: list[str] = field(default_factory=list)
    interaction: str = "none"
    seed: int = 20261010

    def validate(self):
        if self.profile not in {"live", "fixture"}:
            raise ValueError("profile must be live or fixture")
        for key in ("workers", "navigation_seconds", "attempt_seconds", "lease_seconds", "max_hours",
                    "max_attempts", "usable_per_class", "max_requests", "max_transfer_bytes",
                    "max_artifact_bytes", "max_dom_nodes", "viewport_width", "viewport_height"):
            if getattr(self, key) <= 0:
                raise ValueError(f"{key} must be positive")
        if self.observation_seconds < 0 or self.domain_cooldown_seconds < 0 or self.retries < 0:
            raise ValueError("negative durations or retries")
        if self.lease_seconds <= self.attempt_seconds + 15:
            raise ValueError("lease_seconds must exceed attempt_seconds + 15 seconds for teardown")
        if self.interaction not in {"none", "fixture_submit"}:
            raise ValueError("unknown interaction policy")
        if self.profile == "live" and self.interaction != "none":
            raise ValueError("synthetic submissions are restricted to owned fixtures")
        if self.profile == "fixture" and not self.fixture_origins:
            raise ValueError("fixture profile requires exact fixture origins")
        for origin in self.fixture_origins:
            p = urlsplit(origin)
            if p.scheme not in {"http", "https"} or p.hostname not in {"127.0.0.1", "localhost", "::1"} or p.path not in {"", "/"} or p.query or p.username:
                raise ValueError("fixture origins must be explicit loopback origins")
        if self.proxy_required and self.route_id == "direct":
            raise ValueError("proxy_required needs a non-direct route_id")

    @property
    def fingerprint(self):
        return hashlib.sha256(json.dumps(asdict(self), sort_keys=True).encode()).hexdigest()

    def proxy(self):
        server = os.environ.get("STUDY_PROXY_SERVER")
        if self.proxy_required and not server:
            raise ValueError("STUDY_PROXY_SERVER is required; direct fallback is disabled")
        if not self.proxy_required and server:
            raise ValueError("proxy supplied but proxy_required=false; set an explicit proxy route")
        if not server:
            return None
        p = urlsplit(server)
        if p.scheme not in {"http", "https", "socks5"} or not p.hostname or p.username or p.password or p.query:
            raise ValueError("invalid proxy server; supply credentials through separate environment variables")
        out = {"server": server}
        for var, key in (("STUDY_PROXY_USERNAME", "username"), ("STUDY_PROXY_PASSWORD", "password")):
            if os.environ.get(var):
                out[key] = os.environ[var]
        return out


def load(path=None):
    c = Config(**tomllib.loads(Path(path).read_text())) if path else Config()
    c.validate()
    return c
