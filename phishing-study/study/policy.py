"""Defense in depth. Browser routing does NOT replace an egress firewall."""
import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit
from .urls import origin


def public_ip(address):
    try:
        addr = ipaddress.ip_address(address.split("%")[0])
        # IPv4-mapped IPv6 must inherit the IPv4 restriction.
        if getattr(addr, "ipv4_mapped", None):
            addr = addr.ipv4_mapped
        return addr.is_global
    except ValueError:
        return False


class Policy:
    def __init__(self, config):
        self.config = config
        self.allowed_origins = {origin(v) for v in config.fixture_origins}
        self.cache = {}

    async def check(self, url):
        try:
            p = urlsplit(url)
            if p.scheme not in {"http", "https"} or not p.hostname or p.username or p.password:
                return False, "scheme_or_userinfo"
            target = origin(url)
            if self.config.profile == "fixture":
                return (True, "owned_fixture") if target in self.allowed_origins else (False, "outside_fixture_origin")
            if p.port not in {None, 80, 443}:
                return False, "non_web_port"
            host = p.hostname.lower().rstrip(".")
            if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
                return False, "local_hostname"
            if host in self.cache:
                return self.cache[host]
            addresses = await asyncio.wait_for(asyncio.to_thread(socket.getaddrinfo, host, p.port or 443, 0, socket.SOCK_STREAM), timeout=5)
            result = (bool(addresses) and all(public_ip(r[4][0]) for r in addresses), "public_dns")
            if not result[0]:
                result = False, "non_public_dns"
            self.cache[host] = result
            return result
        except (ValueError, OSError, asyncio.TimeoutError):
            return False, "dns_unavailable"


def check_live_environment(config):
    import os
    if config.profile == "live":
        if os.geteuid() == 0:
            raise RuntimeError("live collection requires a non-root user and Chromium sandbox")
        if not config.network_isolation_verified:
            raise RuntimeError("live collection requires a verified network egress policy; see RUNBOOK.md")
    config.proxy()  # fail before any jobs are claimed
